"""FRR NOS provider (Phase 2 §4.5-b, REQ-45b-3; design §3.3).

Carries FRR's NOS content behind the provider contract: identity, capability
declarations, the candidate-surface declaration, and -- as the §4.5-b
extraction lands -- the collection seam (`collect`), the status legs, and the
`cassian collect` target set. Core owns invariants, predicate evaluation,
verdicts, rendering, and artifacts (design §5); this module never decides
pass/fail.

Import floor (REQ-45b-3/-17): stdlib + the types leaf, plus `cassian_common`
for the ruled shared helpers only (A-H3/A-H4: `_canonical_community_token`,
`_BGP_COMMUNITY_CANON`, `_normalize_prefix` -- admitted when the extraction
wires them). Never engine, model, or runtime_container.

Unshipped legs (REQ-45b-3 deferral list) carry the LD-H2 phased-instantiation
placeholder: present (completeness check passes), loud §13-grade if reached,
never a silent no-op. Wiring status per leg:

  gen_node_config    -> deferred (config-generation leg; §4.5-d/-f)
  provision          -> deferred (provisioning leg; §4.5-d/-f)
  nos_ready          -> deferred (readiness leg; §4.5-d/-f)
  convergence_wait   -> deferred (convergence leg; §4.5-d/-f)
  exec_command_rule  -> deferred (§4.5-d; LD-45b-6 / BL-P2-4.5b-1 -- the
                        decision site `_exec_command_allowed` stays inline
                        this handover and NEVER consults this field,
                        REQ-45b-10)
  state_profiles     -> empty (state leg; §4.5-d)
  state_argv_allow   -> deferred (state leg; §4.5-d)
  doctor_checks      -> deferred (per-NOS doctor leg; post-§4.5-b sub-handover,
                        unassigned -- cmd_doctor's image literal derives from
                        `default_image`, not from this leg, REQ-45b-11-ext)
  candidate.validate -> deferred (candidate-apply leg; BL-P2-4.5b-2)
  candidate.apply    -> deferred (candidate-apply leg; BL-P2-4.5b-2 -- the
                        FRR apply machinery stays in cassian_candidate)

Capability note: `interface_state` is deliberately NOT declared here -- its
collection is NOS-agnostic (Linux `ip -j link show` primitives) and stays
core; deny-by-default makes any accidental provider dispatch for it fail
loud. Token vocabulary below = the observation-seam kinds + operational
legs shipped by §4.5-b; alignment with the full §6-checklist token map
matures with the SONiC provider (§4.5-c onward).
"""

from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING, Any

# Justified `cassian_common` leg (REQ-45b-17): the ruled acyclic floor
# (design §3.2) hosting the NOS-neutral helpers the relocated FRR parse
# family reaches -- admitted symbols named here and asserted by
# tests/nos_leaf_import_proof.py.
from cassian_common import (
    _RE_IPV4_PREFIX,
    _RE_NEIGH_LINE,
    _canonical_community_token,
    _normalize_prefix,
)
from cassian_nos_types import (
    CandidateSpec,
    CapabilityDisposition,
    NosProvider,
    Observation,
    ObservationRequest,
    deferred_leg,
    impl,
)

if TYPE_CHECKING:  # annotation-only; no runtime import (REQ-45b-17)
    pass


# -------------------------
# Relocated FRR output-parse family (REQ-45b-21)
# -------------------------
# Byte-identical relocation from cassian_tests.py (v34 L433/451/487/620);
# one-line re-import shims stand at the old sites so cassian.py's facade and
# every importer are byte-untouched (shims owed removal at §4.5-c,
# BL-P2-4.5b-3). These parse NOS output into core-defined structures; they
# decide nothing (design §5).

def parse_frr_show_ip_route_prefixes(text: str) -> set[str]:
    """
    Parse `vtysh -c "show ip route"` and extract IPv4 prefixes.
    This avoids fragile column indexes.
    """
    out: set[str] = set()
    if not text:
        return out

    for line in text.splitlines():
        m = _RE_IPV4_PREFIX.search(line)
        if not m:
            continue
        p = _normalize_prefix(m.group(1))
        if p:
            out.add(p)
    return out

def parse_frr_show_ip_route_prefixes_json(raw: str) -> set[str]:
    """
    Parse `vtysh -c "show ip route json"` into a set of prefixes like "192.168.1.0/24".
    Returns empty set if raw isn't valid/expected JSON.
    """
    raw = (raw or "").strip()
    if not raw:
        return set()

    try:
        doc = json.loads(raw)
    except Exception:
        return set()

    prefixes: set[str] = set()

    # FRR typically returns keys as prefixes at the top level (e.g. "10.0.0.0/31": {...})
    # Some versions may wrap under "routes" or "routeTable"; handle a couple common shapes.
    if isinstance(doc, dict):
        if "routes" in doc and isinstance(doc["routes"], dict):
            route_dict = doc["routes"]
        else:
            route_dict = doc

        for k, v in route_dict.items():
            if not isinstance(k, str):
                continue
            # keep only things that look like prefixes
            try:
                ipaddress.ip_network(k, strict=False)
            except Exception:
                continue
            prefixes.add(k)

    return prefixes

def parse_frr_bgp_summary_neighbors_json(out: str) -> dict[str, dict[str, Any]]:
    """
    Parse FRR `show bgp summary json`.

    Observed schema (FRR):
      {
        "ipv4Unicast": {
          "peers": {
            "10.0.0.1": { "state": "Established", "pfxRcd": 1, "peerState": "OK", ... },
            ...
          }
        }
      }

    Returns:
      { "<neighbor_ip>": {"established": bool, "raw": "<state>"} }

    Notes:
      - We treat `state` as authoritative when present.
      - We only fall back to `peerState` / `pfxRcd` if `state` is missing, because
        `pfxRcd` can remain non-zero even after an admin shutdown (stale last-known).
    """
    import json

    if not out:
        return {}

    try:
        obj = json.loads(out)
    except Exception:
        return {}

    v4 = obj.get("ipv4Unicast")
    if not isinstance(v4, dict):
        return {}

    peers = v4.get("peers")
    if not isinstance(peers, dict):
        return {}

    res: dict[str, dict[str, Any]] = {}

    for nbr_ip, pdata in peers.items():
        if not isinstance(nbr_ip, str):
            continue
        if not _RE_NEIGH_LINE.match(nbr_ip + " "):
            continue

        established = False
        raw_state = ""

        if isinstance(pdata, dict):
            state = pdata.get("state")
            peer_state = pdata.get("peerState")
            pfx = pdata.get("pfxRcd")

            # Authoritative: `state` if present
            if isinstance(state, str) and state.strip():
                raw_state = state.strip()
                established = raw_state.lower().startswith("estab")
            else:
                # Fallback signals only if `state` is missing
                if isinstance(peer_state, str) and peer_state.strip().upper() == "OK":
                    established = True
                elif isinstance(pfx, int):
                    established = True
                elif isinstance(pfx, str) and pfx.isdigit():
                    established = True

        res[nbr_ip] = {"established": bool(established), "raw": raw_state}

    return res

def parse_frr_bgp_summary_neighbors(out: str) -> dict[str, dict[str, Any]]:
    """
    Parse `show bgp summary` and return:
      { "<neighbor_ip>": {"established": bool, "raw": "<line>"} }

    Robust logic:
      - Find the table header and locate the 'State/PfxRcd' column index.
      - Neighbor rows start with an IPv4 address.
      - Established if State/PfxRcd token is numeric OR equals 'Established' (case-insensitive).
    """
    obs: dict[str, dict[str, Any]] = {}
    if not out:
        return obs
    if "No BGP neighbors found" in out:
        return obs

    lines = out.splitlines()

    # 1) Find header and determine column index for State/PfxRcd
    state_idx: int | None = None
    for line in lines:
        if "Neighbor" in line and "State/PfxRcd" in line:
            cols = line.split()
            # Example header tokens:
            # Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd PfxSnt Desc
            for i, c in enumerate(cols):
                if c == "State/PfxRcd":
                    state_idx = i
                    break
            break

    # Fallback: if we can't find header, keep a safe heuristic:
    # treat as established if ANY token is exactly 'Established' OR ANY token is purely numeric
    fallback = (state_idx is None)

    for line in lines:
        m = _RE_NEIGH_LINE.match(line)
        if not m:
            continue

        ip = m.group(1)
        cols = line.split()

        established = False
        if fallback:
            if any(c.lower() == "established" for c in cols):
                established = True
            else:
                # In established rows there is typically at least one numeric token at State/PfxRcd,
                # but fallback is less precise; still better than "last token".
                established = any(c.isdigit() for c in cols)
        else:
            if len(cols) > state_idx:
                state = cols[state_idx]
                if state.isdigit() or state.lower() == "established":
                    established = True

        obs[ip] = {"established": established, "raw": line.rstrip("\n")}

    return obs


# -------------------------
# Observation collection seam (REQ-45b-4, B02)
# -------------------------
# `collect` is the ONE seam invariants/tests use to read FRR state. Each
# handler probes the NOS and normalizes its output into a core-owned
# `Observation`; none of them decides pass/fail (design §5). `data` carries
# the normalized payload core renders as `observed_state`; `evidence` carries
# the command, diagnostics, and the probe outcome (`probe_ok` -- NOS-neutral
# field name for what core's retry loops read as `vtysh_ok`).
#
# Ordering note (verified, §4.5-b): `observed_state`/`evidence` key ORDER is
# not observable -- `write_json_canonical` serializes with sort_keys=True
# (frozen policy) and `_format_observed_state_block` iterates
# sorted(observed_state.keys()). Key sets and values are what must be
# preserved byte-for-byte (REQ-45b-P2).


def _collect_bgp_session_up(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR BGP summary for one declared neighbor."""
    neighbor = str(req.params.get("neighbor") or "").strip()
    cp = rt.exec(lab, node, ["vtysh", "-c", "show bgp summary json"], check=False)
    probe_ok = (getattr(cp, "returncode", 1) == 0)
    out = (cp.stdout or "") if hasattr(cp, "stdout") else ""

    observed_state_str: str = "Unknown"
    last_error: str = ""
    parse_error: str = ""
    peer_present: bool = False

    if probe_ok:
        try:
            data = json.loads(out or "{}")
            peers = None
            top_peers = data.get("peers")
            if isinstance(top_peers, dict):
                peers = top_peers
            else:
                v4u = data.get("ipv4Unicast")
                if isinstance(v4u, dict):
                    inner = v4u.get("peers")
                    if isinstance(inner, dict):
                        peers = inner
            if peers is None:
                for _, v in sorted(data.items()):
                    if isinstance(v, dict):
                        inner = v.get("peers")
                        if isinstance(inner, dict):
                            peers = inner
                            break
            if isinstance(peers, dict):
                p = peers.get(neighbor)
                if isinstance(p, dict):
                    peer_present = True
                    raw_state = p.get("state") or p.get("bgpState") or p.get("peerState")
                    if raw_state:
                        observed_state_str = str(raw_state)
                    reset_reason = p.get("lastResetReason")
                    if reset_reason:
                        last_error = str(reset_reason)
                else:
                    observed_state_str = "NotConfigured"
                    last_error = "neighbor not present in summary"
                    parse_error = "neighbor not present in summary"
            else:
                observed_state_str = "Unknown"
                last_error = "peers not found in summary"
                parse_error = "peers not found in summary"
        except Exception:
            observed_state_str = "Unknown"
            last_error = "vtysh output not parseable as JSON"
            parse_error = "vtysh output not parseable as JSON"
    else:
        observed_state_str = "Unknown"
        last_error = "vtysh command failed"
        parse_error = "vtysh command failed"

    return Observation(
        kind="bgp_session_up",
        data={
            "peer_present": peer_present,
            "state": observed_state_str,
            "last_error": last_error,
        },
        evidence={
            "cmd": "vtysh -c 'show bgp summary json'",
            "parse_error": parse_error,
            "returncode": getattr(cp, "returncode", None),
            "probe_ok": probe_ok,
        },
    )


# Kind -> handler. Migrated incrementally through §4.5-b WI-C3a..C3f; a kind
# absent here is not yet routed through the seam and still runs its
# pre-existing inline core path (not a second seam -- an unmigrated one).


# -------------------------
# BGP attribute-family collection handlers (WI-C3b, REQ-45b-4)
# -------------------------


def _collect_bgp_med_equals(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR `show ip bgp <prefix> json` for bgp_med_equals."""
    norm_prefix = str(req.params.get("prefix") or "").strip()
    cp = rt.exec(
        lab,
        node,
        ["vtysh", "-c", f"show ip bgp {norm_prefix} json"],
        check=False,
        capture_output=True,
    )

    if isinstance(cp, str):
        out = cp
        rc = None
    else:
        out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="replace")
            except Exception:
                out = str(out)
        rc = getattr(cp, "returncode", None)

    probe_ok = (rc in (0, None))

    parse_error = ""
    observed_med = None
    empty_first_doc = (str(out or "").strip() in ("", "{}"))

    try:
        doc = json.loads(str(out or "").strip()) if str(out or "").strip() else {}
        route_obj = None

        if isinstance(doc, dict):
            cand = doc.get(norm_prefix)
            if isinstance(cand, list) and cand:
                route_obj = cand[0]
            elif isinstance(cand, dict):
                route_obj = cand
            elif (
                doc.get("prefix") is not None
                and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == norm_prefix
            ):
                route_obj = doc
            else:
                routes = doc.get("routes")
                if isinstance(routes, dict):
                    cand = routes.get(norm_prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    else:
                        for k, v in routes.items():
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk != norm_prefix:
                                continue
                            if isinstance(v, list) and v:
                                route_obj = v[0]
                                break
                            if isinstance(v, dict):
                                route_obj = v
                                break
                if route_obj is None:
                    for k, v in doc.items():
                        nk = _normalize_prefix(str(k)) or str(k)
                        if nk != norm_prefix:
                            continue
                        if isinstance(v, list) and v:
                            route_obj = v[0]
                            break
                        if isinstance(v, dict):
                            route_obj = v
                            break
        else:
            raise ValueError("unexpected_bgp_prefix_json_shape")

        if not isinstance(route_obj, dict):
            parse_error = "prefix not present in bgp json"
        else:
            for key in ("med", "metric"):
                val = route_obj.get(key)
                if val is None or str(val).strip() == "":
                    continue
                try:
                    observed_med = int(val)
                    break
                except Exception:
                    continue

            if observed_med is None:
                paths = route_obj.get("paths")
                if isinstance(paths, list):
                    for path in paths:
                        if not isinstance(path, dict):
                            continue
                        for key in ("med", "metric"):
                            val = path.get(key)
                            if val is None or str(val).strip() == "":
                                continue
                            try:
                                observed_med = int(val)
                                break
                            except Exception:
                                continue
                        if observed_med is not None:
                            break

            if observed_med is None:
                parse_error = "med not present in bgp json"
    except Exception as e:
        parse_error = str(e)


    observed_state = {
        "norm_prefix": norm_prefix,
        "observed_med": observed_med,
    }
    evidence = {
        "cmd": f"vtysh -c 'show ip bgp {norm_prefix} json'",
        "rc": rc,
        "parse_error": parse_error,
        "empty_first_doc": empty_first_doc,
    }

    return Observation(
        kind="bgp_med_equals",
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )


def _collect_bgp_localpref_equals(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR `show ip bgp <prefix> json` for bgp_localpref_equals."""
    prefix = str(req.params.get("prefix") or "").strip()

    cp = rt.exec(lab, node, ["vtysh", "-c", f"show ip bgp {prefix} json"], check=False)
    out = cp.stdout or ""
    rc = cp.returncode
    if isinstance(out, (bytes, bytearray)):
        try:
            out = out.decode("utf-8", errors="replace")
        except Exception:
            out = str(out)

    probe_ok = (rc == 0)

    parse_error = ""
    observed_localpref = None
    try:
        doc = json.loads(str(out or "").strip()) if str(out or "").strip() else {}
        route_obj = None
        if isinstance(doc, dict):
            cand = doc.get(prefix)
            if isinstance(cand, list) and cand:
                route_obj = cand[0]
            elif isinstance(cand, dict):
                route_obj = cand
            elif (
                doc.get("prefix") is not None
                and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == prefix
            ):
                route_obj = doc
            else:
                routes = doc.get("routes")
                if isinstance(routes, dict):
                    cand = routes.get(prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    else:
                        for k, v in routes.items():
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk != prefix:
                                continue
                            if isinstance(v, list) and v:
                                route_obj = v[0]
                                break
                            if isinstance(v, dict):
                                route_obj = v
                                break
                if route_obj is None:
                    for k, v in doc.items():
                        nk = _normalize_prefix(str(k)) or str(k)
                        if nk != prefix:
                            continue
                        if isinstance(v, list) and v:
                            route_obj = v[0]
                            break
                        if isinstance(v, dict):
                            route_obj = v
                            break
        else:
            raise ValueError("unexpected_bgp_prefix_json_shape")

        if not isinstance(route_obj, dict):
            parse_error = "prefix not present in bgp json"
        else:
            for key in ("locPrf", "localpref", "localPref", "local_preference"):
                val = route_obj.get(key)
                if val is None or str(val).strip() == "":
                    continue
                try:
                    observed_localpref = int(val)
                    break
                except Exception:
                    continue

            if observed_localpref is None:
                paths = route_obj.get("paths")
                if isinstance(paths, list):
                    for path in paths:
                        if not isinstance(path, dict):
                            continue
                        for key in ("locPrf", "localpref", "localPref", "local_preference"):
                            val = path.get(key)
                            if val is None or str(val).strip() == "":
                                continue
                            try:
                                observed_localpref = int(val)
                                break
                            except Exception:
                                continue
                        if observed_localpref is not None:
                            break

            if observed_localpref is None:
                parse_error = "localpref not present in bgp json"
    except Exception as e:
        parse_error = str(e)


    observed_state = {
        "norm_prefix": prefix,
        "observed_localpref": observed_localpref,
    }
    evidence = {
        "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
        "rc": rc,
        "parse_error": parse_error,
    }

    return Observation(
        kind="bgp_localpref_equals",
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )


def _collect_bgp_community(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR `show ip bgp <prefix> json` for bgp_community."""
    prefix = str(req.params.get("prefix") or "").strip()

    cp = rt.exec(lab, node, ["vtysh", "-c", f"show ip bgp {prefix} json"], check=False)
    out = cp.stdout or ""
    rc = cp.returncode
    if isinstance(out, (bytes, bytearray)):
        try:
            out = out.decode("utf-8", errors="replace")
        except Exception:
            out = str(out)

    probe_ok = (rc == 0)

    parse_error = ""
    route_present = False
    observed_tokens = []
    empty_first_doc = False
    try:
        _s = str(out or "").strip()
        doc = json.loads(_s) if _s else {}
        if isinstance(doc, dict) and not doc:
            empty_first_doc = True
        route_obj = None
        if isinstance(doc, dict):
            cand = doc.get(prefix)
            if isinstance(cand, list) and cand:
                route_obj = cand[0]
            elif isinstance(cand, dict):
                route_obj = cand
            elif (
                doc.get("prefix") is not None
                and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == prefix
            ):
                route_obj = doc
            else:
                routes = doc.get("routes")
                if isinstance(routes, dict):
                    cand = routes.get(prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    else:
                        for k, v in routes.items():
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk != prefix:
                                continue
                            if isinstance(v, list) and v:
                                route_obj = v[0]
                                break
                            if isinstance(v, dict):
                                route_obj = v
                                break
                if route_obj is None:
                    for k, v in doc.items():
                        nk = _normalize_prefix(str(k)) or str(k)
                        if nk != prefix:
                            continue
                        if isinstance(v, list) and v:
                            route_obj = v[0]
                            break
                        if isinstance(v, dict):
                            route_obj = v
                            break
        else:
            raise ValueError("unexpected_bgp_prefix_json_shape")

        if isinstance(route_obj, dict):
            route_present = True
            observed_tokens = _route_communities(route_obj)
    except Exception as e:
        parse_error = str(e)


    observed_state = {
        "norm_prefix": prefix,
        "route_present": route_present,
        "observed_communities": sorted({_canonical_community_token(t) for t in observed_tokens}),
    }
    evidence = {
        "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
        "rc": rc,
        "parse_error": parse_error,
        "empty_first_doc": empty_first_doc,
    }

    return Observation(
        kind="bgp_community",
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )


def _collect_bgp_as_path(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR `show ip bgp <prefix> json` for bgp_as_path."""
    prefix = str(req.params.get("prefix") or "").strip()

    cp = rt.exec(lab, node, ["vtysh", "-c", f"show ip bgp {prefix} json"], check=False)
    out = cp.stdout or ""
    rc = cp.returncode
    if isinstance(out, (bytes, bytearray)):
        try:
            out = out.decode("utf-8", errors="replace")
        except Exception:
            out = str(out)

    probe_ok = (rc == 0)

    parse_error = ""
    route_present = False
    observed_path = ""
    empty_first_doc = False
    try:
        _s = str(out or "").strip()
        doc = json.loads(_s) if _s else {}
        if isinstance(doc, dict) and not doc:
            empty_first_doc = True
        route_obj = None
        if isinstance(doc, dict):
            cand = doc.get(prefix)
            if isinstance(cand, list) and cand:
                route_obj = cand[0]
            elif isinstance(cand, dict):
                route_obj = cand
            elif (
                doc.get("prefix") is not None
                and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == prefix
            ):
                route_obj = doc
            else:
                routes = doc.get("routes")
                if isinstance(routes, dict):
                    cand = routes.get(prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    else:
                        for k, v in routes.items():
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk != prefix:
                                continue
                            if isinstance(v, list) and v:
                                route_obj = v[0]
                                break
                            if isinstance(v, dict):
                                route_obj = v
                                break
                if route_obj is None:
                    for k, v in doc.items():
                        nk = _normalize_prefix(str(k)) or str(k)
                        if nk != prefix:
                            continue
                        if isinstance(v, list) and v:
                            route_obj = v[0]
                            break
                        if isinstance(v, dict):
                            route_obj = v
                            break
        else:
            raise ValueError("unexpected_bgp_prefix_json_shape")

        if isinstance(route_obj, dict):
            route_present = True
            observed_path = _route_as_path(route_obj)
    except Exception as e:
        parse_error = str(e)


    observed_state = {
        "norm_prefix": prefix,
        "route_present": route_present,
        "observed_as_path": observed_path,
    }
    evidence = {
        "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
        "rc": rc,
        "parse_error": parse_error,
        "empty_first_doc": empty_first_doc,
    }

    return Observation(
        kind="bgp_as_path",
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )




# -------------------------
# Route-family collection handlers (WI-C3c, REQ-45b-4)
# -------------------------
# One observation serves both members of each pair; the present/absent flip is
# a core predicate decision, never a provider one (design §5).


def _collect_route_prefix_table(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR routing state for route_present, route_absent."""
    norm_prefix = str(req.params.get("prefix") or "").strip()
    cp = rt.exec(
        lab,
        node,
        ["vtysh", "-c", "show ip route json"],
        check=False,
        capture_output=True,
    )

    if isinstance(cp, str):
        out = cp
        rc = None
    else:
        out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="replace")
            except Exception:
                out = str(out)
        rc = getattr(cp, "returncode", None)

    probe_ok = (rc in (0, None))

    observed_prefixes = parse_frr_show_ip_route_prefixes_json(str(out or ""))
    present = norm_prefix in set(observed_prefixes or [])


    observed_state = {
        "norm_prefix": norm_prefix,
        "present": present,
        "observed_prefixes": list(observed_prefixes or []),
    }
    evidence = {
        "cmd": "vtysh -c 'show ip route json'",
        "rc": rc,
    }

    return Observation(
        kind=req.kind,
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )


def _collect_advertised_routes(rt, lab, node, req: ObservationRequest) -> Observation:
    """Probe + normalize FRR routing state for route_advertised_to, route_not_advertised_to."""
    peer_ip = str(req.params.get("peer_ip") or "").strip()
    prefix = str(req.params.get("prefix") or "").strip()

    cp = rt.exec(
        lab,
        node,
        ["vtysh", "-c", f"show ip bgp neighbor {peer_ip} advertised-routes json"],
        check=False,
    )
    out = cp.stdout or ""
    rc = cp.returncode
    if isinstance(out, (bytes, bytearray)):
        try:
            out = out.decode("utf-8", errors="replace")
        except Exception:
            out = str(out)

    probe_ok = (rc == 0)

    raw = str(out or "").strip()
    parse_error = ""
    advertised_prefixes: list = []

    def _collect_adv_prefixes(obj):
        found = []
        if isinstance(obj, dict):
            for container_key in ("advertisedRoutes", "routes"):
                container = obj.get(container_key)
                if isinstance(container, dict):
                    for k, v in container.items():
                        if isinstance(v, (dict, list)):
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk:
                                found.append(nk)
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    nk = _normalize_prefix(str(k)) or str(k)
                    if nk and "/" in nk:
                        found.append(nk)
            for key in ("prefix", "network"):
                val = obj.get(key)
                nk = _normalize_prefix(str(val)) or str(val or "")
                if nk:
                    found.append(nk)
            paths = obj.get("paths")
            if isinstance(paths, list):
                for path in paths:
                    found.extend(_collect_adv_prefixes(path))
        elif isinstance(obj, list):
            for item in obj:
                found.extend(_collect_adv_prefixes(item))
        return found

    try:
        doc = json.loads(raw) if raw else {}
        advertised_prefixes = sorted(set(_collect_adv_prefixes(doc)))
    except Exception as e:
        parse_error = str(e)

    present = prefix in advertised_prefixes


    observed_state = {
        "norm_prefix": prefix,
        "present": present,
        "advertised_prefixes": advertised_prefixes,
    }
    evidence = {
        "cmd": f"vtysh -c 'show ip bgp neighbor {peer_ip} advertised-routes json'",
        "rc": rc,
        "parse_error": parse_error,
    }

    return Observation(
        kind=req.kind,
        data=observed_state,
        evidence=dict(evidence, probe_ok=probe_ok),
    )


_COLLECT_HANDLERS = {
    "bgp_session_up": _collect_bgp_session_up,
    "bgp_med_equals": _collect_bgp_med_equals,
    "bgp_localpref_equals": _collect_bgp_localpref_equals,
    "bgp_community": _collect_bgp_community,
    "bgp_as_path": _collect_bgp_as_path,
    "route_present": _collect_route_prefix_table,
    "route_absent": _collect_route_prefix_table,
    "route_advertised_to": _collect_advertised_routes,
    "route_not_advertised_to": _collect_advertised_routes,
}


def collect(rt, lab, node, req: ObservationRequest) -> Observation:
    """The single provider-side collection entry (REQ-45b-4)."""
    handler = _COLLECT_HANDLERS.get(req.kind)
    if handler is None:
        return deferred_leg(f"collect:{req.kind}", "§4.5-b WI-C3b..C3f")()
    return handler(rt, lab, node, req)


FRR_NODE_TYPE = "frr"

# REQ-45b-11 single source: the model's effective-image default for frr
# derives from this value (one source, two readers with cmd_doctor per
# REQ-45b-11-ext). Value unchanged through the extraction (P2).
FRR_DEFAULT_IMAGE = "frrouting/frr:latest"


# Capability declarations (design §3.4): the (kind, node-type) pairs FRR
# supports through the §4.5-b seams. Deny-by-default -- an absent token is
# UNSUP with a generated message; dispatch sites check before dispatching.
_FRR_CAPABILITIES: dict[str, CapabilityDisposition] = {
    # observation seam -- invariant kinds (model-validated vocabulary)
    "bgp_session_up": impl(),
    "route_present": impl(),
    "route_absent": impl(),
    "bgp_med_equals": impl(),
    "bgp_localpref_equals": impl(),
    "bgp_community": impl(),
    "bgp_as_path": impl(),
    "route_advertised_to": impl(),
    "route_not_advertised_to": impl(),
    "evpn_mac_route_present": impl(),
    "evpn_mac_route_absent": impl(),
    "evpn_vni_route_present": impl(),
    "evpn_bgp_session_up": impl(),
    "ospf_neighbor_up": impl(),
    # observation seam -- test/step kinds routed through the same seam
    "bgp_neighbor": impl(),
    "route_prefix": impl(),
    # operational legs shipped by §4.5-b
    "status_bgp_summary": impl(),
    "status_routes": impl(),
    "collect_bgp_summary": impl(),
    "candidate": impl(),
}


FRR_PROVIDER = NosProvider(
    node_type=FRR_NODE_TYPE,
    default_image=FRR_DEFAULT_IMAGE,
    runtime_requirement=None,
    capabilities=_FRR_CAPABILITIES,
    # -- lifecycle legs: deferred (REQ-45b-3 deferral list) --
    gen_node_config=deferred_leg("gen_node_config", "§4.5-d/-f"),
    provision=deferred_leg("provision", "§4.5-d/-f"),
    nos_ready=deferred_leg("nos_ready", "§4.5-d/-f"),
    convergence_wait=deferred_leg("convergence_wait", "§4.5-d/-f"),
    # -- validation seam: wired by this handover's extraction WI --
    collect=collect,
    # -- change workflow: subdir/extensions ship (REQ-45b-8 derivation
    #    source); validate/apply legs are BL-P2-4.5b-2 NON-GOALs here --
    candidate=CandidateSpec(
        subdir="frr",
        extensions=(".conf",),
        validate=deferred_leg("candidate.validate", "BL-P2-4.5b-2 destination"),
        apply=deferred_leg("candidate.apply", "BL-P2-4.5b-2 destination"),
    ),
    # -- operational legs: wired by this handover's status/collect WIs --
    status_bgp_summary=deferred_leg(
        "status_bgp_summary", "§4.5-b (this handover's status WI)"
    ),
    status_routes=deferred_leg(
        "status_routes", "§4.5-b (this handover's status WI)"
    ),
    collect_targets=(),  # filled by this handover's collect WI (B04)
    doctor_checks=deferred_leg("doctor_checks", "post-§4.5-b (unassigned)"),
    # -- bounded per-type rules: deferred; decision sites stay inline --
    exec_command_rule=deferred_leg("exec_command_rule", "§4.5-d (LD-45b-6)"),
    state_profiles={},
    state_argv_allow=deferred_leg("state_argv_allow", "§4.5-d"),
)


# -------------------------
# FRR route-attribute extractors (scope §2.0 MOVE; founder ruling B' on
# F-45b-C3b-1)
# -------------------------
# Relocated byte-identical from cassian_engine. One-line re-import shims stand
# at the engine sites so `cassian_engine.__dict__` still binds both names --
# four CI-gated proofs outside the §14.4 whitelist read them there
# (bgp_{as_path,community}_{eval_match,replay_determinism}_proof). Shims owed
# removal at §4.5-c (BL-P2-4.5b-3, fourth family).

def _route_communities(route_obj):
    """Extract raw BGP community tokens from a vtysh route object:
    route_obj['community'] {'list'|'string'} (preferred), else the per-path
    paths[].community (the FRR per-path location). Returns a list of raw token
    strings (possibly empty)."""
    def _from_comm(comm):
        if isinstance(comm, dict):
            lst = comm.get("list")
            if isinstance(lst, list) and lst:
                return [str(x) for x in lst]
            s = comm.get("string")
            if isinstance(s, str) and s.strip():
                return [tok for tok in s.split() if tok]
        elif isinstance(comm, str) and comm.strip():
            return [tok for tok in comm.split() if tok]
        return []

    if not isinstance(route_obj, dict):
        return []
    toks = _from_comm(route_obj.get("community"))
    if toks:
        return toks
    paths = route_obj.get("paths")
    if isinstance(paths, list):
        for path in paths:
            if isinstance(path, dict):
                toks = _from_comm(path.get("community"))
                if toks:
                    return toks
    return []


def _route_as_path(route_obj):
    """Extract the AS_PATH from a vtysh route object (`show ip bgp <prefix>
    json`) as a canonical asplain, path-ordered, space-joined string. Read from
    route_obj['aspath']['string'] (defensive top-level mirror) else the per-path
    paths[].aspath.string (the FRR per-path location, real-capture confirmed).
    Returns '' if absent. Order is preserved verbatim -- never sorted (AS_PATH is
    order-significant)."""
    def _from_aspath(asp):
        if isinstance(asp, dict):
            s = asp.get("string")
            if isinstance(s, str) and s.strip():
                return " ".join(tok for tok in s.split() if tok)
        elif isinstance(asp, str) and asp.strip():
            return " ".join(tok for tok in asp.split() if tok)
        return ""

    if not isinstance(route_obj, dict):
        return ""
    s = _from_aspath(route_obj.get("aspath"))
    if s:
        return s
    paths = route_obj.get("paths")
    if isinstance(paths, list):
        for path in paths:
            if isinstance(path, dict):
                s = _from_aspath(path.get("aspath"))
                if s:
                    return s
    return ""
