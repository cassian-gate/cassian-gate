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
from cassian_common import _RE_IPV4_PREFIX, _RE_NEIGH_LINE, _normalize_prefix
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
_COLLECT_HANDLERS = {
    "bgp_session_up": _collect_bgp_session_up,
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
