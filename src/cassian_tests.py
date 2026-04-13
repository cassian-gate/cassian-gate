from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Optional

from cassian_common import (
    run,
    die,
    is_ip_literal,
    validate_ip_literal,
    classify_invalid_target,
)

from cassian_artifacts import (
    lab_dir,
)
from cassian_runtime_container import (
    _normalize_prefix,
    scenario_apply_fault,
    scenario_clear_fault_state,
)

def ensure_nc(rt: Runtime, lab: str, node: str) -> None:
    cp = rt.exec(
        lab,
        node,
        ["sh", "-lc", "command -v nc >/dev/null"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        die(f"{node}: nc not found. Use wbitt/network-multitool for host/nft-fw nodes.")

def ip_no_mask(cidr: str) -> str:
    return cidr.split("/", 1)[0].strip()

def find_nodes_by_type(topo: dict, ntype: str) -> list[dict]:
    return [n for n in topo.get("nodes", []) if n.get("type") == ntype]

def start_tcp_listener(rt: Runtime, lab: str, node: str, port: int) -> None:
    """
    Start a TCP listener inside a node using netcat (nc).

    Requirements:
    - nc must already exist (we do NOT install packages at runtime)
    - Must not fail if nothing is running yet
    - Must not fail if pkill exits non-zero
    """
    ensure_nc(rt, lab, node)

    # Kill any previous listener on that port (never fail)
    rt.exec(
        lab,
        node,
        ["sh", "-lc", f'pkill -f "nc.*-p {port}" 2>/dev/null || true'],
        check=False,
    )

    # Start listener in background
    rt.exec(
        lab,
        node,
        ["sh", "-lc", f"nohup nc -lk -p {port} >/dev/null 2>&1 &"],
        check=False,
    )

def stop_tcp_listeners(rt: Runtime, lab: str, node: str) -> None:
    """
    Stop any nc listeners we started. Never fail the test.
    """
    rt.exec(
        lab,
        node,
        ["sh", "-lc", 'pkill -f "nc.*-p" 2>/dev/null || true'],
        check=False,
    )

def tcp_connect_test(
    rt: Runtime,
    lab: str,
    src_host: str,
    dst_ip: str,
    port: int,
    should_succeed: bool,
) -> None:
    # 'nc -z' = zero-I/O connect test
    cp = rt.exec(
        lab,
        src_host,
        ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
        check=False,
        capture_output=False,
    )

    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"TCP connect should have succeeded but failed: {src_host} -> {dst_ip}:{port}")
    if (not should_succeed) and ok:
        die(f"TCP connect should have failed but succeeded: {src_host} -> {dst_ip}:{port}")

def node_first_ipv4(topo: dict[str, Any], name: str) -> str:
    """
    Resolve a node name to its first IPv4 address from topology links.

    v1-safe enhancement:
      - If 'name' is already an IPv4/IPv6 literal, return it directly.
        (This prevents IP literals from being treated as node names in wait_for/scenario paths.)
    """
    if not isinstance(name, str) or not name.strip():
        die("node_first_ipv4: name must be a non-empty string")

    name_s = name.strip()

    # v1: allow IP literal passthrough (explicit, deterministic)
    if is_ip_literal(name_s):
        validate_ip_literal(name_s, "node_first_ipv4")
        return name_s

    # --- existing behavior below (unchanged logic, just copied from your current function) ---
    for link in topo.get("links", []) or []:
        eps = link.get("endpoints") or []
        ipv4s = link.get("ipv4") or []
        if len(eps) != 2 or len(ipv4s) != 2:
            continue

        a, b = eps[0], eps[1]
        a_ip, b_ip = ipv4s[0], ipv4s[1]

        # endpoint format: "node:ifname"
        if isinstance(a, str) and a.startswith(name_s + ":"):
            return str(a_ip).split("/")[0]
        if isinstance(b, str) and b.startswith(name_s + ":"):
            return str(b_ip).split("/")[0]

    die(f"Could not determine IPv4 for node '{name_s}' from topology links")

def run_ping_once_or_die(
    rt: Runtime,
    lab: str,
    src: str,
    dst_ip: str,
    count: int,
    should_succeed: bool,
) -> str:
    cp = rt.exec(
        lab,
        src,
        ["ping", "-c", str(count), dst_ip],
        check=False,
        capture_output=False,
    )
    ok = (cp.returncode == 0)

    # expected outcome mapping
    expected = "pass" if should_succeed else "drop"
    observed = "pass" if ok else "drop"

    # return verdict for the caller to handle (keep-going, results.json, etc.)
    if observed == expected:
        return "pass"

    return "fail"

def run_tcp_test(
    rt: Runtime,
    lab: str,
    src: str,
    dst_ip: str,
    port: int,
    should_succeed: bool,
) -> None:
    # nc -z checks connect() only
    cp = rt.exec(
        lab,
        src,
        ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
        check=False,
        capture_output=False,
    )
    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"TCP FAIL (expected PASS): {src} -> {dst_ip}:{port}")
    if (not should_succeed) and ok:
        die(f"TCP FAIL (expected DROP): {src} -> {dst_ip}:{port}")

def run_declared_tests(rt: Runtime, lab: str, topo: dict) -> None:
    tests = topo.get("tests") or []
    if not tests:
        return

    # We start listeners only if requested by a tcp test
    listeners_started: list[tuple[str, int]] = []

    try:
        for t in tests:
            tname = t.get("name", "<unnamed>")
            ttype = t.get("kind") or t.get("type")
            src = t.get("src")
            dst = t.get("dst")

            if not ttype or not src or not dst:
                die(f"Invalid test entry (missing type/src/dst): {t}")

            # dst can be a node name or an IP; if it looks like a node name, resolve it
            # Destination already normalized during validation
            dst_kind = t.get("_dst_kind")
            dst_value = t.get("_dst_value")

            if dst_kind == "ip":
                dst_ip = dst_value
            elif dst_kind == "node":
                dst_ip = node_first_ipv4(topo, dst_value)
            else:
                die(f"Ping test missing normalized destination: {t}")

            expect = (t.get("expect") or "pass").lower()
            should_succeed = (expect in ("pass", "allow", "ok", "true"))

            if ttype == "ping":
                count = int(t.get("count") or 2)
                run_ping_once_or_die(rt, lab, src, dst_ip, count=count, should_succeed=should_succeed)

            elif ttype == "tcp":
                port = int(t.get("port"))
                if t.get("listener"):
                    # start listener on the *dst node* (must be a node name)
                    if not isinstance(dst, str) or not any(n.get("name") == dst for n in topo.get("nodes", [])):
                        die(f"{tname}: listener=true requires dst to be a node name, got '{dst}'")
                    start_tcp_listener(rt, lab, dst, port)
                    listeners_started.append((dst, port))

                run_tcp_test(rt, lab, src, dst_ip, port=port, should_succeed=should_succeed)

            else:
                die(f"Unknown test type '{ttype}' in test '{tname}'")

    finally:
        # clean up listeners we started
        for (node, _port) in listeners_started:
            # easiest: stop all nc listeners on node
            stop_tcp_listeners(rt, lab, node)

    print(f"✅ Declared tests PASS ({len(tests)} checks)")


# -------------------------
# Candidate Config Apply (v1.5) - deterministic helpers
# -------------------------

_CANDIDATE_STDIO_TRUNC = 8000

def connected_prefixes_for_router(topo: dict, router_name: str) -> list[str]:
    """
    Returns a list of IPv4 prefixes (e.g. '192.168.1.0/24') that are
    directly connected to this router and should be advertised into BGP.

    Rule (v1):
      - If a link connects router<->host and has explicit link['ipv4'],
        advertise the /24 (or whatever mask) of the router-side IP.
    """
    node_type = {n["name"]: n["type"] for n in topo.get("nodes", [])}
    prefixes: list[str] = []

    for link in topo.get("links", []):
        eps = link.get("endpoints", [])
        ips = link.get("ipv4", [])

        if len(eps) != 2 or len(ips) != 2:
            continue

        (n1, _if1) = eps[0].split(":", 1)
        (n2, _if2) = eps[1].split(":", 1)

        t1 = node_type.get(n1)
        t2 = node_type.get(n2)

        # router <-> host
        if t1 == "frr" and t2 == "host" and n1 == router_name:
            prefixes.append(ips[0])
        elif t2 == "frr" and t1 == "host" and n2 == router_name:
            prefixes.append(ips[1])

    # Convert interface IPs (192.168.1.1/24) to network prefixes (192.168.1.0/24)
    out: list[str] = []
    for cidr in prefixes:
        # lightweight network calculation without extra deps
        ip, mask = cidr.split("/", 1)
        import ipaddress
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        out.append(str(net))

    # de-dupe but keep stable order
    seen = set()
    result = []
    for p in out:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result

# -------------------------
# Topology -> containerlab
# -------------------------

# -------------------------
# Coverage model (advisory-only, declared-only, deterministic)
# -------------------------

def _coverage_test_ids(topo: dict[str, Any]) -> list[str]:
    tests = topo.get("tests", []) or []
    ids: list[str] = []
    for i, t in enumerate(tests, start=1):
        if not isinstance(t, dict):
            die(f"coverage: tests[{i}] is not a dict")
        name = t.get("name")
        if not isinstance(name, str) or not name.strip():
            die(f"coverage: tests[{i}] is unnamed; coverage requires tests[].name for stable IDs")
        ids.append(name.strip())
    # Deterministic: allow duplicates check here (even if validated elsewhere)
    if len(set(ids)) != len(ids):
        dups = sorted([x for x in set(ids) if ids.count(x) > 1])
        die(f"coverage: duplicate test names not allowed: {', '.join(dups)}")
    return ids

def _coverage_scenario_ids(topo: dict[str, Any]) -> list[str]:
    scenarios = topo.get("scenarios") or []
    if not scenarios:
        return []
    if not isinstance(scenarios, list):
        die("coverage: scenarios must be a list")
    out: list[str] = []
    for i, s in enumerate(scenarios, start=1):
        if not isinstance(s, dict):
            die(f"coverage: scenarios[{i}] is not a dict")
        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip():
            die(f"coverage: scenarios[{i}] missing non-empty id")
        out.append(sid.strip())
    if len(set(out)) != len(out):
        dups = sorted([x for x in set(out) if out.count(x) > 1])
        die(f"coverage: duplicate scenario ids not allowed: {', '.join(dups)}")
    return out

def _coverage_touch_nodes_from_test(
    topo: dict[str, Any],
    test: dict[str, Any],
    known_nodes: set[str],
) -> list[str]:
    touched: set[str] = set()
    src = test.get("src")
    dst = test.get("dst")

    if isinstance(src, str) and src.strip():
        s = src.strip()
        if s not in known_nodes:
            die(f"coverage: test '{test.get('name','<unnamed>')}' references unknown src node '{s}'")
        touched.add(s)

    # dst may be node name OR IP literal; only mark if it matches a known node name
    if isinstance(dst, str) and dst.strip():
        d = dst.strip()
        if d in known_nodes:
            touched.add(d)

    return sorted(touched)

import re
import ipaddress

_RE_NEIGH_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+")
_RE_IPV4_PREFIX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

def derive_expected_routes_for_frr(topo: dict[str, Any]) -> dict[str, set[str]]:
    """
    Intent: expected IPv4 prefixes that must appear in each FRR node's routing table.

    v1 rules:
      - router_id => expect router_id/32
      - FRR<->host links => expect connected subnet prefix (network of router-side IP)
      - v1 does NOT infer routing from topology (no static_routes, no auto-BGP)
    """
    nodes = topo.get("nodes", []) or []
    node_type = {n.get("name"): n.get("type") for n in nodes if isinstance(n, dict)}
    expected: dict[str, set[str]] = {}

    # 1) Loopbacks from router_id
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("type") != "frr":
            continue
        name = n.get("name")
        rid = n.get("router_id")
        if isinstance(name, str) and name:
            expected.setdefault(name, set())
            if isinstance(rid, str) and rid:
                p = _normalize_prefix(f"{rid}/32")
                if p:
                    expected[name].add(p)

    # 2) Connected host subnets (FRR<->host links)
    for link in topo.get("links", []) or []:
        eps = link.get("endpoints", []) or []
        ips = link.get("ipv4", []) or []
        if len(eps) != 2 or len(ips) != 2:
            continue

        (n1, _if1) = str(eps[0]).split(":", 1)
        (n2, _if2) = str(eps[1]).split(":", 1)

        t1 = node_type.get(n1)
        t2 = node_type.get(n2)

        # Only FRR<->host in v1
        if t1 == "frr" and t2 == "host":
            router = n1
            router_ip = ips[0]
        elif t2 == "frr" and t1 == "host":
            router = n2
            router_ip = ips[1]
        else:
            continue

        norm = _normalize_prefix(router_ip)
        if norm:
            expected.setdefault(router, set()).add(norm)

    return expected

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

def _node_index_by_name(topo: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Deterministic helper: index topo['nodes'] list by name.

    Kept local to netsim_tests to avoid cross-module coupling for read-only
    derivations used by cmd_status.
    """
    idx: dict[str, dict[str, Any]] = {}
    for n in topo.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if isinstance(name, str) and name:
            idx[name] = n
    return idx

def derive_expected_bgp_neighbors_from_links(topo: dict[str, Any]) -> dict[str, set[str]]:
    """
    Intent: expected BGP neighbors derived from topology links.

    Rule:
      - For each link with 2 endpoints and 2 ipv4 entries
      - If both endpoints are FRR nodes, then each side expects the other side's IP (no mask)
    """
    nodes = _node_index_by_name(topo)
    expected: dict[str, set[str]] = {}

    for link in topo.get("links", []) or []:
        eps = link.get("endpoints") or []
        ips = link.get("ipv4") or []
        if not (isinstance(eps, list) and isinstance(ips, list)):
            continue
        if len(eps) != 2 or len(ips) != 2:
            continue

        ep1, ep2 = eps
        ip1, ip2 = ips
        if not (isinstance(ep1, str) and isinstance(ep2, str) and isinstance(ip1, str) and isinstance(ip2, str)):
            continue
        if ":" not in ep1 or ":" not in ep2:
            continue

        n1, _if1 = ep1.split(":", 1)
        n2, _if2 = ep2.split(":", 1)

        if nodes.get(n1, {}).get("type") != "frr":
            continue
        if nodes.get(n2, {}).get("type") != "frr":
            continue

        # Neighbor IPs: strip CIDR
        nbr_for_n1 = ip2.split("/", 1)[0].strip()
        nbr_for_n2 = ip1.split("/", 1)[0].strip()

        expected.setdefault(n1, set()).add(nbr_for_n1)
        expected.setdefault(n2, set()).add(nbr_for_n2)

    return expected


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

def compare_expected_vs_observed_bgp(expected: set[str], observed: dict[str, dict[str, Any]]) -> dict[str, Any]:
    obs_set = set(observed.keys())
    missing = sorted(expected - obs_set)
    extra = sorted(obs_set - expected)

    established: list[str] = []
    down: list[str] = []
    for ip in sorted(expected & obs_set):
        if observed[ip].get("established"):
            established.append(ip)
        else:
            down.append(ip)

    ok = (not missing) and (not down)

    return {
        "expected": sorted(expected),
        "observed": sorted(obs_set),
        "missing": missing,
        "extra": extra,
        "established": established,
        "down": down,
        "ok": ok,
    }

def wait_for_bgp(rt: Runtime, lab: str, node: str, timeout: int = 30, require_evpn: bool = False) -> None:
    """
    Wait for BGP to be Established-ish on a node.

    FRR "show bgp summary" neighbor lines look like:
      Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd ...

    We treat a neighbor as "up" if State/PfxRcd is either:
      - a number (PfxRcd count)  -> Established
      - the word "Established"   -> also OK

    Anything like Idle/Active/Connect/OpenSent/OpenConfirm is not OK.
    "(Policy)" is not OK.
    """
    import json
    import time

    start = time.time()
    last_summary = ""
    last_neigh_lines: list[str] = []
    last_evpn_details = ""

    def parse_state_pfxrcd(neigh_line: str) -> str:
        parts = neigh_line.split()
        # parts[9] is State/PfxRcd in typical FRR output
        return parts[9] if len(parts) >= 10 else ""

    def evpn_neighbors_up() -> bool:
        nonlocal last_evpn_details
        cp = rt.exec(
            lab,
            node,
            ["vtysh", "-c", "show bgp l2vpn evpn summary json"],
            check=False,
            capture_output=True,
        )
        if cp.returncode != 0:
            last_evpn_details = f"rc={cp.returncode}"
            return False
        raw = (cp.stdout or "").strip()
        if not raw:
            last_evpn_details = "(empty EVPN summary)"
            return False
        try:
            data = json.loads(raw)
        except Exception:
            last_evpn_details = raw
            return False

        peers = data.get("peers") or {}
        if not peers:
            last_evpn_details = "(no EVPN peers)"
            return False

        bad = []
        for peer_ip, meta in peers.items():
            state = str((meta or {}).get("state", ""))
            if state.lower() != "established":
                bad.append(f"{peer_ip}:{state or 'unknown'}")
        if bad:
            last_evpn_details = "\n".join(bad)
            return False

        last_evpn_details = ""
        return True

    while True:
        cp = rt.exec(lab, node, ["vtysh", "-c", "show bgp summary"], check=False, capture_output=True)
        last_summary = cp.stdout or ""
        out = last_summary

        neigh_lines = [ln.strip() for ln in out.splitlines() if ln.strip() and ln.strip()[0].isdigit()]
        last_neigh_lines = neigh_lines

        # If we expect BGP and we have no neighbor lines yet, keep waiting
        if neigh_lines:
            if "(Policy)" in out:
                pass
            else:
                states = [parse_state_pfxrcd(ln) for ln in neigh_lines]

                def is_up(s: str) -> bool:
                    if not s:
                        return False
                    if s.isdigit():
                        return True
                    if s.lower() == "established":
                        return True
                    return False

                if all(is_up(s) for s in states):
                    if not require_evpn or evpn_neighbors_up():
                        return

        if time.time() - start > timeout:
            details = "\n".join(last_neigh_lines) if last_neigh_lines else "(no neighbor lines found)"
            if require_evpn and last_evpn_details:
                details = f"{details}\nEVPN:\n{last_evpn_details}"
            die(f"{node}: BGP did not converge within {timeout}s:\n{details}")

        time.sleep(1)

def configure_frr_static_routes_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    v1 contract: topology must NOT encode routing mechanics.

    This function is intentionally hard-disabled in v1/v1.x to prevent accidental
    authority creep (static routing derived from topology).
    """
    die("v1 contract: static routing from topology is not supported. Use preconfigured images/config outside Cassian Gate v1.")

    # Unreachable: retained only as a historical stub (do not remove without a versioned contract change).
    nodes = _node_index_by_name(topo)

    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue
        routes = n.get("static_routes") or []
        if not isinstance(routes, list):
            continue

        for r in routes:
            if not isinstance(r, str):
                continue
            rt.sh(lab, node, f"ip route replace {r}", check=False, capture_output=False)

def configure_frr_bgp_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    v1 contract: topology must NOT encode routing mechanics.

    This function is intentionally hard-disabled in v1/v1.x to prevent accidental
    authority creep (BGP provisioning derived from topology).
    """
    die("v1 contract: BGP provisioning from topology is not supported. Use preconfigured images/config outside Cassian Gate v1.")

    # Unreachable: retained only as a historical stub (do not remove without a versioned contract change).
    nodes = _node_index_by_name(topo)

    adj: list[tuple[str, str, str, str]] = []

    for link in topo.get("links", []) or []:
        endpoints = link.get("endpoints") or []
        ipv4s = link.get("ipv4") or []
        if not (isinstance(endpoints, list) and isinstance(ipv4s, list)):
            continue
        if len(endpoints) != 2 or len(ipv4s) != 2:
            continue

        ep1, ep2 = endpoints
        ip1, ip2 = ipv4s
        if not (isinstance(ep1, str) and isinstance(ep2, str) and isinstance(ip1, str) and isinstance(ip2, str)):
            continue
        if ":" not in ep1 or ":" not in ep2:
            continue

        n1, _if1 = ep1.split(":", 1)
        n2, _if2 = ep2.split(":", 1)

        if nodes.get(n1, {}).get("type") != "frr":
            continue
        if nodes.get(n2, {}).get("type") != "frr":
            continue

        nbr1 = ip2.split("/", 1)[0]
        nbr2 = ip1.split("/", 1)[0]
        adj.append((n1, nbr1, n2, nbr2))

    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue

        asn = n.get("asn")
        rid = n.get("router_id")
        if not isinstance(asn, int):
            if isinstance(asn, str) and asn.isdigit():
                asn = int(asn)
            else:
                continue

        cmds: list[str] = []
        cmds.append("conf t")
        cmds.append(f"router bgp {asn}")
        if isinstance(rid, str) and rid:
            cmds.append(f"bgp router-id {rid}")

        cmds.append("no bgp ebgp-requires-policy")

        for a, ip_to_b, b, _ip_to_a in adj:
            if a != node:
                continue
            b_asn = nodes.get(b, {}).get("asn")
            if isinstance(b_asn, str) and b_asn.isdigit():
                b_asn = int(b_asn)
            if not isinstance(b_asn, int):
                continue

            cmds.append(f"neighbor {ip_to_b} remote-as {b_asn}")

        cmds.append("end")

        vty_cmd: list[str] = ["vtysh"]
        for c in cmds:
            vty_cmd += ["-c", c]

        rt.exec(lab, node, vty_cmd, check=False, capture_output=False)

def _parse_route_entry(fw_name: str, r: object) -> tuple[str, str]:
    """
    Parse a route entry into (prefix, via) strings.
    Supports:
      - "192.168.1.0/24 via 10.0.0.2"
      - {"prefix": "192.168.1.0/24", "via": "10.0.0.2"}
    """
    if isinstance(r, str):
        if " via " not in r:
            die(f"{fw_name}: route string must look like 'PREFIX via NEXT_HOP' (got: {r!r})")
        prefix, via = r.split(" via ", 1)
        prefix, via = prefix.strip(), via.strip()

    elif isinstance(r, dict):
        prefix = str(r.get("prefix") or "").strip()
        via = str(r.get("via") or "").strip()
        if not prefix or not via:
            die(f"{fw_name}: route dict must include 'prefix' and 'via' (got: {r!r})")

    else:
        die(f"{fw_name}: routes entries must be strings or dicts (got: {type(r).__name__})")

    if not prefix or not via:
        die(f"{fw_name}: invalid route (got prefix={prefix!r}, via={via!r})")

    return prefix, via

def configure_nftfw_routes_from_topology(rt: "Runtime", lab: str, topo: dict) -> None:
    """
    Configure static routes on nft-fw nodes (Linux) based on topology.

    Supports BOTH formats:

    1) String form (like FRR static_routes):
        routes:
          - "192.168.1.0/24 via 10.0.0.2"
          - "192.168.2.0/24 via 10.0.0.5"

    2) Dict form:
        routes:
          - prefix: "192.168.1.0/24"
            via: "10.0.0.2"
          - prefix: "192.168.2.0/24"
            via: "10.0.0.5"

    Uses `ip route replace` to be safe on repeated runs.

    Runtime contract:
      - No direct docker/container_name usage here.
      - All node execution goes through rt.exec().
    """
    nodes = topo.get("nodes", []) or []
    if not isinstance(nodes, list):
        die("topology 'nodes' must be a list")

    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("type") != "nft-fw":
            continue

        fw_name = n.get("name")
        if not isinstance(fw_name, str) or not fw_name.strip():
            die("nft-fw node missing 'name'")
        fw_name = fw_name.strip()

        routes = n.get("routes") or []
        if not isinstance(routes, list) or not routes:
            continue

        for r in routes:
            prefix: str
            via: str

            # Format A: string "PREFIX via NEXT_HOP"
            if isinstance(r, str):
                if " via " not in r:
                    die(f"{fw_name}: route string must look like 'PREFIX via NEXT_HOP' (got: {r!r})")
                p, v = r.split(" via ", 1)
                prefix = p.strip()
                via = v.strip()

            # Format B: dict {"prefix": "...", "via": "..."}
            elif isinstance(r, dict):
                prefix = str(r.get("prefix") or "").strip()
                via = str(r.get("via") or "").strip()
                if not prefix or not via:
                    die(f"{fw_name}: route dict must include 'prefix' and 'via' (got: {r!r})")

            else:
                die(f"{fw_name}: routes entries must be strings or dicts (got: {type(r).__name__})")

            if not prefix or not via:
                die(f"{fw_name}: invalid route (got prefix={prefix!r}, via={via!r})")

            # Apply route inside the firewall node
            rt.exec(
                lab,
                fw_name,
                ["ip", "route", "replace", prefix, "via", via],
                check=True,
                capture_output=False,
            )

def verify_fw_routed_ready(rt: Runtime, lab: str, fw_node: str) -> None:
    """
    Verify that a routed firewall node is ready to forward traffic.

    Readiness criteria (v1):
    - nft binary exists
    - nftables is usable (kernel + permissions OK)
    - IPv4 forwarding is enabled

    This function must be:
    - non-interactive (NO -t)
    - deterministic
    - fail-fast with clear errors
    """

    # ---------------------------------------------------------------------
    # 1) nft must exist in the image
    # ---------------------------------------------------------------------
    cp = rt.exec(
        lab,
        fw_node,
        ["sh", "-lc", "command -v nft >/dev/null"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        die(f"{fw_node}: nft not found (use an image with nftables preinstalled)")

    # ---------------------------------------------------------------------
    # 2) nft must be usable (kernel support + permissions)
    #    This catches cases where nft exists but cannot talk to the kernel.
    # ---------------------------------------------------------------------
    cp = rt.exec(
        lab,
        fw_node,
        ["sh", "-lc", "nft list ruleset >/dev/null 2>&1"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        die(f"{fw_node}: nftables ruleset not accessible")

    # ---------------------------------------------------------------------
    # 3) IPv4 forwarding must be enabled (routed firewall)
    # ---------------------------------------------------------------------
    cp = rt.exec(
        lab,
        fw_node,
        ["sh", "-lc", "sysctl -n net.ipv4.ip_forward"],
        check=False,
        capture_output=True,
    )
    val = (cp.stdout or "").strip()
    if val != "1":
        die(f"{fw_node}: ip_forward is not enabled (got '{val}')")

def _iter_scenarios(topo: dict[str, Any]) -> list[dict[str, Any]]:
    sc = topo.get("scenarios") or []
    if sc is None:
        return []
    if not isinstance(sc, list):
        die("topology 'scenarios' must be a list")
    out: list[dict[str, Any]] = []
    for s in sc:
        if isinstance(s, dict):
            out.append(s)
        else:
            die("each scenario entry must be a dict")
    return out

def validate_scenarios(topo: dict[str, Any]) -> None:
    """
    Fail-fast validation of scenario schema.
    Must run before any scenario execution.

    v1 rules:
      - scenarios optional; if present must be list[dict]
      - scenario keys only: id, description, steps
      - steps is non-empty list
      - each step must contain exactly one of: run | fault | wait_for | wait_for_bgp
      - run: must reference an existing test name
      - fault: exactly one action:
          link_down/link_up: requires a,b; optional a_if,b_if (both-or-none)
          interface_down/interface_up: requires node + if/iface/interface
      - wait_for: type ping|tcp; from/to required; expect pass|fail; tcp requires port

    v1 deep validation (multi-link disambiguation):
      - For link_down/link_up:
          * if a_if/b_if omitted => there must be exactly ONE declared link between a and b
          * if a_if/b_if provided => it must match a declared link exactly
    """
    scenarios = topo.get("scenarios") or []
    if not scenarios:
        return

    if not isinstance(scenarios, list):
        die("scenarios: must be a list")

    # Collect declared test names for run: validation
    tests = topo.get("tests") or []
    test_names: set[str] = set()
    for t in tests:
        if isinstance(t, dict):
            n = t.get("name")
            if isinstance(n, str) and n.strip():
                test_names.add(n.strip())

    # Enforce unique scenario IDs (determinism)
    seen_ids: set[str] = set()

    def _link_matches(a: str, b: str) -> list[tuple[str, str]]:
        """
        Return all interface pairs (a_if, b_if) for declared links between a and b.
        Deterministic: derived only from topo['links'] endpoints.
        """
        links = topo.get("links", []) or []

        def parse_ep(ep: str) -> tuple[str, str] | None:
            if not isinstance(ep, str) or ":" not in ep:
                return None
            n, iface = ep.split(":", 1)
            n = n.strip()
            iface = iface.strip()
            if not n or not iface:
                return None
            return n, iface

        matches: list[tuple[str, str]] = []
        for link in links:
            eps = link.get("endpoints")
            if not isinstance(eps, list) or len(eps) != 2:
                continue
            p0 = parse_ep(eps[0])
            p1 = parse_ep(eps[1])
            if not p0 or not p1:
                continue

            (n0, if0), (n1, if1) = p0, p1
            if n0 == a and n1 == b:
                matches.append((if0, if1))
            elif n0 == b and n1 == a:
                matches.append((if1, if0))

        return matches

    for si, sc in enumerate(scenarios, start=1):
        ctx = f"scenarios[{si}]"

        if not isinstance(sc, dict):
            die(f"{ctx}: must be a dict")

        allowed_sc_keys = {"id", "description", "steps"}
        unknown_sc = set(sc) - allowed_sc_keys
        if unknown_sc:
            die(f"{ctx}: unknown keys {sorted(unknown_sc)}")

        sid = sc.get("id")
        if not isinstance(sid, str) or not sid.strip():
            die(f"{ctx}: 'id' must be a non-empty string")
        sid = sid.strip()

        if sid in seen_ids:
            die(f"{ctx}: duplicate id '{sid}'")
        seen_ids.add(sid)

        steps = sc.get("steps")
        if not isinstance(steps, list) or not steps:
            die(f"scenario '{sid}': 'steps' must be a non-empty list")

        for step_i, step in enumerate(steps, start=1):
            sctx = f"scenario '{sid}' step[{step_i}]"

            if not isinstance(step, dict):
                die(f"{sctx}: step must be a dict")
            if not step:
                die(f"{sctx}: empty step")
            if len(step) != 1:
                keys = sorted(str(k) for k in step.keys())
                die(f"{sctx}: must contain exactly one action category; found {len(keys)}: {', '.join(keys)}")

            action_key = next(iter(step.keys()))
            recognized_actions = {"run", "fault", "wait_for", "wait_for_bgp", "pcap_start", "pcap_stop"}
            if action_key not in recognized_actions:
                die(f"{sctx}: uses unknown action category '{action_key}'")

                        # ---- pcap_start ----
            if "pcap_start" in step:
                ps = step.get("pcap_start")
                if not isinstance(ps, dict):
                    die(f"{sctx}.pcap_start: must be a dict")

                allowed_ps = {"target", "label", "filter", "max_seconds", "max_kb", "snaplen", "mode"}
                unknown = set(ps) - allowed_ps
                if unknown:
                    die(f"{sctx}.pcap_start: unknown keys {sorted(unknown)}")

                if "target" not in ps:
                    die(f"{sctx}.pcap_start: missing required key 'target'")

                # mode (v1.5): interface only
                mode = ps.get("mode")
                if mode is not None:
                    if not isinstance(mode, str) or not mode.strip():
                        die(f"{sctx}.pcap_start.mode: must be a non-empty string")
                    if mode.strip() != "interface":
                        die(f"{sctx}.pcap_start.mode: only 'interface' is supported (got '{mode.strip()}')")

                # label (sanitized later; validate shape only here)
                label = ps.get("label")
                if label is not None:
                    if not isinstance(label, str) or not label.strip():
                        die(f"{sctx}.pcap_start.label: must be a non-empty string")

                # filter (validate shape only; NEVER store in filenames/results)
                flt = ps.get("filter")
                if flt is not None:
                    if not isinstance(flt, str) or not flt.strip():
                        die(f"{sctx}.pcap_start.filter: must be a non-empty string")

                # bounds (explicit if provided; defaults handled elsewhere if added)
                max_seconds = ps.get("max_seconds")
                if max_seconds is not None:
                    if not isinstance(max_seconds, int) or max_seconds < 1:
                        die(f"{sctx}.pcap_start.max_seconds: must be an int >= 1")

                max_kb = ps.get("max_kb")
                if max_kb is not None:
                    if not isinstance(max_kb, int) or max_kb < 1:
                        die(f"{sctx}.pcap_start.max_kb: must be an int >= 1")

                snaplen = ps.get("snaplen")
                if snaplen is not None:
                    if not isinstance(snaplen, int) or snaplen < 1:
                        die(f"{sctx}.pcap_start.snaplen: must be an int >= 1")

                # target schema (explicit, deterministic)
                tgt = ps.get("target")
                if not isinstance(tgt, dict):
                    die(f"{sctx}.pcap_start.target: must be a dict")

                tgt_keys = set(tgt)
                is_iface = ("node" in tgt_keys) or ("iface" in tgt_keys)
                is_link = ("a" in tgt_keys) or ("b" in tgt_keys) or ("a_if" in tgt_keys) or ("b_if" in tgt_keys)

                if is_iface and is_link:
                    die(f"{sctx}.pcap_start.target: ambiguous target shape (choose interface OR link form)")
                if not is_iface and not is_link:
                    die(f"{sctx}.pcap_start.target: must be interface target (node+iface) or link target (a+b with optional a_if/b_if)")

                # Interface target: node + iface
                if is_iface:
                    allowed_t = {"node", "iface"}
                    unknown_t = tgt_keys - allowed_t
                    if unknown_t:
                        die(f"{sctx}.pcap_start.target: unknown keys {sorted(unknown_t)}")

                    node = tgt.get("node")
                    iface = tgt.get("iface")
                    if not isinstance(node, str) or not node.strip():
                        die(f"{sctx}.pcap_start.target.node: must be a non-empty string")
                    if not isinstance(iface, str) or not iface.strip():
                        die(f"{sctx}.pcap_start.target.iface: must be a non-empty string")

                    node_s = node.strip()
                    iface_s = iface.strip()

                    # node must exist
                    nodes = topo.get("nodes") or []
                    by_name: dict[str, dict] = {
                        n.get("name"): n
                        for n in nodes
                        if isinstance(n, dict) and isinstance(n.get("name"), str)
                    }
                    if node_s not in by_name:
                        die(f"{sctx}.pcap_start.target.node: unknown node '{node_s}'")

                    # iface must exist on that node in topo['links'] endpoints
                    links = topo.get("links", []) or []

                    def _parse_ep(ep: str) -> tuple[str, str] | None:
                        if not isinstance(ep, str) or ":" not in ep:
                            return None
                        n, ifx = ep.split(":", 1)
                        n = n.strip()
                        ifx = ifx.strip()
                        if not n or not ifx:
                            return None
                        return n, ifx

                    node_ifaces: set[str] = set()
                    for link in links:
                        eps = link.get("endpoints")
                        if not isinstance(eps, list) or len(eps) != 2:
                            continue
                        for ep in eps:
                            p = _parse_ep(ep)
                            if not p:
                                continue
                            n, ifx = p
                            if n == node_s:
                                node_ifaces.add(ifx)

                    if iface_s not in node_ifaces:
                        known = ", ".join(sorted(node_ifaces)) if node_ifaces else "(none)"
                        die(
                            f"{sctx}.pcap_start.target: interface '{iface_s}' not found on node '{node_s}'. "
                            f"Known interfaces from links: {known}"
                        )

                # Link target: a + b, optional a_if/b_if (both-or-none), must be unambiguous if omitted
                else:
                    allowed_t = {"a", "b", "a_if", "b_if"}
                    unknown_t = tgt_keys - allowed_t
                    if unknown_t:
                        die(f"{sctx}.pcap_start.target: unknown keys {sorted(unknown_t)}")

                    for k in ("a", "b"):
                        v = tgt.get(k)
                        if not isinstance(v, str) or not v.strip():
                            die(f"{sctx}.pcap_start.target.{k}: must be a non-empty string")

                    a_if = tgt.get("a_if")
                    b_if = tgt.get("b_if")

                    # both-or-none
                    if (a_if is None) ^ (b_if is None):
                        die(f"{sctx}.pcap_start.target: must provide both a_if and b_if (or neither)")

                    if a_if is not None:
                        if not isinstance(a_if, str) or not a_if.strip():
                            die(f"{sctx}.pcap_start.target.a_if: must be a non-empty string")
                        if not isinstance(b_if, str) or not b_if.strip():
                            die(f"{sctx}.pcap_start.target.b_if: must be a non-empty string")

                    a = str(tgt.get("a") or "").strip()
                    b = str(tgt.get("b") or "").strip()
                    matches = _link_matches(a, b)

                    if a_if is None and b_if is None:
                        if len(matches) == 0:
                            die(f"{sctx}.pcap_start.target: no declared link found between {a} and {b}")
                        if len(matches) > 1:
                            die(
                                f"{sctx}.pcap_start.target: ambiguous links between {a} and {b} "
                                f"({len(matches)} found); provide a_if/b_if"
                            )
                    else:
                        a_if_s = str(a_if).strip()
                        b_if_s = str(b_if).strip()
                        if (a_if_s, b_if_s) not in matches:
                            known = ", ".join([f"{a}:{x}<->{b}:{y}" for (x, y) in matches]) or "(none)"
                            die(
                                f"{sctx}.pcap_start.target: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                                f"does not match any declared link between {a} and {b}. "
                                f"Known links: {known}"
                            )

            # ---- pcap_stop ----
            if "pcap_stop" in step:
                ps = step.get("pcap_stop")
                if ps is None:
                    ps = {}
                if not isinstance(ps, dict):
                    die(f"{sctx}.pcap_stop: must be a dict")

                allowed_ps = {"target"}
                unknown = set(ps) - allowed_ps
                if unknown:
                    die(f"{sctx}.pcap_stop: unknown keys {sorted(unknown)}")

                tgt = ps.get("target")
                if tgt is None:
                    # stop-all is allowed (resolved at runtime)
                    pass
                else:
                    if not isinstance(tgt, dict):
                        die(f"{sctx}.pcap_stop.target: must be a dict")

                    tgt_keys = set(tgt)
                    is_iface = ("node" in tgt_keys) or ("iface" in tgt_keys)
                    is_link = ("a" in tgt_keys) or ("b" in tgt_keys) or ("a_if" in tgt_keys) or ("b_if" in tgt_keys)

                    if is_iface and is_link:
                        die(f"{sctx}.pcap_stop.target: ambiguous target shape (choose interface OR link form)")
                    if not is_iface and not is_link:
                        die(f"{sctx}.pcap_stop.target: must be interface target (node+iface) or link target (a+b with optional a_if/b_if)")

                    # For v1.5: reuse the same validation rules as pcap_start.target.
                    # We validate resolvability only (does not start capture).
                    if is_iface:
                        allowed_t = {"node", "iface"}
                        unknown_t = tgt_keys - allowed_t
                        if unknown_t:
                            die(f"{sctx}.pcap_stop.target: unknown keys {sorted(unknown_t)}")

                        node = tgt.get("node")
                        iface = tgt.get("iface")
                        if not isinstance(node, str) or not node.strip():
                            die(f"{sctx}.pcap_stop.target.node: must be a non-empty string")
                        if not isinstance(iface, str) or not iface.strip():
                            die(f"{sctx}.pcap_stop.target.iface: must be a non-empty string")

                        node_s = node.strip()
                        iface_s = iface.strip()

                        nodes = topo.get("nodes") or []
                        by_name: dict[str, dict] = {
                            n.get("name"): n
                            for n in nodes
                            if isinstance(n, dict) and isinstance(n.get("name"), str)
                        }
                        if node_s not in by_name:
                            die(f"{sctx}.pcap_stop.target.node: unknown node '{node_s}'")

                        links = topo.get("links", []) or []

                        def _parse_ep(ep: str) -> tuple[str, str] | None:
                            if not isinstance(ep, str) or ":" not in ep:
                                return None
                            n, ifx = ep.split(":", 1)
                            n = n.strip()
                            ifx = ifx.strip()
                            if not n or not ifx:
                                return None
                            return n, ifx

                        node_ifaces: set[str] = set()
                        for link in links:
                            eps = link.get("endpoints")
                            if not isinstance(eps, list) or len(eps) != 2:
                                continue
                            for ep in eps:
                                p = _parse_ep(ep)
                                if not p:
                                    continue
                                n, ifx = p
                                if n == node_s:
                                    node_ifaces.add(ifx)

                        if iface_s not in node_ifaces:
                            known = ", ".join(sorted(node_ifaces)) if node_ifaces else "(none)"
                            die(
                                f"{sctx}.pcap_stop.target: interface '{iface_s}' not found on node '{node_s}'. "
                                f"Known interfaces from links: {known}"
                            )

                    else:
                        allowed_t = {"a", "b", "a_if", "b_if"}
                        unknown_t = tgt_keys - allowed_t
                        if unknown_t:
                            die(f"{sctx}.pcap_stop.target: unknown keys {sorted(unknown_t)}")

                        for k in ("a", "b"):
                            v = tgt.get(k)
                            if not isinstance(v, str) or not v.strip():
                                die(f"{sctx}.pcap_stop.target.{k}: must be a non-empty string")

                        a_if = tgt.get("a_if")
                        b_if = tgt.get("b_if")

                        if (a_if is None) ^ (b_if is None):
                            die(f"{sctx}.pcap_stop.target: must provide both a_if and b_if (or neither)")

                        if a_if is not None:
                            if not isinstance(a_if, str) or not a_if.strip():
                                die(f"{sctx}.pcap_stop.target.a_if: must be a non-empty string")
                            if not isinstance(b_if, str) or not b_if.strip():
                                die(f"{sctx}.pcap_stop.target.b_if: must be a non-empty string")

                        a = str(tgt.get("a") or "").strip()
                        b = str(tgt.get("b") or "").strip()
                        matches = _link_matches(a, b)

                        if a_if is None and b_if is None:
                            if len(matches) == 0:
                                die(f"{sctx}.pcap_stop.target: no declared link found between {a} and {b}")
                            if len(matches) > 1:
                                die(
                                    f"{sctx}.pcap_stop.target: ambiguous links between {a} and {b} "
                                    f"({len(matches)} found); provide a_if/b_if"
                                )
                        else:
                            a_if_s = str(a_if).strip()
                            b_if_s = str(b_if).strip()
                            if (a_if_s, b_if_s) not in matches:
                                known = ", ".join([f"{a}:{x}<->{b}:{y}" for (x, y) in matches]) or "(none)"
                                die(
                                    f"{sctx}.pcap_stop.target: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                                    f"does not match any declared link between {a} and {b}. "
                                    f"Known links: {known}"
                                )

            # ---- run ----
            if "run" in step:
                ref = step.get("run")
                if not isinstance(ref, str) or not ref.strip():
                    die(f"{sctx}.run: must be a non-empty test name string")
                ref = ref.strip()

                if ref not in test_names:
                    die(
                        f"ERROR: scenario '{sid}' references unknown test '{ref}'\n"
                        f"Known tests: [{', '.join(sorted(test_names))}]\n"
                        "Scenario execution aborted before any steps ran."
                    )

            # ---- fault ----
            if "fault" in step:
                fault = step.get("fault")
                if not isinstance(fault, dict) or len(fault) != 1:
                    die(f"{sctx}.fault: must contain exactly one action")

                action, spec = next(iter(fault.items()))
                if action not in (
                    "link_down",
                    "link_up",
                    "interface_down",
                    "interface_up",
                    "packet_loss",
                    "latency",
                    "bandwidth_cap",
                    "prefix_blackhole",
                ):
                    die(f"{sctx}.fault: unsupported action '{action}'")

                if not isinstance(spec, dict):
                    die(f"{sctx}.fault.{action}: must be a dict")

                if action in ("link_down", "link_up"):
                    allowed_spec = {"a", "b", "a_if", "b_if"}
                    unknown = set(spec) - allowed_spec
                    if unknown:
                        die(f"{sctx}.fault.{action}: unknown keys {sorted(unknown)}")

                    for k in ("a", "b"):
                        v = spec.get(k)
                        if not isinstance(v, str) or not v.strip():
                            die(f"{sctx}.fault.{action}.{k}: must be a non-empty string")

                    a_if = spec.get("a_if")
                    b_if = spec.get("b_if")

                    if (a_if is None) ^ (b_if is None):
                        die(f"{sctx}.fault.{action}: must provide both a_if and b_if (or neither)")

                    if a_if is not None:
                        if not isinstance(a_if, str) or not a_if.strip():
                            die(f"{sctx}.fault.{action}.a_if: must be a non-empty string")
                        if not isinstance(b_if, str) or not b_if.strip():
                            die(f"{sctx}.fault.{action}.b_if: must be a non-empty string")

                    a = str(spec.get("a") or "").strip()
                    b = str(spec.get("b") or "").strip()
                    matches = _link_matches(a, b)

                    if a_if is None and b_if is None:
                        if len(matches) == 0:
                            die(f"{sctx}.fault.{action}: no declared link found between {a} and {b}")
                        if len(matches) > 1:
                            die(
                                f"{sctx}.fault.{action}: ambiguous links between {a} and {b} "
                                f"({len(matches)} found); provide a_if/b_if"
                            )
                    else:
                        a_if_s = str(a_if).strip()
                        b_if_s = str(b_if).strip()
                        if (a_if_s, b_if_s) not in matches:
                            known = ", ".join([f"{a}:{x}<->{b}:{y}" for (x, y) in matches]) or "(none)"
                            die(
                                f"{sctx}.fault.{action}: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                                f"does not match any declared link between {a} and {b}. "
                                f"Known links: {known}"
                            )

                elif action in ("packet_loss", "latency", "bandwidth_cap"):
                    allowed_spec = {"a", "b", "a_if", "b_if", "node", "if", "iface", "interface"}
                    if action == "packet_loss":
                        allowed_spec |= {"loss", "loss_percent"}
                    elif action == "latency":
                        allowed_spec |= {"latency_ms"}
                    elif action == "bandwidth_cap":
                        allowed_spec |= {"bandwidth_mbps"}

                    unknown = set(spec) - allowed_spec
                    if unknown:
                        die(f"{sctx}.fault.{action}: unknown keys {sorted(unknown)}")

                    has_iface_target = any(k in spec for k in ("node", "if", "iface", "interface"))
                    has_link_target = any(k in spec for k in ("a", "b", "a_if", "b_if"))

                    if has_iface_target and has_link_target:
                        die(f"{sctx}.fault.{action}: choose node+if OR a/b link form, not both")

                    if has_iface_target:
                        node = spec.get("node")
                        if not isinstance(node, str) or not node.strip():
                            die(f"{sctx}.fault.{action}.node: must be a non-empty string")

                        iface_keys = ["if", "iface", "interface"]
                        provided = [k for k in iface_keys if k in spec and spec.get(k) is not None]
                        if len(provided) == 0:
                            die(f"{sctx}.fault.{action}: must include exactly one of if/iface/interface")
                        if len(provided) > 1:
                            die(
                                f"{sctx}.fault.{action}: provide only one of if/iface/interface "
                                f"(got {provided})"
                            )

                        iface_val = spec.get(provided[0])
                        if not isinstance(iface_val, str) or not iface_val.strip():
                            die(f"{sctx}.fault.{action}.{provided[0]}: must be a non-empty string")
                    else:
                        a = spec.get("a")
                        b = spec.get("b")
                        if not isinstance(a, str) or not a.strip():
                            die(f"{sctx}.fault.{action}.a: must be a non-empty string")
                        if not isinstance(b, str) or not b.strip():
                            die(f"{sctx}.fault.{action}.b: must be a non-empty string")

                        a_if = spec.get("a_if")
                        b_if = spec.get("b_if")
                        if (a_if is None) ^ (b_if is None):
                            die(f"{sctx}.fault.{action}: must provide both a_if and b_if (or neither)")

                        if a_if is not None:
                            if not isinstance(a_if, str) or not a_if.strip():
                                die(f"{sctx}.fault.{action}.a_if: must be a non-empty string")
                            if not isinstance(b_if, str) or not b_if.strip():
                                die(f"{sctx}.fault.{action}.b_if: must be a non-empty string")

                        matches = _link_matches(str(a).strip(), str(b).strip())
                        if a_if is None and b_if is None:
                            if len(matches) == 0:
                                die(f"{sctx}.fault.{action}: no declared link found between {a} and {b}")
                            if len(matches) > 1:
                                die(
                                    f"{sctx}.fault.{action}: ambiguous links between {a} and {b} "
                                    f"({len(matches)} found); provide a_if/b_if"
                                )
                        else:
                            a_if_s = str(a_if).strip()
                            b_if_s = str(b_if).strip()
                            if (a_if_s, b_if_s) not in matches:
                                known = ", ".join([f"{a}:{x}<->{b}:{y}" for (x, y) in matches]) or "(none)"
                                die(
                                    f"{sctx}.fault.{action}: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                                    f"does not match any declared link between {a} and {b}. "
                                    f"Known links: {known}"
                                )

                    if action == "packet_loss":
                        loss = spec.get("loss_percent")
                        if loss is None:
                            loss = spec.get("loss")
                        if not isinstance(loss, int):
                            die(f"{sctx}.fault.packet_loss: loss/loss_percent must be an int")

                    elif action == "latency":
                        latency_ms = spec.get("latency_ms")
                        if not isinstance(latency_ms, int):
                            die(f"{sctx}.fault.latency: latency_ms must be int")

                        if latency_ms < 0:
                            die(f"{sctx}.fault.latency: latency_ms must be >= 0")

                elif action == "prefix_blackhole":
                    allowed_spec = {"node", "prefix"}
                    unknown = set(spec) - allowed_spec
                    if unknown:
                        die(f"{sctx}.fault.{action}: unknown keys {sorted(unknown)}")

                    node = spec.get("node")
                    prefix = spec.get("prefix")

                    if not isinstance(node, str) or not node.strip():
                        die(f"{sctx}.fault.{action}.node: must be a non-empty string")
                    node_s = node.strip()

                    nodes = topo.get("nodes") or []
                    by_name: dict[str, dict] = {
                        n.get("name"): n
                        for n in nodes
                        if isinstance(n, dict) and isinstance(n.get("name"), str)
                    }
                    if node_s not in by_name:
                        die(f"{sctx}.fault.{action}.node: unknown node '{node_s}'")

                    if not isinstance(prefix, str) or not prefix.strip():
                        die(f"{sctx}.fault.{action}.prefix: must be a non-empty string")
                    _normalize_prefix(prefix.strip())

                else:
                    # interface_down / interface_up
                    allowed_spec = {"node", "if", "iface", "interface"}
                    unknown = set(spec) - allowed_spec
                    if unknown:
                        die(f"{sctx}.fault.{action}: unknown keys {sorted(unknown)}")

                    node = spec.get("node")
                    if not isinstance(node, str) or not node.strip():
                        die(f"{sctx}.fault.{action}.node: must be a non-empty string")
                    node_s = node.strip()

                    # Exactly ONE of if/iface/interface must be provided (no ambiguity)
                    iface_keys = ["if", "iface", "interface"]
                    provided = [k for k in iface_keys if k in spec and spec.get(k) is not None]

                    if len(provided) == 0:
                        die(f"{sctx}.fault.{action}: must include exactly one of if/iface/interface")
                    if len(provided) > 1:
                        die(
                            f"{sctx}.fault.{action}: provide only one of if/iface/interface "
                            f"(got {provided})"
                        )

                    iface_val = spec.get(provided[0])
                    if not isinstance(iface_val, str) or not iface_val.strip():
                        die(f"{sctx}.fault.{action}.{provided[0]}: must be a non-empty string")
                    iface_s = iface_val.strip()

                    # --- deeper v1 validation: node exists in topo['nodes'] ---
                    nodes = topo.get("nodes") or []
                    by_name: dict[str, dict] = {
                        n.get("name"): n
                        for n in nodes
                        if isinstance(n, dict) and isinstance(n.get("name"), str)
                    }
                    nrec = by_name.get(node_s)
                    if not nrec:
                        die(f"{sctx}.fault.{action}.node: unknown node '{node_s}'")

                    # --- deeper v1 validation: interface exists for that node in topo['links'] endpoints ---
                    links = topo.get("links", []) or []

                    def _parse_ep(ep: str) -> tuple[str, str] | None:
                        if not isinstance(ep, str) or ":" not in ep:
                            return None
                        n, ifx = ep.split(":", 1)
                        n = n.strip()
                        ifx = ifx.strip()
                        if not n or not ifx:
                            return None
                        return n, ifx

                    node_ifaces: set[str] = set()
                    for link in links:
                        eps = link.get("endpoints")
                        if not isinstance(eps, list) or len(eps) != 2:
                            continue
                        for ep in eps:
                            p = _parse_ep(ep)
                            if not p:
                                continue
                            n, ifx = p
                            if n == node_s:
                                node_ifaces.add(ifx)

                    if iface_s not in node_ifaces:
                        known = ", ".join(sorted(node_ifaces)) if node_ifaces else "(none)"
                        die(
                            f"{sctx}.fault.{action}: interface '{iface_s}' not found on node '{node_s}'. "
                            f"Known interfaces from links: {known}"
                        )

            # ---- wait_for ----
            if "wait_for" in step:
                wf = step.get("wait_for")
                if not isinstance(wf, dict):
                    die(f"{sctx}.wait_for: must be a dict")

                # Canonical bounded schema (v1.5 extension, validate-time only):
                # - explicit bounds: timeout + interval_s are REQUIRED
                # - type supports: ping | tcp | route_prefix
                if "type" not in wf:
                    die(f"{sctx}.wait_for: missing keys ['type']")

                t = wf.get("type")
                if not isinstance(t, str) or not t.strip():
                    die(f"{sctx}.wait_for.type: must be a non-empty string")
                t = t.strip()

                if t not in ("ping", "tcp", "route_prefix"):
                    die(f"{sctx}.wait_for.type: must be ping|tcp|route_prefix")

                # Base required keys (all types)
                base_required = {"type", "from", "expect", "timeout", "interval_s"}
                missing = base_required - set(wf)
                if missing:
                    die(f"{sctx}.wait_for: missing keys {sorted(missing)}")

                # Type-specific required keys + allowed key sets
                if t == "ping":
                    type_required = {"to"}
                    allowed_wf = base_required | type_required | {
                        "count",
                        "per_attempt_timeout_s",
                        "src_ip",
                        "src_if",
                    }
                elif t == "tcp":
                    type_required = {"to", "port"}
                    allowed_wf = base_required | type_required | {
                        "per_attempt_timeout_s",
                        "src_ip",
                        "src_if",
                    }
                else:
                    # route_prefix
                    # Accept 'on' as alias for 'src' (fail-fast if both present and disagree)
                    on_v = wf.get("on")
                    src_v = wf.get("src")
                    if on_v is not None and src_v is not None:
                        if str(on_v).strip() != str(src_v).strip():
                            die(f"{sctx}.wait_for: route_prefix on/src mismatch (provide only one or same value)")
                    if src_v is None and on_v is not None:
                        wf["src"] = str(on_v).strip()
                    type_required = {"src", "prefix"}
                    allowed_wf = base_required | type_required | {
                        "on",
                        "per_attempt_timeout_s",
                    }

                missing = type_required - set(wf)
                if missing:
                    # route_prefix requires clearer, contract-aligned messages
                    if t == "route_prefix":
                        if "src" in missing:
                            die(f"{sctx}.wait_for: route_prefix wait_for requires 'on/src' as a node name")
                        if "prefix" in missing:
                            die(f"{sctx}.wait_for: route_prefix wait_for requires 'prefix' as CIDR")
                    die(f"{sctx}.wait_for: missing keys {sorted(missing)}")

                unknown = set(wf) - allowed_wf
                if unknown:
                    die(f"{sctx}.wait_for: unknown keys {sorted(unknown)}")

                # expect
                exp = wf.get("expect")
                if exp not in ("pass", "fail"):
                    die(f"{sctx}.wait_for.expect: must be pass|fail")

                # bounds
                to = wf.get("timeout")
                if not isinstance(to, int) or to <= 0:
                    die(f"{sctx}.wait_for.timeout: must be a positive int")

                iv = wf.get("interval_s")
                if not isinstance(iv, (int, float)) or float(iv) <= 0:
                    die(f"{sctx}.wait_for.interval_s: must be a positive number")

                # optional per-attempt timeout
                if "per_attempt_timeout_s" in wf:
                    pat = wf.get("per_attempt_timeout_s")
                    if not isinstance(pat, int) or pat < 1:
                        die(f"{sctx}.wait_for.per_attempt_timeout_s: must be an int >= 1")

                # optional ping count (ping only)
                if t == "ping" and "count" in wf:
                    c = wf.get("count")
                    if not isinstance(c, int) or c < 1:
                        die(f"{sctx}.wait_for.count: must be an int >= 1")

                # node index for deterministic validation
                nodes = topo.get("nodes") or []
                by_name: dict[str, dict[str, Any]] = {
                    n.get("name"): n
                    for n in nodes
                    if isinstance(n, dict) and isinstance(n.get("name"), str)
                }

                # from: must be an existing node name
                v_from = wf.get("from")
                if not isinstance(v_from, str) or not v_from.strip():
                    die(f"{sctx}.wait_for.from: must be a non-empty string")
                from_s = v_from.strip()
                if from_s not in by_name:
                    die(f"{sctx}.wait_for.from: unknown node '{from_s}'")

                # Optional deterministic source selector (shared with ping test semantics)
                src_ip = wf.get("src_ip")
                src_if = wf.get("src_if")

                if src_ip is not None and src_if is not None:
                    die(f"{sctx}.wait_for: specify only one of src_ip or src_if")

                if src_ip is not None:
                    if not isinstance(src_ip, str) or not src_ip.strip():
                        die(f"{sctx}.wait_for.src_ip: must be a non-empty string")
                    validate_ip_literal(src_ip.strip(), f"{sctx}.wait_for.src_ip")

                if src_if is not None:
                    if not isinstance(src_if, str) or not src_if.strip():
                        die(f"{sctx}.wait_for.src_if: must be a non-empty string")
                    if any(ch.isspace() for ch in src_if):
                        die(f"{sctx}.wait_for.src_if: must not contain whitespace")

                # per-type target validation
                if t in ("ping", "tcp"):
                    v_to = wf.get("to")
                    if not isinstance(v_to, str) or not v_to.strip():
                        die(f"{sctx}.wait_for.to: must be a non-empty string")

                    to_raw = v_to.strip()

                    # v1.x: wait_for ping/tcp destinations accept node name OR IPv4 literal
                    # (IPv6 and hostnames rejected deterministically)
                    if is_ip_literal(to_raw) and ":" in to_raw:
                        reason = classify_invalid_target(to_raw)  # should say IPv6
                        die(
                            f"{sctx}.wait_for.to: invalid destination '{to_raw}'. "
                            "Allowed: node name declared in topology (e.g. 'h2') OR IPv4 literal (e.g. '192.168.2.10'). "
                            "Hostnames/DNS are not supported (determinism). "
                            f"Detail: {reason}"
                        )

                    if is_ip_literal(to_raw):
                        validate_ip_literal(to_raw, f"{sctx}.wait_for.to")
                    else:
                        if to_raw not in by_name:
                            reason = classify_invalid_target(to_raw)
                            die(
                                f"{sctx}.wait_for.to: invalid destination '{to_raw}'. "
                                "Allowed: node name declared in topology (e.g. 'h2') OR IPv4 literal (e.g. '192.168.2.10'). "
                                "Hostnames/DNS are not supported (determinism). "
                                f"Detail: {reason}"
                            )

                if t == "tcp":
                    port = wf.get("port")
                    try:
                        port_i = int(port)
                    except Exception:
                        die(f"{sctx}.wait_for.port: must be an int")
                    if port_i < 1 or port_i > 65535:
                        die(f"{sctx}.wait_for.port: must be in range 1..65535")

                if t == "route_prefix":
                    v_src = wf.get("src")
                    if not isinstance(v_src, str) or not v_src.strip():
                        die(f"{sctx}.wait_for.src: must be a non-empty string")
                    src_s = v_src.strip()
                    if src_s not in by_name:
                        die(f"{sctx}.wait_for.src: unknown node '{src_s}'")

                    pfx = wf.get("prefix")
                    if not isinstance(pfx, str) or not pfx.strip():
                        die(f"{sctx}.wait_for.prefix: must be a non-empty string CIDR")
                    norm = _normalize_prefix(pfx.strip())
                    if not norm:
                        die(f"{sctx}.wait_for.prefix: invalid CIDR {pfx!r}")
                    # Keep normalized form (deterministic) for downstream execution
                    wf["prefix"] = norm

            # ---- wait_for_bgp ----
            if "wait_for_bgp" in step:
                wf = step.get("wait_for_bgp")
                if not isinstance(wf, dict):
                    die(f"{sctx}.wait_for_bgp: must be a dict")

                allowed = {"node", "timeout"}
                unknown = set(wf) - allowed
                if unknown:
                    die(f"{sctx}.wait_for_bgp: unknown keys {sorted(unknown)}")

                node = wf.get("node")
                if not isinstance(node, str) or not node.strip():
                    die(f"{sctx}.wait_for_bgp.node: must be a non-empty string")
                node = node.strip()

                if "timeout" in wf:
                    to = wf.get("timeout")
                    if not isinstance(to, int) or to <= 0:
                        die(f"{sctx}.wait_for_bgp.timeout: must be a positive int")

                # Optional: ensure node exists + is frr (fail-fast, deterministic)
                nodes = topo.get("nodes") or []
                by_name = {n.get("name"): n for n in nodes if isinstance(n, dict)}
                nrec = by_name.get(node)
                if not nrec:
                    die(f"{sctx}.wait_for_bgp.node: unknown node '{node}'")

                nt = nrec.get("type") or nrec.get("kind")
                if nt != "frr":
                    die(f"{sctx}.wait_for_bgp.node: node '{node}' is not type/kind 'frr' (got {nt!r})")

def build_test_index(topo: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Map test name -> test dict. Names must be unique.
    """
    tests = topo.get("tests") or []
    idx: dict[str, dict[str, Any]] = {}

    for i, t in enumerate(tests):
        if not isinstance(t, dict):
            continue
        name = t.get("name") or f"tests[{i+1}]"
        if not isinstance(name, str) or not name.strip():
            name = f"tests[{i+1}]"
        if name in idx:
            die(f"Duplicate test name '{name}' (scenario run references require unique names)")
        idx[name] = t
    return idx

def resolve_dst_to_ip(topo: dict[str, Any], dst: str) -> str:
    """
    dst may be:
      - node name in topo.nodes -> resolve via node_first_ipv4
      - an IPv4/IPv6 literal -> return as-is
    Anything else is an error (fail fast).

    NOTE (v1.x determinism): DNS/hostnames are not supported.
    """
    if not isinstance(dst, str) or not dst.strip():
        die("resolve_dst_to_ip: dst must be a non-empty string")

    dst_s = dst.strip()

    # If literal IP, use directly (v1-safe)
    # If literal IP, use directly (v1-safe)
    if is_ip_literal(dst_s):
        # v1.x: for wait_for ping destinations, IPv4-only (determinism / scope)
        if ":" in dst_s:
            reason = classify_invalid_target(dst_s)  # should report IPv6
            die(
                f"wait_for ping: invalid destination '{dst_s}'.\n\n"
                "Allowed forms:\n"
                "- node name declared in topology (e.g. 'h2')\n"
                "- IPv4 literal (e.g. '192.168.2.10')\n\n"
                "Hostnames / DNS are not supported (determinism).\n"
                f"Detail: {reason}"
            )
        validate_ip_literal(dst_s, "wait_for.to")
        return dst_s

    # Otherwise must be a node name
    nodes = topo.get("nodes", []) or []
    if any(isinstance(n, dict) and n.get("name") == dst_s for n in nodes):
        return node_first_ipv4(topo, dst_s)

    reason = classify_invalid_target(dst_s)
    die(
        f"wait_for ping: invalid destination '{dst_s}'.\n\n"
        "Allowed forms:\n"
        "- node name declared in topology (e.g. 'h2')\n"
        "- IPv4 literal (e.g. '192.168.2.10')\n\n"
        "Hostnames / DNS are not supported (determinism).\n"
        f"Detail: {reason}"
    )

def wait_for_condition(
    rt: "Runtime",
    lab: str,
    topo: dict[str, Any],
    cond: dict[str, Any],
    *,
    interval_s: float = 1.0,
) -> tuple[bool, int]:
    """
    Explicit convergence wait. Retries only because user declared wait_for + timeout.
    Returns: (ok, attempts)
    """
    ctype = (cond.get("type") or "").strip().lower()
    src = cond.get("from")
    expect = (cond.get("expect") or "pass").lower()
    timeout = int(cond.get("timeout") or 30)

    if ctype not in ("ping", "tcp", "route_prefix"):
        die(f"wait_for: unsupported type {ctype!r}")

    if not isinstance(src, str) or not src.strip():
        die("wait_for: invalid from (must be node name)")

    if expect not in ("pass", "fail"):
        die("wait_for: expect must be pass|fail")

    should_succeed = (expect == "pass")

    # Optional per-attempt timeout (explicit)
    per_attempt_timeout_s = int(cond.get("per_attempt_timeout_s") or 1)
    if per_attempt_timeout_s < 1:
        die("wait_for: per_attempt_timeout_s must be >= 1")

    def attempt() -> tuple[bool, Any]:
        # -------------------------
        # ping
        # -------------------------
        if ctype == "ping":
            dst = cond.get("to")
            if not isinstance(dst, str) or not dst.strip():
                die("wait_for: invalid to (must be node name or IP literal)")

            count = int(cond.get("count") or 1)
            if count < 1:
                die("wait_for ping: count must be >= 1")

            dst_ip = resolve_dst_to_ip(topo, dst.strip())
            cp = rt.exec(lab, src, ["ping", "-c", str(count), "-W", str(per_attempt_timeout_s), dst_ip], check=False)
            ok = (cp.returncode == 0)
            return (ok == should_succeed), cp

        # -------------------------
        # tcp
        # -------------------------
        if ctype == "tcp":
            dst = cond.get("to")
            if not isinstance(dst, str) or not dst.strip():
                die("wait_for: invalid to (must be node name or IP literal)")

            port = cond.get("port")
            try:
                port_i = int(port)
            except Exception:
                die("wait_for tcp: port must be an int")

            dst_ip = resolve_dst_to_ip(topo, dst.strip())
            ensure_nc(rt, lab, src)
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w {per_attempt_timeout_s} {dst_ip} {port_i}"], check=False)
            ok = (cp.returncode == 0)
            return (ok == should_succeed), cp

        # -------------------------
        # route_prefix
        # -------------------------
        vantage = cond.get("src") or cond.get("on")
        if not isinstance(vantage, str) or not vantage.strip():
            die("wait_for route_prefix: requires src/on as a node name")

        prefix = cond.get("prefix")
        if not isinstance(prefix, str) or not prefix.strip():
            die("wait_for route_prefix: requires prefix as CIDR")

        cp = rt.exec(lab, vantage.strip(), ["sh", "-lc", f"ip -4 route show {prefix.strip()} 2>/dev/null || true"], check=False)
        out = getattr(cp, "stdout", "") or ""
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="replace")
            except Exception:
                out = str(out)

        present = (prefix.strip() in str(out))
        ok = bool(present)
        return ((ok == should_succeed)), cp

    # retry_until already enforces explicit wait semantics
    ok, _last, attempts, _dur_ms = retry_until(timeout, interval_s, attempt)
    return ok, attempts

def retry_until(timeout_s: int, interval_s: float, fn) -> tuple[bool, object, int, int]:
    """
    Returns: ok, last_val, attempts, duration_ms

    Deterministic polling:
      - fixed interval (no jitter)
      - retries happen ONLY because caller explicitly requested a wait/timeout
      - no hidden backoff or randomness
    """
    import time

    start = time.time()
    attempts = 0
    last_val: object = None

    while True:
        attempts += 1
        ok, val = fn()
        last_val = val

        if ok:
            dur_ms = int((time.time() - start) * 1000)
            return True, last_val, attempts, dur_ms

        if (time.time() - start) >= float(timeout_s):
            dur_ms = int((time.time() - start) * 1000)
            return False, last_val, attempts, dur_ms

        time.sleep(float(interval_s))

_PCAP_LABEL_SAFE = re.compile(r"[^A-Za-z0-9._-]+")

def _pcap_sanitize_label(label: str) -> str:
    s = (label or "").strip()
    if not s:
        return "capture"
    s = _PCAP_LABEL_SAFE.sub("_", s)
    return s[:64] or "capture"

def _pcap_sanitize_scenario_id(sid: str) -> str:
    s = (sid or "").strip()
    if not s:
        return "scenario"
    s = _PCAP_LABEL_SAFE.sub("_", s)
    return s[:64] or "scenario"

def _pcap_step_seq(idx0: int) -> str:
    # idx0 is 0-based step index in executor; artifacts use 1-based, zero-padded width=3
    n = int(idx0) + 1
    return f"{n:03d}"

def _pcap_artifact_paths(lab: str, scenario_id: str, seq: str, label: str, node: str, iface: str) -> tuple[Path, Path]:
    scen = _pcap_sanitize_scenario_id(scenario_id)
    lbl = _pcap_sanitize_label(label)
    fname = f"{seq}_{lbl}_{node}_{iface}"
    root = lab_dir(lab) / "artifacts" / "pcap" / scen
    pcap = root / f"{fname}.pcap"
    meta = root / f"{fname}.meta.json"
    return pcap, meta

def _pcap_resolve_target_to_node_iface(topo: dict[str, Any], target: dict[str, Any]) -> tuple[str, str]:
    """
    Resolve validated target -> concrete (node, iface) capture point.
    v1.5 rule: for link targets, capture on a deterministic container-side interface:
      - choose the lexicographically smaller endpoint string among the matched link endpoints.
    """
    # Interface target
    if "node" in target and "iface" in target:
        return str(target["node"]).strip(), str(target["iface"]).strip()

    # Link target
    a = str(target.get("a") or "").strip()
    b = str(target.get("b") or "").strip()
    a_if = target.get("a_if")
    b_if = target.get("b_if")

    links = topo.get("links", []) or []

    def parse_ep(ep: str) -> tuple[str, str] | None:
        if not isinstance(ep, str) or ":" not in ep:
            return None
        n, ifx = ep.split(":", 1)
        n, ifx = n.strip(), ifx.strip()
        if not n or not ifx:
            return None
        return n, ifx

    matches: list[tuple[str, str]] = []
    for link in links:
        eps = link.get("endpoints")
        if not isinstance(eps, list) or len(eps) != 2:
            continue
        p0 = parse_ep(eps[0])
        p1 = parse_ep(eps[1])
        if not p0 or not p1:
            continue
        (n0, if0), (n1, if1) = p0, p1

        # normalize to (a_side_iface, b_side_iface)
        if n0 == a and n1 == b:
            matches.append((if0, if1))
        elif n0 == b and n1 == a:
            matches.append((if1, if0))

    # At this point, validation already enforced unambiguous match rules.
    if a_if is None and b_if is None:
        if not matches:
            # safety fallback; should not happen if validated
            return a, "eth0"
        # only one
        (ai, bi) = matches[0]
    else:
        ai = str(a_if).strip()
        bi = str(b_if).strip()

    # Choose deterministic capture point: smaller endpoint string
    ep_a = f"{a}:{ai}"
    ep_b = f"{b}:{bi}"
    chosen = ep_a if ep_a <= ep_b else ep_b
    node, iface = chosen.split(":", 1)
    return node, iface

def _pcap_tool_precheck(rt: "Runtime", lab: str, node: str) -> tuple[bool, str]:
    cp = rt.exec(lab, node, ["sh", "-lc", "command -v tcpdump >/dev/null"], check=False, capture_output=True)
    if cp.returncode != 0:
        return False, "tcpdump not found"
    return True, "ok"

def _pcap_start(
    rt: "Runtime",
    lab: str,
    node: str,
    iface: str,
    tmp_pcap: str,
    pidfile: str,
    *,
    snaplen: int | None,
    max_seconds: int | None,
    max_kb: int | None,
    bpf_filter: str | None,
) -> tuple[bool, str]:
    """
    Start tcpdump in background inside node.
    Returns (ok, status_reason). Never raises.
    """
    # Build tcpdump args (NO host-wide 'any' allowed; validated elsewhere, but enforce here too)
    if iface.strip() == "any":
        return False, "forbidden interface 'any'"

    # size cap: tcpdump -C is in MB (decimal-ish). Convert KB -> MB ceiling, min 1.
    c_mb = None
    if isinstance(max_kb, int) and max_kb > 0:
        c_mb = max(1, int((max_kb + 1023) / 1024))

    parts: list[str] = []
    parts.append("set -e")
    parts.append(f"rm -f {pidfile} {tmp_pcap} 2>/dev/null || true")

    # tcpdump command
    cmd = ["tcpdump", "-i", iface, "-w", tmp_pcap]
    if isinstance(snaplen, int) and snaplen > 0:
        cmd += ["-s", str(snaplen)]
    if isinstance(max_seconds, int) and max_seconds > 0:
        cmd += ["-G", str(max_seconds), "-W", "1"]
    if c_mb is not None:
        cmd += ["-C", str(c_mb)]
    if isinstance(bpf_filter, str) and bpf_filter.strip():
        cmd += [bpf_filter.strip()]

    # Run in background + pidfile
    sh_cmd = " ".join([json.dumps(x) for x in cmd])
    parts.append(f"nohup sh -lc {json.dumps(sh_cmd)} >/dev/null 2>&1 & echo $! > {pidfile}")

    script = " ; ".join(parts)
    cp = rt.exec(lab, node, ["sh", "-lc", script], check=False, capture_output=True)
    if cp.returncode != 0:
        return False, "tcpdump start failed"
    return True, "ok"

def _pcap_stop(rt: "Runtime", lab: str, node: str, pidfile: str) -> tuple[bool, str]:
    """
    Stop background tcpdump if running. Never raises.
    """
    script = (
        "set -e ; "
        f"if [ -f {pidfile} ]; then "
        f"  pid=$(cat {pidfile} 2>/dev/null || true) ; "
        "  if [ -n \"$pid\" ]; then kill \"$pid\" 2>/dev/null || true ; fi ; "
        f"  rm -f {pidfile} 2>/dev/null || true ; "
        "fi ; "
        "true"
    )
    cp = rt.exec(lab, node, ["sh", "-lc", script], check=False, capture_output=True)
    if cp.returncode != 0:
        return False, "tcpdump stop failed"
    return True, "ok"

def execute_scenario(
    *,
    rt: "Runtime",
    lab: str,
    topo: dict[str, Any],
    scenario: dict[str, Any],
    test_index: dict[str, dict[str, Any]],
    run_atomic_test_fn,
) -> dict[str, Any]:
    """
    Execute one scenario deterministically.

    run_atomic_test_fn(test_dict) -> bool (pass=True/fail=False)
    Must also record atomic test into results via existing record_test() pipeline.

    Scenario verdict:
      - pass only if all steps pass
      - scenario step failures are visible and do not overwrite atomic verdicts
    """
    sid = str(scenario.get("id"))
    steps = scenario.get("steps") or []

    scen_rec: dict[str, Any] = {
        "id": sid,
        "description": str(scenario.get("description") or ""),
        "steps": [],
        "verdict": "pass",
    }

    # v1.5: at most one active capture per scenario
    active_pcap: dict[str, Any] | None = None
    active_fault_states: list[dict[str, Any]] = []

    for idx, step in enumerate(steps):
        if not isinstance(step, dict) or not step:
            # schema should have been validated already; keep executor deterministic
            scen_rec["steps"].append(
                {"type": "invalid_step", "verdict": "fail", "error": "invalid scenario step (not a non-empty dict)"}
            )
            scen_rec["verdict"] = "fail"
            break

        step_keys = list(step.keys())
        stype = step_keys[0]
        started = time.time()
        
        step_rec: dict[str, Any] = {"type": stype}

        # ---- pcap_start (evidence-only, non-gating) ----
        if stype == "pcap_start":
            spec = step.get("pcap_start") or {}
            step_rec["verdict"] = "pass"
            step_rec["authority"] = "supporting_evidence"

            if active_pcap is not None:
                # v1.5 concurrency rule: record warning, do not start another capture
                step_rec["warning"] = "pcap already active; v1.5 allows at most one active capture per scenario"
                step_rec["pcap"] = {"tool_status": "failed"}
                step_rec["duration_ms"] = int((time.time() - started) * 1000)
                scen_rec["steps"].append(step_rec)
                continue

            # resolve capture point
            target = spec.get("target") or {}
            node, iface = _pcap_resolve_target_to_node_iface(topo, target)

            label = _pcap_sanitize_label(str(spec.get("label") or "capture"))
            seq = _pcap_step_seq(idx)
            out_pcap, out_meta = _pcap_artifact_paths(lab, sid, seq, label, node, iface)

            # tool precheck
            ok_tool, reason = _pcap_tool_precheck(rt, lab, node)

            # paths inside node
            tmp_dir = "/tmp"
            tmp_pcap = f"{tmp_dir}/ai-netsim_{_pcap_sanitize_scenario_id(sid)}_{seq}_{label}.pcap"
            pidfile = f"{tmp_dir}/ai-netsim_{_pcap_sanitize_scenario_id(sid)}_{seq}_{label}.pid"

            tool_status = "ok"
            err = ""

            if not ok_tool:
                tool_status = "unavailable"
                err = reason
            else:
                # ensure artifact dir exists deterministically
                out_pcap.parent.mkdir(parents=True, exist_ok=True)

                snaplen = spec.get("snaplen")
                max_seconds = spec.get("max_seconds")
                max_kb = spec.get("max_kb")
                bpf_filter = spec.get("filter")

                ok_start, start_reason = _pcap_start(
                    rt,
                    lab,
                    node,
                    iface,
                    tmp_pcap,
                    pidfile,
                    snaplen=snaplen if isinstance(snaplen, int) else None,
                    max_seconds=max_seconds if isinstance(max_seconds, int) else None,
                    max_kb=max_kb if isinstance(max_kb, int) else None,
                    bpf_filter=bpf_filter if isinstance(bpf_filter, str) else None,
                )
                if not ok_start:
                    tool_status = "failed"
                    err = start_reason

            active_pcap = {
                "scenario_id": sid,
                "step_seq_start": int(seq),
                "step_seq_stop": None,
                "node": node,
                "iface": iface,
                "label": label,
                "pidfile": pidfile,
                "tmp_pcap": tmp_pcap,
                "out_pcap": str(out_pcap),
                "out_meta": str(out_meta),
                "started_at": time.time(),
                "tool_status": tool_status,
                "error": err,
                "spec": spec,
            }

            step_rec["pcap"] = {
                "tool_status": tool_status,
                "target": {"node": node, "iface": iface},
                "pcap_file": str(Path(out_pcap).relative_to(lab_dir(lab))),
            }
            if err:
                step_rec["pcap"]["error"] = err

            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)
            continue

        # ---- pcap_stop (evidence-only, non-gating) ----
        if stype == "pcap_stop":
            step_rec["verdict"] = "pass"
            step_rec["authority"] = "supporting_evidence"

            if active_pcap is None:
                step_rec["warning"] = "no active pcap to stop"
                step_rec["pcap"] = {"tool_status": "ok"}
                step_rec["duration_ms"] = int((time.time() - started) * 1000)
                scen_rec["steps"].append(step_rec)
                continue

            # Stop the capture process (even if it was unavailable/failed, we still finalize meta deterministically)
            node = active_pcap["node"]
            iface = active_pcap["iface"]
            pidfile = active_pcap["pidfile"]
            tmp_pcap = active_pcap["tmp_pcap"]
            out_pcap = active_pcap["out_pcap"]
            out_meta = active_pcap["out_meta"]
            spec = active_pcap.get("spec") or {}

            tool_status = str(active_pcap.get("tool_status") or "failed")
            err = str(active_pcap.get("error") or "")

            if tool_status == "ok":
                _pcap_stop(rt, lab, node, pidfile)

                # copy pcap out (best-effort, non-gating)
                cp_ok = True
                try:
                    rt.copy_from_node(lab, node, tmp_pcap, out_pcap, check=True)
                except Exception:
                    cp_ok = False
                    tool_status = "failed"
                    if not err:
                        err = "pcap copy-out failed"

                # attempt to remove tmp pcap (never fail)
                rt.exec(lab, node, ["sh", "-lc", f"rm -f {tmp_pcap} 2>/dev/null || true"], check=False)

                # bytes written (host-side)
                bytes_written = 0
                try:
                    bytes_written = Path(out_pcap).stat().st_size if cp_ok else 0
                except Exception:
                    bytes_written = 0

            else:
                bytes_written = 0

            stopped_at = time.time()
            duration_s = float(max(0.0, stopped_at - float(active_pcap.get("started_at") or stopped_at)))

            # write meta json (supporting evidence only)
            meta_obj: dict[str, Any] = {
                "authority": "supporting_evidence",
                "scenario_id": sid,
                "step_seq_start": int(active_pcap.get("step_seq_start") or 0),
                "step_seq_stop": int(_pcap_step_seq(idx)),
                "target": {"node": node, "iface": iface},
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(active_pcap.get("started_at") or stopped_at))),
                "stopped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stopped_at)),
                "duration_s": duration_s,
                "tool": "tcpdump",
                "tool_status": tool_status,
                "bytes_written": int(bytes_written),
                "pcap_file": str(Path(out_pcap).relative_to(lab_dir(lab))),
            }

            # only record booleans/limits (never store filter text by default)
            if "filter" in spec:
                meta_obj["filter_applied"] = bool(isinstance(spec.get("filter"), str) and spec.get("filter").strip())
            for k in ("snaplen", "max_seconds", "max_kb"):
                v = spec.get(k)
                if isinstance(v, int):
                    meta_obj[k] = v

            if err:
                meta_obj["error"] = err[:200]

            Path(out_meta).parent.mkdir(parents=True, exist_ok=True)
            Path(out_meta).write_text(json.dumps(meta_obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            step_rec["pcap"] = {
                "tool_status": tool_status,
                "target": {"node": node, "iface": iface},
                "pcap_file": str(Path(out_pcap).relative_to(lab_dir(lab))),
                "meta_file": str(Path(out_meta).relative_to(lab_dir(lab))),
                "bytes_written": int(bytes_written),
            }
            if err:
                step_rec["pcap"]["error"] = err

            # also emit top-level supporting evidence (non-gating)
            try:
                results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                    {
                        "type": "pcap",
                        "authority": "supporting_evidence",
                        "scenario_id": sid,
                        "step": int(_pcap_step_seq(idx)),
                        "tool_status": tool_status,
                        "error": err if err else "",
                        "pcap_file": str(Path(out_pcap).relative_to(lab_dir(lab))),
                    }
                )
            except Exception:
                pass

            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)

            active_pcap = None
            continue

        # ---- run ----
        if stype == "run":

            ref = step["run"]
            step_rec["ref"] = ref

            t = test_index.get(ref)
            if not t:
                step_rec["verdict"] = "fail"
                step_rec["error"] = f"unknown test ref '{ref}'"
                step_rec["duration_ms"] = int((time.time() - started) * 1000)
                scen_rec["steps"].append(step_rec)
                scen_rec["verdict"] = "fail"
                break

            ok = bool(run_atomic_test_fn(t))
            step_rec["verdict"] = "pass" if ok else "fail"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)

            if not ok:
                scen_rec["verdict"] = "fail"
                break

        # ---- wait ----
        elif stype == "wait":
            sec = int(step["wait"]["seconds"])
            time.sleep(sec)
            step_rec["seconds"] = sec
            step_rec["verdict"] = "pass"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)

        # ---- wait_for ----
        elif stype == "wait_for":
            cond = step["wait_for"]
            step_rec["condition"] = cond
            ok, attempts = wait_for_condition(rt, lab, topo, cond, interval_s=float(cond.get("interval_s") or 1.0))
            step_rec["attempts"] = attempts
            step_rec["verdict"] = "pass" if ok else "fail"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)

            if not ok:
                scen_rec["verdict"] = "fail"
                break

        # ---- fault ----
        elif stype == "fault":
            fault = step["fault"]
            action, spec = next(iter(fault.items()))
            try:
                applied = scenario_apply_fault(rt, lab, topo, action, spec)
            except SystemExit as e:
                step_rec["fault"] = fault
                step_rec["verdict"] = "fail"
                step_rec["error"] = f"fault step failed: {action} (exit={e.code})"
                step_rec["duration_ms"] = int((time.time() - started) * 1000)
                scen_rec["steps"].append(step_rec)
                scen_rec["verdict"] = "fail"
                raise

            step_rec["fault"] = fault
            step_rec["action"] = applied["action"]
            step_rec["target"] = applied["target"]

            if "loss_percent" in applied:
                step_rec["loss_percent"] = applied["loss_percent"]
            if "latency_ms" in applied:
                step_rec["latency_ms"] = applied["latency_ms"]
            if "bandwidth_mbps" in applied:
                step_rec["bandwidth_mbps"] = applied["bandwidth_mbps"]
            if "prefix" in applied:
                step_rec["prefix"] = applied["prefix"]

            step_rec["verdict"] = "pass"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)

            fault_event = {
                "kind": "scenario_fault",
                "scenario_id": scen_id,
                "step": idx,
                "action": applied["action"],
                "target": applied["target"],
            }
            if "loss_percent" in applied:
                fault_event["loss_percent"] = applied["loss_percent"]
            if "latency_ms" in applied:
                fault_event["latency_ms"] = applied["latency_ms"]
            if "bandwidth_mbps" in applied:
                fault_event["bandwidth_mbps"] = applied["bandwidth_mbps"]
            if "prefix" in applied:
                fault_event["prefix"] = applied["prefix"]
            events.append(fault_event)

            state = applied.get("state")
            if state:
                active_fault_states.append(state)
                
    if active_pcap is not None:
        node = active_pcap["node"]
        iface = active_pcap["iface"]
        pidfile = active_pcap["pidfile"]
        tmp_pcap = active_pcap["tmp_pcap"]
        out_pcap = active_pcap["out_pcap"]
        out_meta = active_pcap["out_meta"]
        spec = active_pcap.get("spec") or {}

        tool_status = str(active_pcap.get("tool_status") or "failed")
        err = str(active_pcap.get("error") or "")

        if tool_status == "ok":
            _pcap_stop(rt, lab, node, pidfile)
            try:
                Path(out_pcap).parent.mkdir(parents=True, exist_ok=True)
                rt.copy_from_node(lab, node, tmp_pcap, out_pcap, check=True)
            except Exception:
                tool_status = "failed"
                if not err:
                    err = "pcap copy-out failed"
            rt.exec(lab, node, ["sh", "-lc", f"rm -f {tmp_pcap} 2>/dev/null || true"], check=False)

        bytes_written = 0
        try:
            bytes_written = Path(out_pcap).stat().st_size if tool_status != "unavailable" else 0
        except Exception:
            bytes_written = 0

        stopped_at = time.time()
        duration_s = float(max(0.0, stopped_at - float(active_pcap.get("started_at") or stopped_at)))

        meta_obj: dict[str, Any] = {
            "authority": "supporting_evidence",
            "scenario_id": sid,
            "step_seq_start": int(active_pcap.get("step_seq_start") or 0),
            "step_seq_stop": None,
            "target": {"node": node, "iface": iface},
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(active_pcap.get("started_at") or stopped_at))),
            "stopped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stopped_at)),
            "duration_s": duration_s,
            "tool": "tcpdump",
            "tool_status": "auto_stopped" if tool_status == "ok" else tool_status,
            "bytes_written": int(bytes_written),
            "pcap_file": str(Path(out_pcap).relative_to(lab_dir(lab))),
        }

        if "filter" in spec:
            meta_obj["filter_applied"] = bool(isinstance(spec.get("filter"), str) and spec.get("filter").strip())
        for k in ("snaplen", "max_seconds", "max_kb"):
            v = spec.get(k)
            if isinstance(v, int):
                meta_obj[k] = v

        if err:
            meta_obj["error"] = err[:200]

        Path(out_meta).parent.mkdir(parents=True, exist_ok=True)
        Path(out_meta).write_text(json.dumps(meta_obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    while active_fault_states:
        state = active_fault_states.pop()
        scenario_clear_fault_state(rt, lab, state)

    return scen_rec

def _atomic_test_ids(topo: dict) -> list[str]:
    tests = topo.get("tests", []) or []
    ids: list[str] = []
    for idx, t in enumerate(tests, start=1):
        # Keep deterministic naming aligned with cmd_test()
        if isinstance(t, dict) and t.get("name"):
            ids.append(str(t["name"]))
        else:
            ids.append(f"tests[{idx}]")
    return ids

def validate_scenario_run_refs_or_die(topo: dict, scenario_ids: list[str] | None = None) -> None:
    """
    Hard rule — Scenario References Must Resolve (Fail-Fast)

    Before executing ANY scenario steps, validate that every `steps[].run: <test_name>`
    references a declared atomic test name in `topo["tests"]`.

    If any ref is missing/invalid:
      - FAIL FAST
      - BEFORE executing any runtime actions
      - WITH a clear deterministic error
      - NO partial execution

    scenario_ids:
      - None  => validate all scenarios in topo
      - list  => validate only those scenario ids
    """
    known = _atomic_test_ids(topo)  # authoritative list of test names (deterministic order)
    known_set = set(known)

    scenarios = topo.get("scenarios", []) or []
    if not isinstance(scenarios, list):
        die("ERROR: topology 'scenarios' must be a list")

    # Filter scenarios if requested (deterministic) + fail-fast if scenario id not found
    scenarios_all = [s for s in scenarios if isinstance(s, dict)]

    available_ids = sorted(
        {str(s.get("id", "")).strip() for s in scenarios_all if str(s.get("id", "")).strip()}
    )
    available_set = set(available_ids)

    if scenario_ids is not None:
        want_list = [str(x).strip() for x in scenario_ids if str(x).strip()]
        want_set = set(want_list)

        missing = sorted(want_set - available_set)
        if missing:
            if not available_ids:
                die(
                    f"no scenarios are defined in this topology (requested: {', '.join(missing)})"
                )
            if len(missing) == 1:
                die(
                    f"scenario id '{missing[0]}' not found. Valid scenario ids: {', '.join(available_ids)}"
                )
            die(
                f"scenario ids not found: {', '.join(missing)}. Valid scenario ids: {', '.join(available_ids)}"
            )

        scenarios = [s for s in scenarios_all if str(s.get("id", "")).strip() in want_set]
    else:
        scenarios = scenarios_all

    # Deterministic ordering for validation / error reporting
    scenarios_sorted = sorted(
        scenarios,
        key=lambda s: str(s.get("id", "")).strip(),
    )

    for s in scenarios_sorted:
        sid = str(s.get("id") or "<unnamed>")
        steps = s.get("steps", [])
        if steps is None:
            steps = []
        if not isinstance(steps, list):
            die(f"ERROR: scenario '{sid}' steps must be a list")

        for idx, st in enumerate(steps, start=1):
            if not isinstance(st, dict):
                die(f"ERROR: scenario '{sid}' step[{idx}] must be a dict (invalid schema)")

            # Only validate run refs here (fault/wait/wait_for validation is separate)
            if "run" in st:
                ref = st.get("run")

                if not isinstance(ref, str) or not ref.strip():
                    die(f"ERROR: scenario '{sid}' step[{idx}] has invalid run ref (must be non-empty string)")

                ref = ref.strip()
                if ref not in known_set:
                    known_str = ", ".join(known)
                    die(
                        f"ERROR: scenario '{sid}' references unknown test '{ref}'\n"
                        f"Known tests: [{known_str}]\n"
                        f"Scenario execution aborted before any steps ran."
                    )

    # Optional: if the user asked to validate a specific scenario id and it doesn't exist,
    # fail here (still pre-execution). This helps avoid “it ran nothing” ambiguity.
    if scenario_ids is not None:
        topo_ids = set(str(s.get("id", "")) for s in (topo.get("scenarios", []) or []) if isinstance(s, dict))
        missing = [sid for sid in (str(x) for x in scenario_ids) if sid not in topo_ids]
        if missing:
            missing_sorted = ", ".join(sorted(missing))
            die(f"ERROR: requested scenario id(s) not found in topology: {missing_sorted}")

def _fmt_dur_s(dur_ms: object) -> str:
    try:
        ms = int(dur_ms)
        if ms < 0:
            return ""
        return f"{ms/1000.0:.1f}s"
    except Exception:
        return ""

def _render_scenarios_summary(results: dict) -> str:
    scenarios = results.get("scenarios") or []
    if not isinstance(scenarios, list) or not scenarios:
        return ""

    # Deterministic ordering by scenario id (string)
    scenarios_all = [s for s in scenarios if isinstance(s, dict)]
    scenarios_sorted = sorted(
        scenarios_all,
        key=lambda s: str(s.get("id") or "").strip(),
    )

    out: list[str] = []
    out.append("=== Scenarios ===")

    for s in scenarios_sorted:
        sid = str(s.get("id") or "").strip() or "<missing-id>"
        verdict = str(s.get("verdict") or "").strip().lower() or "unknown"
        dur_s = _fmt_dur_s(s.get("duration_ms"))
        dur_part = f" (duration: {dur_s})" if dur_s else ""

        out.append(f"scenario {sid}: {verdict.upper()}{dur_part}")

        steps = s.get("steps") or []
        if not isinstance(steps, list) or not steps:
            continue

        for i, st in enumerate(steps, start=1):
            if not isinstance(st, dict):
                continue

            stype = str(st.get("type") or "").strip() or "step"
            line_parts: list[str] = [f"  [{i}] {stype}"]

            # Key identifiers per step type
            if stype == "run":
                ref = st.get("ref")
                if isinstance(ref, str) and ref.strip():
                    line_parts.append(f"test={ref.strip()}")

            elif stype == "fault":
                action = st.get("action")
                if isinstance(action, str) and action.strip():
                    line_parts.append(action.strip())
                target = st.get("target")
                if isinstance(target, str) and target.strip():
                    line_parts.append(target.strip())

            elif stype == "wait_for":
                wf = st.get("wait_for") or {}
                if isinstance(wf, dict):
                    wtype = wf.get("type")
                    if isinstance(wtype, str) and wtype.strip():
                        line_parts.append(wtype.strip())

                    src = wf.get("from")
                    dst = wf.get("to") or wf.get("to_ip")
                    src_s = src.strip() if isinstance(src, str) and src.strip() else ""
                    dst_s = dst.strip() if isinstance(dst, str) and dst.strip() else ""
                    if src_s and dst_s:
                        line_parts.append(f"{src_s}->{dst_s}")

                    exp = wf.get("expect")
                    if isinstance(exp, str) and exp.strip():
                        line_parts.append(f"expect={exp.strip()}")

                    # Optional selectors
                    src_if = wf.get("src_if")
                    if isinstance(src_if, str) and src_if.strip():
                        line_parts.append(f"src_if={src_if.strip()}")

            elif stype == "wait_for_bgp":
                node = st.get("node")
                if isinstance(node, str) and node.strip():
                    line_parts.append(f"node={node.strip()}")

            # verdict / observed / expected when present
            v = st.get("verdict")
            if isinstance(v, str) and v.strip():
                line_parts.append(f"verdict={v.strip().lower()}")

            expected = st.get("expected")
            observed = st.get("observed")
            if expected is not None:
                line_parts.append(f"expected={expected}")
            if observed is not None:
                line_parts.append(f"observed={observed}")

            dur_step = _fmt_dur_s(st.get("duration_ms"))
            if dur_step:
                line_parts.append(f"dur={dur_step}")

            out.append("  " + " ".join(line_parts))

    return "\n".join(out) + "\n"

def _format_test_summary(results: dict) -> str:
    lab = results.get("lab", "")
    summ = results.get("summary", {}) or {}
    duration_ms = summ.get("duration_ms")

    # Declared tests summary (authoritative steady-state tests)
    # In scenario-only mode, you likely want these to remain 0/0/0 (by design).
    total = int(summ.get("total") or 0)
    passed = int(summ.get("passed") or 0)
    failed = int(summ.get("failed") or 0)

    lines: list[str] = []
    lines.append(f"lab: {lab}")
    # Non-authoritative summary line; result is authoritative in results.json.
    lines.append(f"result: {results.get('result', 'unknown')}")
    # Supporting-only summary must be deterministic; duration varies run-to-run.
    # Authoritative duration remains in results.json; do not duplicate nondeterminism here.

    # Keep tests as declared tests summary (Option A)
    lines.append(f"tests: total={total} passed={passed} failed={failed}")

    # -------------------------------------------------------------------------
    # Hard failure (runtime fault) summary
    # - MUST surface "ERROR:" in summary for runtime faults
    # - MUST NOT affect gate semantics (human-only)
    # -------------------------------------------------------------------------
    hf = results.get("hard_failure") or {}
    if isinstance(hf, dict) and bool(hf.get("occurred")):
        phase = str(hf.get("phase") or "").strip()
        err = str(hf.get("error") or "").strip()

        # Ensure explicit ERROR: prefix for runtime faults (summary-only).
        if err and not err.startswith("ERROR:"):
            err = "ERROR: " + err
        if not err:
            err = "ERROR:"

        if phase:
            lines.append(f"hard_failure: phase={phase} error={err}")
        else:
            lines.append(f"hard_failure: error={err}")
    # Fallback: runtime hard-failures are sometimes represented as failed prereq tests
    # (e.g., container not running). These MUST surface as ERROR: in the summary.
    if not (isinstance(hf, dict) and bool(hf.get("occurred"))):
        tests = results.get("tests", []) or []
        prereq_err: str | None = None
        if isinstance(tests, list):
            for tt in tests:
                if not isinstance(tt, dict):
                    continue
                if str(tt.get("kind") or "") != "prereq":
                    continue
                if str(tt.get("verdict") or "") != "fail":
                    continue
                e = str(tt.get("error") or "").strip()
                prereq_err = e or "runtime prereq failed"
                break

        if prereq_err:
            if not prereq_err.startswith("ERROR:"):
                prereq_err = "ERROR: " + prereq_err
            lines.append(f"hard_failure: error={prereq_err}")

    # -------------------------------------------------------------------------
    # Scenario event runs summary (Option A): scenario_test_run events
    # -------------------------------------------------------------------------
    events = results.get("events", []) or []
    scenario_runs = [e for e in events if e.get("type") == "scenario_test_run"]
    if scenario_runs:
        sr_total = len(scenario_runs)
        sr_passed = sum(1 for e in scenario_runs if e.get("verdict") == "pass")
        sr_failed = sr_total - sr_passed
        lines.append(f"scenario_test_runs: total={sr_total} passed={sr_passed} failed={sr_failed}")

    # -------------------------------------------------------------------------
    # Scenarios summary (optional; non-authoritative; does not change result)
    # -------------------------------------------------------------------------
    scenarios = results.get("scenarios", []) or []
    if scenarios:
        sc_total = len(scenarios)
        sc_passed = sum(1 for s in scenarios if s.get("verdict") == "pass")
        sc_failed = sc_total - sc_passed
        lines.append(f"scenarios: total={sc_total} passed={sc_passed} failed={sc_failed}")

    # -------------------------------------------------------------------------
    # Failed declared tests (results["tests"])
    # -------------------------------------------------------------------------
    failed_tests = []
    for t in results.get("tests", []) or []:
        if t.get("verdict") == "fail":
            name = t.get("name", "<unnamed>")
            kind = t.get("kind", "")
            src = t.get("from", "")
            dst = t.get("to", "")
            err = t.get("error", "")

            # Gate-failure messaging normalization (human-only):
            # failed_tests are gate failures; they must never surface "ERROR:" prefix.
            if isinstance(err, str):
                e = err.strip()
                if e.startswith("ERROR:"):
                    tail = e[len("ERROR:"):].lstrip()
                    err = f"FAIL: {tail}" if tail else "FAIL:"
                else:
                    err = err

            failed_tests.append((name, kind, src, dst, err))

    failed_tests.sort()

    if failed_tests:
        lines.append("failed_tests:")
        cap = 10
        for (name, kind, src, dst, err) in failed_tests[:cap]:
            line = f" - {name} ({kind}) {src}->{dst}"
            if err:
                line += f" : {err}"
            lines.append(line)
        if len(failed_tests) > cap:
            lines.append(f" - (+{len(failed_tests) - cap} more)")
    else:
        lines.append("failed_tests: (none)")

    # -------------------------------------------------------------------------
    # Failed scenarios list (optional)
    # -------------------------------------------------------------------------
    if scenarios:
        failed_scenarios = []
        for s in scenarios:
            if s.get("verdict") == "fail":
                sid = s.get("id", "<unnamed>")
                failed_scenarios.append(sid)

        failed_scenarios.sort()
        if failed_scenarios:
            lines.append("failed_scenarios:")
            cap = 10
            for sid in failed_scenarios[:cap]:
                lines.append(f" - {sid}")
            if len(failed_scenarios) > cap:
                lines.append(f" - (+{len(failed_scenarios) - cap} more)")
        else:
            lines.append("failed_scenarios: (none)")

    # -------------------------------------------------------------------------
    # Scenario step breakdown (human-only, deterministic, non-authoritative)
    # -------------------------------------------------------------------------
    scen_txt = _render_scenarios_summary(results)
    if scen_txt:
        lines.append(scen_txt.rstrip("\n"))


    return "\n".join(lines) + "\n"

def render_gate_result_block(results: dict, *, authority_kind: str | None = None) -> str:
    """
    Deterministic, presentation-only CLI block derived from already-computed results.
    Must NOT:
      - recompute verdicts
      - mutate results
      - depend on terminal width or timestamps
    """
    lab = str(results.get("lab") or "").strip()
    if not lab:
        try:
            lab_obj = results.get("lab_obj")
            if isinstance(lab_obj, dict):
                lab = str(lab_obj.get("name") or "").strip()
        except Exception:
            pass
    if not lab:
        try:
            topo_obj = results.get("topology")
            if isinstance(topo_obj, dict):
                lab = str(topo_obj.get("name") or "").strip()
        except Exception:
            pass
    if not lab:
        lab = "(unknown — could not parse topology name)"

    topo_path = str(results.get("topology_path") or "").strip()

    summ = results.get("summary", {}) or {}
    total = int(summ.get("total") or 0)

    scenarios = results.get("scenarios", []) or []
    scen_total = len(scenarios) if isinstance(scenarios, list) else 0

    res = str(results.get("result") or "unknown").strip().lower()
    verdict_s = "PASS" if res == "pass" else "FAIL"
    is_smoke = (verdict_s == "PASS" and total == 0 and scen_total == 0)

    ak = str(authority_kind or "gate").strip().lower()
    if ak in ("gate", "authoritative", "topology"):
        heading = "Cassian Gate Result"
        authority_line = "Authority: GATE (authoritative)"
        mode_line = "Mode: gate (clean-state topology)"
    elif ak in ("run", "explore", "exploration"):
        heading = "Cassian Run Result"
        authority_line = "Authority: RUN (non-authoritative)"
        mode_line = "Mode: run (workflow)"
    else:
        # default: existing runtime checks against an existing lab
        heading = "Cassian Lab Test Result"
        authority_line = "Authority: LAB-TEST (non-authoritative)"
        mode_line = "Mode: lab (existing runtime)"

    out: list[str] = []
    # Split prereq checks from declared tests (presentation-only; results schema unchanged)
    tests = results.get("tests", []) or []
    prereqs_executed = 0
    declared_executed = 0
    if isinstance(tests, list):
        for t in tests:
            if not isinstance(t, dict):
                continue
            nm = str(t.get("name") or "").strip().lower()
            kd = str(t.get("kind") or "").strip().lower()
            if kd == "prereq" or nm.startswith("prereq:"):
                prereqs_executed += 1
            else:
                declared_executed += 1

    out.append("────────────────────────────────────────")
    out.append(heading)
    out.append("────────────────────────────────────────")

    # Identity (must never be blank)
    lab_disp = lab if lab else "(unknown — could not parse topology name)"
    out.append(f"Lab: {lab_disp}")

    # Topology path (only when invoked with a topology path; presentation-only)
    topo_path = results.get("topology_path")
    if isinstance(topo_path, str) and topo_path.strip():
        out.append(f"Topology: {topo_path.strip()}")

    out.append(authority_line)
    out.append(mode_line)
    out.append(f"Prereqs executed: {prereqs_executed}")
    out.append(f"Declared tests executed: {declared_executed}")
    out.append(f"Scenarios executed: {scen_total}")
    out.append("")

    # Hard-failure clarity (phase + reason + executed/skipped) for early failures.
    hf = results.get("hard_failure") or {}
    if isinstance(hf, dict) and bool(hf.get("occurred")):
        ph_raw = str(hf.get("phase") or "").strip().lower()
        ph_map = {
            "resolve": "RESOLVE",
            "validate": "RESOLVE",
            "generate": "GENERATE",
            "deploy": "DEPLOY",
            "provision": "PROVISION",
            "test": "TEST",
            "collect": "COLLECT",
            "destroy": "DESTROY",
        }
        ph = ph_map.get(ph_raw, ph_raw.upper() if ph_raw else "")
        if ph:
            out.append(f"Failure phase: {ph}")

        err = str(hf.get("error") or "").strip()
        if err.startswith("ERROR:"):
            err = err[len("ERROR:"):].lstrip()
        if err:
            if "\n" in err:
                err = err.splitlines()[0].strip()
            out.append(f"Reason: {err}")

        # Executed vs skipped (deterministic, presentation-only)
        exec_s = ""
        if ph == "RESOLVE":
            exec_s = "Execution: resolve/validate only (generate/deploy/provision/test skipped)"
        elif ph == "GENERATE":
            exec_s = "Execution: resolve+generate attempted; generate failed (deploy/provision/test skipped)"
        elif ph == "DEPLOY":
            exec_s = "Execution: resolve+generate attempted; deploy failed (provision/test skipped)"
        elif ph == "PROVISION":
            exec_s = "Execution: resolve+generate+deploy succeeded; provision failed (test skipped)"
        elif ph == "TEST":
            exec_s = "Execution: full lifecycle through test (collect+destroy still executed)"
        elif ph:
            exec_s = "Execution: fail-fast (later phases skipped)"
        if exec_s:
            out.append(exec_s)

        out.append("")
    else:
        # If tests ran (PASS/FAIL), we can state full lifecycle through test for gate-mode.
        if str(authority_kind or "").strip().lower() in ("gate", "authoritative", "topology"):
            out.append("Execution: full lifecycle through test (collect+destroy still executed)")
            out.append("")

    # WI-4: If scenarios ran but declared tests were not counted, be explicit.
    # This is presentation-only; it does not change what ran or how verdicts are computed.
    if scen_total > 0 and total == 0:
        out.append("Note: scenario mode ran; declared tests were skipped (tests executed = 0).")
        out.append("")

    if is_smoke:
        out.append("RESULT: PASS (SMOKE)")
        out.append("Note: no tests or scenarios were executed.")
    else:
        if verdict_s == "FAIL":
            out.append("RESULT: FAIL (validation)")
        else:
            out.append(f"RESULT: {verdict_s}")

    # Failed assertions (execution order; no sorting)
    failed: list[dict] = []
    tests = results.get("tests", []) or []
    if isinstance(tests, list):
        for t in tests:
            if not isinstance(t, dict):
                continue
            if str(t.get("verdict") or "").strip().lower() != "fail":
                continue
            failed.append(t)

    # WI-1: On PASS, show which tests ran (bounded; deterministic; derived from results["tests"]).
    # Presentation-only: must not affect verdicts, exit codes, or artifacts.
    if verdict_s == "PASS" and (not is_smoke) and isinstance(tests, list) and tests:
        out.append("")
        out.append("Tests:")
        cap = 10
        for t in tests[:cap]:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name") or "<unnamed>").strip() or "<unnamed>"
            out.append(f" - PASS {name}")
        if len(tests) > cap:
            out.append(f" - (+{len(tests) - cap} more)")

    if verdict_s == "FAIL":
        out.append("")

        # WI-2: prereq failures must not be presented as test execution.
        # If prereqs ran but no declared tests ran, label explicitly.
        fail_hdr = "Failed assertions:"
        if prereqs_executed > 0 and declared_executed == 0:
            fail_hdr = "Failed prerequisites:"
        out.append(fail_hdr)

        if not failed:
            out.append(" - (none recorded)")
        else:
            for t in failed:
                name = str(t.get("name") or "<unnamed>").strip()
                exp = t.get("expected")
                obs = t.get("observed")

                # Evidence: prefer explicit evidence; fall back to error; keep single-line and bounded.
                ev = t.get("evidence")
                if not isinstance(ev, str) or not ev.strip():
                    ev = t.get("error")
                ev_s = str(ev or "").strip()
                if "\n" in ev_s:
                    ev_s = ev_s.splitlines()[0].strip()
                if len(ev_s) > 160:
                    ev_s = ev_s[:160] + "…"

                out.append(f" - {name}")
                out.append(f"   Expected: {exp}")
                out.append(f"   Observed: {obs}")
                out.append(f"   Evidence: {ev_s}")

    # Scenario timeline clarity (no durations; recorded order)
    if scen_total:
        out.append("")
        out.append("Scenario timelines:")
        for s in scenarios:
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or "<unknown>").strip()
            out.append(f"Scenario: {sid}")

            steps = s.get("steps", []) or []
            if not isinstance(steps, list) or not steps:
                out.append("  Step 1: (no steps recorded)")
                continue

            for i, st in enumerate(steps, start=1):
                if not isinstance(st, dict):
                    out.append(f"  Step {i}: unknown")
                    continue
                stype = str(st.get("type") or "unknown").strip()

                # Build a deterministic, minimal step label
                label_parts: list[str] = [stype]

                if stype == "run":
                    tn = st.get("test")
                    if isinstance(tn, str) and tn.strip():
                        label_parts.append(tn.strip())

                elif stype == "fault":
                    action = st.get("action")
                    if isinstance(action, str) and action.strip():
                        label_parts.append(action.strip())
                    a = st.get("a")
                    a_if = st.get("a_if")
                    b = st.get("b")
                    b_if = st.get("b_if")
                    node = st.get("node")
                    iface = st.get("if")

                    if isinstance(node, str) and node.strip():
                        if isinstance(iface, str) and iface.strip():
                            label_parts.append(f"{node.strip()}:{iface.strip()}")
                        else:
                            label_parts.append(node.strip())
                    elif isinstance(a, str) and a.strip() and isinstance(b, str) and b.strip():
                        if isinstance(a_if, str) and a_if.strip():
                            left = f"{a.strip()}:{a_if.strip()}"
                        else:
                            left = a.strip()
                        if isinstance(b_if, str) and b_if.strip():
                            right = f"{b.strip()}:{b_if.strip()}"
                        else:
                            right = b.strip()
                        label_parts.append(f"{left}<->{right}")

                elif stype == "wait_for":
                    wtype = st.get("wait_for_type") or st.get("wtype") or st.get("type")
                    if isinstance(wtype, str) and wtype.strip():
                        label_parts.append(wtype.strip())
                    src = st.get("from")
                    dst = st.get("to") or st.get("to_ip")
                    if isinstance(src, str) and src.strip() and isinstance(dst, str) and dst.strip():
                        label_parts.append(f"{src.strip()}->{dst.strip()}")
                    exp = st.get("expected") or st.get("expect")
                    if isinstance(exp, str) and exp.strip():
                        label_parts.append(f"expect={exp.strip()}")

                elif stype == "wait_for_bgp":
                    node = st.get("node")
                    if isinstance(node, str) and node.strip():
                        label_parts.append(f"node={node.strip()}")

                out.append(f"  Step {i}: " + " ".join(label_parts).strip())

    return "\n".join(out).rstrip() + "\n"

def write_test_summary_artifact(lab: str, results: dict) -> Path:
    """
    Non-authoritative, human-scannable summary.
    Deterministic header is required (presentation-only; no gate semantics).
    """
    out = lab_dir(lab) / "results.summary.txt"

    # -----------------------------
    # Deterministic header (v1.5)
    # -----------------------------
    # verdict: derived from already-computed overall result
    res = str(results.get("result") or "unknown").strip().lower()
    verdict_s = "PASS" if res == "pass" else "FAIL"

    # topology identity: prefer structured topology.name, then lab, then unknown
    topo_name = "unknown"
    topo_obj = results.get("topology")
    if isinstance(topo_obj, dict):
        tname = topo_obj.get("name")
        if isinstance(tname, str) and tname.strip():
            topo_name = tname.strip()
    if topo_name == "unknown":
        if isinstance(lab, str) and lab.strip():
            topo_name = lab.strip()

    # tests selection encoding (deterministic; derived from invocation intent already stored in results.summary)
    summ = results.get("summary", {}) or {}
    filter_name = summ.get("filtered_by_name") if isinstance(summ, dict) else ""
    filter_kind = summ.get("filtered_by_kind") if isinstance(summ, dict) else ""

    tests_sel = "all"
    sel_parts: list[str] = []
    if isinstance(filter_name, str) and filter_name.strip():
        sel_parts.append(f"name:{filter_name.strip()}")
    if isinstance(filter_kind, str) and filter_kind.strip():
        sel_parts.append(f"kind:{filter_kind.strip()}")
    if sel_parts:
        tests_sel = "filtered:" + ",".join(sel_parts)

    # scenarios selection encoding (deterministic; derived from invocation intent already stored in results.summary)
    scenarios_sel = "none"
    all_scen = bool(summ.get("all_scenarios")) if isinstance(summ, dict) else False
    scen_id = summ.get("scenario") if isinstance(summ, dict) else ""
    if all_scen:
        scenarios_sel = "all"
    else:
        if isinstance(scen_id, str) and scen_id.strip():
            scenarios_sel = f"one:{scen_id.strip()}"

    # -----------------------------
    # CI Summary deterministic header (v1.5)
    # -----------------------------
    # Must be line-1 in results.summary.txt, fixed order, stable fields only.
    failed_test_ids: list[str] = []
    for t in results.get("tests", []) or []:
        if t.get("verdict") == "fail":
            n = str(t.get("name") or "<unnamed>").strip()
            if n:
                failed_test_ids.append(n)
    failed_test_ids = sorted(set(failed_test_ids))

    failed_scenario_ids: list[str] = []
    for s in results.get("scenarios", []) or []:
        if s.get("verdict") == "fail":
            sid = str(s.get("id") or "<unnamed>").strip()
            if sid:
                failed_scenario_ids.append(sid)
    failed_scenario_ids = sorted(set(failed_scenario_ids))

    # JSON-style, single-line arrays, no spaces after commas
    ci_failed_tests = json.dumps(failed_test_ids, ensure_ascii=False, separators=(",", ":"))
    ci_failed_scenarios = json.dumps(failed_scenario_ids, ensure_ascii=False, separators=(",", ":"))

    # artifact_root must be relative (frozen): labs/clab-<lab>/
    artifact_root = f"labs/{lab_dir(lab).name}/"

    ci_header = (
        "=== CI SUMMARY ===\n"
        f"verdict: {verdict_s}\n"
        f"failed_tests: {ci_failed_tests}\n"
        f"failed_scenarios: {ci_failed_scenarios}\n"
        f"artifact_root: {artifact_root}\n"
        "\n"
    )

    header = (
        "=== AUTHORITATIVE TEST VERDICT ===\n"
        f"verdict: {verdict_s}\n"
        f"scope: topology={topo_name} tests={tests_sel} scenarios={scenarios_sel}\n"
        "\n"
    )

    # Existing body remains non-authoritative; improve readability only.
    # Rules:
    # - Do NOT change deterministic header (first 10 lines validated by verify_phase1.sh)
    # - Do NOT duplicate summary content
    # - Do NOT add timestamps/durations
    body = _format_test_summary(results)

    # Deterministic readability normalization (supporting-only):
    # ensure exactly one blank line between header and body, and ensure body ends with newline.
    body = (body or "").lstrip("\n")
    if not body.endswith("\n"):
        body += "\n"

    # -----------------------------
    # Stable summary keys (v2) — additive only
    # -----------------------------
    # Must not change CI header ordering/format (verify_phase1.sh validates it).
    # Must remain deterministic: no timestamps, no container IDs, no random tokens.
    tests = results.get("tests", []) or []
    scenarios = results.get("scenarios", []) or []

    tests_executed = len(tests) if isinstance(tests, list) else 0
    scenarios_executed = len(scenarios) if isinstance(scenarios, list) else 0

    failures = 0
    fail_lines: list[str] = []

    if isinstance(tests, list):
        for t in tests:
            if not isinstance(t, dict):
                continue
            if str(t.get("verdict") or "").strip().lower() == "fail":
                failures += 1
                name = str(t.get("name") or "<unnamed>").strip()
                exp = str((t.get("expected") or "")).strip().lower() or "unknown"
                obs = str((t.get("observed") or "")).strip().lower() or "unknown"
                fail_lines.append(f"FAIL: test={name} expected={exp} observed={obs}")

    if isinstance(scenarios, list):
        for s in scenarios:
            if not isinstance(s, dict):
                continue
            if str(s.get("verdict") or "").strip().lower() == "fail":
                failures += 1
                sid = str(s.get("id") or "<unnamed>").strip()
                exp = str((s.get("expected") or "")).strip().lower() or "unknown"
                obs = str((s.get("observed") or "")).strip().lower() or "unknown"
                fail_lines.append(f"FAIL: scenario={sid} expected={exp} observed={obs}")

    result_block = (
        "\n"
        "Result:\n"
        f"  RESULT: {verdict_s}\n"
    )

    scope_validated: list[str] = []
    if tests_executed > 0:
        scope_validated.append("declared tests")
    if scenarios_executed > 0:
        scope_validated.append("declared scenarios")
    if not scope_validated:
        scope_validated.append("deploy/provision only")

    scope_not_validated: list[str] = []
    if tests_executed == 0 and scenarios_executed == 0:
        scope_not_validated.extend(["connectivity behavior", "routing behavior", "policy behavior", "scenario behavior"])
    elif tests_executed == 0:
        scope_not_validated.append("declared test behavior")
    elif scenarios_executed == 0:
        scope_not_validated.append("scenario behavior")

    scope_block = (
        "\n"
        "Scope:\n"
        f"  Validated: {', '.join(scope_validated)}\n"
        f"  Not validated: {', '.join(scope_not_validated) if scope_not_validated else '(none declared outside executed scope)'}\n"
    )

    failure_meaning_lines: list[str] = []
    if verdict_s == "PASS":
        pass_meaning_block = (
            "\n"
            "PASS means:\n"
            "  All executed declared checks matched their expected outcomes within the scope shown above\n"
            "\n"
            "PASS does not mean:\n"
            "  Full network correctness outside the executed scope\n"
        )
        fail_meaning_block = ""
    else:
        hard_failure = results.get("hard_failure") or {}
        hard_failure_occurred = bool(
            isinstance(hard_failure, dict) and hard_failure.get("occurred") is True
        )
        if hard_failure_occurred:
            failure_meaning_lines.append("  A system/runtime failure interrupted validation")
            phase = str(hard_failure.get("phase") or "").strip()
            if phase:
                failure_meaning_lines.append(f"  Failure phase: {phase.upper()}")
        else:
            failure_meaning_lines.append("  One or more declared checks did not match expected outcomes")
            failure_meaning_lines.append("  This is a validation failure, not a system/runtime failure")
        pass_meaning_block = ""
        fail_meaning_block = (
            "\n"
            "FAIL means:\n"
            + "\n".join(failure_meaning_lines)
            + "\n"
        )

    validation_summary_block = (
        "\n"
        "Validation summary:\n"
        f"  Lab: {lab}\n"
        f"  Artifacts: {artifact_root}\n"
        f"  Tests executed: {tests_executed}\n"
        f"  Scenarios executed: {scenarios_executed}\n"
        f"  Failures: {failures}\n"
    )
    if fail_lines:
        validation_summary_block += "".join(f"  {line}\n" for line in fail_lines)

    authority_block = (
        "\n"
        "Authority:\n"
        "  results.json is the authoritative verdict artifact\n"
        "\n"
        "Summary:\n"
        "  results.summary.txt is explanatory only and does not determine verdicts\n"
    )

    share_block = (
        "\n"
        "Share this:\n"
        f"  {artifact_root}/results.json\n"
    )

    stable_keys = (
        result_block
        + authority_block
        + scope_block
        + pass_meaning_block
        + fail_meaning_block
        + validation_summary_block
        + share_block
    )

    out.write_text(ci_header + header + body + stable_keys, encoding="utf-8")
    return out

# -------------------------
# Preflight (advisory-only, resolve-time only)
# -------------------------

def _preflight_default_out() -> Path:
    # Deterministic, repo-safe default (no labs/, no runtime)
    return Path("artifacts") / "preflight" / "preflight.json"

def _preflight_write(out_path: Path, report: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def _preflight_load_adapters(adapter_paths: list[str]) -> dict:
    """
    Read normalized adapters.v1 JSON files as advisory-only context.
    Deterministic:
      - stable ordering by (source_type, source_path, path)
      - no timestamps
    Failure semantics (authoritative for preflight --adapter):
      - missing/unreadable/invalid schema -> SystemExit with a deterministic message
      - parse_errors inside adapter JSON do NOT fail (advisory-only)
    """
    if not isinstance(adapter_paths, list):
        raise SystemExit("preflight: --adapter must be repeatable (list)")

    inputs: list[dict] = []
    for p in adapter_paths:
        path = str(p or "").strip()
        if not path:
            raise SystemExit("preflight: --adapter path is empty")

        ap = Path(path).expanduser()
        if not ap.exists() or not ap.is_file():
            raise SystemExit(f"preflight: adapter not found: {ap}")

        try:
            payload = json.loads(ap.read_text(encoding="utf-8"))
        except Exception:
            raise SystemExit(f"preflight: adapter unreadable/invalid json: {ap}")

        if not isinstance(payload, dict):
            raise SystemExit(f"preflight: adapter must be a JSON object: {ap}")

        sv = str(payload.get("schema_version") or "")
        auth = str(payload.get("authority") or "")
        if sv != "adapters.v1" or auth != "advisory":
            raise SystemExit(f"preflight: adapter schema mismatch (need adapters.v1 advisory): {ap}")

        source_type = str(payload.get("source_type") or "")
        source_path = str(payload.get("source_path") or "")
        summ = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        pe = payload.get("parse_errors") if isinstance(payload.get("parse_errors"), list) else []
        pw = payload.get("parse_warnings") if isinstance(payload.get("parse_warnings"), list) else []

        inputs.append(
            {
                "path": str(ap),
                "schema_version": sv,
                "authority": auth,
                "source_type": source_type,
                "source_path": source_path,
                "summary": summ,
                "parse_errors_count": int(len(pe)),
                "parse_warnings_count": int(len(pw)),
            }
        )

    inputs.sort(key=lambda x: (str(x.get("source_type") or ""), str(x.get("source_path") or ""), str(x.get("path") or "")))
    return {"count": int(len(inputs)), "inputs": inputs}

def _preflight_canonical_link_id(endpoints: object) -> str:
    # endpoints like ["r1:eth1", "r2:eth1"] (resolved, must be deterministic)
    if not isinstance(endpoints, list) or len(endpoints) != 2:
        return "unknown<->unknown"
    a = str(endpoints[0] or "").strip()
    b = str(endpoints[1] or "").strip()
    # Canonical ordering by endpoint string (which includes node:iface)
    x, y = (a, b) if a <= b else (b, a)
    return f"{x}<->{y}"

def _preflight_contains_key(obj: object, needle: str) -> bool:
    # Declared-only structural scan (no semantics). Deterministic.
    if isinstance(obj, dict):
        if needle in obj:
            return True
        for v in obj.values():
            if _preflight_contains_key(v, needle):
                return True
    elif isinstance(obj, list):
        for it in obj:
            if _preflight_contains_key(it, needle):
                return True
    return False

def _preflight_get_touched_nodes(cov: dict) -> set[str]:
    # Be tolerant to minor schema evolution; prefer explicit top-level fields if present.
    v = cov.get("touched_nodes")
    if isinstance(v, list):
        return set(str(x) for x in v if isinstance(x, str))
    v2 = (cov.get("touched") or {}).get("nodes")
    if isinstance(v2, list):
        return set(str(x) for x in v2 if isinstance(x, str))
    return set()

def _preflight_get_touched_links(cov: dict) -> set[str]:
    v = cov.get("touched_links")
    if isinstance(v, list):
        return set(str(x) for x in v if isinstance(x, str))
    v2 = (cov.get("touched") or {}).get("links")
    if isinstance(v2, list):
        return set(str(x) for x in v2 if isinstance(x, str))
    return set()

def _preflight_findings(resolved: dict, cov: dict) -> list[dict]:
    nodes = resolved.get("nodes") or []
    links = resolved.get("links") or []
    tests = resolved.get("tests") or []
    scenarios = resolved.get("scenarios") or []

    node_names: list[str] = sorted(
        [n.get("name") for n in nodes if isinstance(n, dict) and isinstance(n.get("name"), str)]
    )

    link_ids: list[str] = []
    for lk in links:
        if not isinstance(lk, dict):
            continue
        link_ids.append(_preflight_canonical_link_id(lk.get("endpoints")))
    link_ids = sorted(link_ids)

    touched_nodes = set(sorted(_preflight_get_touched_nodes(cov)))
    touched_links = set(sorted(_preflight_get_touched_links(cov)))

    findings: list[dict] = []

    # 1) Untouched nodes (warn, one finding per node)
    for n in node_names:
        if n not in touched_nodes:
            findings.append(
                {
                    "id": f"coverage_gap.untouched_node.{n}",
                    "severity": "warn",
                    "category": "coverage_gap",
                    "message": f"Node '{n}' is never exercised by any declared test or scenario step.",
                    "refs": {"nodes": [n]},
                }
            )

    # 2) Untouched links (warn, one finding per link)
    for lid in link_ids:
        if lid not in touched_links:
            findings.append(
                {
                    "id": f"coverage_gap.untouched_link.{lid}",
                    "severity": "warn",
                    "category": "coverage_gap",
                    "message": f"Link '{lid}' is never exercised by any declared test or scenario step.",
                    "refs": {"links": [lid]},
                }
            )

    # Scenario presence / gaps
    if not scenarios:
        findings.append(
            {
                "id": "scenario_gap.no_scenarios",
                "severity": "info",
                "category": "scenario_gap",
                "message": "No scenarios declared. Resiliency / failure choreography is not validated.",
                "refs": {},
            }
        )
    else:
        # 4) Scenarios present but no fault steps
        has_any_fault = False
        has_link_down = False
        has_link_up = False
        has_if_down = False
        has_if_up = False
        has_wait_for_bgp = False

        for sc in scenarios:
            if not isinstance(sc, dict):
                continue
            steps = sc.get("steps") or []
            for st in steps:
                if not isinstance(st, dict):
                    continue
                if "wait_for_bgp" in st:
                    has_wait_for_bgp = True
                f = st.get("fault")
                if isinstance(f, dict):
                    has_any_fault = True
                    action = f.get("action")
                    if isinstance(action, str):
                        if action == "link_down":
                            has_link_down = True
                        elif action == "link_up":
                            has_link_up = True
                        elif action == "interface_down":
                            has_if_down = True
                        elif action == "interface_up":
                            has_if_up = True

        if not has_any_fault:
            findings.append(
                {
                    "id": "scenario_gap.no_fault_steps",
                    "severity": "warn",
                    "category": "scenario_gap",
                    "message": "Scenarios exist but none inject faults (no 'fault' steps). Failover/resiliency is not exercised.",
                    "refs": {},
                }
            )

        # 5) Fault injected but no restore (global presence heuristic; deterministic)
        if has_link_down and not has_link_up:
            findings.append(
                {
                    "id": "scenario_gap.missing_link_restore",
                    "severity": "warn",
                    "category": "scenario_gap",
                    "message": "At least one scenario injects link_down but no scenario includes link_up (restore missing).",
                    "refs": {},
                }
            )
        if has_if_down and not has_if_up:
            findings.append(
                {
                    "id": "scenario_gap.missing_interface_restore",
                    "severity": "warn",
                    "category": "scenario_gap",
                    "message": "At least one scenario injects interface_down but no scenario includes interface_up (restore missing).",
                    "refs": {},
                }
            )

        # Allowed advisory note (declared-only): scenarios never use wait_for_bgp
        if not has_wait_for_bgp:
            findings.append(
                {
                    "id": "scenario_gap.no_wait_for_bgp",
                    "severity": "info",
                    "category": "scenario_gap",
                    "message": "Scenarios never use wait_for_bgp. Control-plane convergence checks may be missing (declared-only note).",
                    "refs": {},
                }
            )

    # Declared allowlist / deny-all gap (ONLY if schema contains allowlist-like keys)
    has_allowlist = _preflight_contains_key(resolved, "allowlist") or _preflight_contains_key(resolved, "allowlists")
    if has_allowlist:
        has_negative = False
        for t in tests:
            if not isinstance(t, dict):
                continue
            exp = t.get("expected")
            if isinstance(exp, str) and exp.strip().lower() == "fail":
                has_negative = True
                break
        if not has_negative:
            findings.append(
                {
                    "id": "intent_gap.allowlist_no_negative_tests",
                    "severity": "warn",
                    "category": "intent_gap",
                    "message": "Allowlist-like constructs are declared but no expected-fail (negative) tests exist. You may be missing must-not validation.",
                    "refs": {},
                }
            )

    # Deterministic ordering: warn before info, then category, then id
    def _sev_rank(s: str) -> int:
        return 0 if s == "warn" else 1

    for f in findings:
        refs = f.get("refs")
        if isinstance(refs, dict):
            for k in ("nodes", "links", "tests", "scenarios"):
                if isinstance(refs.get(k), list):
                    refs[k] = sorted([str(x) for x in refs[k]])
            f["refs"] = refs

    findings = sorted(findings, key=lambda f: (_sev_rank(str(f.get("severity"))), str(f.get("category")), str(f.get("id"))))
    return findings

def _preflight_report(input_ref: str, topo_path: Path, resolved: dict, cov: dict, adapters: dict | None = None) -> dict:
    findings = _preflight_findings(resolved, cov)

    # summary counts
    by_sev = {"warn": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "")
        if sev in by_sev:
            by_sev[sev] += 1

    cov_summary = cov.get("summary") if isinstance(cov.get("summary"), dict) else {}
    coverage_obj = {
        "schema_version": str(cov.get("schema_version") or ""),
        "summary": cov_summary,
    }

    return {
        "schema_version": "preflight.v1",
        "tool": "ai-netsim",
        "command": "preflight",
        "authority": "advisory",
        "topology": {
            "input": input_ref,
            "resolved_name": str(resolved.get("name") or ""),
        },
        "adapters": adapters if isinstance(adapters, dict) else {"count": 0, "inputs": []},
        "coverage": coverage_obj,
        "findings": findings,
        "summary": {
            "finding_counts_by_severity": {"info": int(by_sev["info"]), "warn": int(by_sev["warn"])},
            "notes": [],
        },
    }

def _preflight_format_text(report: dict) -> str:
    # Deterministic plain-text (CI readable)
    topo = report.get("topology") or {}
    counts = (report.get("summary") or {}).get("finding_counts_by_severity") or {}
    lines: list[str] = []
    lines.append("=== Preflight (advisory-only) ===")
    lines.append(f"topology: {topo.get('input')}")
    lines.append(f"resolved_name: {topo.get('resolved_name')}")
    lines.append(f"findings: warn={counts.get('warn', 0)} info={counts.get('info', 0)}")
    ad = report.get("adapters") if isinstance(report.get("adapters"), dict) else {}
    lines.append(f"adapters: {int(ad.get('count', 0) or 0)}")
    lines.append("")
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "")
        cat = str(f.get("category") or "")
        fid = str(f.get("id") or "")
        msg = str(f.get("message") or "")
        lines.append(f"- [{sev}] {cat} {fid}: {msg}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"
