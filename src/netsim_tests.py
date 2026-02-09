from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Optional

from netsim_common import (
    run,
    die,
    is_ip_literal,
    validate_ip_literal,
    classify_invalid_target,
)

from netsim_artifacts import (
    lab_dir,
)
from netsim_runtime_container import _normalize_prefix

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

def wait_for_bgp(rt: Runtime, lab: str, node: str, timeout: int = 30) -> None:
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
    import time

    start = time.time()
    last_summary = ""
    last_neigh_lines: list[str] = []

    def parse_state_pfxrcd(neigh_line: str) -> str:
        parts = neigh_line.split()
        # parts[9] is State/PfxRcd in typical FRR output
        return parts[9] if len(parts) >= 10 else ""

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
                    return

        if time.time() - start > timeout:
            details = "\n".join(last_neigh_lines) if last_neigh_lines else "(no neighbor lines found)"
            die(f"{node}: BGP did not converge within {timeout}s:\n{details}")

        time.sleep(1)

def configure_frr_static_routes_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    v1 contract: topology must NOT encode routing mechanics.

    This function is intentionally hard-disabled in v1/v1.x to prevent accidental
    authority creep (static routing derived from topology).
    """
    die("v1 contract: static routing from topology is not supported. Use preconfigured images/config outside ai-netsim v1.")

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
    die("v1 contract: BGP provisioning from topology is not supported. Use preconfigured images/config outside ai-netsim v1.")

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

            allowed_step_keys = {"run", "fault", "wait_for", "wait_for_bgp"}
            keys = set(step)
            unknown_step = keys - allowed_step_keys
            if unknown_step:
                die(f"{sctx}: unknown keys {sorted(unknown_step)}")
            if len(keys) != 1:
                die(f"{sctx}: step must contain exactly one of {sorted(allowed_step_keys)}")

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
                if action not in ("link_down", "link_up", "interface_down", "interface_up"):
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

                    # both-or-none
                    if (a_if is None) ^ (b_if is None):
                        die(f"{sctx}.fault.{action}: must provide both a_if and b_if (or neither)")

                    if a_if is not None:
                        if not isinstance(a_if, str) or not a_if.strip():
                            die(f"{sctx}.fault.{action}.a_if: must be a non-empty string")
                        if not isinstance(b_if, str) or not b_if.strip():
                            die(f"{sctx}.fault.{action}.b_if: must be a non-empty string")

                    # --- deeper v1 validation: link disambiguation must match topo['links'] ---
                    a = str(spec.get("a") or "").strip()
                    b = str(spec.get("b") or "").strip()
                    matches = _link_matches(a, b)

                    if a_if is None and b_if is None:
                        # implicit path must be unambiguous
                        if len(matches) == 0:
                            die(f"{sctx}.fault.{action}: no declared link found between {a} and {b}")
                        if len(matches) > 1:
                            die(
                                f"{sctx}.fault.{action}: ambiguous links between {a} and {b} "
                                f"({len(matches)} found); provide a_if/b_if"
                            )
                    else:
                        # explicit path must match exactly one declared link
                        a_if_s = str(a_if).strip()
                        b_if_s = str(b_if).strip()
                        if (a_if_s, b_if_s) not in matches:
                            known = ", ".join([f"{a}:{x}<->{b}:{y}" for (x, y) in matches]) or "(none)"
                            die(
                                f"{sctx}.fault.{action}: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                                f"does not match any declared link between {a} and {b}. "
                                f"Known links: {known}"
                            )
                    # -------------------------------------------------------------------------

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

                required = {"type", "from", "to", "expect"}
                missing = required - set(wf)
                if missing:
                    die(f"{sctx}.wait_for: missing keys {sorted(missing)}")

                # v1.x: allow ping tuning + optional deterministic source selector
                allowed_wf = required | {
                    "timeout",
                    "interval_s",
                    "count",
                    "per_attempt_timeout_s",
                    "src_ip",
                    "src_if",
                }
                unknown = set(wf) - allowed_wf
                if unknown:
                    die(f"{sctx}.wait_for: unknown keys {sorted(unknown)}")

                t = wf.get("type")
                if t != "ping":
                    die(f"{sctx}.wait_for.type: must be ping (v1)")

                # v1.x optional ping source selector (Tier-1 validation only)
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

                if "count" in wf:
                    c = wf.get("count")
                    if not isinstance(c, int) or c < 1:
                        die(f"{sctx}.wait_for.count: must be an int >= 1")

                if "per_attempt_timeout_s" in wf:
                    pat = wf.get("per_attempt_timeout_s")
                    if not isinstance(pat, int) or pat < 1:
                        die(f"{sctx}.wait_for.per_attempt_timeout_s: must be an int >= 1")

                exp = wf.get("expect")
                if exp not in ("pass", "fail"):
                    die(f"{sctx}.wait_for.expect: must be pass|fail")

                for k in ("from", "to"):
                    v = wf.get(k)
                    if not isinstance(v, str) or not v.strip():
                        die(f"{sctx}.wait_for.{k}: must be a non-empty string")

                # v1: wait_for.to may be a node name OR an IP literal
                to_raw = str(wf.get("to")).strip()
                # v1.x: wait_for ping destinations are IPv4-only (no IPv6)
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
                    # must be an existing node name
                    nodes = topo.get("nodes", []) or []
                    if not any(isinstance(n, dict) and n.get("name") == to_raw for n in nodes):
                        reason = classify_invalid_target(to_raw)
                        die(
                            f"{sctx}.wait_for.to: invalid destination '{to_raw}'. "
                            f"Allowed: node name declared in topology (e.g. 'h2') OR IPv4 literal (e.g. '192.168.2.10'). "
                            f"Hostnames/DNS are not supported (determinism). Detail: {reason}"
                        )

                if "timeout" in wf:
                    to = wf.get("timeout")
                    if not isinstance(to, int) or to <= 0:
                        die(f"{sctx}.wait_for.timeout: must be a positive int")

                if "interval_s" in wf:
                    iv = wf.get("interval_s")
                    if not isinstance(iv, (int, float)) or float(iv) <= 0:
                        die(f"{sctx}.wait_for.interval_s: must be a positive number")

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
    ctype = cond.get("type")
    src = cond.get("from")
    dst = cond.get("to")
    expect = (cond.get("expect") or "pass").lower()
    timeout = int(cond.get("timeout") or 30)

    if ctype not in ("ping", "tcp"):
        die(f"wait_for: unsupported type {ctype!r}")

    if not isinstance(src, str) or not src.strip():
        die("wait_for: invalid from (must be node name)")
    if not isinstance(dst, str) or not dst.strip():
        die("wait_for: invalid to (must be node name or IP literal)")

    if expect not in ("pass", "fail"):
        die("wait_for: expect must be pass|fail")

    dst_ip = resolve_dst_to_ip(topo, dst.strip())
    should_succeed = (expect == "pass")

    def attempt() -> tuple[bool, Any]:
        if ctype == "ping":
            cp = rt.exec(lab, src, ["ping", "-c", "2", "-W", "1", dst_ip], check=False)
            ok = (cp.returncode == 0)
            return (ok == should_succeed), cp

        # tcp wait_for (if you use it)
        port = cond.get("port")
        try:
            port_i = int(port)
        except Exception:
            die("wait_for tcp: port must be an int")

        ensure_nc(rt, lab, src)
        cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port_i}"], check=False)
        ok = (cp.returncode == 0)
        return (ok == should_succeed), cp

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

    for idx, step in enumerate(steps):
        step_keys = list(step.keys())
        stype = step_keys[0]
        started = time.time()

        step_rec: dict[str, Any] = {"type": stype}

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
            # Step 1: executor skeleton only.
            # Step 2 will implement runtime-backed fault primitives.
            step_rec["fault"] = step["fault"]
            step_rec["verdict"] = "fail"
            step_rec["error"] = "fault primitives not implemented yet (Step 2)"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)
            scen_rec["verdict"] = "fail"
            break

        else:
            step_rec["verdict"] = "fail"
            step_rec["error"] = f"unknown step type '{stype}'"
            step_rec["duration_ms"] = int((time.time() - started) * 1000)
            scen_rec["steps"].append(step_rec)
            scen_rec["verdict"] = "fail"
            break

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
    lines.append(f"result: {results.get('result', 'unknown')}")
    if duration_ms is not None:
        lines.append(f"duration_ms: {int(duration_ms)}")

    # Keep tests as declared tests summary (Option A)
    lines.append(f"tests: total={total} passed={passed} failed={failed}")

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

def write_test_summary_artifact(lab: str, results: dict) -> Path:
    out = lab_dir(lab) / "results.summary.txt"
    out.write_text(_format_test_summary(results), encoding="utf-8")
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

def _preflight_report(input_ref: str, topo_path: Path, resolved: dict, cov: dict) -> dict:
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
