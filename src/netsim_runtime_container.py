from __future__ import annotations

import hashlib
import json
import subprocess
import time
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from netsim_common import LABS_DIR, TOPO_DIR, run, die
from netsim_artifacts import lab_dir, load_yaml, write_file
from netsim_model import ensure_valid_topology, resolve_topology, topo_to_containerlab

def gen_nft_fw_rules(node: dict) -> str:
    """
    Generate nftables rules for nft-fw node.

    Supported keys in YAML:
      allow_icmp: true/false
      allow_tcp: [443, 22, ...]
      allow_udp: [53, ...]
    Default policy is DROP in forward chain.
    """
    allow_icmp = bool(node.get("allow_icmp", False))
    allow_tcp = node.get("allow_tcp", []) or []
    allow_udp = node.get("allow_udp", []) or []

    def fmt_ports(ports: list[int]) -> str:
        # nft expects: { 22, 443 }
        ports = [int(p) for p in ports]
        return "{ " + ", ".join(str(p) for p in ports) + " }"

    lines: list[str] = []
    lines.append("flush ruleset")
    lines.append("table inet filter {")
    lines.append("  chain forward {")
    lines.append("    type filter hook forward priority 0; policy drop;")
    lines.append("    ct state established,related accept")

    if allow_icmp:
        lines.append("    ip protocol icmp accept")

    if allow_tcp:
        lines.append(f"    tcp dport {fmt_ports(allow_tcp)} accept")

    if allow_udp:
        lines.append(f"    udp dport {fmt_ports(allow_udp)} accept")

    lines.append("  }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)

def _coverage_canonical_link_id(a_ep: str, b_ep: str) -> str:
    a = str(a_ep).strip()
    b = str(b_ep).strip()
    if not a or not b:
        die("coverage: link endpoint is empty")
    end1, end2 = (a, b) if a <= b else (b, a)
    return f"{end1}<->{end2}"

def _coverage_inventory_nodes(topo: dict[str, Any]) -> list[str]:
    nodes = topo.get("nodes", []) or []
    out: list[str] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    # Stable, unique
    out = sorted(set(out))
    return out

def _coverage_inventory_links(topo: dict[str, Any]) -> list[str]:
    links = topo.get("links", []) or []
    out: list[str] = []
    for l in links:
        if not isinstance(l, dict):
            continue
        eps = l.get("endpoints") or []
        if not (isinstance(eps, list) and len(eps) == 2):
            continue
        out.append(_coverage_canonical_link_id(str(eps[0]).strip(), str(eps[1]).strip()))
    return sorted(set(out))

def _coverage_hash_resolved_topology(resolved: dict[str, Any]) -> str:
    """
    Deterministic hash: YAML dump with sort_keys=True (stable dict ordering),
    encoded as UTF-8, SHA-256 hex.
    """
    import hashlib
    blob = yaml.safe_dump(resolved, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _coverage_resolve_link_between(
    topo: dict[str, Any],
    a: str,
    b: str,
    a_if: str | None,
    b_if: str | None,
) -> str:
    """
    Declared-only link resolution to canonical link id.
    Matches validate_scenarios() rules:
      - if a_if/b_if omitted: must be exactly ONE link between a and b
      - if a_if/b_if provided: must match exactly
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

    matches: list[tuple[str, str]] = []  # (a_ep, b_ep) canonical endpoint strings
    for l in links:
        if not isinstance(l, dict):
            continue
        eps = l.get("endpoints") or []
        if not (isinstance(eps, list) and len(eps) == 2):
            continue

        p1 = parse_ep(eps[0])
        p2 = parse_ep(eps[1])
        if not p1 or not p2:
            continue
        n1, i1 = p1
        n2, i2 = p2

        # match unordered nodes a/b
        if not ((n1 == a and n2 == b) or (n1 == b and n2 == a)):
            continue

        # normalize endpoints as "<node>:<iface>" in a/b direction
        if n1 == a and n2 == b:
            a_ep = f"{n1}:{i1}"
            b_ep = f"{n2}:{i2}"
        else:
            a_ep = f"{n2}:{i2}"
            b_ep = f"{n1}:{i1}"

        # if specific interfaces provided, they must match
        if a_if is not None and b_if is not None:
            if a_ep != f"{a}:{a_if}" or b_ep != f"{b}:{b_if}":
                continue

        matches.append((a_ep, b_ep))

    if a_if is None and b_if is None:
        if len(matches) != 1:
            die(f"coverage: link resolution between '{a}' and '{b}' is ambiguous or missing ({len(matches)} matches)")
        a_ep, b_ep = matches[0]
        return _coverage_canonical_link_id(a_ep, b_ep)

    # both-or-none must already be validated, but enforce anyway
    if (a_if is None) != (b_if is None):
        die("coverage: link fault must specify both a_if and b_if, or neither")

    if len(matches) != 1:
        die(f"coverage: link resolution for '{a}:{a_if}' <-> '{b}:{b_if}' is missing or ambiguous ({len(matches)} matches)")
    a_ep, b_ep = matches[0]
    return _coverage_canonical_link_id(a_ep, b_ep)

def build_coverage_model(resolved: dict[str, Any], topo_path: Path) -> dict[str, Any]:
    """
    Pure, declared-only coverage model computed from resolved topology.
    MUST NOT call runtime/deploy/provision/test.
    """
    from netsim_tests import _coverage_test_ids, _coverage_scenario_ids, _coverage_touch_nodes_from_test

    # Inventory
    node_list = _coverage_inventory_nodes(resolved)
    link_list = _coverage_inventory_links(resolved)
    known_nodes = set(node_list)

    test_ids_declared = _coverage_test_ids(resolved)
    scenario_ids_declared = _coverage_scenario_ids(resolved)

    tests = resolved.get("tests", []) or []
    scenarios = resolved.get("scenarios") or []

    # Per-test coverage
    by_test: dict[str, Any] = {}
    for t in tests:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("name") or "").strip()
        if not tid:
            die("coverage: unnamed test found (should have failed earlier)")

        touched_nodes = _coverage_touch_nodes_from_test(resolved, t, known_nodes)

        by_test[tid] = {
            "touched_nodes": touched_nodes,
            "touched_links": [],          # no inference
            "touched_wait_classes": [],   # atomic tests do not add waits
            "notes": [],
        }

    # Scenario coverage
    by_scenario: dict[str, Any] = {}
    touched_fault_classes_all: set[str] = set()
    touched_wait_classes_all: set[str] = set()
    touched_nodes_all: set[str] = set()
    touched_links_all: set[str] = set()

    # Build quick test lookup for union behavior
    test_touch_nodes_map: dict[str, list[str]] = {}
    for tid in test_ids_declared:
        test_touch_nodes_map[tid] = list(by_test.get(tid, {}).get("touched_nodes", []))

    if scenarios:
        if not isinstance(scenarios, list):
            die("coverage: scenarios must be a list")
        for s in scenarios:
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or "").strip()
            if not sid:
                die("coverage: scenario missing id (should have failed earlier)")

            steps = s.get("steps") or []
            if not isinstance(steps, list):
                die(f"coverage: scenario '{sid}' steps must be a list")

            scen_nodes: set[str] = set()
            scen_links: set[str] = set()
            scen_faults: set[str] = set()
            scen_waits: set[str] = set()
            scen_tests: set[str] = set()

            for st in steps:
                if not isinstance(st, dict):
                    die(f"coverage: scenario '{sid}' step is not a dict")

                # step is exactly one action (already validated), but we stay explicit here
                if "fault" in st:
                    f = st.get("fault")
                    if not isinstance(f, dict) or len(f) != 1:
                        die(f"coverage: scenario '{sid}' fault must be a dict with exactly one action")

                    action, spec = next(iter(f.items()))
                    if action not in ("link_down", "link_up", "interface_down", "interface_up"):
                        die(f"coverage: scenario '{sid}' has unknown fault action '{action}'")

                    if not isinstance(spec, dict):
                        die(f"coverage: scenario '{sid}' fault.{action} must be a dict")

                    scen_faults.add(action)

                    if action in ("link_down", "link_up"):
                        a = str(spec.get("a") or "").strip()
                        b = str(spec.get("b") or "").strip()
                        if not a or not b:
                            die(f"coverage: scenario '{sid}' fault.{action} requires a and b")
                        if a not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{a}'")
                        if b not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{b}'")
                        scen_nodes.add(a)
                        scen_nodes.add(b)

                        a_if_raw = spec.get("a_if")
                        b_if_raw = spec.get("b_if")

                        a_if = str(a_if_raw).strip() if isinstance(a_if_raw, str) and a_if_raw.strip() else None
                        b_if = str(b_if_raw).strip() if isinstance(b_if_raw, str) and b_if_raw.strip() else None

                        link_id = _coverage_resolve_link_between(resolved, a, b, a_if, b_if)
                        scen_links.add(link_id)

                    else:
                        node = str(spec.get("node") or "").strip()
                        if not node:
                            die(f"coverage: scenario '{sid}' fault.{action} requires node")
                        if node not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{node}'")
                        scen_nodes.add(node)

                elif "wait_for_bgp" in st:
                    scen_waits.add("wait_for_bgp")
                    wf = st.get("wait_for_bgp") or {}
                    if not isinstance(wf, dict):
                        die(f"coverage: scenario '{sid}' wait_for_bgp must be a dict")
                    node = wf.get("node")
                    if isinstance(node, str) and node.strip():
                        n = node.strip()
                        if n not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{n}'")
                        scen_nodes.add(n)

                elif "wait_for" in st:
                    wf = st.get("wait_for") or {}
                    if not isinstance(wf, dict):
                        die(f"coverage: scenario '{sid}' wait_for must be a dict")

                    wtype = str(wf.get("type") or "").strip().lower()
                    if wtype not in ("ping", "tcp", "route_prefix"):
                        die(
                            f"coverage: scenario '{sid}' wait_for type '{wtype}' is not supported by coverage schema "
                            "(only ping|tcp|route_prefix)"
                        )

                    # Record wait type for coverage summary
                    if wtype == "ping":
                        scen_waits.add("wait_for_ping")
                    elif wtype == "tcp":
                        scen_waits.add("wait_for_tcp")
                    else:
                        scen_waits.add("wait_for_route_prefix")

                    frm = wf.get("from")
                    to = wf.get("to")

                    if isinstance(frm, str) and frm.strip():
                        fnode = frm.strip()
                        if fnode not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown from node '{fnode}'")
                        scen_nodes.add(fnode)

                    if isinstance(to, str) and to.strip():
                        tval = to.strip()
                        if tval in known_nodes:
                            scen_nodes.add(tval)

                elif "pcap_start" in st:
                    spec = st.get("pcap_start") or {}
                    if not isinstance(spec, dict):
                        die(f"coverage: scenario '{sid}' pcap_start must be a dict")

                    target = spec.get("target")
                    if not isinstance(target, dict):
                        die(f"coverage: scenario '{sid}' pcap_start.target must be a dict")

                    # Interface target: {node, iface}
                    if ("node" in target) or ("iface" in target):
                        node = str(target.get("node") or "").strip()
                        iface = str(target.get("iface") or "").strip()
                        if not node or not iface:
                            die(f"coverage: scenario '{sid}' pcap_start.target requires node and iface")
                        if node not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{node}'")
                        scen_nodes.add(node)

                    # Link target: {a,b,a_if?,b_if?}
                    elif ("a" in target) or ("b" in target):
                        a = str(target.get("a") or "").strip()
                        b = str(target.get("b") or "").strip()
                        if not a or not b:
                            die(f"coverage: scenario '{sid}' pcap_start.target requires a and b")
                        if a not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{a}'")
                        if b not in known_nodes:
                            die(f"coverage: scenario '{sid}' references unknown node '{b}'")
                        scen_nodes.add(a)
                        scen_nodes.add(b)

                        a_if_raw = target.get("a_if")
                        b_if_raw = target.get("b_if")
                        a_if = str(a_if_raw).strip() if isinstance(a_if_raw, str) and a_if_raw.strip() else None
                        b_if = str(b_if_raw).strip() if isinstance(b_if_raw, str) and b_if_raw.strip() else None

                        link_id = _coverage_resolve_link_between(resolved, a, b, a_if, b_if)
                        scen_links.add(link_id)

                    else:
                        die(f"coverage: scenario '{sid}' pcap_start.target must be interface-target or link-target")

                elif "pcap_stop" in st:
                    spec = st.get("pcap_stop") or {}
                    if not isinstance(spec, dict):
                        die(f"coverage: scenario '{sid}' pcap_stop must be a dict")

                    # target is optional (stop-all semantics). If provided, validate shape for coverage consistency.
                    target = spec.get("target")
                    if target is None:
                        pass
                    elif not isinstance(target, dict):
                        die(f"coverage: scenario '{sid}' pcap_stop.target must be a dict")
                    else:
                        # Interface target: {node, iface}
                        if ("node" in target) or ("iface" in target):
                            node = str(target.get("node") or "").strip()
                            iface = str(target.get("iface") or "").strip()
                            if not node or not iface:
                                die(f"coverage: scenario '{sid}' pcap_stop.target requires node and iface")
                            if node not in known_nodes:
                                die(f"coverage: scenario '{sid}' references unknown node '{node}'")
                            scen_nodes.add(node)

                        # Link target: {a,b,a_if?,b_if?}
                        elif ("a" in target) or ("b" in target):
                            a = str(target.get("a") or "").strip()
                            b = str(target.get("b") or "").strip()
                            if not a or not b:
                                die(f"coverage: scenario '{sid}' pcap_stop.target requires a and b")
                            if a not in known_nodes:
                                die(f"coverage: scenario '{sid}' references unknown node '{a}'")
                            if b not in known_nodes:
                                die(f"coverage: scenario '{sid}' references unknown node '{b}'")
                            scen_nodes.add(a)
                            scen_nodes.add(b)

                            a_if_raw = target.get("a_if")
                            b_if_raw = target.get("b_if")
                            a_if = str(a_if_raw).strip() if isinstance(a_if_raw, str) and a_if_raw.strip() else None
                            b_if = str(b_if_raw).strip() if isinstance(b_if_raw, str) and b_if_raw.strip() else None

                            link_id = _coverage_resolve_link_between(resolved, a, b, a_if, b_if)
                            scen_links.add(link_id)

                        else:
                            die(f"coverage: scenario '{sid}' pcap_stop.target must be interface-target or link-target")

                elif "run" in st:
                    ref = st.get("run")
                    # v17 schema: run is a string test name (after include:all expansion)
                    if not isinstance(ref, str) or not ref.strip():
                        die(f"coverage: scenario '{sid}' run must be a non-empty string test name")
                    tn = ref.strip()
                    if tn not in test_touch_nodes_map:
                        die(f"coverage: scenario '{sid}' references unknown test '{tn}'")
                    scen_tests.add(tn)

                else:
                    die(f"coverage: scenario '{sid}' step has no recognized action")

            # Union rule: scenario touched_nodes includes nodes from invoked tests (declared-only)
            for tid in sorted(scen_tests):
                for n in test_touch_nodes_map.get(tid, []):
                    scen_nodes.add(n)

            # Finalize per-scenario
            by_scenario[sid] = {
                "steps_count": int(len(steps)),
                "touched_nodes": sorted(scen_nodes),
                "touched_links": sorted(scen_links),
                "touched_fault_classes": sorted(scen_faults),
                "touched_wait_classes": sorted(scen_waits),
                "referenced_tests": sorted(scen_tests),
            }

            touched_nodes_all |= scen_nodes
            touched_links_all |= scen_links
            touched_fault_classes_all |= scen_faults
            touched_wait_classes_all |= scen_waits

    # Summary touched from tests as well
    for tid in test_ids_declared:
        for n in by_test.get(tid, {}).get("touched_nodes", []) or []:
            touched_nodes_all.add(n)

    inv_nodes_set = set(node_list)
    inv_links_set = set(link_list)

    coverage = {
        "authority": "advisory",
        "schema_version": "coverage.v1",
        "generated_from": {
            "topology_name": str((resolved.get("name") or "").strip()),
            "topology_hash": _coverage_hash_resolved_topology(resolved),
            "topology_path": str(topo_path),
        },
        "inventory": {
            "nodes": node_list,
            "links": link_list,
        },
        "tests": {
            "declared": sorted(test_ids_declared),
            "by_test": {k: by_test[k] for k in sorted(by_test)},
        },
        "scenarios": {
            "declared": sorted(scenario_ids_declared),
            "by_scenario": {k: by_scenario[k] for k in sorted(by_scenario)},
        },
        "summary": {
            "touched_nodes": sorted(touched_nodes_all),
            "untouched_nodes": sorted(inv_nodes_set - touched_nodes_all),
            "touched_links": sorted(touched_links_all),
            "untouched_links": sorted(inv_links_set - touched_links_all),
            "touched_fault_classes": sorted(touched_fault_classes_all),
            "touched_wait_classes": sorted(touched_wait_classes_all),
        },
    }
    return coverage

def write_coverage_artifact(lab: str, coverage: dict[str, Any]) -> Path:
    """
    Advisory-only artifact:
      labs/clab-<lab>/artifacts/coverage/coverage.json
    Written during resolve/validate flow (no deploy required).
    """
    import json
    out = lab_dir(lab) / "artifacts" / "coverage" / "coverage.json"
    write_file(out, json.dumps(coverage, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return out

def write_containerlab_file(topo_path: Path) -> Path:
    topo = load_yaml(topo_path)
    ensure_valid_topology(topo)

    resolved = resolve_topology(topo)
    from netsim_tests import validate_scenarios
    validate_scenarios(resolved)

    # Advisory-only coverage model (declared-only, resolve-time)
    cov = build_coverage_model(resolved, topo_path=topo_path)
    write_coverage_artifact(resolved["name"], cov)

    # Store both: original + resolved
    write_file(lab_dir(topo["name"]) / "topology.yaml", yaml.safe_dump(topo, sort_keys=False))
    write_file(lab_dir(topo["name"]) / "topology.resolved.yaml", yaml.safe_dump(resolved, sort_keys=False))

    clab = topo_to_containerlab(resolved)

    LABS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = LABS_DIR / f"{resolved['name']}.clab.yaml"
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(clab, f, sort_keys=False)

    print(f"Wrote: {out_path}")
    return out_path

# -------------------------
# Runtime helpers
# -------------------------

def _normalize_prefix(cidr: str) -> str | None:
    try:
        # Accept inputs that may already be parsed (e.g., IPv4Network) by coercing to str.
        if not isinstance(cidr, str):
            cidr = str(cidr)

        cidr = cidr.strip()
        if not cidr:
            return None

        n = ipaddress.ip_network(cidr, strict=False)
        if n.version != 4:
            return None
        return str(n)
    except Exception:
        return None

def compare_expected_vs_observed_prefixes(expected: set[str], observed: set[str]) -> dict[str, Any]:
    missing = sorted([p for p in expected if p not in observed])
    return {
        "expected": sorted(expected),
        "observed": sorted(observed),
        "missing": missing,
        "ok": (len(missing) == 0),
    }

def container_name(lab_name: str, node: str) -> str:
    """
    Back-compat helper.
    Historically returned the docker container name. Now returns the runtime node id.
    """
    rt = get_runtime()
    return rt.node_id(lab_name, node)

def _node_index_by_name(topo: dict[str, Any]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for n in topo.get("nodes", []) or []:
        name = n.get("name")
        if isinstance(name, str) and name:
            idx[name] = n
    return idx

def configure_frr_interfaces_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    For each link with ipv4 addressing, assign the per-endpoint IP to the correct interface,
    BUT only for endpoints that are FRR nodes.

    Also configures loopback with router_id/32 if present.

    Runtime contract:
      - No direct docker/container name usage here
      - All node execution goes through rt.exec()/rt.sh()
    """
    nodes = _node_index_by_name(topo)

    # 1) Assign interface IPs from links
    for link in topo.get("links", []) or []:
        endpoints = link.get("endpoints") or []
        ipv4s = link.get("ipv4") or []

        if not (isinstance(endpoints, list) and isinstance(ipv4s, list)):
            continue
        if len(endpoints) != len(ipv4s):
            continue

        for ep, ipcidr in zip(endpoints, ipv4s):
            if not (isinstance(ep, str) and isinstance(ipcidr, str)):
                continue
            if ":" not in ep:
                continue

            node, iface = ep.split(":", 1)
            n = nodes.get(node)
            if not n or n.get("type") != "frr":
                continue

            # bring up + set address
            rt.exec(lab, node, ["ip", "link", "set", iface, "up"], check=False, capture_output=False)
            rt.exec(lab, node, ["ip", "addr", "flush", "dev", iface], check=False, capture_output=False)
            rt.exec(lab, node, ["ip", "addr", "add", ipcidr, "dev", iface], check=True, capture_output=False)

    # 2) Router-id loopback (router_id/32) if provided
    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue
        rid = n.get("router_id")
        if not (isinstance(rid, str) and rid):
            continue

        rt.exec(lab, node, ["ip", "link", "set", "lo", "up"], check=False, capture_output=False)
        # Keep it simple: flush + set router_id/32
        rt.exec(lab, node, ["ip", "addr", "flush", "dev", "lo"], check=False, capture_output=False)
        rt.exec(lab, node, ["ip", "addr", "add", f"{rid}/32", "dev", "lo"], check=True, capture_output=False)

def configure_hosts_from_topology(rt: "Runtime", lab_name: str, topo: dict) -> None:
    """
    Configure host nodes based on links that include explicit link['ipv4'] entries.
    For a host<->router link, we:
      - set host IP on its interface
      - set host default route via router IP on that same link

    Runtime contract:
      - No direct docker/container name usage here.
      - All node execution goes through rt.exec()/rt.sh() via host_configure().
    """
    # Quick lookup: node name -> type
    node_type = {n["name"]: n["type"] for n in topo.get("nodes", [])}

    for link in topo.get("links", []):
        eps = link.get("endpoints", [])
        ips = link.get("ipv4", [])

        # Only configure when ipv4 is explicitly defined on the link
        if len(eps) != 2 or len(ips) != 2:
            continue

        (n1, if1) = eps[0].split(":", 1)
        (n2, if2) = eps[1].split(":", 1)
        ip1 = ips[0]  # e.g. 192.168.1.10/24
        ip2 = ips[1]  # e.g. 192.168.1.1/24

        # Host on side 1?
        if node_type.get(n1) == "host" and node_type.get(n2) in ("frr", "linux"):
            host_configure(rt, lab_name, n1, if1, ip1, ip2.split("/")[0])

        # Host on side 2?
        if node_type.get(n2) == "host" and node_type.get(n1) in ("frr", "linux"):
            host_configure(rt, lab_name, n2, if2, ip2, ip1.split("/")[0])

def host_configure(rt: "Runtime", lab_name: str, host: str, iface: str, ip_cidr: str, gw: str) -> None:
    """
    Inside host node:
      - flush and set IP on iface
      - bring iface up
      - set default route via gw
    """
    rt.exec(lab_name, host, ["ip", "link", "set", iface, "up"], check=False, capture_output=False)
    rt.exec(lab_name, host, ["ip", "addr", "flush", "dev", iface], check=False, capture_output=False)
    rt.exec(lab_name, host, ["ip", "addr", "add", ip_cidr, "dev", iface], check=True, capture_output=False)
    rt.exec(lab_name, host, ["ip", "route", "replace", "default", "via", gw], check=True, capture_output=False)

def configure_nftfw_from_topology(rt: "Runtime", lab_name: str, topo: dict) -> None:
    for link in topo.get("links", []):
        eps = link.get("endpoints", [])
        ips = link.get("ipv4", [])
        if len(eps) != 2 or len(ips) != 2:
            continue

        for ep, ip in zip(eps, ips):
            node, iface = ep.split(":", 1)
            if not ip:
                continue

            is_fw = (
                node.startswith("fw")
                or node == "fw1"
                or any(n.get("name") == node and n.get("type") == "nft-fw" for n in topo.get("nodes", []))
            )
            if not is_fw:
                continue

            rt.exec(lab_name, node, ["ip", "link", "set", iface, "up"], check=False, capture_output=False)
            rt.exec(lab_name, node, ["ip", "addr", "flush", "dev", iface], check=False, capture_output=False)
            rt.exec(lab_name, node, ["ip", "addr", "add", ip, "dev", iface], check=True, capture_output=False)

def nft_fw_apply(rt: "Runtime", lab_name: str, node: str, ruleset: str) -> None:
    # Require nft exists in the image (NO runtime installs)
    cp = rt.sh(lab_name, node, "command -v nft >/dev/null", check=False, capture_output=False)
    if cp.returncode != 0:
        die(f"{node}: nft not found (use an nftables-capable image, e.g. ghcr.io/andrew-ai-netsim/nft-fw:latest)")

    # Load ruleset (fail-fast if nft rejects it)
    cmd = (
        "set -e\n"
        "cat > /tmp/rules.nft <<'EOF'\n"
        f"{ruleset}\n"
        "EOF\n"
        "nft -f /tmp/rules.nft\n"
    )
    rt.sh(lab_name, node, cmd, check=True, capture_output=False)

def verify_host_ready(rt: Runtime, lab: str, host: str) -> None:
    """
    Host readiness gate (v1).

    We consider a host "ready" if:
      - `ip` exists
      - it has at least one global IPv4 address configured on a non-lo interface

    IMPORTANT:
    - Do not rely on awk/busybox differences across images.
    - Use `ip -4 -o addr show` which is consistent.
    """

    # ip command should exist
    cp = rt.exec(lab, host, ["sh", "-lc", "command -v ip >/dev/null"], check=False)
    if cp.returncode != 0:
        die(f"{host}: 'ip' not found")

    # must have at least one global IPv4 (excluding lo)
    # Example output:
    #   7: eth1    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth1
    cp = rt.exec(
        lab,
        host,
        ["sh", "-lc", "ip -4 -o addr show scope global | grep -q 'inet '"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        # Helpful debug output
        dbg = rt.exec(
            lab,
            host,
            ["sh", "-lc", "ip -br addr; echo '---'; ip -4 -o addr show scope global || true"],
            check=False,
            capture_output=True,
        )
        die(f"{host}: no global IPv4 configured (host not ready)\n{(dbg.stdout or '').strip()}")

def verify_frr_ready(rt: Runtime, lab: str, rtr: str) -> None:
    # vtysh must work
    cp = rt.exec(
        lab,
        rtr,
        ["vtysh", "-c", "show version"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        die(f"{rtr}: vtysh not ready")

def verify_sonic_vm_ready(rt: Runtime, lab: str, node: str) -> None:
    """
    VM substrate readiness gate (v1.5).

    This is intentionally minimal and deterministic:
      - verifies the containerlab node instance is running
      - verifies a QEMU process exists inside the wrapper container (vrnetlab-style)
    No NOS CLI parsing. No semantic interpretation.
    """
    if not rt.is_running(lab, node):
        die(f"{node}: VM substrate container is not running")

    # vrnetlab-style containers run QEMU inside the container.
    # Deterministic bounded wait (explicit timeout + interval; no jitter).
    boot_timeout_s = 60
    interval_s = 1.0
    deadline = time.time() + boot_timeout_s

    while True:
        cp = rt.exec(
            lab,
            node,
            ["sh", "-lc", "ps -eo comm,args | grep -E '[q]emu-system|[q]emu-kvm' >/dev/null"],
            check=False,
            capture_output=False,
        )
        if cp.returncode == 0:
            break

        if time.time() >= deadline:
            die(f"{node}: VM substrate not ready within {boot_timeout_s}s (qemu process not detected)")

        time.sleep(interval_s)

def verify_lab_ready(rt: Runtime, topo: dict, lab: str) -> None:
    nodes = topo.get("nodes", []) or []
    for n in nodes:
        name = n.get("name")
        t = n.get("type")

        if not name or not t:
            die("Node missing 'name' or 'type' in topology")

        if t == "host":
            verify_host_ready(rt, lab, name)
        elif t == "nft-fw":
            from netsim_tests import verify_fw_routed_ready
            verify_fw_routed_ready(rt, lab, name)
        elif t == "frr":
            verify_frr_ready(rt, lab, name)
        elif t == "sonic-vm":
            verify_sonic_vm_ready(rt, lab, name)

def fw_next_hops_from_links(topo: dict, fw_name: str) -> list[str]:
    """
    Returns the L3 peer IPs on links that connect to fw_name:* (uses topo['links'][*]['ipv4']).
    Example: ["10.0.0.2", "10.0.0.5"]
    """
    hops: list[str] = []
    for l in topo.get("links", []) or []:
        eps = l.get("endpoints") or []
        ipv4s = l.get("ipv4") or []
        if len(eps) != 2 or len(ipv4s) != 2:
            continue

        a_ep, b_ep = eps
        a_ipcidr, b_ipcidr = ipv4s

        if a_ep.startswith(fw_name + ":"):
            hops.append(b_ipcidr.split("/")[0])
        elif b_ep.startswith(fw_name + ":"):
            hops.append(a_ipcidr.split("/")[0])

    # de-dupe but keep order
    out: list[str] = []
    for h in hops:
        if h not in out:
            out.append(h)
    return out

def nft_fw_setup_bridge(rt: "Runtime", lab_name: str, node: str) -> None:
    # Create bridge br0 and enslave eth1/eth2
    cmd = r"""
set -e
ip link add br0 type bridge 2>/dev/null || true
ip link set eth1 up
ip link set eth2 up
ip link set eth1 master br0 2>/dev/null || true
ip link set eth2 master br0 2>/dev/null || true
ip link set br0 up
"""
    rt.sh(lab_name, node, cmd, check=True, capture_output=False)

def lab_file_from_name(lab_name: str) -> Path:
    return LABS_DIR / f"{lab_name}.clab.yaml"

def parse_lab_nodes(lab_name: str) -> list[str]:
    lf = lab_file_from_name(lab_name)
    if not lf.exists():
        die(f"Lab file not found: {lf} (run gen/up first)")
    data = load_yaml(lf)
    nodes = list((data.get("topology", {}).get("nodes", {}) or {}).keys())
    return nodes

def docker_is_running(container: str) -> bool:
    """
    Back-compat shim. If callers pass a container string, we can only support this
    in docker runtime. Prefer rt.is_running(lab,node) everywhere.
    """
    rt = get_runtime()
    return rt.is_running_id(container)

def vty(rt: Runtime, lab: str, node: str, cmd: str) -> subprocess.CompletedProcess:
    return rt.exec(lab, node, ["vtysh", "-c", cmd], check=False, capture_output=True)

def ensure_ip_tools(rt: "Runtime", lab: str, node: str) -> None:
    """
    Ensure the 'ip' command is available inside the node.

    Runtime contract:
      - No docker/container_name usage
      - No package installs
      - Pure capability check
    """
    cp = rt.sh(
        lab,
        node,
        "command -v ip >/dev/null",
        check=False,
        capture_output=False,
    )
    if cp.returncode != 0:
        die(f"{node}: 'ip' not found (image must include iproute2)")

def resolved_topology_path(lab: str) -> Path:
    return lab_dir(lab) / "topology.resolved.yaml"

def load_resolved_topology(lab: str) -> dict[str, Any] | None:
    p = resolved_topology_path(lab)
    if not p.exists():
        return None
    try:
        return load_yaml(p)
    except Exception:
        return None

def frr_nodes_from_topology(topo: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for n in topo.get("nodes", []):
        if n.get("type") == "frr" and n.get("name"):
            out.add(n["name"])
    return out

def _container_is_running(container_name: str) -> bool:
    """
    Legacy helper kept for compatibility.
    IMPORTANT: must not call docker directly; runtime owns execution.
    """
    rt = get_runtime()
    return rt.is_running_id(container_name)

class Runtime:
    """
    Runtime abstraction stub.

    v1: container-only
    future: vm runtime can be added behind this interface without changing command logic.
    """

    def node_id(self, lab: str, node: str) -> str:
        raise NotImplementedError

    def exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        raise NotImplementedError
    
    def copy_from_node(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        """
        Copy a file FROM a node/container to the host filesystem (dst_path).

        Evidence-only helper (e.g. PCAP). Must be deterministic and non-interactive.
        """
        raise NotImplementedError

    def sh(
        self,
        lab: str,
        node: str,
        script: str,
        *,
        check: bool = False,
        capture_output: bool = True,   # <-- match exec default
    ) -> subprocess.CompletedProcess:
        return self.exec(
            lab,
            node,
            ["sh", "-lc", script],
            check=check,
            capture_output=capture_output,
        )

    def is_running(self, lab: str, node: str) -> bool:
        raise NotImplementedError
    
    def restart_node(self, lab: str, node: str) -> subprocess.CompletedProcess:
        """
        Deterministic runtime-owned restart primitive.
        Must not leak docker/containerlab calls outside Runtime.
        """
        raise NotImplementedError
    
    def container_id(self, lab: str, node: str) -> str:
        """
        Deterministically return the runtime-specific immutable identity for the node instance.

        ContainerRuntime: docker container ID (full ID string).
        VMRuntime (future): VM UUID, etc.
        """
        raise NotImplementedError

    def copy_to_node(self, lab: str, node: str, src: Path, dst: str) -> subprocess.CompletedProcess:
        """
        Deterministically copy a host file into the node instance.

        ContainerRuntime: implemented via `docker cp` (runtime-owned).
        """
        raise NotImplementedError

    def is_running_id(self, node_id: str) -> bool:
        """
        Return True if the runtime instance identified by node_id exists and is running.

        ContainerRuntime: node_id is a docker container name like "clab-<lab>-<node>"
        VMRuntime (future): node_id could be VM name/uuid, etc.
        """
        raise NotImplementedError
    
    def exists_id(self, node_id: str) -> bool:
        """
        Return True if the runtime instance identified by node_id exists (running or not).

        ContainerRuntime: implemented via container runtime inspect return code.
        VMRuntime (future): VM exists check.
        """
        raise NotImplementedError

class ContainerRuntime(Runtime):
    def node_id(self, lab: str, node: str) -> str:
        return f"clab-{lab}-{node}"
    
    def exists_id(self, node_id: str) -> bool:
        cp = run(["docker", "inspect", node_id], check=False, capture_output=True)
        return cp.returncode == 0

    def restart_node(self, lab: str, node: str) -> subprocess.CompletedProcess:
        """
        Runtime-owned node restart.
        v1 runtime uses docker; callers must not invoke docker directly.
        """
        c = self.node_id(lab, node)
        return run(["docker", "restart", c], check=False, capture_output=True)
    
    def container_id(self, lab: str, node: str) -> str:
        c = self.node_id(lab, node)
        cp = run(["docker", "inspect", "-f", "{{.Id}}", c], check=False, capture_output=True)
        if cp.returncode != 0:
            # Keep message deterministic and safe
            die(f"runtime.container_id failed for node {node} (container={c})", code=cp.returncode)
        return (cp.stdout or "").strip()

    def copy_to_node(self, lab: str, node: str, src: Path, dst: str) -> subprocess.CompletedProcess:
        c = self.node_id(lab, node)
        # docker cp syntax: SRC_PATH CONTAINER:DEST_PATH
        return run(["docker", "cp", str(src), f"{c}:{dst}"], check=False, capture_output=True)

    def exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        c = self.node_id(lab, node)

        argv: list[str] = ["docker", "exec"]
        if interactive:
            # interactive calls should not capture output (TTY behavior)
            argv += ["-it"]
            argv += [c, *cmd]
            # Ignore timeout for interactive exec (TTY semantics)
            return run(argv, check=check, capture_output=False, timeout_s=None)

        argv += [c, *cmd]

        # Non-interactive calls: capture output by default so helpers can parse stdout
        return run(argv, check=check, capture_output=capture_output, timeout_s=timeout_s)
    
    def copy_from_node(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        if not isinstance(src_path, str) or not src_path.strip():
            die("copy_from_node: src_path must be a non-empty string")
        if not isinstance(dst_path, str) or not dst_path.strip():
            die("copy_from_node: dst_path must be a non-empty string")

        # dst_path is a host path; ensure parent exists deterministically
        Path(dst_path).parent.mkdir(parents=True, exist_ok=True)

        # containerlab names containers as: clab-<lab>-<node>
        cname = f"clab-{lab}-{node}"

        # docker cp <container>:<src> <dst>
        cp = run(
            ["docker", "cp", f"{cname}:{src_path}", dst_path],
            check=check,
            capture_output=True,
            text=True,
        )
        return cp

    def is_running(self, lab: str, node: str) -> bool:
        return self.is_running_id(self.node_id(lab, node))

    def is_running_id(self, node_id: str) -> bool:
        cp = run(["docker", "inspect", "-f", "{{.State.Running}}", node_id], check=False, capture_output=True)
        if cp.returncode != 0:
            return False

        out = cp.stdout
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        return (out or "").strip() == "true"


class VmRuntimeStub(Runtime):
    def __init__(self) -> None:
        self._msg = "VM runtime not implemented yet (Phase-1 stub). Use container runtime."

    def node_id(self, lab: str, node: str) -> str:
        die(self._msg)
        raise RuntimeError(self._msg)

    def exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
    ) -> subprocess.CompletedProcess:
        die(self._msg)
        raise RuntimeError(self._msg)

    def is_running(self, lab: str, node: str) -> bool:
        die(self._msg)
        return False

    def is_running_id(self, node_id: str) -> bool:
        die(self._msg)
        return False
    
    def exists_id(self, node_id: str) -> bool:
        die(self._msg)
        return False

def get_runtime(topo: dict[str, Any] | None = None) -> Runtime:
    """
    Decide runtime. For now:
      - default: container
      - allow future extension: topo['runtime'] or node['runtime'] (not required yet)
    """
    return ContainerRuntime()

def list_owned_labs_from_artifacts() -> list[tuple[str, Path]]:
    """
    Ownership source of truth (LOCKED):
      - ONLY labs with artifact directories under labs/clab-*
      - Never scan Docker globally
      - Deterministic ordering (lexicographic by directory name)
    Returns: [(lab_name, artifact_dir), ...]
    """
    if not LABS_DIR.exists():
        return []

    out: list[tuple[str, Path]] = []
    for p in LABS_DIR.iterdir():
        if not p.is_dir():
            continue
        if not p.name.startswith("clab-"):
            continue
        lab = p.name[len("clab-") :].strip()
        if not lab:
            continue
        out.append((lab, p))

    out.sort(key=lambda t: t[1].name)
    return out

def list_owned_labs_from_generated_files() -> list[str]:
    """
    Ownership marker (generated files, deterministic):
      - labs/<lab>.clab.yaml (or .clab.yml) created by netsim gen/up
      - Never scans Docker globally
      - Deterministic ordering (lexicographic by lab name)

    Returns: ["lab1", "lab2", ...]
    """
    if not LABS_DIR.exists():
        return []

    out: list[str] = []
    for p in LABS_DIR.iterdir():
        if not p.is_file():
            continue
        if p.suffix not in (".yaml", ".yml"):
            continue

        name = p.name
        if not name.endswith(".clab.yaml") and not name.endswith(".clab.yml"):
            continue

        lab = name.split(".clab.", 1)[0].strip()
        if not lab:
            continue

        out.append(lab)

    return sorted(set(out))


