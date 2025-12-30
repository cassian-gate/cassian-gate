#!/usr/bin/env python3
"""
ai-netsim execution engine

Design contract (must not be violated):
- Deterministic lifecycle (resolve → generate → deploy → provision → test → collect → destroy)
- Inputs are authoritative: topologies/
- Outputs are generated: labs/ (including *.clab.yaml, topology.resolved.yaml, results.json)
- Defaults only during resolve and visible in resolved topology
- Negative tests are first-class (expected fail + observed fail = verdict pass)

See: docs/design-contract.md
"""
import argparse
import subprocess
import sys
import time
import shutil

from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
TOPO_DIR = BASE_DIR / "topologies"
LABS_DIR = BASE_DIR / "labs"

DEFAULT_IMAGES = {
    "frr": "frrouting/frr:latest",
    "linux": "alpine:latest",
    "host": "alpine:latest",
    "nft-fw": "alpine:latest",
}

# -------------------------
# Shell helpers
# -------------------------

def run(
    cmd: list[str],
    check: bool = True,
    capture: bool = False,
    capture_output: bool | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run a command deterministically.
    - capture=True is the legacy flag (captures stdout/stderr)
    - capture_output overrides capture if explicitly set
    """
    print("+", " ".join(cmd))

    if capture_output is None:
        capture_output = capture

    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
    )

def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)

def ensure_nc(lab: str, node: str) -> None:
    c = container_name(lab, node)
    cp = run(
        ["docker", "exec", c, "sh", "-lc", "command -v nc >/dev/null"],
        check=False,
    )
    if cp.returncode != 0:
        die(f"{node}: nc not found. Use wbitt/network-multitool for host/nft-fw nodes.")

def ip_no_mask(cidr: str) -> str:
    return cidr.split("/", 1)[0].strip()


def find_nodes_by_type(topo: dict, ntype: str) -> list[dict]:
    return [n for n in topo.get("nodes", []) if n.get("type") == ntype]

def start_tcp_listener(lab: str, node: str, port: int) -> None:
    """
    Start a TCP listener inside a container using netcat (nc).

    Requirements:
    - nc must already exist (we do NOT install packages at runtime)
    - Must not fail if nothing is running yet
    - Must not fail if pkill exits non-zero
    """
    ensure_nc(lab, node)

    c = container_name(lab, node)

    # Kill any previous listener on that port (never fail)
    run(
        ["docker", "exec", c, "sh", "-lc", f'pkill -f "nc.*-p {port}" 2>/dev/null || true'],
        check=False,
    )

    # Start listener in background
    run(
        ["docker", "exec", c, "sh", "-lc", f"nohup nc -lk -p {port} >/dev/null 2>&1 &"],
        check=False,
    )

def stop_tcp_listeners(lab: str, node: str) -> None:
    """
    Stop any nc listeners we started. Never fail the test.
    """
    c = container_name(lab, node)
    run(["docker", "exec", c, "sh", "-lc", "pkill -f \"nc.*-p\" 2>/dev/null || true"], check=False)

def tcp_connect_test(lab: str, src_host: str, dst_ip: str, port: int, should_succeed: bool) -> None:
    c = container_name(lab, src_host)

    # 'nc -z' = zero-I/O connect test
    cp = run(
        ["docker", "exec", c, "sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
        check=False,
    )

    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"TCP connect should have succeeded but failed: {src_host} -> {dst_ip}:{port}")
    if (not should_succeed) and ok:
        die(f"TCP connect should have failed but succeeded: {src_host} -> {dst_ip}:{port}")

def node_first_ipv4(topo: dict, node_name: str) -> str:
    """
    Return the first IPv4 address (no prefix) found for node_name from topo['links'].
    Assumes link entries have explicit 'ipv4' with same ordering as 'endpoints'.
    """
    for link in topo.get("links", []) or []:
        eps = link.get("endpoints", []) or []
        ips = link.get("ipv4", []) or []
        if len(eps) != 2 or len(ips) != 2:
            continue

        nA = eps[0].split(":", 1)[0]
        nB = eps[1].split(":", 1)[0]

        if nA == node_name:
            return ips[0].split("/")[0]
        if nB == node_name:
            return ips[1].split("/")[0]

    die(f"Could not determine IPv4 for node '{node_name}' from topology links")


def run_ping_test(lab: str, src: str, dst_ip: str, count: int, should_succeed: bool) -> None:
    cp = run(
        ["docker", "exec", container_name(lab, src), "ping", "-c", str(count), dst_ip],
        check=False,
    )
    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"PING FAIL (expected PASS): {src} -> {dst_ip}")
    if (not should_succeed) and ok:
        die(f"PING FAIL (expected DROP): {src} -> {dst_ip}")


def run_tcp_test(lab: str, src: str, dst_ip: str, port: int, should_succeed: bool) -> None:
    # nc -z checks connect() only
    cp = run(
        ["docker", "exec", container_name(lab, src), "sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
        check=False,
    )
    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"TCP FAIL (expected PASS): {src} -> {dst_ip}:{port}")
    if (not should_succeed) and ok:
        die(f"TCP FAIL (expected DROP): {src} -> {dst_ip}:{port}")


def run_declared_tests(lab: str, topo: dict) -> None:
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
            dst_ip = t.get("dst_ip")
            if not dst_ip:
                if isinstance(dst, str) and any(n.get("name") == dst for n in topo.get("nodes", [])):
                    dst_ip = node_first_ipv4(topo, dst)
                else:
                    dst_ip = dst  # treat as raw IP string

            expect = (t.get("expect") or "pass").lower()
            should_succeed = (expect in ("pass", "allow", "ok", "true"))

            if ttype == "ping":
                count = int(t.get("count") or 2)
                run_ping_test(lab, src, dst_ip, count=count, should_succeed=should_succeed)

            elif ttype == "tcp":
                port = int(t.get("port"))
                if t.get("listener"):
                    # start listener on the *dst node* (must be a node name)
                    if not isinstance(dst, str) or not any(n.get("name") == dst for n in topo.get("nodes", [])):
                        die(f"{tname}: listener=true requires dst to be a node name, got '{dst}'")
                    start_tcp_listener(lab, dst, port)
                    listeners_started.append((dst, port))

                run_tcp_test(lab, src, dst_ip, port=port, should_succeed=should_succeed)

            else:
                die(f"Unknown test type '{ttype}' in test '{tname}'")

    finally:
        # clean up listeners we started
        for (node, _port) in listeners_started:
            # easiest: stop all nc listeners on node
            stop_tcp_listeners(lab, node)

    print(f"✅ Declared tests PASS ({len(tests)} checks)")

# -------------------------
# YAML + validation
# -------------------------

def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        die(f"Empty YAML file: {path}")
    return data

def ensure_valid_topology(topo: dict) -> None:
    if not isinstance(topo, dict):
        die("Topology YAML must be a mapping.")
    for k in ("name", "nodes", "links"):
        if k not in topo:
            die(f"Missing required key: '{k}'")

    if not isinstance(topo["nodes"], list) or not topo["nodes"]:
        die("'nodes' must be a non-empty list.")
    if not isinstance(topo["links"], list):
        die("'links' must be a list.")

    names = set()
    for n in topo["nodes"]:
        if "name" not in n or "type" not in n:
            die("Each node must have 'name' and 'type'.")
        if n["name"] in names:
            die(f"Duplicate node name: {n['name']}")
        names.add(n["name"])

    for i, link in enumerate(topo["links"], start=1):
        eps = link.get("endpoints")
        if not isinstance(eps, list) or len(eps) != 2:
            die(f"Link #{i} must have exactly 2 endpoints.")
        for ep in eps:
            if not isinstance(ep, str) or ":" not in ep:
                die(f"Invalid endpoint '{ep}' in link #{i}. Use 'node:iface'.")
            node, _iface = ep.split(":", 1)
            if node not in names:
                die(f"Endpoint references unknown node '{node}' in link #{i}.")

# -------------------------
# Paths for generated lab artifacts
# -------------------------

def lab_dir(lab_name: str) -> Path:
    return LABS_DIR / f"clab-{lab_name}"

def node_cfg_dir(lab_name: str, node: str) -> Path:
    return lab_dir(lab_name) / "nodes" / node

def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous run created a directory where we expect a file, fix it.
    if path.exists() and path.is_dir():
        shutil.rmtree(path)

    path.write_text(content, encoding="utf-8")

# -------------------------
# FRR config generation (simple v1)
# -------------------------

def gen_frr_daemons() -> str:
    return """zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
"""

def gen_vtysh_conf() -> str:
    # removes "Can't open /etc/frr/vtysh.conf"
    return "service integrated-vtysh-config\n"

def build_node_links(topo: dict) -> dict:
    """
    Build per-node link info from topo['links'].

    Returns:
      {
        "r1": [
          {"iface": "eth1", "peer": "r2", "ip": "10.0.0.0/31", "peer_ip": "10.0.0.1"},
          ...
        ],
        ...
      }
    """
    links_by_node: dict[str, list[dict]] = {}

    for link in topo.get("links", []):
        eps = link.get("endpoints", [])
        ips = link.get("ipv4", [])
        if len(eps) != 2 or len(ips) != 2:
            die("Each link must have exactly 2 endpoints and 2 IPv4 addresses")

        (n1, if1) = eps[0].split(":", 1)
        (n2, if2) = eps[1].split(":", 1)
        ip1, ip2 = ips[0], ips[1]

        links_by_node.setdefault(n1, []).append({
            "iface": if1,
            "peer": n2,
            "ip": ip1,
            "peer_ip": ip2.split("/")[0],
        })
        links_by_node.setdefault(n2, []).append({
            "iface": if2,
            "peer": n1,
            "ip": ip2,
            "peer_ip": ip1.split("/")[0],
        })

    return links_by_node

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

def gen_frr_conf(node: dict, topo: dict) -> str:
    """
    Generate FRR integrated config.

    - Configures interfaces based on topo links (only for this node)
    - Builds eBGP neighbors ONLY to peers that have an ASN (i.e. other FRR nodes)
    - Advertises loopback /32
    - Adds optional node["static_routes"] into config so they exist at boot
      (important because /etc/frr/frr.conf is bind-mounted read-only)
    """
    name = node["name"]
    asn = int(node["asn"])
    rid = node.get("router_id")
    if not rid:
        die(f"FRR node '{name}' missing router_id")

    # quick lookup: node_name -> node_dict
    nodes_by_name = {n["name"]: n for n in topo.get("nodes", [])}

    # Build node link list from topology
    links_by_node = build_node_links(topo)
    node_links = links_by_node.get(name, [])

    cfg: list[str] = []
    cfg.append("frr version 8")
    cfg.append("frr defaults traditional")
    cfg.append(f"hostname {name}")
    cfg.append("no ipv6 forwarding")
    cfg.append("service integrated-vtysh-config")
    cfg.append("!")

    # Loopback / router-id
    cfg.append("interface lo")
    cfg.append(f" ip address {rid}/32")
    cfg.append("!")

    # Interfaces from topology endpoints (only this node's endpoints)
    for l in node_links:
        cfg.append(f"interface {l['iface']}")
        cfg.append(f" ip address {l['ip']}")
        cfg.append("!")

    # Static routes (optional) - rendered into config at boot.
    # Accepts strings like:
    #   static_routes:
    #     - "192.168.1.0/24 via 10.0.0.0"
    for r in node.get("static_routes", []) or []:
        if not isinstance(r, str) or " via " not in r:
            die(f"{name}: static_routes must be strings like 'PREFIX via NEXT_HOP'")

        prefix, nh = r.split(" via ", 1)
        cfg.append(f"ip route {prefix.strip()} {nh.strip()}")

    if node.get("static_routes"):
        cfg.append("!")

    # BGP
    cfg.append(f"router bgp {asn}")
    cfg.append(f" bgp router-id {rid}")
    cfg.append(" no bgp ebgp-requires-policy")

    # Add BGP neighbors ONLY for directly-connected peers that have an ASN
    for l in node_links:
        peer_name = l["peer"]
        peer = nodes_by_name.get(peer_name)

        # If peer is not an FRR/BGP node (e.g. host or nft-fw), skip
        if not peer or "asn" not in peer:
            continue

        peer_asn = int(peer["asn"])
        cfg.append(f" neighbor {l['peer_ip']} remote-as {peer_asn}")

    cfg.append(" !")
    cfg.append(" address-family ipv4 unicast")
    cfg.append(f"  network {rid}/32")

    for l in node_links:
        peer_name = l["peer"]
        peer = nodes_by_name.get(peer_name)
        if not peer or "asn" not in peer:
            continue
        cfg.append(f"  neighbor {l['peer_ip']} activate")

    cfg.append(" exit-address-family")
    cfg.append("!")
    cfg.append("line vty")
    cfg.append("!")
    return "\n".join(cfg) + "\n"

# -------------------------
# Topology -> containerlab
# -------------------------

def topo_to_containerlab(topo: dict) -> dict:
    clab = {
        "name": topo["name"],
        "topology": {"nodes": {}, "links": []},
    }

    for n in topo["nodes"]:
        ntype = n["type"]
        image = n.get("image") or DEFAULT_IMAGES.get(ntype)
        if not image:
            die(f"No default image for node type '{ntype}'. Set node.image explicitly.")

        binds = []
        if ntype == "frr":
            cfgdir = node_cfg_dir(topo["name"], n["name"])
            write_file(cfgdir / "daemons", gen_frr_daemons())
            write_file(cfgdir / "vtysh.conf", gen_vtysh_conf())
            write_file(cfgdir / "frr.conf", gen_frr_conf(n, topo))

            binds = [
                f"{cfgdir}/daemons:/etc/frr/daemons:ro",
                f"{cfgdir}/vtysh.conf:/etc/frr/vtysh.conf:ro",
                f"{cfgdir}/frr.conf:/etc/frr/frr.conf:ro",
            ]

        node_def = {"kind": "linux"}

        t = n.get("type")

        if t == "host":
            node_def["image"] = "wbitt/network-multitool:latest"
        elif t == "nft-fw":
            node_def["image"] = "netsim/nft-fw:latest"
        elif t == "frr":
            node_def["image"] = "frrouting/frr:latest"
        else:
            node_def["image"] = n.get("image") or "alpine:latest"

        # Hosts should stay alive (alpine has no long-running process by default)
        if ntype == "host":
            node_def["cmd"] = "sleep infinity"

        # nft-fw should stay alive and forward
        if ntype == "nft-fw":
            node_def["cmd"] = "sleep infinity"
            node_def["sysctls"] = {
                "net.ipv4.ip_forward": "1",
                "net.ipv4.conf.all.rp_filter": "0",
                "net.ipv4.conf.default.rp_filter": "0",

                # Let bridged IPv4/IPv6 traffic hit the inet forward hook (iptables/nft)
                "net.bridge.bridge-nf-call-iptables": "1",
            "net.bridge.bridge-nf-call-ip6tables": "1",
            }

        # FRR nodes should behave like routers (kernel forwarding + no rp_filter drops)
        if ntype == "frr":
            node_def["sysctls"] = {
                "net.ipv4.ip_forward": "1",
                "net.ipv4.conf.all.rp_filter": "0",
                "net.ipv4.conf.default.rp_filter": "0",
            }

        if binds:
            node_def["binds"] = binds

        clab["topology"]["nodes"][n["name"]] = node_def

    for link in topo["links"]:
        clab["topology"]["links"].append({"endpoints": link["endpoints"]})

    return clab

def resolve_topology(topo: dict) -> dict:
    """
    Return a copy of topo with missing link IPv4 addresses allocated.
    For now: allocate /31s sequentially from 10.0.0.0/16 in link order.

    Also normalizes schema for resolved output:
    - tests[].kind is canonical
    - accept legacy tests[].type, rewriting it to kind
    - fail fast if both kind and type are present in a test
    """
    resolved = yaml.safe_load(yaml.safe_dump(topo))  # simple deep copy

    # ----------------------------
    # 1) Auto-address point-to-point links (10.0.0.0/16, sequential /31s)
    # ----------------------------
    next_host = 0  # host index inside 10.0.0.0/16
    for link in resolved.get("links", []):
        if "ipv4" in link and link["ipv4"]:
            continue  # user already specified

        eps = link["endpoints"]
        if len(eps) != 2:
            die("Auto-IP currently supports only point-to-point links with 2 endpoints")

        # Allocate a /31: two addresses
        a = next_host
        b = next_host + 1
        next_host += 2

        def ip(n: int) -> str:
            # 10.0.(n//256).(n%256)
            return f"10.0.{n//256}.{n%256}"

        link["ipv4"] = [f"{ip(a)}/31", f"{ip(b)}/31"]

    # ----------------------------
    # 2) Normalize tests schema (v1)
    #    - 'kind' is canonical for tests
    #    - accept legacy 'type' but rewrite to 'kind'
    #    - fail fast if both are present
    # ----------------------------
    tests = resolved.get("tests", []) or []
    for idx, t in enumerate(tests):
        i = idx + 1

        if not isinstance(t, dict):
            die(f"tests[{i}]: must be a dict")

        if "kind" in t and "type" in t:
            die(f"tests[{i}]: has both 'kind' and 'type' (use only 'kind')")

        if "type" in t and "kind" not in t:
            t["kind"] = t.pop("type")

    return resolved


def write_containerlab_file(topo_path: Path) -> Path:
    topo = load_yaml(topo_path)
    ensure_valid_topology(topo)

    resolved = resolve_topology(topo)

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

import re

_RE_NEIGH_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+")

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


def wait_for_bgp(lab: str, node: str, timeout: int = 30) -> None:
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
    start = time.time()
    last_summary = ""
    last_neigh_lines: list[str] = []

    def parse_state_pfxrcd(neigh_line: str) -> str:
        parts = neigh_line.split()
        # parts[9] is State/PfxRcd in typical FRR output
        return parts[9] if len(parts) >= 10 else ""

    while True:
        cp = vty(lab, node, "show bgp summary")
        last_summary = cp.stdout or ""
        out = last_summary

        neigh_lines = [ln.strip() for ln in out.splitlines() if ln.strip() and ln.strip()[0].isdigit()]
        last_neigh_lines = neigh_lines

        # If we expect BGP and we have no neighbor lines yet, keep waiting
        if neigh_lines:
            if "(Policy)" in out:
                # still not acceptable
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

def container_name(lab_name: str, node: str) -> str:
    return f"clab-{lab_name}-{node}"

def _node_index_by_name(topo: dict[str, Any]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for n in topo.get("nodes", []) or []:
        name = n.get("name")
        if isinstance(name, str) and name:
            idx[name] = n
    return idx


def configure_frr_interfaces_from_topology(lab: str, topo: dict[str, Any]) -> None:
    """
    For each link with ipv4 addressing, assign the per-endpoint IP to the correct interface,
    BUT only for endpoints that are FRR nodes.

    Also configures loopback with router_id/32 if present.
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

            cname = f"clab-{lab}-{node}"

            # bring up + set address
            run(["docker", "exec", cname, "ip", "link", "set", iface, "up"], check=False)
            run(["docker", "exec", cname, "ip", "addr", "flush", "dev", iface], check=False)
            run(["docker", "exec", cname, "ip", "addr", "add", ipcidr, "dev", iface], check=True)

    # 2) Router-id loopback (router_id/32) if provided
    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue
        rid = n.get("router_id")
        if not (isinstance(rid, str) and rid):
            continue

        cname = f"clab-{lab}-{node}"
        run(["docker", "exec", cname, "ip", "link", "set", "lo", "up"], check=False)
        # Keep it simple: flush + set router_id/32
        run(["docker", "exec", cname, "ip", "addr", "flush", "dev", "lo"], check=False)
        run(["docker", "exec", cname, "ip", "addr", "add", f"{rid}/32", "dev", "lo"], check=True)


def configure_frr_static_routes_from_topology(lab: str, topo: dict[str, Any]) -> None:
    """
    Apply node-level static_routes entries like:
      - 192.168.2.0/24 via 10.0.0.1
    """
    nodes = _node_index_by_name(topo)

    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue
        routes = n.get("static_routes") or []
        if not isinstance(routes, list):
            continue

        cname = f"clab-{lab}-{node}"
        for r in routes:
            if not isinstance(r, str):
                continue
            # Expect "PREFIX via NEXTHOP"
            # We'll just pass it directly to ip route replace
            run(["docker", "exec", cname, "sh", "-lc", f"ip route replace {r}"], check=False)


def configure_frr_bgp_from_topology(lab: str, topo: dict[str, Any]) -> None:
    """
    Minimal BGP neighbor provisioning:
    - For each link between TWO FRR nodes with ipv4 /31 or /30 addressing:
      configure them as neighbors (remote-as from topo nodes' asn).
    - Configure router-id if present.
    - Allow eBGP without policy (MVP) so later advertisements work.
    """
    nodes = _node_index_by_name(topo)

    # Build a list of FRR-FRR adjacencies from links
    adj: list[tuple[str, str, str, str]] = []
    # (nodeA, ipA, nodeB, ipB)

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

        # neighbor IPs: strip CIDR
        nbr1 = ip2.split("/", 1)[0]
        nbr2 = ip1.split("/", 1)[0]
        adj.append((n1, nbr1, n2, nbr2))

    # Apply config per node
    for node, n in nodes.items():
        if n.get("type") != "frr":
            continue

        asn = n.get("asn")
        rid = n.get("router_id")
        if not isinstance(asn, int):
            # if your YAML stores as strings, support that too
            if isinstance(asn, str) and asn.isdigit():
                asn = int(asn)
            else:
                continue

        cname = f"clab-{lab}-{node}"

        # Start BGP process
        cmds: list[str] = []
        cmds.append("conf t")
        cmds.append(f"router bgp {asn}")
        if isinstance(rid, str) and rid:
            cmds.append(f"bgp router-id {rid}")

        # MVP friendliness: don't require policy for eBGP announcements
        cmds.append("no bgp ebgp-requires-policy")

        # Neighbors from adj list
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

        # Execute via vtysh (one call per node)
        vty_args = ["docker", "exec", cname, "vtysh"]
        for c in cmds:
            vty_args += ["-c", c]
        run(vty_args, check=False)

def configure_hosts_from_topology(lab_name: str, topo: dict) -> None:
    """
    Configure host nodes based on links that include explicit link['ipv4'] entries.
    For a host<->router link, we:
      - set host IP on its interface
      - set host default route via router IP on that same link
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
            host_configure(lab_name, n1, if1, ip1, ip2.split("/")[0])

        # Host on side 2?
        if node_type.get(n2) == "host" and node_type.get(n1) in ("frr", "linux"):
            host_configure(lab_name, n2, if2, ip2, ip1.split("/")[0])


def configure_nftfw_routes_from_topology(lab: str, topo: dict) -> None:
    """
    Configure static routes on nft-fw nodes (Linux) based on topology.

    Supports BOTH formats:

    1) String form (like your FRR static_routes):
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
    """
    for n in topo.get("nodes", []) or []:
        if n.get("type") != "nft-fw":
            continue

        fw_name = n.get("name")
        if not fw_name:
            die("nft-fw node missing 'name'")

        routes = n.get("routes", []) or []
        if not routes:
            continue

        for r in routes:
            prefix = None
            via = None

            # Format A: string "PREFIX via NEXT_HOP"
            if isinstance(r, str):
                if " via " not in r:
                    die(f"{fw_name}: route string must look like 'PREFIX via NEXT_HOP' (got: {r!r})")
                prefix, via = r.split(" via ", 1)
                prefix = prefix.strip()
                via = via.strip()

            # Format B: dict {"prefix": "...", "via": "..."}
            elif isinstance(r, dict):
                prefix = (r.get("prefix") or "").strip()
                via = (r.get("via") or "").strip()
                if not prefix or not via:
                    die(f"{fw_name}: route dict must include 'prefix' and 'via' (got: {r!r})")

            else:
                die(f"{fw_name}: routes entries must be strings or dicts (got: {type(r).__name__})")

            # Apply route
            run(["docker", "exec", container_name(lab, fw_name),
                 "ip", "route", "replace", prefix, "via", via])

def host_configure(lab_name: str, host: str, iface: str, ip_cidr: str, gw: str) -> None:
    """
    Inside host container:
      - flush and set IP on iface
      - bring iface up
      - set default route via gw
    """
    c = container_name(lab_name, host)

    # Ensure interface exists/up
    run(["docker", "exec", c, "ip", "link", "set", iface, "up"], check=False)

    # Replace IP (flush then add)
    run(["docker", "exec", c, "ip", "addr", "flush", "dev", iface], check=False)
    run(["docker", "exec", c, "ip", "addr", "add", ip_cidr, "dev", iface])

    # Default route
    run(["docker", "exec", c, "ip", "route", "replace", "default", "via", gw])

def configure_nftfw_from_topology(lab_name: str, topo: dict) -> None:
    for link in topo.get("links", []):
        eps = link.get("endpoints", [])
        ips = link.get("ipv4", [])
        if len(eps) != 2 or len(ips) != 2:
            continue

        for ep, ip in zip(eps, ips):
            node, iface = ep.split(":", 1)
            if not ip:
                continue
            if node.startswith("fw") or node == "fw1" or any(n.get("name") == node and n.get("type") == "nft-fw" for n in topo.get("nodes", [])):
                c = container_name(lab_name, node)
                run(["docker", "exec", c, "ip", "link", "set", iface, "up"])
                run(["docker", "exec", c, "ip", "addr", "flush", "dev", iface])
                run(["docker", "exec", c, "ip", "addr", "add", ip, "dev", iface])

def nft_fw_apply(lab_name: str, node: str, ruleset: str) -> None:
    c = container_name(lab_name, node)

    # Ensure nft exists (multitool does NOT include it)
    cp = run(["docker", "exec", c, "sh", "-lc", "command -v nft >/dev/null"], check=False)
    if cp.returncode != 0:
        # Try Alpine install (works if the image is Alpine-based)
        run(
            ["docker", "exec", c, "sh", "-lc", "apk add --no-cache nftables >/dev/null 2>&1"],
            check=False,
        )
        # Check again, fail clearly if still missing
        cp2 = run(["docker", "exec", c, "sh", "-lc", "command -v nft >/dev/null"], check=False)
        if cp2.returncode != 0:
            die(f"{node}: nft not found (either use an nftables-capable image, or keep install logic)")

    # Load ruleset
    cmd = (
        "set -e\n"
        "cat > /tmp/rules.nft <<'EOF'\n"
        f"{ruleset}\n"
        "EOF\n"
        "nft -f /tmp/rules.nft\n"
        "nft list ruleset\n"
    )
    run(["docker", "exec", c, "sh", "-lc", cmd])

def verify_fw_routed_ready(lab: str, fw_node: str) -> None:
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
    c = container_name(lab, fw_node)

    # ---------------------------------------------------------------------
    # 1) nft must exist in the image
    # ---------------------------------------------------------------------
    cp = run(
        ["docker", "exec", c, "sh", "-lc", "command -v nft >/dev/null"],
        check=False,
    )
    if cp.returncode != 0:
        die(f"{fw_node}: nft not found (use an image with nftables preinstalled)")

    # ---------------------------------------------------------------------
    # 2) nft must be usable (kernel support + permissions)
    #    This catches cases where nft exists but cannot talk to the kernel.
    # ---------------------------------------------------------------------
    cp = run(
        ["docker", "exec", c, "sh", "-lc", "nft list ruleset >/dev/null 2>&1"],
        check=False,
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        die(f"{fw_node}: nftables ruleset not accessible")

    # ---------------------------------------------------------------------
    # 3) IPv4 forwarding must be enabled (routed firewall)
    # ---------------------------------------------------------------------
    cp = run(
        ["docker", "exec", c, "sh", "-lc", "sysctl -n net.ipv4.ip_forward"],
        check=False,
        capture_output=True,
        text=True,
    )
    val = (cp.stdout or "").strip()
    if val != "1":
        die(f"{fw_node}: ip_forward is not enabled (got '{val}')")

def verify_host_ready(lab: str, host: str) -> None:
    """
    Host readiness gate (v1).

    We consider a host "ready" if:
      - `ip` exists
      - it has at least one global IPv4 address configured on a non-lo interface

    IMPORTANT:
    - Do not rely on awk/busybox differences across images.
    - Use `ip -4 -o addr show` which is consistent.
    """
    c = container_name(lab, host)

    # ip command should exist
    cp = run(["docker", "exec", c, "sh", "-lc", "command -v ip >/dev/null"], check=False)
    if cp.returncode != 0:
        die(f"{host}: 'ip' not found")

    # must have at least one global IPv4 (excluding lo)
    # Example output:
    #   7: eth1    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth1
    cp = run(
        ["docker", "exec", c, "sh", "-lc", "ip -4 -o addr show scope global | grep -q 'inet '"],
        check=False,
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        # Helpful debug output
        dbg = run(
            ["docker", "exec", c, "sh", "-lc", "ip -br addr; echo '---'; ip -4 -o addr show scope global || true"],
            check=False,
            capture_output=True,
            text=True,
        )
        die(f"{host}: no global IPv4 configured (host not ready)\n{(dbg.stdout or '').strip()}")

def verify_frr_ready(lab: str, rtr: str) -> None:
    c = container_name(lab, rtr)

    # vtysh must work
    cp = run(
        ["docker", "exec", c, "vtysh", "-c", "show version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        die(f"{rtr}: vtysh not ready")


def verify_lab_ready(topo: dict, lab: str) -> None:
    nodes = topo.get("nodes", []) or []
    for n in nodes:
        name = n.get("name")
        t = n.get("type")

        if not name or not t:
            die("Node missing 'name' or 'type' in topology")

        if t == "host":
            verify_host_ready(lab, name)
        elif t == "nft-fw":
            verify_fw_routed_ready(lab, name)
        elif t == "frr":
            verify_frr_ready(lab, name)

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

def nft_fw_setup_bridge(lab_name: str, node: str) -> None:
    c = container_name(lab_name, node)

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
    run(["docker", "exec", c, "sh", "-lc", cmd])

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
    cp = run(["docker", "inspect", "-f", "{{.State.Running}}", container], check=False, capture=True)
    return cp.returncode == 0 and cp.stdout.strip() == "true"

def vty(lab: str, node: str, cmd: str) -> subprocess.CompletedProcess:
    c = container_name(lab, node)
    return run(["docker", "exec", c, "vtysh", "-c", cmd], check=False, capture=True)

def topo_path_for_lab(lab_name: str) -> Path:
    p_resolved = lab_dir(lab_name) / "topology.resolved.yaml"
    if p_resolved.exists():
        return p_resolved

    p1 = lab_dir(lab_name) / "topology.yaml"
    if p1.exists():
        return p1

    return TOPO_DIR / f"{lab_name}.yaml"

def nodes_by_type(topo: dict, ntype: str) -> list[str]:
    return [n["name"] for n in topo.get("nodes", []) if n.get("type") == ntype]

def ensure_ip_tools(lab: str, node: str) -> None:
    c = container_name(lab, node)
    # If 'ip' exists and supports iproute2-ish output, we're good.
    cp = run(["docker", "exec", c, "sh", "-lc", "command -v ip >/dev/null"], check=False)
    if cp.returncode == 0:
        return

    # Fallback: try install iproute2 (only works on Alpine/Debian-like with package manager)
    run(["docker", "exec", c, "sh", "-lc", "apk add --no-cache iproute2 >/dev/null || true"], check=False)

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
    Return True if the given container exists and is running.
    Uses docker inspect and captures output (no noisy stdout).
    """
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            text=True,
        )
        return out.strip().lower() == "true"
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        # docker binary missing
        return False


# -------------------------
# Commands
# -------------------------

def cmd_test(args: argparse.Namespace) -> None:
    import json
    import time

    lab = args.lab
    filter_name: str | None = getattr(args, "name", None)
    filter_kind: str | None = getattr(args, "kind", None)
    keep_going: bool = bool(getattr(args, "keep_going", False))
    print_json: bool = bool(getattr(args, "json", False))

    started_at = time.time()

    # =============================================================================
    # 0) Load & validate the resolved topology that created this lab
    # =============================================================================
    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    nodes = topo.get("nodes", []) or []
    nodes_by_name = {n["name"]: n for n in nodes}

    # Results artifact (written at end, even on failure if possible)
    results: dict = {
        "schema_version": "1",
        "lab": lab,
        "result": "unknown",
        "summary": {
            "started_at": started_at,
            "finished_at": None,
            "duration_ms": None,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "filtered_by_name": filter_name or "",
            "filtered_by_kind": filter_kind or "",
            # Helps you debug “why didn’t my topology edit apply?”
            "resolved_topology_path": str(tpath),
            "resolved_topology_mtime": tpath.stat().st_mtime,
        },
        "tests": [],  # list of per-test records
    }

    def record_test(
        *,
        name: str,
        kind: str,
        src: str,
        dst: str,
        expected: str,
        observed: str,
        verdict: str,
        duration_ms: int,
        error: str = "",
        meta: dict | None = None,
    ) -> None:
        rec = {
            "name": name,
            "kind": kind,
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": duration_ms,
            "error": error,
        }
        if meta:
            rec["meta"] = meta
        results["tests"].append(rec)

    def write_results() -> None:
        out = lab_dir(lab) / "results.json"
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote: {out}")
        if print_json:
            print(json.dumps(results, indent=2))

    def retry_until(timeout_s: int, interval_s: float, fn) -> tuple[bool, object, int]:
        """
        Run fn() repeatedly until it returns (True, value) or timeout.
        fn must return: (ok: bool, value: any)
        Returns: (ok, last_value, attempts)
        """
        start = time.time()
        attempts = 0
        last_val: object = None
        while True:
            attempts += 1
            ok, val = fn()
            last_val = val
            if ok:
                return True, last_val, attempts
            if time.time() - start >= timeout_s:
                return False, last_val, attempts
            time.sleep(interval_s)

    def fail_or_continue(msg: str) -> None:
        if keep_going:
            print(f"ERROR: {msg}")
            return
        # fail-fast default (results will still be written by finally where possible)
        die(msg)

    # =============================================================================
    # 1) Verify all containers are running (hard prerequisite for everything else)
    # =============================================================================
    for n in nodes:
        name = n["name"]
        c = container_name(lab, name)
        if not docker_is_running(c):
            # We can write results deterministically here and exit
            record_test(
                name="prereq:container-running",
                kind="prereq",
                src="",
                dst=name,
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error=f"{c} is not running",
            )
            results["result"] = "fail"
            results["summary"]["finished_at"] = time.time()
            results["summary"]["duration_ms"] = int((results["summary"]["finished_at"] - started_at) * 1000)
            results["summary"]["total"] = len(results["tests"])
            results["summary"]["passed"] = 0
            results["summary"]["failed"] = len(results["tests"])
            write_results()
            die(f"{c} is not running")

    # =============================================================================
    # 2) Node readiness gate (no control-plane assumptions yet)
    # =============================================================================
    try:
        verify_lab_ready(topo, lab)
    except SystemExit:
        results["result"] = "fail"
        results["summary"]["finished_at"] = time.time()
        results["summary"]["duration_ms"] = int((results["summary"]["finished_at"] - started_at) * 1000)
        write_results()
        raise

    # =============================================================================
    # 3) Optional control-plane checks (FRR/BGP)
    # =============================================================================
    frr_nodes = [n for n in nodes if n.get("type") == "frr"]
    links_by_node = build_node_links(topo)

    def expected_bgp_peers(node_name: str) -> list[dict]:
        out: list[dict] = []
        for l in links_by_node.get(node_name, []) or []:
            peer_name = l.get("peer")
            peer = nodes_by_name.get(peer_name)
            if peer and peer.get("type") == "frr" and "asn" in peer:
                out.append(l)
        return out

    bgp_participants: list[dict] = []
    for n in frr_nodes:
        if expected_bgp_peers(n["name"]):
            bgp_participants.append(n)

    if bgp_participants:
        try:
            for n in bgp_participants:
                wait_for_bgp(lab, n["name"], timeout=30)
        except SystemExit:
            results["result"] = "fail"
            results["summary"]["finished_at"] = time.time()
            results["summary"]["duration_ms"] = int((results["summary"]["finished_at"] - started_at) * 1000)
            write_results()
            raise

    # =============================================================================
    # 4) Declared dataplane / policy tests (ping/tcp)
    # =============================================================================
    tests = topo.get("tests", []) or []
    if not tests:
        results["result"] = "pass"
        results["summary"]["finished_at"] = time.time()
        results["summary"]["duration_ms"] = int((results["summary"]["finished_at"] - started_at) * 1000)
        results["summary"]["total"] = 0
        results["summary"]["passed"] = 0
        results["summary"]["failed"] = 0
        write_results()
        print("✅ TEST PASS: containers running" + (" + BGP OK" if bgp_participants else ""))
        return

    def node_ip_or_die(node_name: str) -> str:
        ip = node_first_ipv4(topo, node_name)
        if not ip:
            die(f"TEST FAIL: could not determine IPv4 for node '{node_name}'")
        return ip

    listeners_started: dict[str, set[int]] = {}

    def start_listener(dst: str, port: int) -> None:
        listeners_started.setdefault(dst, set())
        if port in listeners_started[dst]:
            return
        start_tcp_listener(lab, dst, port)
        listeners_started[dst].add(port)

    matched = 0  # YAML tests that matched filters and were executed

    try:
        for idx, t in enumerate(tests):
            i = idx + 1
            test_name = t.get("name") if isinstance(t, dict) else None
            if not test_name:
                test_name = f"tests[{i}]"

            # --name filter (after canonical naming)
            if filter_name and test_name != filter_name:
                continue

            if not isinstance(t, dict):
                record_test(
                    name=test_name,
                    kind="unknown",
                    src="",
                    dst="",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="test entry must be a dict",
                )
                fail_or_continue(f"tests[{i}]: must be a dict")
                continue

            # ---- test kind normalization / validation ----
            if "kind" in t and "type" in t:
                record_test(
                    name=test_name,
                    kind="unknown",
                    src=t.get("src") or "",
                    dst=t.get("dst") or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="has both 'kind' and 'type'",
                )
                fail_or_continue(f"tests[{i}]: has both 'kind' and 'type' (use only 'kind')")
                continue

            kind = t.get("kind") or t.get("type")
            if not kind:
                record_test(
                    name=test_name,
                    kind="unknown",
                    src=t.get("src") or "",
                    dst=t.get("dst") or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="missing 'kind'",
                )
                fail_or_continue(f"tests[{i}]: missing 'kind'")
                continue

            src = t.get("src")
            dst = t.get("dst")

            if kind not in ("ping", "tcp"):
                record_test(
                    name=test_name,
                    kind=str(kind),
                    src=src or "",
                    dst=dst or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error=f"unsupported kind '{kind}'",
                )
                fail_or_continue(f"tests[{i}]: unsupported kind '{kind}' (supported: ping, tcp)")
                continue

            # --kind filter (after validation)
            if filter_kind and kind != filter_kind:
                continue

            # At this point: it matched filters and will execute
            matched += 1

            if not src or not dst:
                record_test(
                    name=test_name,
                    kind=kind,
                    src=src or "",
                    dst=dst or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="missing src/dst",
                )
                fail_or_continue(f"tests[{i}]: missing src/dst")
                continue

            dst_ip = node_ip_or_die(dst)

            # ---- ping ----
            if kind == "ping":
                expected = (t.get("expect") or "pass").lower()
                if expected not in ("pass", "fail"):
                    expected = "pass"

                count = int(t.get("count") or 2)

                # Retry window to survive early ARP / route programming
                timeout_s = int(t.get("timeout_s") or 15)
                interval_s = float(t.get("retry_interval_s") or 1.0)

                def attempt_ping():
                    cp = run(
                        ["docker", "exec", container_name(lab, src), "ping", "-c", str(count), "-W", "1", dst_ip],
                        check=False,
                    )
                    return (cp.returncode == 0), cp

                start = time.time()
                ok, last_cp, attempts = retry_until(timeout_s, interval_s, attempt_ping)
                dur_ms = int((time.time() - start) * 1000)

                observed = "pass" if ok else "fail"
                should_succeed = (expected == "pass")
                verdict = "pass" if (ok == should_succeed) else "fail"

                record_test(
                    name=test_name,
                    kind="ping",
                    src=src,
                    dst=dst,
                    expected=expected,
                    observed=observed,
                    verdict=verdict,
                    duration_ms=dur_ms,
                    error="" if verdict == "pass" else f"ping mismatch (expected {expected}, observed {observed})",
                    meta={
                        "dst_ip": dst_ip,
                        "count": count,
                        "attempts": attempts,
                        "timeout_s": timeout_s,
                        "retry_interval_s": interval_s,
                        "last_rc": getattr(last_cp, "returncode", None),
                    },
                )

                if verdict != "pass":
                    fail_or_continue(
                        f"tests[{i}] ping mismatch: {src} -> {dst} ({dst_ip}) expected {expected}, observed {observed}"
                    )
                continue

            # ---- tcp ----
            port = t.get("port")
            expected = (t.get("expect") or "pass").lower()
            listener = bool(t.get("listener", True))  # default True

            if expected not in ("pass", "fail"):
                expected = "pass"

            if not isinstance(port, int):
                record_test(
                    name=test_name,
                    kind="tcp",
                    src=src,
                    dst=dst,
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="'port' must be an int",
                )
                fail_or_continue(f"tests[{i}] tcp: 'port' must be an int")
                continue

            if listener:
                start_listener(dst, port)

            # Retry TCP connects only for expect=pass (helps with early readiness)
            timeout_s = int(t.get("timeout_s") or (10 if expected == "pass" else 0))
            interval_s = float(t.get("retry_interval_s") or 1.0)

            def attempt_tcp():
                cp = run(
                    ["docker", "exec", container_name(lab, src), "sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
                    check=False,
                )
                return (cp.returncode == 0), cp

            start = time.time()
            if expected == "pass" and timeout_s > 0:
                ok, last_cp, attempts = retry_until(timeout_s, interval_s, attempt_tcp)
            else:
                # Single-shot for expect=fail (you don't want "eventually allowed")
                cp = run(
                    ["docker", "exec", container_name(lab, src), "sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"],
                    check=False,
                )
                ok, last_cp, attempts = (cp.returncode == 0), cp, 1

            dur_ms = int((time.time() - start) * 1000)

            observed = "pass" if ok else "fail"
            should_succeed = (expected == "pass")
            verdict = "pass" if (ok == should_succeed) else "fail"

            record_test(
                name=test_name,
                kind="tcp",
                src=src,
                dst=dst,
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=dur_ms,
                error="" if verdict == "pass" else f"tcp mismatch (expected {expected}, observed {observed})",
                meta={
                    "dst_ip": dst_ip,
                    "port": int(port),
                    "listener": bool(listener),
                    "attempts": attempts,
                    "timeout_s": timeout_s,
                    "retry_interval_s": interval_s,
                    "rc": getattr(last_cp, "returncode", None),
                },
            )

            if verdict != "pass":
                fail_or_continue(
                    f"tests[{i}] tcp mismatch: {src} -> {dst} ({dst_ip}:{port}) expected {expected}, observed {observed}"
                )

    finally:
        # Always stop any listeners we started (deterministic cleanup)
        for dst_node in listeners_started.keys():
            run(
                ["docker", "exec", container_name(lab, dst_node), "sh", "-lc", 'pkill -f "nc.*-p" 2>/dev/null || true'],
                check=False,
            )

        # Fill summary + final result and write results.json
        finished_at = time.time()
        results["summary"]["finished_at"] = finished_at
        results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)

        # Deterministic failure if filters were used and nothing matched
        if (filter_name or filter_kind) and matched == 0:
            label_parts = []
            if filter_name:
                label_parts.append(f"--name {filter_name!r}")
            if filter_kind:
                label_parts.append(f"--kind {filter_kind!r}")
            label = " ".join(label_parts) if label_parts else "(none)"

            record_test(
                name="filter:no-match",
                kind=filter_kind or "unknown",
                src="",
                dst="",
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error=f"no test matched filters {label}",
            )

        total = len(results["tests"])
        failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
        passed_count = total - failed_count

        results["summary"]["total"] = total
        results["summary"]["passed"] = passed_count
        results["summary"]["failed"] = failed_count

        results["result"] = "fail" if failed_count > 0 else "pass"
        write_results()

    # =============================================================================
    # 5) Success output (human-friendly)
    # =============================================================================
    if results["result"] == "fail":
        die(f"TEST FAIL: {results['summary']['failed']} failed / {results['summary']['total']} total")

    # If we got here, everything passed
    if bgp_participants:
        print(f"✅ Control-plane PASS: BGP established ({len(bgp_participants)} participants)")
    print(f"✅ Declared tests PASS ({results['summary']['passed']} checks)")
    print("✅ TEST PASS: containers running + checks OK")

def cmd_gen(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    out = write_containerlab_file(topo_path)
    print(f"Generated containerlab file: {out}")

def cmd_up(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # If --reconfigure: destroy + remove root-owned lab dir FIRST.
    if getattr(args, "reconfigure", False):
        lab_name = None
        try:
            topo_for_name = load_yaml(topo_path)
            lab_name = (topo_for_name or {}).get("name")
        except Exception:
            lab_name = None

        if lab_name:
            existing_clab = LABS_DIR / f"{lab_name}.clab.yaml"
            if existing_clab.exists():
                run(["sudo", "containerlab", "destroy", "-t", str(existing_clab)], check=False)

            # containerlab creates labs/clab-<lab> as root; remove it as root
            run(["sudo", "rm", "-rf", str(lab_dir(lab_name))], check=False)

    # Generate AFTER destroy/cleanup
    out = write_containerlab_file(topo_path)

    # Deploy
    run(["sudo", "containerlab", "deploy", "-t", str(out)])

    lab_name = out.name.replace(".clab.yaml", "")
    resolved_path = lab_dir(lab_name) / "topology.resolved.yaml"
    if not resolved_path.exists():
        return

    topo = load_yaml(resolved_path) or {}

    # 1) Hosts (IPs + default route)
    configure_hosts_from_topology(lab_name, topo)

    # 2) nft-fw interface IPs + forwarding (NO nft rules here)
    configure_nftfw_from_topology(lab_name, topo)

    # 3) nft-fw static routes
    configure_nftfw_routes_from_topology(lab_name, topo)

    # 4) nft rules last (so forwarding + routes exist first)
    for n in topo.get("nodes", []):
        if n.get("type") == "nft-fw":
            nft_fw_apply(lab_name, n["name"], gen_nft_fw_rules(n))
            nhs = fw_next_hops_from_links(topo, n["name"])
            if nhs:
                verify_fw_routed_ready(lab_name, n["name"])

    # 5) FRR provisioning (THIS was missing)
    configure_frr_interfaces_from_topology(lab_name, topo)
    configure_frr_static_routes_from_topology(lab_name, topo)
    configure_frr_bgp_from_topology(lab_name, topo)

def cmd_down(args: argparse.Namespace) -> None:
    out = lab_file_from_name(args.name)
    if not out.exists():
        die(f"Lab file not found: {out} (did you run gen/up first?)")
    run(["sudo", "containerlab", "destroy", "-t", str(out)])

def cmd_exec(args: argparse.Namespace) -> None:
    c = container_name(args.lab, args.node)
    if not args.command:
        # Open interactive shell if no command given
        run(["docker", "exec", "-it", c, "bash"], check=False)
        return

    # Use -t only (not -it) for non-interactive commands
    cp = run(["docker", "exec", c] + args.command, check=False)
    if cp.returncode != 0:
        die(f"Command failed inside {c} (exit {cp.returncode})", code=cp.returncode)

def cmd_vty(args: argparse.Namespace) -> None:
    # command is provided as a single string; e.g. "show bgp summary"
    cp = vty(args.lab, args.node, args.command)
    # vtysh prints errors to stdout typically; just show output
    sys.stdout.write(cp.stdout or "")
    sys.stderr.write(cp.stderr or "")
    if cp.returncode != 0:
        die(f"vtysh command failed (exit {cp.returncode})", code=cp.returncode)

def _load_resolved_topology(lab_name: str) -> dict[str, Any]:
    lab_dir = LABS_DIR / f"clab-{lab_name}"
    topo_path = lab_dir / "topology.resolved.yaml"
    if not topo_path.is_file():
        die(f"Resolved topology not found: {topo_path} (is the lab up?)")
    return load_yaml(topo_path)

def _iter_nodes(topo: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = topo.get("nodes", [])
    # Support both styles: list (preferred) or dict (legacy)
    if isinstance(nodes, list):
        return [n for n in nodes if isinstance(n, dict)]
    if isinstance(nodes, dict):
        out: list[dict[str, Any]] = []
        for name, n in nodes.items():
            if isinstance(n, dict):
                nn = dict(n)
                nn.setdefault("name", name)
                out.append(nn)
        return out
    return []

import re

def cmd_status(args: argparse.Namespace) -> None:
    lab = args.lab

    topo = _load_resolved_topology(lab)
    nodes = _iter_nodes(topo)

    print(f"Lab: {lab}")
    print("Nodes:")

    if not nodes:
        print("  (no nodes found in topology.resolved.yaml)")
        return

    bgp_enabled = bool(getattr(args, "bgp", False))
    bgp_verbose = bool(getattr(args, "bgp_verbose", False))
    bgp_strict = bool(getattr(args, "strict", False))
    show_intf = bool(getattr(args, "interfaces", False))
    show_summary = bool(getattr(args, "summary", False))

    def _docker_exec(cname: str, cmd: list[str]) -> str:
        cp = run(["docker", "exec", cname, *cmd], check=False, capture_output=True)
        out = cp.stdout
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        return (out or "").strip()

    # Intent: expected neighbors derived from topology links (FRR<->FRR)
    expected_by_node: dict[str, set[str]] = derive_expected_bgp_neighbors_from_links(topo)

    # Totals for --summary / --strict
    total_nodes = 0
    running_nodes = 0

    # For summary, count only expected peers (intent-based)
    exp_total_peers = 0
    exp_established_peers = 0
    frr_nodes_with_expected_peers = 0

    strict_fail = False

    for n in nodes:
        name = str(n.get("name", "")).strip()
        ntype = str(n.get("type", "")).strip()
        if not name:
            continue

        total_nodes += 1
        cname = f"clab-{lab}-{name}"
        running = _container_is_running(cname)
        if running:
            running_nodes += 1

        state = "running" if running else "not running"
        print(f"  - {name:<8} ({cname}) : {state}")

        if not running:
            continue

        # optional interfaces
        if show_intf:
            try:
                intf_out = _docker_exec(cname, ["sh", "-lc", "ip -br a"])
                if intf_out:
                    print("      IF:")
                    for line in intf_out.splitlines():
                        print(f"      {line}")
            except Exception as e:
                print(f"      IF: failed ({e})")

        # optional BGP (intent-aware)
        if bgp_enabled and ntype == "frr":
            expected = expected_by_node.get(name, set())

            try:
                bgp_out = _docker_exec(cname, ["vtysh", "-c", "show bgp summary"])
                observed = parse_frr_bgp_summary_neighbors(bgp_out)
                cmp = compare_expected_vs_observed_bgp(expected, observed)

                # Summary counters (only based on intent)
                if expected:
                    frr_nodes_with_expected_peers += 1
                    exp_total_peers += len(expected)
                    exp_established_peers += len(cmp["established"])

                if not expected:
                    # If no expected neighbors, we keep the previous UX: "BGP (none)"
                    print("      BGP (none)")
                else:
                    if cmp["ok"]:
                        print(f"      BGP expected {len(expected)} | Established {len(cmp['established'])}/{len(expected)} (OK)")
                    else:
                        print(f"      BGP expected {len(expected)} | Established {len(cmp['established'])}/{len(expected)} (MISMATCH)")
                        if cmp["missing"]:
                            print(f"      BGP missing: {', '.join(cmp['missing'])}")
                        if cmp["down"]:
                            print(f"      BGP down:    {', '.join(cmp['down'])}")
                            # DEBUG: show raw neighbor lines for down peers
                            for ip in cmp["down"]:
                                raw = observed.get(ip, {}).get("raw", "")
                                if raw:
                                    print(f"      BGP down raw: {raw}")
                        if cmp["extra"]:
                            print(f"      BGP extra:   {', '.join(cmp['extra'])}")

                        if bgp_strict:
                            strict_fail = True

                if bgp_verbose and bgp_out:
                    print("      --- show bgp summary ---")
                    for line in bgp_out.splitlines():
                        print(f"      {line}")

            except Exception as e:
                print(f"      BGP: failed to query ({e})")
                if bgp_strict and expected:
                    strict_fail = True

    # summary line
    if show_summary:
        parts = [f"containers {running_nodes}/{total_nodes} running"]
        if bgp_enabled:
            parts.append(f"BGP expected peers {exp_established_peers}/{exp_total_peers} established")
            parts.append(f"FRR nodes w/expected peers {frr_nodes_with_expected_peers}")
        print("Summary: " + " | ".join(parts))

    # strict exit behavior (CI-friendly)
    if bgp_enabled and bgp_strict and strict_fail:
        raise SystemExit(2)
    
def cmd_collect(args: argparse.Namespace) -> None:
    import json
    import re
    from typing import Any

    lab = args.lab
    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    outdir = lab_dir(lab) / "artifacts"
    outdir.mkdir(parents=True, exist_ok=True)

    def write(name: str, content: str) -> None:
        (outdir / name).write_text(content, encoding="utf-8")

    def require_running(container: str) -> None:
        cp = run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            check=False,
            capture_output=True,
        )
        if (cp.stdout or "").strip() != "true":
            die(f"COLLECT FAIL: {container} is not running")

    def normalize_bgp_summary(text: str) -> str:
        """
        Deterministic BGP neighbor snapshot from `show bgp summary`.

        We intentionally discard volatile counters/timers and keep only:
        - neighbor address
        - ASN (best-effort parse)
        - state (Established vs Idle/Active/etc.)

        Output format (one per neighbor):
          <NEIGHBOR> AS=<ASN or ?> STATE=<STATE>
        """
        lines = (text or "").splitlines()
        out: list[str] = []
        in_table = False

        for line in lines:
            # Detect the table header
            if ("Neighbor" in line) and ("Up/Down" in line):
                in_table = True
                out.append(line.rstrip())
                continue

            if not in_table:
                # Keep pre-table lines as-is (usually stable)
                out.append(line.rstrip())
                continue

            if not line.strip():
                out.append("")
                continue

            parts = line.split()
            if len(parts) < 2:
                out.append(line.rstrip())
                continue

            nbr = parts[0]
            # Neighbor column must look like an IP (v4/v6) to be a row
            if not re.match(r"^[0-9A-Fa-f:.]+$", nbr):
                out.append(line.rstrip())
                continue

            # Heuristic: AS is the first integer token shortly after the neighbor/V columns
            asn: str | None = None
            for tok in parts[1:6]:
                if tok.isdigit():
                    asn = tok
                    break

            # Last token often is State/PfxRcd. If it's numeric => Established.
            last = parts[-1]
            state = "Established" if last.isdigit() else last

            out.append(f"{nbr} AS={asn or '?'} STATE={state}")

        return "\n".join(out).rstrip() + "\n"

    def scrub_containerlab_inspect_json(raw: str) -> str:
        """
        Containerlab inspect JSON can include volatile fields.
        We remove common volatile keys and sort keys for stable output.
        """
        try:
            obj = json.loads(raw)
        except Exception:
            # Fall back to raw text (useful, but may be nondeterministic)
            return (raw or "").rstrip() + "\n"

        volatile_keys = {
            "pid", "pids",
            "startedAt", "finishedAt",
            "created", "createdAt",
            "uptime",
            "status", "state",
            "container_id", "containerID",
            "ipv4", "ipv6",
            "mgmtIPv4Address", "mgmtIPv6Address",
        }

        def drop_keys(o: Any) -> None:
            if isinstance(o, dict):
                for k in list(o.keys()):
                    if k in volatile_keys:
                        o.pop(k, None)
                for v in o.values():
                    drop_keys(v)
            elif isinstance(o, list):
                for v in o:
                    drop_keys(v)

        drop_keys(obj)
        return json.dumps(obj, sort_keys=True, indent=2).rstrip() + "\n"

    # Strict: ensure all expected containers are running before collecting
    nodes = sorted((topo.get("nodes", []) or []), key=lambda n: n.get("name", ""))
    for n in nodes:
        require_running(container_name(lab, n["name"]))

    # Stable docker snapshot (sorted)
    cp = run(
        ["sh", "-lc", "docker ps --format '{{.Names}}\t{{.Image}}' | sort"],
        check=False,
        capture_output=True,
    )
    write("docker-ps.txt", cp.stdout or cp.stderr or "")

    # Containerlab inspect JSON (scrubbed)
    clab_yaml = LABS_DIR / f"{lab}.clab.yaml"
    cp = run(
        ["sudo", "containerlab", "inspect", "-t", str(clab_yaml), "--format", "json"],
        check=False,
        capture_output=True,
    )
    write("containerlab-inspect.json", scrub_containerlab_inspect_json(cp.stdout or cp.stderr or ""))

    # Optional: logs are nondeterministic; keep off by default
    include_logs = False

    # Per-node snapshots (deterministic order)
    for n in nodes:
        name = n["name"]
        c = container_name(lab, name)

        cp = run(["docker", "exec", c, "sh", "-lc", "ip -br a"], check=False, capture_output=True)
        write(f"{name}.ip-addr.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        cp = run(["docker", "exec", c, "sh", "-lc", "ip route"], check=False, capture_output=True)
        write(f"{name}.ip-route.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        if n.get("type") == "nft-fw":
            cp = run(["docker", "exec", c, "sh", "-lc", "nft list ruleset"], check=False, capture_output=True)
            write(f"{name}.nft-ruleset.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

            cp = run(["docker", "exec", c, "sh", "-lc", "sysctl -n net.ipv4.ip_forward"], check=False, capture_output=True)
            write(f"{name}.ip-forward.txt", (cp.stdout or cp.stderr or "").strip() + "\n")

        if n.get("type") == "frr":
            cp = run(["docker", "exec", c, "vtysh", "-c", "show bgp summary"], check=False, capture_output=True)
            write(f"{name}.bgp-summary.txt", normalize_bgp_summary(cp.stdout or cp.stderr or ""))

        if include_logs:
            cp = run(["docker", "logs", "--tail", "300", c], check=False, capture_output=True)
            write(f"{name}.docker-logs.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

    print(f"✅ COLLECT PASS: wrote artifacts to {outdir}")

def cmd_run(args: argparse.Namespace) -> None:
    """
    Ephemeral workflow:
      up -> test -> collect -> (down)

    Teardown policy:
      - Default: destroy ONLY on full success (so failures keep the lab for debugging)
      - --destroy-always: attempt destroy even if something fails
      - --keep: never destroy (overrides --destroy-always)

    Other:
      - collect runs best-effort even if test fails (unless --no-collect)
    """
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # Derive lab name robustly from topology (authoritative)
    try:
        topo_for_name = load_yaml(topo_path)
    except Exception as e:
        die(f"Failed to load topology YAML '{topo_path}': {e}")

    lab_name = (topo_for_name or {}).get("name")
    if not lab_name or not isinstance(lab_name, str):
        die(f"Topology '{topo_path}' has no valid 'name' field (required).")

    # Flags
    keep = bool(getattr(args, "keep", False))
    destroy_always = bool(getattr(args, "destroy_always", False))
    do_collect = not bool(getattr(args, "no_collect", False))
    do_reconfigure = bool(getattr(args, "reconfigure", False))

    exit_code: int | None = None   # None means "no failure captured"
    up_ok = False

    def _as_exit_code(code: object) -> int:
        # SystemExit.code can be None, int, str, etc.
        try:
            return int(code) if code is not None else 1
        except Exception:
            return 1

    def record_failure(code: object = None) -> None:
        nonlocal exit_code
        if exit_code is None:
            exit_code = _as_exit_code(code)

    try:
        # 1) up
        try:
            cmd_up(argparse.Namespace(topology=str(topo_path), reconfigure=do_reconfigure))
            up_ok = True
        except SystemExit as e:
            record_failure(getattr(e, "code", 1))
        except Exception:
            record_failure(1)

        # If up failed, skip the rest (but still hit finally + final reporting)
        if up_ok:
            # 2) test
            try:
                cmd_test(argparse.Namespace(lab=lab_name))
            except SystemExit as e:
                record_failure(getattr(e, "code", 1))
            except Exception:
                record_failure(1)

            # 3) collect (best-effort; very useful for debugging failures)
            if do_collect:
                try:
                    cmd_collect(argparse.Namespace(lab=lab_name))
                except SystemExit as e:
                    record_failure(getattr(e, "code", 1))
                except Exception:
                    record_failure(1)

    finally:
        # 4) down decision
        # keep wins (never destroy)
        # otherwise:
        #   - destroy_always => always attempt down
        #   - default => only down on full success (exit_code is None)
        if keep:
            should_destroy = False
        elif destroy_always:
            should_destroy = True
        else:
            should_destroy = (exit_code is None)

        if should_destroy:
            try:
                cmd_down(argparse.Namespace(name=lab_name))
            except SystemExit as e:
                # If we were successful until teardown, teardown failure matters.
                if exit_code is None:
                    record_failure(getattr(e, "code", 1))
            except Exception:
                if exit_code is None:
                    record_failure(1)

    # Final reporting + exit behavior (never lie)
    if exit_code is not None and int(exit_code) != 0:
        if keep:
            print(f"❌ RUN FAIL: exit={exit_code} (lab kept by --keep): {lab_name}")
        elif destroy_always:
            print(f"❌ RUN FAIL: exit={exit_code} (attempted teardown via --destroy-always): {lab_name}")
        else:
            print(f"❌ RUN FAIL: exit={exit_code} (lab kept for debugging): {lab_name}")
        raise SystemExit(int(exit_code))

    # Success
    if keep:
        print(f"✅ RUN PASS: up + test + collect completed (lab kept): {lab_name}")
    else:
        print(f"✅ RUN PASS: up + test + collect completed (lab destroyed): {lab_name}")

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netsim",
        description="ai-netsim: topo YAML -> containerlab (local MVP)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # gen
    p_gen = sub.add_parser("gen", help="Generate containerlab file from topology")
    p_gen.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_gen.set_defaults(func=cmd_gen)

    # up
    p_up = sub.add_parser("up", help="Generate + deploy")
    p_up.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_up.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_up.set_defaults(func=cmd_up)

    # down
    p_down = sub.add_parser("down", help="Destroy a deployed lab by name")
    p_down.add_argument("name", help="Lab name (topology 'name')")
    p_down.set_defaults(func=cmd_down)

    # exec
    p_exec = sub.add_parser("exec", help="Exec a command inside a node container; if no command, open bash")
    p_exec.add_argument("lab", help="Lab name (topology 'name')")
    p_exec.add_argument("node", help="Node name (e.g. r1)")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command to run inside container")
    p_exec.set_defaults(func=cmd_exec)

    # collect
    p_collect = sub.add_parser("collect", help="Collect runtime artifacts for a lab")
    p_collect.add_argument("lab", help="Lab name (topology 'name')")
    p_collect.set_defaults(func=cmd_collect)

    # vty
    p_vty = sub.add_parser("vty", help="Run a vtysh command easily")
    p_vty.add_argument("lab", help="Lab name (topology 'name')")
    p_vty.add_argument("node", help="Node name (e.g. r1)")
    p_vty.add_argument("command", help='vtysh command as one string, e.g. "show bgp summary"')
    p_vty.set_defaults(func=cmd_vty)

    # status
    p_status = sub.add_parser("status", help="Show lab status (containers + optional BGP summary)")
    p_status.add_argument("lab", help="Lab name (topology 'name')")
    p_status.add_argument("--bgp", action="store_true", help="Include 'show bgp summary' for FRR nodes")
    p_status.add_argument("--bgp-verbose", action="store_true", help="Print full 'show bgp summary' output")
    p_status.add_argument("--strict", action="store_true", help="Exit non-zero if any FRR peers are not Established")
    p_status.add_argument("--interfaces", action="store_true", help="Include 'ip -br a' output per node")
    p_status.add_argument("--summary", action="store_true", help="Print a one-line summary at the end")
    p_status.add_argument("--json", action="store_true", help="Emit machine-readable JSON (no human output)")
    p_status.set_defaults(func=cmd_status)

    # test
    p_test = sub.add_parser("test", help="Run declared tests for a lab")
    p_test.add_argument("lab", help="Lab name (e.g. three-frr-two-hosts-fw-routed)")
    p_test.add_argument("--name", help="Run only the test with this name (e.g. tests[4] or a named test)")
    p_test.add_argument("--kind", choices=["ping", "tcp"], help="Run only tests of this kind")
    p_test.add_argument(
        "--keep-going",
        action="store_true",
        help="Run all tests even if one fails (still exits non-zero if any fail)",
    )
    p_test.add_argument(
        "--json",
        action="store_true",
        help="Print results.json to stdout in addition to writing the file",
    )
    p_test.set_defaults(func=cmd_test)

    # run
    p_run = sub.add_parser("run", help="Ephemeral workflow: up -> test -> collect -> down (CI-friendly)")
    p_run.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_run.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_run.add_argument(
        "--keep",
        action="store_true",
        help="Do not destroy the lab at the end (useful for debugging failures).",
    )
    p_run.add_argument(
        "--destroy-always",
        action="store_true",
        help="Attempt to destroy the lab even if up/test/collect fails.",
    )
    p_run.add_argument(
        "--no-collect",
        action="store_true",
        help="Skip collect (faster, but no artifacts).",
    )
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
