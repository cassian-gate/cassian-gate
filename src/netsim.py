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
from __future__ import annotations

import argparse
import subprocess
import sys
import time
import shutil
import json
import ipaddress
import re

from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
TOPO_DIR = BASE_DIR / "topologies"
LABS_DIR = BASE_DIR / "labs"
QUIET_RUN = False


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
    global QUIET_RUN
    if not QUIET_RUN:
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

def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False

def validate_ip_literal(value: str, ctx: str) -> None:
    try:
        ipaddress.ip_address(value.strip())
    except Exception:
        die(f"{ctx}: invalid IPv4/IPv6 literal: {value!r}")

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

def run_ping_test(
    rt: Runtime,
    lab: str,
    src: str,
    dst_ip: str,
    count: int,
    should_succeed: bool,
) -> None:
    cp = rt.exec(
        lab,
        src,
        ["ping", "-c", str(count), dst_ip],
        check=False,
        capture_output=False,
    )
    ok = (cp.returncode == 0)
    if should_succeed and not ok:
        die(f"PING FAIL (expected PASS): {src} -> {dst_ip}")
    if (not should_succeed) and ok:
        die(f"PING FAIL (expected DROP): {src} -> {dst_ip}")

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
                run_ping_test(rt, lab, src, dst_ip, count=count, should_succeed=should_succeed)

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

        # ----------------------------
        # v1 ping destination normalization
        # ----------------------------
        if t.get("kind") == "ping":
            ctx = f"tests[{i}] ({t.get('name', '<unnamed>')})"

            src = t.get("src") or t.get("from")
            dst = t.get("dst") or t.get("to")
            dst_ip = t.get("dst_ip") or t.get("to_ip")

            if not src or not isinstance(src, str):
                die(f"{ctx}: ping test requires 'from/src' as a node name")

            if not dst or not isinstance(dst, str):
                die(f"{ctx}: ping test requires 'to/dst' as node name or IP literal")

            dst = dst.strip()

            # Case 1: to/dst is an IP literal
            if is_ip_literal(dst):
                if dst_ip is not None:
                    die(f"{ctx}: 'to_ip/dst_ip' not allowed when 'to/dst' is already an IP")
                validate_ip_literal(dst, ctx)
                t["_dst_kind"] = "ip"
                t["_dst_value"] = dst
                continue

            # Case 2: to/dst must be a node name
            nodes = {n.get("name") for n in resolved.get("nodes", []) or []}
            if dst not in nodes:
                die(f"{ctx}: 'to/dst' must be a valid node name or IP literal")

            if dst_ip is not None:
                if not isinstance(dst_ip, str):
                    die(f"{ctx}: 'to_ip/dst_ip' must be a string")
                validate_ip_literal(dst_ip.strip(), ctx)
                t["_dst_kind"] = "ip"
                t["_dst_value"] = dst_ip.strip()
            else:
                t["_dst_kind"] = "node"
                t["_dst_value"] = dst

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
import ipaddress

_RE_NEIGH_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+")
_RE_IPV4_PREFIX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

def _normalize_prefix(cidr: str) -> str | None:
    try:
        n = ipaddress.ip_network(cidr.strip(), strict=False)
        if n.version != 4:
            return None
        return str(n)
    except Exception:
        return None

def derive_expected_routes_for_frr(topo: dict[str, Any]) -> dict[str, set[str]]:
    """
    Intent: expected IPv4 prefixes that must appear in each FRR node's routing table.

    v1 rules:
      - router_id => expect router_id/32
      - FRR<->host links => expect connected subnet prefix (network of router-side IP)
      - node.static_routes => expect each prefix part (before ' via ')
    """
    nodes = topo.get("nodes", []) or []
    node_type = {n.get("name"): n.get("type") for n in nodes if isinstance(n, dict)}
    nodes_by_name = {n.get("name"): n for n in nodes if isinstance(n, dict)}

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

        # Convert router interface IP/mask into its network prefix
        norm = _normalize_prefix(router_ip)
        if norm:
            expected.setdefault(router, set()).add(norm)

    # 3) Static routes declared on FRR nodes
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("type") != "frr":
            continue
        name = n.get("name")
        if not isinstance(name, str) or not name:
            continue

        srs = n.get("static_routes") or []
        if not isinstance(srs, list):
            continue

        for r in srs:
            if not isinstance(r, str) or " via " not in r:
                continue
            prefix, _nh = r.split(" via ", 1)
            p = _normalize_prefix(prefix)
            if p:
                expected.setdefault(name, set()).add(p)

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

def compare_expected_vs_observed_prefixes(expected: set[str], observed: set[str]) -> dict[str, Any]:
    missing = sorted([p for p in expected if p not in observed])
    return {
        "expected": sorted(expected),
        "observed": sorted(observed),
        "missing": missing,
        "ok": (len(missing) == 0),
    }

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

def configure_frr_static_routes_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    Apply node-level static_routes entries like:
      - 192.168.2.0/24 via 10.0.0.1

    Runtime contract:
      - No direct docker/container name usage here
      - All node execution goes through rt.exec()/rt.sh()
    """
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
            # Expect "PREFIX via NEXTHOP"
            # Keep existing behavior: pass to ip route replace as a shell line.
            rt.sh(lab, node, f"ip route replace {r}", check=False, capture_output=False)

def configure_frr_bgp_from_topology(rt: "Runtime", lab: str, topo: dict[str, Any]) -> None:
    """
    Minimal BGP neighbor provisioning:

    - For each link between TWO FRR nodes with ipv4 /31 or /30 addressing:
      configure them as neighbors (remote-as from topo nodes' asn).
    - Configure router-id if present.
    - Allow eBGP without policy (MVP) so later advertisements work.

    Runtime contract:
      - No direct docker/container name usage here.
      - All node execution goes through rt.exec().
    """
    nodes = _node_index_by_name(topo)

    # Build a list of FRR-FRR adjacencies from links
    # (nodeA, nbr_ip_on_A, nodeB, nbr_ip_on_B)
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
        vty_cmd: list[str] = ["vtysh"]
        for c in cmds:
            vty_cmd += ["-c", c]

        rt.exec(lab, node, vty_cmd, check=False, capture_output=False)

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
        die(f"{node}: nft not found (use an nftables-capable image, e.g. netsim/nft-fw:latest)")

    # Load ruleset (fail-fast if nft rejects it)
    cmd = (
        "set -e\n"
        "cat > /tmp/rules.nft <<'EOF'\n"
        f"{ruleset}\n"
        "EOF\n"
        "nft -f /tmp/rules.nft\n"
    )
    rt.sh(lab_name, node, cmd, check=True, capture_output=False)

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
            verify_fw_routed_ready(rt, lab, name)
        elif t == "frr":
            verify_frr_ready(rt, lab, name)

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
    Deterministic schema validation for v1 scenarios.

    Rules:
      - scenarios is optional; if present must be a list
      - each scenario has:
          id: string (unique)
          steps: list (non-empty)
      - each step is exactly ONE of:
          {run: <test_name>}
          {fault: {...}}
          {wait: {seconds: <int>}}
          {wait_for: {...}}
      - no loops/conditionals are possible in this schema (ordered list only)
    """
    scenarios = _iter_scenarios(topo)
    if not scenarios:
        return

    seen_ids: set[str] = set()

    for idx, s in enumerate(scenarios):
        i = idx + 1
        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip():
            die(f"scenarios[{i}]: missing/invalid 'id'")
        sid = sid.strip()
        if sid in seen_ids:
            die(f"scenarios[{i}]: duplicate id '{sid}'")
        seen_ids.add(sid)

        steps = s.get("steps")
        if not isinstance(steps, list) or not steps:
            die(f"scenario '{sid}': 'steps' must be a non-empty list")

        for jdx, step in enumerate(steps):
            j = jdx + 1
            if not isinstance(step, dict) or not step:
                die(f"scenario '{sid}' step[{j}]: must be a non-empty dict")

            keys = list(step.keys())
            if len(keys) != 1:
                die(f"scenario '{sid}' step[{j}]: must have exactly one key (got {keys})")

            k = keys[0]
            if k not in ("run", "fault", "wait", "wait_for"):
                die(f"scenario '{sid}' step[{j}]: unknown step type '{k}'")

            if k == "run":
                v = step.get("run")
                if not isinstance(v, str) or not v.strip():
                    die(f"scenario '{sid}' step[{j}]: run must be a test name string")

            elif k == "wait":
                v = step.get("wait")
                if not isinstance(v, dict):
                    die(f"scenario '{sid}' step[{j}]: wait must be a dict like {{seconds: 5}}")
                sec = v.get("seconds")
                if not isinstance(sec, int) or sec < 0:
                    die(f"scenario '{sid}' step[{j}]: wait.seconds must be a non-negative int")

            elif k == "wait_for":
                v = step.get("wait_for")
                if not isinstance(v, dict):
                    die(f"scenario '{sid}' step[{j}]: wait_for must be a dict")
                t = v.get("type")
                if t not in ("ping", "tcp"):
                    die(f"scenario '{sid}' step[{j}]: wait_for.type must be ping|tcp")
                src = v.get("from")
                dst = v.get("to")
                exp = (v.get("expect") or "pass").lower()
                if not isinstance(src, str) or not src.strip():
                    die(f"scenario '{sid}' step[{j}]: wait_for.from must be a node name")
                if not isinstance(dst, str) or not dst.strip():
                    die(f"scenario '{sid}' step[{j}]: wait_for.to must be an ip or node name")
                if exp not in ("pass", "fail"):
                    die(f"scenario '{sid}' step[{j}]: wait_for.expect must be pass|fail")
                to = v.get("timeout")
                if not isinstance(to, int) or to <= 0:
                    die(f"scenario '{sid}' step[{j}]: wait_for.timeout must be a positive int")
                if t == "tcp":
                    port = v.get("port")
                    if not isinstance(port, int) or not (1 <= port <= 65535):
                        die(f"scenario '{sid}' step[{j}]: wait_for.port must be a valid int for tcp")

            elif k == "fault":
                # For Step 1 we only validate the shape; Step 2 will validate action details.
                v = step.get("fault")
                if not isinstance(v, dict) or not v:
                    die(f"scenario '{sid}' step[{j}]: fault must be a non-empty dict")

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
    """
    if not isinstance(dst, str) or not dst.strip():
        die("resolve_dst_to_ip: dst must be a non-empty string")

    dst_s = dst.strip()

    # If literal IP, use directly (v1-safe)
    if is_ip_literal(dst_s):
        validate_ip_literal(dst_s, "wait_for.to")
        return dst_s

    # Otherwise must be a node name
    nodes = topo.get("nodes", []) or []
    if any(isinstance(n, dict) and n.get("name") == dst_s for n in nodes):
        return node_first_ipv4(topo, dst_s)

    die(f"wait_for.to must be a valid node name or IPv4/IPv6 literal (got {dst_s!r})")

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

    # Filter scenarios if requested (deterministic)
    if scenario_ids is not None:
        want = set(str(x) for x in scenario_ids)
        scenarios = [s for s in scenarios if isinstance(s, dict) and str(s.get("id", "")) in want]

    # Deterministic ordering for validation / error reporting
    scenarios_sorted = sorted(
        (s for s in scenarios if isinstance(s, dict)),
        key=lambda s: str(s.get("id", "")),
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
        capture_output: bool = True,   # <-- IMPORTANT: default True so helpers can parse stdout
        interactive: bool = False,
    ) -> subprocess.CompletedProcess:
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

    def is_running_id(self, node_id: str) -> bool:
        """
        Return True if the runtime instance identified by node_id exists and is running.

        ContainerRuntime: node_id is a docker container name like "clab-<lab>-<node>"
        VMRuntime (future): node_id could be VM name/uuid, etc.
        """
        raise NotImplementedError


class ContainerRuntime(Runtime):
    def node_id(self, lab: str, node: str) -> str:
        return f"clab-{lab}-{node}"

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
        c = self.node_id(lab, node)

        argv: list[str] = ["docker", "exec"]
        if interactive:
            # interactive calls should not capture output (TTY behavior)
            argv += ["-it"]
            argv += [c, *cmd]
            # Ensure we don't accidentally depend on stdout/stderr for interactive calls
            return run(argv, check=check, capture_output=False)

        argv += [c, *cmd]

        # Non-interactive calls: capture output by default so scenario helpers can parse stdout
        # (e.g., ip route snapshots for deterministic restoration after link up)
        return run(argv, check=check, capture_output=capture_output)


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


def get_runtime(topo: dict[str, Any] | None = None) -> Runtime:
    """
    Decide runtime. For now:
      - default: container
      - allow future extension: topo['runtime'] or node['runtime'] (not required yet)
    """
    return ContainerRuntime()

# -------------------------
# Commands
# -------------------------

def cmd_test(args: argparse.Namespace) -> None:
    """
    v1 update (Section C): Scenarios wired into cmd_test (minimal invasive).

    - Default behavior unchanged: readiness + optional BGP + declared tests (steady-state).
    - Opt-in scenarios:
        * netsim test --scenario <id>
        * netsim test --all-scenarios
      When a scenario is requested, cmd_test executes ONLY the requested scenario(s).
      Scenario steps call existing atomic tests via `run: <test_name>`.

    Hard guardrail:
      If scenarios are requested, validate ALL scenario run refs up-front and FAIL FAST
      (before any runtime actions) if a referenced atomic test name does not exist.
    """
    import json
    import time

    lab = args.lab
    filter_name: str | None = getattr(args, "name", None)
    filter_kind: str | None = getattr(args, "kind", None)
    keep_going: bool = bool(getattr(args, "keep_going", False))
    print_json: bool = bool(getattr(args, "json", False))

    # Scenario CLI (opt-in)
    scenario_id: str | None = getattr(args, "scenario", None)
    all_scenarios: bool = bool(getattr(args, "all_scenarios", False))
    scenario_verbose: bool = bool(getattr(args, "scenario_verbose", False))
    want_scenarios = bool(scenario_id or all_scenarios)

    started_at = time.time()

    # =============================================================================
    # 0) Load & validate the resolved topology that created this lab
    # =============================================================================
    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    # -----------------------------------------------------------------------------
    # Hard guardrail: validate scenario run refs up-front (no partial execution)
    # This MUST happen before ANY runtime actions (docker/VM exec, faults, waits, etc.)
    # -----------------------------------------------------------------------------
    if want_scenarios:
        scenario_ids: list[str] | None = None
        if scenario_id:
            scenario_ids = [scenario_id]
        elif all_scenarios:
            scenario_ids = None  # validate all
        validate_scenario_run_refs_or_die(topo, scenario_ids=scenario_ids)

    # Disallow filters when running scenarios: avoids silent "pass" with 0 executed runs
    if want_scenarios and (filter_name or filter_kind):
        die("ERROR: --name/--kind filters are not supported with --scenario/--all-scenarios (would skip scenario run steps).")

    # Phase-1 runtime abstraction (container today, VM later)
    rt = get_runtime(topo)

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
            "resolved_topology_path": str(tpath),
            "resolved_topology_mtime": tpath.stat().st_mtime,
            "scenario": scenario_id or "",
            "all_scenarios": bool(all_scenarios),
        },
        "tests": [],
        "scenarios": [],
        "events": [],
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

    def record_event_test_run(
        *,
        scenario_id: str,
        step_index: int,
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
            "type": "scenario_test_run",
            "scenario_id": scenario_id,
            "step": int(step_index),
            "name": name,
            "kind": kind,
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": int(duration_ms),
            "error": error,
        }
        if meta:
            rec["meta"] = meta
        results["events"].append(rec)

    def write_results() -> None:
        out = lab_dir(lab) / "results.json"
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote: {out}")

        summary_path = write_test_summary_artifact(lab, results)
        print(f"Wrote: {summary_path}")

        if print_json:
            print(json.dumps(results, indent=2))

    def retry_until(timeout_s: int, interval_s: float, fn) -> tuple[bool, object, int, int]:
        """
        Returns: ok, last_val, attempts, duration_ms
        Deterministic polling interval; no jitter; no hidden retries beyond caller request.
        """
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
            if time.time() - start >= timeout_s:
                dur_ms = int((time.time() - start) * 1000)
                return False, last_val, attempts, dur_ms
            time.sleep(interval_s)

    def fail_or_continue(msg: str) -> None:
        if keep_going:
            print(f"ERROR: {msg}")
            return
        die(msg)

    def node_ip_or_die(node_name: str) -> str:
        ip = node_first_ipv4(topo, node_name)
        if not ip:
            die(f"TEST FAIL: could not determine IPv4 for node '{node_name}'")
        return ip

    # TCP listeners we started (for deterministic cleanup)
    listeners_started: dict[str, set[int]] = {}

    def start_listener(dst: str, port: int) -> None:
        listeners_started.setdefault(dst, set())
        if port in listeners_started[dst]:
            return
        start_tcp_listener(rt, lab, dst, port)
        listeners_started[dst].add(port)

    # -----------------------------
    # Atomic test execution helpers
    # -----------------------------
    def run_ping_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> str:
        expected = (t.get("expect") or "pass").lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        # ---- destination resolution (v1-safe) ----
        # Prefer normalized fields from resolve_topology(), but support strict fallback too.
        dst_kind = t.get("_dst_kind")
        dst_value = t.get("_dst_value")

        override = t.get("dst_ip") or t.get("to_ip")

        if dst_kind == "ip":
            dst_ip = str(dst_value).strip()
            validate_ip_literal(dst_ip, f"test {test_name}")

        elif dst_kind == "node":
            # resolve node -> IP using your existing helper
            dst_ip = node_ip_or_die(str(dst_value))

        else:
            # Fallback (still strict): allow literal IP in dst; allow override only when dst is node
            if isinstance(dst, str) and is_ip_literal(dst.strip()):
                if override is not None:
                    die(f"test {test_name}: 'dst_ip/to_ip' not allowed when dst/to is already an IP literal")
                dst_ip = dst.strip()
                validate_ip_literal(dst_ip, f"test {test_name}")
            else:
                if override is not None:
                    if not isinstance(override, str) or not override.strip():
                        die(f"test {test_name}: 'dst_ip/to_ip' must be a non-empty IPv4/IPv6 literal")
                    dst_ip = override.strip()
                    validate_ip_literal(dst_ip, f"test {test_name}")
                else:
                    dst_ip = node_ip_or_die(dst)

        # ---- execution ----
        count = int(t.get("count") or 2)
        timeout_s = int(t.get("timeout_s") or 15)
        interval_s = float(t.get("retry_interval_s") or 1.0)

        def attempt():
            cp = rt.exec(lab, src, ["ping", "-c", str(count), "-W", "1", dst_ip], check=False)
            return (cp.returncode == 0), cp

        ok, last_cp, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        record_fn(
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

        return verdict

    def run_tcp_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> str:
        expected = (t.get("expect") or "pass").lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        port = t.get("port")
        if not isinstance(port, int):
            record_fn(
                name=test_name,
                kind="tcp",
                src=src,
                dst=dst,
                expected=expected,
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error="'port' must be an int",
                meta={"port": port},
            )
            return "fail"

        dst_ip = node_ip_or_die(dst)
        listener = bool(t.get("listener", True))
        if listener:
            start_listener(dst, port)

        timeout_s = int(t.get("timeout_s") or (10 if expected == "pass" else 0))
        interval_s = float(t.get("retry_interval_s") or 1.0)

        def attempt():
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            return (cp.returncode == 0), cp

        start = time.time()
        if expected == "pass" and timeout_s > 0:
            ok, last_cp, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        else:
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            ok, last_cp, attempts = (cp.returncode == 0), cp, 1
            dur_ms = int((time.time() - start) * 1000)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        record_fn(
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
        return verdict


    # Build name->test map once (authoritative declared tests)
    declared_tests = topo.get("tests", []) or []
    tests_by_name: dict[str, dict] = {}
    for idx, t in enumerate(declared_tests):
        if isinstance(t, dict) and t.get("name"):
            tests_by_name[str(t["name"])] = t

    def run_named_test(ref: str, *, scenario_ctx: tuple[str, int] | None = None) -> str:
        """
        Execute a declared atomic test by name (used by scenarios).
        Returns: "pass" | "fail"
        """
        if ref not in tests_by_name:
            # With fail-fast validation, this should never happen.
            die(f"INTERNAL ERROR: scenario referenced unknown test '{ref}' after pre-validation")

        t = tests_by_name[ref]

        # Apply existing filters even for scenario-runs (minimal invasive, consistent behavior)
        kind = (t.get("kind") or t.get("type") or "").strip()
        if filter_name and ref != filter_name:
            return "pass"  # filtered-out: treat as non-executed (scenario still proceeds)
        if filter_kind and kind != filter_kind:
            return "pass"

        src = t.get("src")
        dst = t.get("dst")
        if not src or not dst:
            record_test(
                name=ref,
                kind=kind or "unknown",
                src=src or "",
                dst=dst or "",
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error="missing src/dst",
            )
            return "fail"

        record_fn = None
        if scenario_ctx:
            sid, step_idx = scenario_ctx
            record_fn = lambda **kw: record_event_test_run(scenario_id=sid, step_index=step_idx, **kw)

        if kind == "ping":
            if record_fn:
                return run_ping_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_ping_test(test_name=ref, src=src, dst=dst, t=t)

        if kind == "tcp":
            if record_fn:
                return run_tcp_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_tcp_test(test_name=ref, src=src, dst=dst, t=t)

        record_test(
            name=ref,
            kind=str(kind or "unknown"),
            src=src,
            dst=dst,
            expected="pass",
            observed="fail",
            verdict="fail",
            duration_ms=0,
            error=f"unsupported kind '{kind}' (supported: ping, tcp)",
        )
        return "fail"
    
    # Scenario fault state (per test run, in-memory only; deterministic)
    # key: (node, iface) -> list[str] of "ip route" lines to restore
    fault_state_routes_v4: dict[tuple[str, str], list[str]] = {}

    def _clean_route_line(line: str) -> str:
        """
        Remove transient/non-authoritative tokens from `ip route show` output so we can
        deterministically restore routes after interface flaps.
        """
        s = line.strip()

        # Remove transient kernel status tokens
        # e.g. "via 10.0.0.2 linkdown" -> "via 10.0.0.2"
        s = re.sub(r"\s+linkdown\b", "", s)

        # Remove optional fields that can vary and aren't needed for restore
        # Examples:
        #   "proto bgp" / "proto static"
        #   "metric 20"
        #   "src 10.0.0.3"
        #   "pref medium" (rare)
        s = re.sub(r"\s+proto\s+\S+", "", s)
        s = re.sub(r"\s+metric\s+\d+", "", s)
        s = re.sub(r"\s+src\s+\S+", "", s)
        s = re.sub(r"\s+pref\s+\S+", "", s)

        # Collapse whitespace to keep stable splitting
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def _snapshot_v4_via_routes(node: str, iface: str) -> list[str]:
        """
        Capture interface-scoped *via* routes that Linux may remove when iface goes down.
        Deterministic: exact command, stable filtering + sanitization.
        """
        cp = rt.exec(lab, node, ["ip", "-4", "route", "show", "dev", str(iface)], check=False)
        out = (cp.stdout or "") if hasattr(cp, "stdout") else ""
        lines: list[str] = []

        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue

            # Only restore routed entries (not connected proto kernel routes)
            if " via " not in f" {line} ":
                continue

            # Ignore cached/temporary artifacts if present
            if line.endswith(" cache") or " cache " in line:
                continue

            cleaned = _clean_route_line(line)
            if cleaned:
                lines.append(cleaned)

        return sorted(set(lines))

    def _restore_v4_routes(node: str, routes: list[str]) -> None:
        """
        Restore routes using `ip -4 route replace <route-line>`.
        Best-effort but deterministic: run in sorted order, no retries.
        """
        for r in sorted(set(routes)):
            rt.exec(lab, node, ["ip", "-4", "route", "replace"] + r.split(), check=False)

    def _find_link_interfaces_from_topology(topo: dict, a: str, b: str) -> tuple[str | None, str | None]:
        """
        Deterministically resolve interface names for a<->b from topo["links"].

        Expects links like:
        - endpoints: ["r2:eth2", "fw1:eth1"]
        """
        links = topo.get("links", []) or []
        for link in links:
            if not isinstance(link, dict):
               continue
            eps = link.get("endpoints") or []
            if not (isinstance(eps, list) and len(eps) == 2):
                continue

            def split_ep(ep: object) -> tuple[str | None, str | None]:
                if not isinstance(ep, str) or ":" not in ep:
                    return None, None
                n, i = ep.split(":", 1)
                return n.strip(), i.strip()

            n1, i1 = split_ep(eps[0])
            n2, i2 = split_ep(eps[1])

            if not n1 or not n2 or not i1 or not i2:
                continue

            if (n1 == a and n2 == b):
                return i1, i2
            if (n1 == b and n2 == a):
                return i2, i1

        return None, None

    def _find_link_interfaces(a: str, b: str) -> tuple[str | None, str | None]:
    # Prefer authoritative topo["links"] parsing (most reliable)
        a_if, b_if = _find_link_interfaces_from_topology(topo, a, b)
        if a_if and b_if:
            return a_if, b_if

    # Fallback: best-effort from build_node_links() if present
        a_if = None
        b_if = None
        for l in links_by_node.get(a, []) or []:
            if l.get("peer") == b:
                a_if = l.get("ifname") or l.get("iface") or l.get("interface")
                b_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                break
        if b_if is None:
            for l in links_by_node.get(b, []) or []:
                if l.get("peer") == a:
                    b_if = l.get("ifname") or l.get("iface") or l.get("interface")
                    if a_if is None:
                        a_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                    break
        return a_if, b_if

    def apply_fault(
        fault: dict,
        *,
        fault_state_routes_v4: dict[tuple[str, str], list[str]],
    ) -> tuple[str, str, dict]:
        """
        Returns: (action, target_label, meta)
        meta includes restored_routes for link_up/interface_up
        """

        def _iface_down(node: str, iface: str) -> None:
            key = (node, iface)
            fault_state_routes_v4[key] = _snapshot_v4_via_routes(node, iface)
            rt.exec(lab, node, ["ip", "link", "set", "dev", str(iface), "down"], check=False)

        def _iface_up(node: str, iface: str) -> int:
            rt.exec(lab, node, ["ip", "link", "set", "dev", str(iface), "up"], check=False)
            key = (node, iface)
            routes = fault_state_routes_v4.get(key) or []
            if routes:
                _restore_v4_routes(node, routes)
            return len(routes)

        if "link_down" in fault or "link_up" in fault:
            action = "link_down" if "link_down" in fault else "link_up"
            spec = fault.get(action) or {}
            a = spec.get("a")
            b = spec.get("b")
            if not a or not b:
                raise ValueError(f"{action}: requires a,b")

            a_if, b_if = _find_link_interfaces(a, b)
            if not a_if or not b_if:
                raise ValueError(f"{action}: could not determine interfaces for link {a}<->{b}")

            if action == "link_down":
                _iface_down(a, a_if)
                _iface_down(b, b_if)
                return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": 0}

            ra = _iface_up(a, a_if)
            rb = _iface_up(b, b_if)
            return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": (ra + rb)}

        if "interface_down" in fault or "interface_up" in fault:
            action = "interface_down" if "interface_down" in fault else "interface_up"
            spec = fault.get(action) or {}
            node = spec.get("node")
            iface = spec.get("if") or spec.get("iface") or spec.get("interface")
            if not node or not iface:
                raise ValueError(f"{action}: requires node + if")

            if action == "interface_down":
                _iface_down(node, str(iface))
                return action, f"{node}:{iface}", {"restored_routes": 0}

            r = _iface_up(node, str(iface))
            return action, f"{node}:{iface}", {"restored_routes": r}

        if "node_stop" in fault or "node_start" in fault:
            action = "node_stop" if "node_stop" in fault else "node_start"
            spec = fault.get(action) or {}
            node = spec.get("node")
            if not node:
                raise ValueError(f"{action}: requires node")
            fn_name = "node_stop" if action == "node_stop" else "node_start"
            if not hasattr(rt, fn_name):
                raise ValueError(f"{action}: runtime does not implement {fn_name}() yet")
            getattr(rt, fn_name)(lab, node)  # type: ignore[misc]
            return action, str(node), {"restored_routes": 0}

        raise ValueError(f"unsupported fault primitive: {list(fault.keys())}")

    def wait_seconds(seconds: int) -> int:
        start = time.time()
        time.sleep(max(0, int(seconds)))
        return int((time.time() - start) * 1000)

    def wait_for_predicate(wait_for: dict) -> tuple[str, str, str, int, dict, str]:
        """
        Returns: (type, expected, observed, duration_ms, meta, verdict)

        v1 supports:
        - type: ping (from/to/expect/timeout)

        Semantics:
        - expect: pass => succeed when ping succeeds
        - expect: fail => succeed when ping fails
        """
        wtype = wait_for.get("type")
        if wtype != "ping":
            raise ValueError(f"wait_for: unsupported type '{wtype}' (v1 supports: ping)")

        src = wait_for.get("from")
        to = wait_for.get("to")
        expected = (wait_for.get("expect") or "pass").lower()
        timeout_s = int(wait_for.get("timeout") or 30)
        interval_s = float(wait_for.get("interval_s") or 1.0)

        if expected not in ("pass", "fail"):
            expected = "pass"
        if not src or not to:
            raise ValueError("wait_for ping: requires from + to")

        # If "to" looks like a node name, resolve to its first IPv4
        dst_ip = None
        if isinstance(to, str):
            ip = node_first_ipv4(topo, to)
            dst_ip = ip if ip else to
        else:
            dst_ip = str(to)

        should_succeed = (expected == "pass")

        def attempt():
            cp = rt.exec(
                lab,
                str(src),
                ["ping", "-c", "1", "-W", "1", str(dst_ip)],
                check=False,
            )
            ping_ok = (cp.returncode == 0)

            # Condition is met when ping_ok matches what we expect
            condition_met = (ping_ok == should_succeed)
            return condition_met, (cp, ping_ok)

        ok, last_val, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        cp, ping_ok = last_val  # type: ignore[misc]

        observed = "pass" if ping_ok else "fail"
        verdict = "pass" if ok else "fail"

        meta = {
            "from": str(src),
            "to": str(to),
            "dst_ip": str(dst_ip),
            "attempts": attempts,
            "timeout_s": timeout_s,
            "interval_s": interval_s,
            "last_rc": getattr(cp, "returncode", None),
        }
        return "ping", expected, observed, dur_ms, meta, verdict

    def run_scenario(s: dict) -> str:
        sid = s.get("id") or ""
        desc = s.get("description") or ""
        steps = s.get("steps", []) or []
        scen_started = time.time()

        scen_rec: dict = {
            "id": sid,
            "description": desc,
            "steps": [],
            "verdict": "unknown",
            "duration_ms": None,
        }

        def scen_step(rec: dict) -> None:
            scen_rec["steps"].append(rec)

        # Optional: set this earlier from CLI flag:
        # use the parsed flag from cmd_test scope
        # (assumes scenario_verbose variable exists above)

        def _sv(msg: str) -> None:
            if scenario_verbose:
                print(msg)

        scen_failed = False

        for step_idx, step in enumerate(steps, start=1):
            step_started = time.time()

            if not isinstance(step, dict):
                scen_step({
                    "type": "invalid",
                    "verdict": "fail",
                    "duration_ms": 0,
                    "error": "step must be a dict",
                    "step": step_idx,
                })
                _sv(f"[scenario {sid}] {step_idx:02d}. invalid step (not a dict)")
                scen_failed = True
                if not keep_going:
                    break
                continue

            # -------------------------
            # run: <test_name>
            # -------------------------
            if "run" in step:
                ref = step.get("run")
                if not isinstance(ref, str) or not ref:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "run",
                        "ref": str(ref),
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "run must be a non-empty string",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref!r} -> FAIL (invalid ref)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref}")
                verdict = run_named_test(ref, scenario_ctx=(sid, step_idx))  # <-- IMPORTANT
                dur_ms = int((time.time() - step_started) * 1000)

                scen_step({
                    "type": "run",
                    "ref": ref,
                    "verdict": verdict,
                    "duration_ms": dur_ms,
                    "step": step_idx,
                })

                _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref} -> {verdict.upper()} ({dur_ms}ms)")
                if verdict != "pass":
                    scen_failed = True
                    if not keep_going:
                        break
                continue

            # -------------------------
            # fault: { ... }
            # -------------------------
            if "fault" in step:
                fault = step.get("fault")
                if not isinstance(fault, dict):
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "fault must be a dict",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL (fault not a dict)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                try:
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault apply")

                    action, target, meta = apply_fault(
                        fault,
                        fault_state_routes_v4=fault_state_routes_v4,
                    )
                    dur_ms = int((time.time() - step_started) * 1000)

                    scen_step({
                        "type": "fault",
                        "action": action,
                        "target": target,
                        "verdict": "pass",
                        "duration_ms": dur_ms,
                        "step": step_idx,
                        "meta": meta,
                    })

                    note = ""
                    if action in ("link_up", "interface_up"):
                        note = f" (restored_routes={int((meta or {}).get('restored_routes') or 0)})"

                    _sv(
                        f"[scenario {sid}] {step_idx:02d}. fault action={action} target={target}{note} -> PASS ({dur_ms}ms)"
                    )

                except Exception as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": str(e),
                        "fault": fault,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL ({e})")
                    scen_failed = True
                    if not keep_going:
                        break

                continue
            # -------------------------
            # wait: {seconds: N}
            # -------------------------
            if "wait" in step:
                w = step.get("wait") or {}
                seconds = int((w.get("seconds") or 0))
                _sv(f"[scenario {sid}] {step_idx:02d}. wait seconds={seconds}")
                dur_ms = wait_seconds(seconds)

                scen_step({
                    "type": "wait",
                    "seconds": seconds,
                    "verdict": "pass",
                    "duration_ms": dur_ms,
                    "step": step_idx,
                })
                _sv(f"[scenario {sid}] {step_idx:02d}. wait -> PASS ({dur_ms}ms)")
                continue

            # -------------------------
            # wait_for: { ... }
            # -------------------------
            if "wait_for" in step:
                wf = step.get("wait_for")
                if not isinstance(wf, dict):
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "wait_for must be a dict",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for -> FAIL (not a dict)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                try:
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for")
                    wtype, expected, observed, dur_ms, meta, verdict = wait_for_predicate(wf)

                    scen_step({
                        "type": "wait_for",
                        "wait_type": wtype,
                        "expected": expected,
                        "observed": observed,
                        "verdict": verdict,
                        "duration_ms": dur_ms,
                        "meta": meta,
                        "step": step_idx,
                    })

                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for type={wtype} expected={expected} observed={observed} -> {verdict.upper()} ({dur_ms}ms)")

                    if verdict != "pass":
                        scen_failed = True
                        if not keep_going:
                            break

                except Exception as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": str(e),
                        "wait_for": wf,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for -> FAIL ({e})")
                    scen_failed = True
                    if not keep_going:
                        break
                continue

            # -------------------------
            # unknown step
            # -------------------------
            dur_ms = int((time.time() - step_started) * 1000)
            scen_step({
                "type": "unknown",
                "verdict": "fail",
                "duration_ms": dur_ms,
                "error": f"unsupported step keys: {list(step.keys())}",
                "step": step_idx,
            })
            _sv(f"[scenario {sid}] {step_idx:02d}. unknown -> FAIL (unsupported keys)")
            scen_failed = True
            if not keep_going:
                break

        scen_finished = time.time()
        scen_rec["duration_ms"] = int((scen_finished - scen_started) * 1000)
        scen_rec["verdict"] = "fail" if scen_failed else "pass"
        results["scenarios"].append(scen_rec)
        return scen_rec["verdict"]

    # =============================================================================
    # 1) Verify all nodes are running (hard prerequisite for everything else)
    # =============================================================================
    for n in nodes:
        name = n["name"]
        if not rt.is_running(lab, name):
            record_test(
                name="prereq:node-running",
                kind="prereq",
                src="",
                dst=name,
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error=f"{name} is not running",
            )
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
            results["summary"]["total"] = len(results["tests"])
            results["summary"]["passed"] = 0
            results["summary"]["failed"] = len(results["tests"])
            write_results()
            die(f"{name} is not running")

    # =============================================================================
    # 2) Node readiness gate (no control-plane assumptions yet)
    # =============================================================================
    try:
        verify_lab_ready(rt, topo, lab)
    except SystemExit:
        results["result"] = "fail"
        finished_at = time.time()
        results["summary"]["finished_at"] = finished_at
        results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
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
                wait_for_bgp(rt, lab, n["name"], timeout=30)
        except SystemExit:
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
            write_results()
            raise

    # =============================================================================
    # 4) Scenarios (opt-in) OR Declared tests (default)
    # =============================================================================
    scenarios = topo.get("scenarios", []) or []

    try:
        if want_scenarios:
            if not scenarios:
                record_test(
                    name="scenarios:none-defined",
                    kind="scenario",
                    src="",
                    dst="",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="no scenarios defined in topology (missing top-level 'scenarios:')",
                )
                fail_or_continue("No scenarios defined in topology")
            else:
                if all_scenarios:
                    selected = [s for s in scenarios if isinstance(s, dict)]
                else:
                    selected = [s for s in scenarios if isinstance(s, dict) and s.get("id") == scenario_id]

                if not selected:
                    record_test(
                        name="scenarios:not-found",
                        kind="scenario",
                        src="",
                        dst="",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"scenario id not found: {scenario_id!r}",
                    )
                    fail_or_continue(f"Scenario not found: {scenario_id!r}")
                else:
                    for s in selected:
                        sid = s.get("id") or "<unknown>"
                        verdict = run_scenario(s)
                        if verdict != "pass":
                            fail_or_continue(f"Scenario FAIL: {sid}")

        else:
            # Default behavior: run declared tests (steady-state)
            if not declared_tests:
                results["result"] = "pass"
                finished_at = time.time()
                results["summary"]["finished_at"] = finished_at
                results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
                results["summary"]["total"] = 0
                results["summary"]["passed"] = 0
                results["summary"]["failed"] = 0
                write_results()
                print("✅ TEST PASS: nodes running" + (" + BGP OK" if bgp_participants else ""))
                return

            matched = 0
            for idx, t in enumerate(declared_tests):
                i = idx + 1
                test_name = t.get("name") if isinstance(t, dict) else None
                if not test_name:
                    test_name = f"tests[{i}]"

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

                if filter_kind and kind != filter_kind:
                    continue

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

                if kind == "ping":
                    verdict = run_ping_test(test_name=test_name, src=src, dst=dst, t=t)
                    if verdict != "pass":
                        fail_or_continue(f"tests[{i}] ping mismatch: {src} -> {dst} expected {t.get('expect','pass')}")
                    continue

                verdict = run_tcp_test(test_name=test_name, src=src, dst=dst, t=t)
                if verdict != "pass":
                    port = t.get("port")
                    fail_or_continue(f"tests[{i}] tcp mismatch: {src} -> {dst}:{port} expected {t.get('expect','pass')}")

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

    finally:
        # Always stop any listeners we started (deterministic cleanup)
        for dst_node in listeners_started.keys():
            rt.exec(lab, dst_node, ["sh", "-lc", 'pkill -f "nc.*-p" 2>/dev/null || true'], check=False)

        finished_at = time.time()
        results["summary"]["finished_at"] = finished_at
        results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)

        # Atomic tests are authoritative (results["tests"])
        total = len(results["tests"])
        failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
        passed_count = total - failed_count

        results["summary"]["total"] = total
        results["summary"]["passed"] = passed_count
        results["summary"]["failed"] = failed_count

        # If scenarios were requested and any scenario failed but no atomic test recorded failure,
        # mark overall fail by injecting a visibility record.
        scenario_failed = any(s.get("verdict") == "fail" for s in (results.get("scenarios") or []))
        if want_scenarios and scenario_failed and failed_count == 0:
            record_test(
                name="scenarios:verdict",
                kind="scenario",
                src="",
                dst="",
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error="one or more scenarios failed (see results.scenarios)",
            )
            total = len(results["tests"])
            failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
            passed_count = total - failed_count
            results["summary"]["total"] = total
            results["summary"]["passed"] = passed_count
            results["summary"]["failed"] = failed_count

        results["result"] = "fail" if results["summary"]["failed"] > 0 else "pass"
        write_results()

    # =============================================================================
    # 5) Success output (human-friendly)
    # =============================================================================
    if results["result"] == "fail":
        die(f"TEST FAIL: {results['summary']['failed']} failed / {results['summary']['total']} total")

    if bgp_participants:
        print(f"✅ Control-plane PASS: BGP established ({len(bgp_participants)} participants)")

    if want_scenarios:
        passed_s = sum(1 for s in results["scenarios"] if s.get("verdict") == "pass")
        total_s = len(results["scenarios"])
        print(f"✅ Scenarios PASS ({passed_s}/{total_s})")

        # Scenario-only runs record atomic invocations under results["events"]
        event_runs = [
            e for e in (results.get("events") or [])
            if e.get("type") == "scenario_test_run"
        ]
        ev_pass = sum(1 for e in event_runs if e.get("verdict") == "pass")
        ev_total = len(event_runs)
        print(f"✅ Scenario test runs PASS ({ev_pass}/{ev_total})")
    else:
        print(f"✅ Declared tests PASS ({results['summary']['passed']} checks)")

    print("✅ TEST PASS: containers running + checks OK")

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
    # Scenario step breakdown (human-only, best-effort, non-authoritative)
    # -------------------------------------------------------------------------
    if scenarios:
        lines.append("scenario_steps:")
        for s in scenarios:
            sid = s.get("id", "<unnamed>")
            sverdict = s.get("verdict", "unknown")
            sdur = s.get("duration_ms")
            if sdur is None:
                header = f" - {sid} verdict={sverdict}"
            else:
                header = f" - {sid} verdict={sverdict} duration_ms={int(sdur)}"
            lines.append(header)

            steps = s.get("steps", []) or []
            for idx0, st in enumerate(steps, start=1):
                idx = int(st.get("step") or idx0)
                stype = st.get("type", "unknown")
                sdur2 = st.get("duration_ms")
                sdur_str = f"{int(sdur2)}ms" if sdur2 is not None else "?"
                sv = st.get("verdict")
                sv_str = f" verdict={sv}" if sv else ""

                if stype == "run":
                    ref = st.get("ref", "<missing-ref>")
                    lines.append(f"   {idx:02d}. run ref={ref}{sv_str} duration={sdur_str}")

                elif stype == "wait_for":
                    wtype = st.get("wait_type", "<missing-wait_type>")
                    expected = st.get("expected")
                    observed = st.get("observed")
                    eo = ""
                    if expected is not None or observed is not None:
                        eo = f" expected={expected} observed={observed}"
                    lines.append(f"   {idx:02d}. wait_for type={wtype}{eo}{sv_str} duration={sdur_str}")

                elif stype == "fault":
                    action = st.get("action", "<missing-action>")
                    target = st.get("target", "")
                    tgt = f" target={target}" if target else ""

                    note = ""
                    if action in ("link_up", "interface_up"):
                        meta = st.get("meta") or {}
                        rr_raw = meta.get("restored_routes")
                        try:
                            rr = int(rr_raw or 0)
                        except Exception:
                            rr = 0
                        note = f" (restored_routes={rr})"

                    lines.append(
                        f"   {idx:02d}. fault action={action}{tgt}{note}{sv_str} duration={sdur_str}"
                    )

                elif stype == "wait":
                    seconds = st.get("seconds")
                    sec = f" seconds={seconds}" if seconds is not None else ""
                    lines.append(f"   {idx:02d}. wait{sec}{sv_str} duration={sdur_str}")

                else:
                    lines.append(f"   {idx:02d}. {stype}{sv_str} duration={sdur_str}")

    return "\n".join(lines) + "\n"

def write_test_summary_artifact(lab: str, results: dict) -> Path:
    out = lab_dir(lab) / "results.summary.txt"
    out.write_text(_format_test_summary(results), encoding="utf-8")
    return out

def cmd_gen(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    out = write_containerlab_file(topo_path)
    print(f"Generated containerlab file: {out}")

def cmd_up(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # If --reconfigure: destroy + remove root-owned lab dir FIRST.
    if getattr(args, "reconfigure", False):
        lab_name: str | None = None
        try:
            topo_for_name = load_yaml(topo_path)
            lab_name = (topo_for_name or {}).get("name")
        except Exception:
            lab_name = None

        if isinstance(lab_name, str) and lab_name.strip():
            lab_name = lab_name.strip()
            existing_clab = LABS_DIR / f"{lab_name}.clab.yaml"
            if existing_clab.exists():
                run(["sudo", "containerlab", "destroy", "-t", str(existing_clab)], check=False)

            # containerlab creates labs/clab-<lab> as root; remove it as root
            run(["sudo", "rm", "-rf", str(lab_dir(lab_name))], check=False)

    # Generate AFTER destroy/cleanup
    out = write_containerlab_file(topo_path)

    # Deploy
    run(["sudo", "containerlab", "deploy", "-t", str(out)])

    # Derive lab name deterministically from generated file
    lab_name = out.name.replace(".clab.yaml", "")

    # Load resolved topology (authoritative for provisioning)
    resolved_path = lab_dir(lab_name) / "topology.resolved.yaml"
    if not resolved_path.exists():
        die(f"Resolved topology not found after deploy: {resolved_path}")

    topo = load_yaml(resolved_path) or {}

    # Runtime is created AFTER topology is known (future-proof for vm/container selection)
    rt = get_runtime(topo)

    # ---------------------------------------------------------------------
    # Provisioning (runtime-driven)
    # ---------------------------------------------------------------------

    # 1) Hosts (IPs + default route)
    configure_hosts_from_topology(rt, lab_name, topo)

    # 2) nft-fw interface IPs + forwarding (NO nft rules here)
    configure_nftfw_from_topology(rt, lab_name, topo)

    # 3) nft-fw static routes
    configure_nftfw_routes_from_topology(rt, lab_name, topo)

    # 4) nft rules last (so forwarding + routes exist first)
    for n in topo.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        if n.get("type") != "nft-fw":
            continue

        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            die("nft-fw node missing 'name'")
        name = name.strip()

        # Apply nft rules
        nft_fw_apply(rt, lab_name, name, gen_nft_fw_rules(n))

        # Routed fw readiness only if it has next-hops (derived from links)
        nhs = fw_next_hops_from_links(topo, name)
        if nhs:
            verify_fw_routed_ready(rt, lab_name, name)

    # 5) FRR provisioning
    configure_frr_interfaces_from_topology(rt, lab_name, topo)
    configure_frr_static_routes_from_topology(rt, lab_name, topo)
    configure_frr_bgp_from_topology(rt, lab_name, topo)

def cmd_down(args: argparse.Namespace) -> None:
    out = lab_file_from_name(args.name)
    if not out.exists():
        die(f"Lab file not found: {out} (did you run gen/up first?)")
    run(["sudo", "containerlab", "destroy", "-t", str(out)])

def cmd_exec(args: argparse.Namespace) -> None:
    rt = get_runtime()

    if not args.command:
        # Interactive shell (runtime decides how)
        cp = rt.exec(args.lab, args.node, ["bash"], check=False, capture_output=False, interactive=True)
        return

    cp = rt.exec(args.lab, args.node, args.command, check=False, capture_output=False)
    if cp.returncode != 0:
        die(f"Command failed inside {rt.node_id(args.lab, args.node)} (exit {cp.returncode})",
            code=cp.returncode)

def cmd_vty(args: argparse.Namespace) -> None:
    rt = get_runtime()

    # command is provided as a single string; e.g. "show bgp summary"
    cp = vty(rt, args.lab, args.node, args.command)

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

def _fmt_list_cap(items: list[str], cap: int = 5) -> str:
    """
    Deterministically render a list with a cap:
      ["a","b","c","d","e","f"] -> "a, b, c, d, e (+1 more)"
    """
    items = [str(x) for x in items if str(x)]
    items = sorted(set(items))
    if not items:
        return ""
    if len(items) <= cap:
        return ", ".join(items)
    head = ", ".join(items[:cap])
    return f"{head} (+{len(items) - cap} more)"

def cmd_status(args: argparse.Namespace) -> None:
    """
    Read-only lab status.

    - Default: human-friendly output.
    - --json: machine output only (no "+ docker ..." command echoes).
    - --bgp: intent-aware BGP checks (expected from topology.resolved.yaml).
      * tries `show bgp summary json` first, falls back to text summary parsing
    - --routes: intent-aware route presence checks (read-only), derived from topology.resolved.yaml.
    - Exit code changes ONLY with --strict (per design contract).

    Improvements in this version:
      1) Human --summary prints reliably.
      2) Human mismatch lines include parser mode (parser=json|text|none).
      3) In --strict, containers not running are treated as prerequisite failures,
         producing deterministic reasons like:
           "container not running: r2 (container=clab-<lab>-r2)"
    """
    import json
    rt = get_runtime()
    lab = args.lab

    bgp_enabled = bool(getattr(args, "bgp", False))
    bgp_verbose = bool(getattr(args, "bgp_verbose", False))
    strict = bool(getattr(args, "strict", False))
    show_intf = bool(getattr(args, "interfaces", False))
    show_summary = bool(getattr(args, "summary", False))
    as_json = bool(getattr(args, "json", False))

    routes_enabled = bool(getattr(args, "routes", False))
    routes_verbose = bool(getattr(args, "routes_verbose", False))

    # Suppress "+ <cmd>" echoes during JSON mode (so JSON is clean)
    global QUIET_RUN
    old_quiet = QUIET_RUN
    if as_json:
        QUIET_RUN = True

    try:
        topo = _load_resolved_topology(lab)
        nodes = sorted(_iter_nodes(topo), key=lambda n: str(n.get("name", "")))

        expected_bgp_by_node = derive_expected_bgp_neighbors_from_links(topo)
        expected_routes_by_frr = derive_expected_routes_for_frr(topo) if routes_enabled else {}

        def _node_exec(node: str, cmd: list[str]) -> str:
            cp = rt.exec(lab, node, cmd, check=False, capture_output=True)
            out = cp.stdout.decode("utf-8", errors="replace") if isinstance(cp.stdout, bytes) else cp.stdout
            return (out or "").strip()

        # Deterministic list formatting helper (cap for readability)
        def _fmt_list_cap(items: list[str], cap: int = 5) -> str:
            items = sorted(set(str(x) for x in items if str(x)))
            if not items:
                return ""
            if len(items) <= cap:
                return ", ".join(items)
            return f"{', '.join(items[:cap])} (+{len(items) - cap} more)"

        def _extend_bgp_reasons(node: str, bgp: dict[str, Any], reasons_list: list[str], cap: int = 5) -> None:
            if not bgp.get("expected"):
                return
            mode = str(bgp.get("parser_mode") or "none")

            if bgp.get("missing"):
                reasons_list.append(
                    f"bgp missing on {node}: {_fmt_list_cap(bgp['missing'], cap)} (parser={mode})"
                )
            if bgp.get("down"):
                reasons_list.append(
                    f"bgp down on {node}: {_fmt_list_cap(bgp['down'], cap)} (parser={mode})"
                )
            if bgp.get("extra"):
                reasons_list.append(
                    f"bgp extra on {node}: {_fmt_list_cap(bgp['extra'], cap)} (parser={mode})"
                )

        def _extend_routes_reasons(node: str, routes: dict[str, Any], reasons_list: list[str], cap: int = 5) -> None:
            if not routes.get("expected"):
                return
            mode = str(routes.get("parser_mode") or "none")
            if routes.get("missing"):
                reasons_list.append(
                    f"routes missing on {node}: {_fmt_list_cap(routes['missing'], cap)} (parser={mode})"
                )

        def _extend_container_reasons(
            down_nodes: list[tuple[str, str]],
            reasons_list: list[str],
            cap: int = 5,
        ) -> None:
            """
            down_nodes: [(node_name, container_name), ...]
            Deterministic, capped reasons for prerequisite failures.
            """
            if not down_nodes:
                return
            # Deterministic order
            down_nodes = sorted(set(down_nodes), key=lambda t: (t[0], t[1]))
            rendered = [f"{n} (container={c})" for (n, c) in down_nodes]
            reasons_list.append(f"containers not running: {_fmt_list_cap(rendered, cap)}")

        # Counters
        total_nodes = 0
        running_nodes = 0
        exp_total_peers = 0
        exp_established_peers = 0
        frr_nodes_with_expected_peers = 0
        routes_total_prefixes = 0
        routes_present_prefixes = 0
        frr_nodes_with_expected_routes = 0

        strict_fail = False
        reasons: list[str] = []

        # Track container-down prereq failures deterministically
        down_containers: list[tuple[str, str]] = []

        out_doc: dict[str, Any] = {
            "schema_version": "1",
            "lab": lab,
            "nodes": [],
            "summary": {},
            "verdict": "pass",
            "reasons": [],
        }

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
            else:
                down_containers.append((name, cname))

            node_rec: dict[str, Any] = {
                "name": name,
                "type": ntype,
                "container": cname,
                "running": bool(running),
            }

            # Interfaces
            if running and show_intf:
                try:
                    node_rec["interfaces"] = _node_exec(name, ["sh", "-lc", "ip -br a"]).splitlines()
                except Exception as e:
                    node_rec["interfaces_error"] = str(e)

            # BGP
            if running and bgp_enabled and ntype == "frr":
                expected = expected_bgp_by_node.get(name, set())
                bgp_rec: dict[str, Any] = {
                    "expected": sorted(expected),
                    "observed": [],
                    "missing": [],
                    "down": [],
                    "extra": [],
                    "established": [],
                    "ok": True,
                    "parser_mode": "none",
                }

                try:
                    out_json = _node_exec(name, ["vtysh", "-c", "show bgp summary json"])
                    observed = parse_frr_bgp_summary_neighbors_json(out_json)
                    if observed:
                        bgp_rec["parser_mode"] = "json"
                    else:
                        out_text = _node_exec(name, ["vtysh", "-c", "show bgp summary"])
                        observed = parse_frr_bgp_summary_neighbors(out_text)
                        bgp_rec["parser_mode"] = "text"

                    cmp = compare_expected_vs_observed_bgp(expected, observed)
                    bgp_rec.update(cmp)

                    if expected:
                        frr_nodes_with_expected_peers += 1
                        exp_total_peers += len(expected)
                        exp_established_peers += len(cmp["established"])

                    if bgp_verbose and not as_json:
                        bgp_rec["raw_text"] = _node_exec(name, ["vtysh", "-c", "show bgp summary"])

                    if strict and expected and not bgp_rec["ok"]:
                        strict_fail = True
                        _extend_bgp_reasons(name, bgp_rec, reasons)

                except Exception as e:
                    bgp_rec["error"] = str(e)
                    bgp_rec["ok"] = False
                    if strict and expected:
                        strict_fail = True
                        reasons.append(
                            f"bgp error on {name}: {type(e).__name__} (parser={bgp_rec.get('parser_mode','none')})"
                        )

                node_rec["bgp"] = bgp_rec

            # ROUTES
            if running and routes_enabled and ntype == "frr":
                expected_routes = expected_routes_by_frr.get(name, set())
                routes_rec: dict[str, Any] = {
                    "expected": sorted(expected_routes),
                    "observed": [],
                    "missing": [],
                    "ok": True,
                    "parser_mode": "none",
                }

                try:
                    rt_json = _node_exec(name, ["vtysh", "-c", "show ip route json"])
                    observed = parse_frr_show_ip_route_prefixes_json(rt_json)
                    rt_text = ""
                    if observed:
                        routes_rec["parser_mode"] = "json"
                    else:
                        rt_text = _node_exec(name, ["vtysh", "-c", "show ip route"])
                        observed = parse_frr_show_ip_route_prefixes(rt_text)
                        routes_rec["parser_mode"] = "text"

                    cmp = compare_expected_vs_observed_prefixes(expected_routes, observed)
                    routes_rec.update(cmp)

                    if expected_routes:
                        frr_nodes_with_expected_routes += 1
                        routes_total_prefixes += len(expected_routes)
                        routes_present_prefixes += len(expected_routes) - len(cmp["missing"])

                    if routes_verbose and not as_json:
                        routes_rec["raw_text"] = rt_text if routes_rec["parser_mode"] == "text" else rt_json

                    if strict and expected_routes and not routes_rec["ok"]:
                        strict_fail = True
                        _extend_routes_reasons(name, routes_rec, reasons)

                except Exception as e:
                    routes_rec["error"] = str(e)
                    routes_rec["ok"] = False
                    if strict and expected_routes:
                        strict_fail = True
                        reasons.append(
                            f"routes error on {name}: {type(e).__name__} (parser={routes_rec.get('parser_mode','none')})"
                        )

                node_rec["routes"] = routes_rec

            out_doc["nodes"].append(node_rec)

        # NEW: prereq failure => strict_fail + reasons (deterministic)
        if strict and down_containers:
            strict_fail = True
            _extend_container_reasons(down_containers, reasons, cap=5)

        # Summary (always produced)
        out_doc["summary"] = {
            "containers_running": {"running": running_nodes, "total": total_nodes}
        }
        if bgp_enabled:
            out_doc["summary"]["bgp_expected_peers"] = {
                "established": exp_established_peers,
                "total": exp_total_peers,
                "frr_nodes_with_expected_peers": frr_nodes_with_expected_peers,
            }
        if routes_enabled:
            out_doc["summary"]["routes_expected_prefixes"] = {
                "present": routes_present_prefixes,
                "total": routes_total_prefixes,
                "frr_nodes_with_expected_routes": frr_nodes_with_expected_routes,
            }

        if strict_fail:
            out_doc["verdict"] = "fail"
            out_doc["reasons"] = sorted(set(reasons))
        else:
            out_doc["verdict"] = "pass"
            out_doc["reasons"] = []

        # JSON output mode: no human printing
        if as_json:
            print(json.dumps(out_doc, indent=2, sort_keys=True))
            if strict and strict_fail:
                raise SystemExit(2)
            return

        # -------------------------
        # Human output (updated)
        # -------------------------
        print(f"Lab: {lab}")
        print("Nodes:")

        if not out_doc["nodes"]:
            print("  (no nodes found in topology.resolved.yaml)")
            # Even here, honor --summary
            if show_summary:
                print(f"Summary: containers {running_nodes}/{total_nodes} running")
            return

        for node_rec in out_doc["nodes"]:
            name = node_rec["name"]
            cname = node_rec["container"]
            running = node_rec["running"]
            print(f"  - {name:<8} ({cname}) : {'running' if running else 'not running'}")

            if running and show_intf and "interfaces" in node_rec and node_rec["interfaces"]:
                print("      IF:")
                for line in node_rec["interfaces"]:
                    print(f"      {line}")

            if running and bgp_enabled and node_rec.get("type") == "frr":
                bgp = node_rec.get("bgp") or {}
                expected = bgp.get("expected") or []
                pm = str(bgp.get("parser_mode") or "none")

                if not expected:
                    print("      BGP (none)")
                else:
                    est = len(bgp.get("established") or [])
                    tot = len(expected)
                    if bgp.get("ok"):
                        print(f"      BGP expected {tot} | Established {est}/{tot} (OK, parser={pm})")
                    else:
                        print(f"      BGP expected {tot} | Established {est}/{tot} (MISMATCH, parser={pm})")
                        if bgp.get("missing"):
                            print(f"      BGP missing: {_fmt_list_cap(bgp['missing'], 8)}")
                        if bgp.get("down"):
                            print(f"      BGP down:    {_fmt_list_cap(bgp['down'], 8)}")
                        if bgp.get("extra"):
                            print(f"      BGP extra:   {_fmt_list_cap(bgp['extra'], 8)}")

                if bgp_verbose:
                    raw_text = (bgp.get("raw_text") or "").splitlines()
                    if raw_text:
                        print("      --- show bgp summary ---")
                        for line in raw_text:
                            print(f"      {line}")

            if running and routes_enabled and node_rec.get("type") == "frr":
                rts = node_rec.get("routes") or {}
                expected = rts.get("expected") or []
                pm = str(rts.get("parser_mode") or "none")

                if expected:
                    missing = rts.get("missing") or []
                    present = len(expected) - len(missing)
                    tot = len(expected)
                    if rts.get("ok"):
                        print(f"      ROUTES expected {tot} | Present {present}/{tot} (OK, parser={pm})")
                    else:
                        print(f"      ROUTES expected {tot} | Present {present}/{tot} (MISMATCH, parser={pm})")
                        if missing:
                            print(f"      ROUTES missing: {_fmt_list_cap(missing, 8)}")

                if routes_verbose:
                    raw_text = (rts.get("raw_text") or "").splitlines()
                    if raw_text:
                        print("      --- show ip route ---")
                        for line in raw_text:
                            print(f"      {line}")

        # NEW: summary prints reliably when requested
        if show_summary:
            parts = [f"containers {running_nodes}/{total_nodes} running"]
            if bgp_enabled:
                parts.append(f"BGP expected peers {exp_established_peers}/{exp_total_peers} established")
                parts.append(f"FRR nodes w/expected peers {frr_nodes_with_expected_peers}")
            if routes_enabled:
                parts.append(f"ROUTES expected {routes_present_prefixes}/{routes_total_prefixes} present")
                parts.append(f"FRR nodes w/expected routes {frr_nodes_with_expected_routes}")
            print("Summary: " + " | ".join(parts))

        if strict and strict_fail:
            raise SystemExit(2)

    finally:
        QUIET_RUN = old_quiet

def cmd_collect(args: argparse.Namespace) -> None:
    import json
    import re
    from typing import Any

    lab = args.lab
    rt = get_runtime()

    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    outdir = lab_dir(lab) / "artifacts"
    outdir.mkdir(parents=True, exist_ok=True)

    def write(name: str, content: str) -> None:
        (outdir / name).write_text(content, encoding="utf-8")

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

    # Strict: ensure all expected nodes are running before collecting
    nodes_raw = topo.get("nodes", []) or []
    nodes = sorted((nodes_raw if isinstance(nodes_raw, list) else []), key=lambda n: (n or {}).get("name", ""))
    for n in nodes:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            die(f"Invalid node entry in topology (missing name): {n!r}")
        name = name.strip()

        if not rt.is_running(lab, name):
            die(f"COLLECT FAIL: {rt.node_id(lab, name)} is not running")

    # Containerlab inspect JSON (scrubbed) — stable, runtime-neutral enough for now
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
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()

        cp = rt.sh(lab, name, "ip -br a", check=False, capture_output=True)
        write(f"{name}.ip-addr.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        cp = rt.sh(lab, name, "ip route", check=False, capture_output=True)
        write(f"{name}.ip-route.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        if n.get("type") == "nft-fw":
            cp = rt.sh(lab, name, "nft list ruleset", check=False, capture_output=True)
            write(f"{name}.nft-ruleset.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

            cp = rt.sh(lab, name, "sysctl -n net.ipv4.ip_forward", check=False, capture_output=True)
            write(f"{name}.ip-forward.txt", (cp.stdout or cp.stderr or "").strip() + "\n")

        if n.get("type") == "frr":
            cp = rt.exec(lab, name, ["vtysh", "-c", "show bgp summary"], check=False, capture_output=True)
            write(f"{name}.bgp-summary.txt", normalize_bgp_summary(cp.stdout or cp.stderr or ""))

        if include_logs:
            # Runtime should own log collection in future; keep docker-less for now.
            # If you later add rt.logs(...), call it here.
            pass

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
    p_status.add_argument("--json", action="store_true", help="Emit machine-readable JSON (no command echo)")
    p_status.add_argument("--routes", action="store_true", help="Validate expected routes exist (read-only)")
    p_status.add_argument("--routes-verbose", action="store_true", help="Include raw 'show ip route' output (human mode)")
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
    p_test.add_argument("--scenario", help="Run only this scenario id (scenarios[*].id)")
    p_test.add_argument("--all-scenarios", action="store_true", help="Run all scenarios after steady-state tests")
    p_test.add_argument("--scenario-verbose", action="store_true", help="Print each scenario step as it runs (human-only; does not change artifacts)",)

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
