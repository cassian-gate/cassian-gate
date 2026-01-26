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
import hashlib
import os, time
from typing import Any

from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
TOPO_DIR = BASE_DIR / "topologies"
LABS_DIR = BASE_DIR / "labs"
QUIET_RUN = False
_QUIET_DIE = False


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

LAST_ERROR_MSG: str | None = None

def die(msg: str, code: int = 1) -> None:
    global _QUIET_DIE
    if _QUIET_DIE:
        # IMPORTANT: raise with the MESSAGE (string), not the int code
        # so cmd_validate can capture str(e) and put it into JSON.
        raise SystemExit(str(msg))

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

def classify_invalid_target(token: str) -> str:
    """
    Messaging-only helper. Does NOT change acceptance rules.
    Returns a short reason string for common invalid destination patterns.
    """
    t = (token or "").strip()
    if not t:
        return "empty destination"

    # IP:port (common copy/paste)
    if ":" in t:
        # If it's a pure IPv6 literal, it'll also contain ":".
        # Detect IP:port by "one colon" + numeric port and left side looks like IPv4.
        parts = t.rsplit(":", 1)
        if len(parts) == 2:
            left, right = parts[0].strip(), parts[1].strip()
            if right.isdigit() and is_ip_literal(left) and "." in left:
                return "appears to be IP:port; expected IPv4 literal only (no port)"

    # CIDR
    if "/" in t:
        left = t.split("/", 1)[0].strip()
        if is_ip_literal(left) and "." in left:
            return "appears to be CIDR; expected single IPv4 address (no /mask)"

    # IPv6 (v1.x: IPv4-only in these target contexts)
    if ":" in t and not t.count(":") == 1:
        # Heuristic: multiple colons strongly indicates IPv6
        return "appears to be IPv6; v1.x supports IPv4 only here"

    # Hostname-like (letters + dots)
    has_letter = any(ch.isalpha() for ch in t)
    if has_letter and "." in t:
        return "appears to be a hostname; DNS/hostnames are not supported (determinism)"

    # Generic fallback
    return "invalid destination (must be node name or IPv4 literal)"

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
# YAML + validation
# -------------------------
def _is_direct_link(topo: dict, a: str, b: str) -> bool:
    for link in topo.get("links", []) or []:
        eps = link.get("endpoints") or []
        if not isinstance(eps, list) or len(eps) != 2:
            continue
        try:
            n1 = str(eps[0]).split(":", 1)[0]
            n2 = str(eps[1]).split(":", 1)[0]
        except Exception:
            continue
        if (n1 == a and n2 == b) or (n1 == b and n2 == a):
            return True
    return False

def _has_candidate_context(topo: dict) -> bool:
    cc = topo.get("candidate_changes")
    return isinstance(cc, list) and len(cc) > 0

def _is_multihop_ping_test(topo: dict, test: dict) -> bool:
    # v1 scope: only ping kind
    if test.get("kind") != "ping":
        return False
    src = test.get("src")
    dst = test.get("dst")
    if not (isinstance(src, str) and isinstance(dst, str) and src and dst):
        return False
    # If directly linked, it is not multi-hop.
    return not _is_direct_link(topo, src, dst)

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

    # v1.x guardrail hardening (clarified):
    # - Topology MUST NOT encode routing mechanics (protocols/metrics/policy).
    # - FRR nodes MAY include metadata like asn/router_id, but these do not imply routing.
    # - If present, validate types deterministically.
    for i, n in enumerate(topo["nodes"], start=1):
        if not isinstance(n, dict):
            continue
        if n.get("type") != "frr":
            continue

        name = n.get("name") or f"nodes[{i}]"

        # Reject topology-encoded routing mechanics (locked boundary)
        if "static_routes" in n and n.get("static_routes") not in (None, [], {}):
            die(
                f"Topology invalid: nodes[{i}] '{name}': 'static_routes' is not allowed. "
                f"v1 boundary: routing mechanics must come from device configuration outside ai-netsim v1 "
                f"(preconfigured images/config or manual exploration), and must be proven via tests."
            )

        # asn is optional metadata; if present, must be int-coercible
        if "asn" in n and n.get("asn") is not None:
            try:
                int(n.get("asn"))
            except Exception:
                die(
                    f"Topology invalid: nodes[{i}] '{name}': field 'asn' must be int-coercible if provided "
                    f"(e.g. 65001)."
                )

        # router_id is optional metadata; if present, must be IPv4 literal
        if "router_id" in n and n.get("router_id") is not None:
            rid = str(n.get("router_id") or "").strip()
            try:
                ip = ipaddress.ip_address(rid)
                if ip.version != 4:
                    raise ValueError("router_id must be IPv4")
            except Exception:
                die(
                    f"Topology invalid: nodes[{i}] '{name}': field 'router_id' must be an IPv4 literal if provided "
                    f"(e.g. 1.1.1.1)."
                )

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

    # ----------------------------
    # v1: Change Context (Step 1) — candidate_changes declaration validation
    #   - context only; never consumed by runtime
    #   - no file reads here
    # ----------------------------
    if "candidate_changes" in topo and topo["candidate_changes"] is not None:
        cc = topo["candidate_changes"]
        if not isinstance(cc, list):
            die("'candidate_changes' must be a list.")

        allowed_keys = {"id", "description", "scope", "file", "inline", "format"}
        seen_ids: set[str] = set()

        for idx, item in enumerate(cc, start=1):
            if not isinstance(item, dict):
                die(f"candidate_changes[{idx}]: must be a dict")

            extra = sorted(set(item.keys()) - allowed_keys)
            if extra:
                die(f"candidate_changes[{idx}]: unknown keys: {extra} (allowed: {sorted(allowed_keys)})")

            cid = item.get("id")
            if not isinstance(cid, str) or not cid.strip():
                die(f"candidate_changes[{idx}].id: must be a non-empty string")
            cid = cid.strip()
            if cid in seen_ids:
                die(f"candidate_changes[{idx}].id: duplicate id '{cid}'")
            seen_ids.add(cid)

            # Exactly one source: file OR inline
            has_file = "file" in item and item.get("file") is not None
            has_inline = "inline" in item and item.get("inline") is not None
            if has_file and has_inline:
                die(f"candidate_changes[{idx}] ({cid}): choose only one of 'file' or 'inline'")
            if not has_file and not has_inline:
                die(f"candidate_changes[{idx}] ({cid}): missing source: provide 'file' or 'inline'")

            if has_file:
                f = item.get("file")
                if not isinstance(f, str) or not f.strip():
                    die(f"candidate_changes[{idx}] ({cid}).file: must be a non-empty string")

            if has_inline:
                s = item.get("inline")
                if not isinstance(s, str) or not s.strip():
                    die(f"candidate_changes[{idx}] ({cid}).inline: must be a non-empty string")

            # Optional description
            if "description" in item and item.get("description") is not None:
                d = item.get("description")
                if not isinstance(d, str) or not d.strip():
                    die(f"candidate_changes[{idx}] ({cid}).description: must be a non-empty string if provided")

            # Optional format
            if "format" in item and item.get("format") is not None:
                fmt = item.get("format")
                if not isinstance(fmt, str) or not fmt.strip():
                    die(f"candidate_changes[{idx}] ({cid}).format: must be a non-empty string if provided")

            # Optional scope: list of node names (must exist)
            if "scope" in item and item.get("scope") is not None:
                scope = item.get("scope")
                if not isinstance(scope, list):
                    die(f"candidate_changes[{idx}] ({cid}).scope: must be a list of node names")
                for j, nname in enumerate(scope, start=1):
                    if not isinstance(nname, str) or not nname.strip():
                        die(f"candidate_changes[{idx}] ({cid}).scope[{j}]: must be a non-empty string")
                    if nname.strip() not in names:
                        die(f"candidate_changes[{idx}] ({cid}).scope[{j}]: unknown node '{nname.strip()}'")

    # ----------------------------
    # v1 gate semantics guardrails (tests)
    # ----------------------------
    tests = topo.get("tests") or []
    if isinstance(tests, list) and tests:
        for idx, t in enumerate(tests, start=1):
            if not isinstance(t, dict):
                continue

            kind = (t.get("kind") or t.get("type") or "").strip().lower()
            nm = t.get("name")
            label = nm.strip() if isinstance(nm, str) and nm.strip() else f"tests[{idx}]"

            exp = t.get("expect") or "pass"
            exp = exp.strip().lower() if isinstance(exp, str) else exp
            if exp not in ("pass", "fail"):
                exp = "pass"

            # Ping: count must be int >= 1 if provided
            if kind == "ping" and "count" in t and t.get("count") is not None:
                try:
                    c = int(t.get("count"))
                    if c < 1:
                        raise ValueError()
                except Exception:
                    die(f"Topology invalid: {label}: ping count must be an integer >= 1")

            # Ping: expected FAIL must be fail-fast (no retries/timeouts)
            if kind == "ping" and exp == "fail":
                if "timeout_s" in t and t.get("timeout_s") is not None:
                    die(
                        f"Topology invalid: {label}: ping expect: fail must not set timeout_s "
                        f"(v1 fail-fast semantics)"
                    )
                if "retry_interval_s" in t and t.get("retry_interval_s") is not None:
                    die(
                        f"Topology invalid: {label}: ping expect: fail must not set retry_interval_s "
                        f"(v1 fail-fast semantics)"
                    )

    # v1.x fail-fast educational guardrail (v1-truthful):
    # - ai-netsim v1 does NOT infer routing intent and does NOT auto-configure routing protocols.
    # - Therefore, multi-hop reachability cannot be *proven* to pass from topology alone.
    # - If a multi-hop test expects PASS, it must rely on an equivalent pre-configured device image/config
    #   outside ai-netsim v1, otherwise the expectation is invalid and should be changed.
    #
    # v1.x exception:
    # - If ALL FRR nodes in the topology are explicitly declared as frr_mode: preconfigured,
    #   then multi-hop expect: pass is allowed (routing comes from the image/config outside v1).
    tests = topo.get("tests") or []
    if isinstance(tests, list) and tests:
        offenders: list[str] = []

        # Determine whether the topology explicitly declares preconfigured routing on all FRR nodes.
        nodes = topo.get("nodes") or []
        all_frr_preconfigured = True
        saw_frr = False

        if isinstance(nodes, list):
            for n in nodes:
                if not isinstance(n, dict):
                    continue
                if n.get("type") != "frr":
                    continue
                saw_frr = True
                mode = n.get("frr_mode")
                mode_norm = str(mode).strip().lower() if mode is not None else "generated"
                if mode_norm != "preconfigured":
                    all_frr_preconfigured = False
                    break
        else:
            all_frr_preconfigured = False

        # Only enforce the fail-fast rule when we are NOT explicitly in "preconfigured routing" mode.
        if not (saw_frr and all_frr_preconfigured):
            for idx, t in enumerate(tests, start=1):
                if not isinstance(t, dict):
                    continue
                if not _is_multihop_ping_test(topo, t):
                    continue

                exp = (t.get("expect") or "").strip().lower() if isinstance(t.get("expect"), str) else t.get("expect")
                if exp == "pass":
                    nm = t.get("name")
                    label = nm.strip() if isinstance(nm, str) and nm.strip() else f"tests[{idx}]"
                    offenders.append(label)

            if offenders:
                die(
                    "Topology invalid: multi-hop ping test(s) declare expect: pass, but ai-netsim v1 does not infer routing "
                    "intent or auto-configure routing protocols, so multi-hop pass cannot be proven from topology alone. "
                    "Fix: either (a) change these tests to expect: fail, (b) limit tests to directly-connected reachability, "
                    "or (c) run with an equivalent pre-configured device image/config outside ai-netsim v1. "
                    f"Affected tests: {', '.join(offenders)}"
                )

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
    Generate FRR integrated config (routing-neutral).

    - Configures interface IPs from topology links (only for this node)
    - Optionally configures loopback /32 if router_id is provided
    - Does NOT configure routing protocols (BGP/OSPF/etc.)
    - Does NOT accept topology-encoded routing mechanics (static routes, policy, metrics)
      Routing behavior must come from device configuration (candidate config or equivalent)
      and be proven via tests.
    """
    name = node["name"]

    rid = node.get("router_id")
    rid = str(rid).strip() if rid is not None else ""

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

    # Optional loopback / router-id (metadata only; does not imply protocols)
    if rid:
        cfg.append("interface lo")
        cfg.append(f" ip address {rid}/32")
        cfg.append("!")

    # Interfaces from topology endpoints (only this node's endpoints)
    for l in node_links:
        cfg.append(f"interface {l['iface']}")
        cfg.append(f" ip address {l['ip']}")
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

    # Hard defaults for core node types (deterministic + first-time UX safe).
    # node.image always overrides these.
    hard_defaults = {
        "host": "wbitt/network-multitool:latest",
        "nft-fw": "netsim/nft-fw:latest",
        "frr": "frrouting/frr:latest",
    }

    for n in topo["nodes"]:
        ntype = n["type"]

        # Resolve image once (node.image overrides defaults)
        image = n.get("image") or hard_defaults.get(ntype) or DEFAULT_IMAGES.get(ntype)
        if not image:
            die(f"No default image for node type '{ntype}'. Set node.image explicitly.")

        node_def = {"kind": "linux", "image": image}

        binds: list[str] = []

        if ntype == "frr":
            # v1.x: allow demo/preconfigured FRR images without any /etc/frr binds
            # frr_mode:
            #   - "generated" (default): bind generated /etc/frr/{daemons,vtysh.conf,frr.conf}
            #   - "preconfigured": do NOT bind /etc/frr/* (image owns routing + daemons)
            frr_mode = (n.get("frr_mode") or "generated").strip().lower()
            if frr_mode not in ("generated", "preconfigured"):
                die(
                    f"Topology invalid: node '{n.get('name')}': "
                    f"frr_mode must be 'generated' or 'preconfigured'"
                )

            if frr_mode == "generated":
                cfgdir = node_cfg_dir(topo["name"], n["name"])
                write_file(cfgdir / "daemons", gen_frr_daemons())
                write_file(cfgdir / "vtysh.conf", gen_vtysh_conf())
                write_file(cfgdir / "frr.conf", gen_frr_conf(n, topo))

                binds = [
                    f"{cfgdir}/daemons:/etc/frr/daemons:ro",
                    f"{cfgdir}/vtysh.conf:/etc/frr/vtysh.conf:ro",
                    f"{cfgdir}/frr.conf:/etc/frr/frr.conf:ro",
                ]
            else:
                # preconfigured: image provides /etc/frr/* and starts the right daemons (e.g., bgpd)
                binds = []

        # Hosts should stay alive
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

        # FRR nodes should behave like routers
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
        # v1: normalize test field aliases
        # Accept 'from'/'to' as aliases for 'src'/'dst' with strict disagreement checks.
        # ----------------------------
        if "from" in t and "src" in t:
            a = str(t.get("from") or "").strip()
            b = str(t.get("src") or "").strip()
            if a and b and a != b:
                die(f"tests[{i}]: 'from' and 'src' disagree ({a!r} vs {b!r})")

        if "to" in t and "dst" in t:
            a = str(t.get("to") or "").strip()
            b = str(t.get("dst") or "").strip()
            if a and b and a != b:
                die(f"tests[{i}]: 'to' and 'dst' disagree ({a!r} vs {b!r})")

        if "src" not in t and "from" in t:
            t["src"] = t.get("from")

        if "dst" not in t and "to" in t:
            # IMPORTANT (v1): for ping tests, do NOT alias 'to' into 'dst'.
            # Ping normalization below treats 'to'/'to_ip' as IP-literal targets.
            if t.get("kind") != "ping":
                t["dst"] = t.get("to")

        # ----------------------------
        # v1 ping destination normalization
        # ----------------------------
        # ----------------------------
        # v1 ping destination normalization (strict)
        #   - dst: node name
        #   - to/to_ip: IP literal
        #   - fail-fast on ambiguity
        # ----------------------------
        if t.get("kind") == "ping":
            ctx = f"tests[{i}] ({t.get('name', '<unnamed>')})"

            src = t.get("src") or t.get("from")
            if not src or not isinstance(src, str):
                die(f"{ctx}: ping test requires 'from/src' as a node name")

            # Target forms
            has_dst = "dst" in t and t.get("dst") is not None
            has_to = "to" in t and t.get("to") is not None
            has_to_ip = "to_ip" in t and t.get("to_ip") is not None

            # Disallow ambiguous targets (v1 contract)
            #   - dst (node) OR to/to_ip (ip) but not both
            if has_dst and (has_to or has_to_ip):
                die(f"{ctx}: ping test target is ambiguous: use 'dst' (node) OR 'to'/'to_ip' (ip literal), not both")
            if has_to and has_to_ip:
                die(f"{ctx}: ping test target is ambiguous: use only one of 'to' or 'to_ip'")

            # IP-literal target path
            if has_to or has_to_ip:
                ip_val = t.get("to") if has_to else t.get("to_ip")
                if not isinstance(ip_val, str) or not is_ip_literal(ip_val.strip()):
                    die(f"{ctx}: ping test: 'to'/'to_ip' must be a valid IPv4/IPv6 literal")
                ip_val = ip_val.strip()
                validate_ip_literal(ip_val, ctx)
                t["_dst_kind"] = "ip"
                t["_dst_value"] = ip_val
                continue

            # Node-name target path (dst required)
            dst = t.get("dst")
            if not dst or not isinstance(dst, str):
                die(f"{ctx}: ping test requires 'dst' as a node name (or use 'to'/'to_ip' for an IP literal)")

            dst = dst.strip()
            if is_ip_literal(dst):
                t["_dst_kind"] = "ip"
                t["_dst_value"] = dst
                continue

            nodes = {n.get("name") for n in resolved.get("nodes", []) or []}
            if dst not in nodes:
                die(f"{ctx}: 'dst' must be a valid node name")

            t["_dst_kind"] = "node"
            t["_dst_value"] = dst

    # ----------------------------
    # 3) v1.x ergonomics: scenario run include expansion
    #    - Supports:  run: { include: all }
    #    - Expands deterministically at resolve time into multiple run steps
    #    - Uses declared tests order (as written in topology)
    # ----------------------------
    scenarios = resolved.get("scenarios", []) or []
    if scenarios:
        # Precompute ordered test names (declared order)
        ordered_test_names: list[str] = []
        unnamed_tests: list[str] = []
        for idx, t in enumerate(tests):
            if not isinstance(t, dict):
                # already rejected above, but keep deterministic
                continue
            nm = t.get("name")
            if isinstance(nm, str) and nm.strip():
                ordered_test_names.append(nm.strip())
            else:
                unnamed_tests.append(f"tests[{idx+1}]")

        for sidx, s in enumerate(scenarios):
            if not isinstance(s, dict):
                continue
            sid = s.get("id")
            sid_label = str(sid) if isinstance(sid, str) and sid.strip() else f"scenarios[{sidx+1}]"

            steps = s.get("steps")
            if not isinstance(steps, list):
                continue

            new_steps: list[dict] = []
            for step_i, step in enumerate(steps, start=1):
                # Only transform steps shaped like: {run: {include: all}}
                if isinstance(step, dict) and "run" in step and isinstance(step.get("run"), dict):
                    run_spec = step.get("run") or {}
                    extra_keys = sorted(set(run_spec.keys()) - {"include"})
                    if extra_keys:
                        die(
                            f"{sid_label}: steps[{step_i}].run: unsupported keys {extra_keys} "
                            f"(v1 supports only: include)"
                        )

                    inc = run_spec.get("include")
                    if not (isinstance(inc, str) and inc.strip().lower() == "all"):
                        die(
                            f"{sid_label}: steps[{step_i}].run.include: only 'all' is supported in v1 "
                            f"(got {inc!r})"
                        )

                    # include: all requires every declared test to have a name,
                    # because scenario run refs are name-based and must be auditable.
                    if unnamed_tests:
                        die(
                            f"{sid_label}: steps[{step_i}]: run include: all requires every test to have a non-empty "
                            f"'name' (missing for: {', '.join(unnamed_tests)})"
                        )

                    for tn in ordered_test_names:
                        new_steps.append({"run": tn})
                    continue

                # default: keep step as-is
                if isinstance(step, dict):
                    new_steps.append(step)
                else:
                    # keep non-dict as-is; validate_scenarios will reject deterministically
                    new_steps.append(step)

            s["steps"] = new_steps

        # ----------------------------
    # v1: Change Context (Step 1) — candidate_changes declaration validation
    #   - context only; never consumed by runtime
    #   - no file reads here
    # ----------------------------
    if "candidate_changes" in topo and topo["candidate_changes"] is not None:
        cc = topo["candidate_changes"]
        if not isinstance(cc, list):
            die("'candidate_changes' must be a list.")

        allowed_keys = {"id", "description", "scope", "file", "inline", "format"}
        seen_ids: set[str] = set()

        for idx, item in enumerate(cc, start=1):
            if not isinstance(item, dict):
                die(f"candidate_changes[{idx}]: must be a dict")

            extra = sorted(set(item.keys()) - allowed_keys)
            if extra:
                die(f"candidate_changes[{idx}]: unknown keys: {extra} (allowed: {sorted(allowed_keys)})")

            cid = item.get("id")
            if not isinstance(cid, str) or not cid.strip():
                die(f"candidate_changes[{idx}].id: must be a non-empty string")
            cid = cid.strip()
            if cid in seen_ids:
                die(f"candidate_changes[{idx}].id: duplicate id '{cid}'")
            seen_ids.add(cid)

            # Exactly one source: file OR inline
            has_file = "file" in item and item.get("file") is not None
            has_inline = "inline" in item and item.get("inline") is not None
            if has_file and has_inline:
                die(f"candidate_changes[{idx}] ({cid}): choose only one of 'file' or 'inline'")
            if not has_file and not has_inline:
                die(f"candidate_changes[{idx}] ({cid}): missing source: provide 'file' or 'inline'")

            if has_file:
                f = item.get("file")
                if not isinstance(f, str) or not f.strip():
                    die(f"candidate_changes[{idx}] ({cid}).file: must be a non-empty string")

            if has_inline:
                s = item.get("inline")
                if not isinstance(s, str) or not s.strip():
                    die(f"candidate_changes[{idx}] ({cid}).inline: must be a non-empty string")

            # Optional description
            if "description" in item and item.get("description") is not None:
                d = item.get("description")
                if not isinstance(d, str) or not d.strip():
                    die(f"candidate_changes[{idx}] ({cid}).description: must be a non-empty string if provided")

            # Optional format
            if "format" in item and item.get("format") is not None:
                fmt = item.get("format")
                if not isinstance(fmt, str) or not fmt.strip():
                    die(f"candidate_changes[{idx}] ({cid}).format: must be a non-empty string if provided")

            # Optional scope: list of node names (must exist)
            if "scope" in item and item.get("scope") is not None:
                scope = item.get("scope")
                if not isinstance(scope, list):
                    die(f"candidate_changes[{idx}] ({cid}).scope: must be a list of node names")
                for j, nname in enumerate(scope, start=1):
                    if not isinstance(nname, str) or not nname.strip():
                        die(f"candidate_changes[{idx}] ({cid}).scope[{j}]: must be a non-empty string")
                    if nname.strip() not in names:
                        die(f"candidate_changes[{idx}] ({cid}).scope[{j}]: unknown node '{nname.strip()}'")

    return resolved

def write_containerlab_file(topo_path: Path) -> Path:
    topo = load_yaml(topo_path)
    ensure_valid_topology(topo)

    resolved = resolve_topology(topo)
    validate_scenarios(resolved)


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

def _two_run_load_yaml_path(arg: str) -> Path:
    p = (TOPO_DIR / arg) if not Path(arg).is_file() else Path(arg)
    return p

def _two_run_make_temp_topology(*, base_topo_path: Path, new_name: str, out_path: Path) -> None:
    topo = load_yaml(base_topo_path) or {}
    if not isinstance(topo, dict):
        die(f"two-run: topology must be a mapping: {base_topo_path}")
    topo["name"] = new_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(topo, sort_keys=True), encoding="utf-8")

def _two_run_copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)

def _two_run_load_json(p: Path) -> dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"two-run: failed to read JSON {p}: {e}")
    raise RuntimeError("unreachable")

def _two_run_normalized_topo_hash(resolved_topo_path: Path) -> str:
    topo = load_yaml(resolved_topo_path) or {}
    if not isinstance(topo, dict):
        return ""
    topo2 = dict(topo)
    topo2.pop("name", None)
    blob = json.dumps(topo2, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _two_run_extract_declared_sets(resolved_topo_path: Path) -> tuple[list[str], list[tuple[str, int, list[str]]]]:
    topo = load_yaml(resolved_topo_path) or {}
    tests = topo.get("tests", []) or []
    test_names: list[str] = []
    for i, t in enumerate(tests, start=1):
        if isinstance(t, dict) and isinstance(t.get("name"), str) and t.get("name").strip():
            test_names.append(t["name"].strip())
        else:
            test_names.append(f"tests[{i}]")

    scenarios = topo.get("scenarios", []) or []
    scen_sig: list[tuple[str, int, list[str]]] = []
    for s in scenarios:
        if not isinstance(s, dict):
            continue
        sid = str(s.get("id") or "").strip()
        steps = s.get("steps", []) or []
        step_types: list[str] = []
        if isinstance(steps, list):
            for st in steps:
                if not isinstance(st, dict):
                    step_types.append("invalid")
                    continue
                # determine step type by key intersection (contract)
                keys = set(st.keys())
                for k in ("run", "fault", "wait_for", "wait_for_bgp"):
                    if k in keys:
                        step_types.append(k)
                        break
                else:
                    step_types.append("unknown")
        scen_sig.append((sid, len(steps) if isinstance(steps, list) else 0, step_types))

    scen_sig.sort(key=lambda x: x[0])
    return (test_names, scen_sig)

def _two_run_compare(*, baseline_dir: Path, change_dir: Path, base_name: str) -> tuple[dict[str, Any], str]:
    b_results = _two_run_load_json(baseline_dir / "results.json")
    c_results = _two_run_load_json(change_dir / "results.json")

    b_resolved = baseline_dir / "topology.resolved.yaml"
    c_resolved = change_dir / "topology.resolved.yaml"

    topo_hash_b = _two_run_normalized_topo_hash(b_resolved)
    topo_hash_c = _two_run_normalized_topo_hash(c_resolved)

    b_tests, b_scens = _two_run_extract_declared_sets(b_resolved)
    c_tests, c_scens = _two_run_extract_declared_sets(c_resolved)

    comparability_errors: list[str] = []
    if topo_hash_b != topo_hash_c:
        comparability_errors.append("topology identity mismatch (normalized resolved topology differs)")
    if b_tests != c_tests:
        comparability_errors.append("declared test set mismatch between baseline and change")
    if b_scens != c_scens:
        comparability_errors.append("declared scenario set mismatch between baseline and change")

    def _index_tests(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for t in results.get("tests", []) or []:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name") or "").strip()
            if not name:
                continue
            out[name] = t
        return out

    b_idx = _index_tests(b_results)
    c_idx = _index_tests(c_results)

    # Deterministic per-test diffs (declared order)
    test_diffs: list[dict[str, Any]] = []
    for name in b_tests:
        bt = b_idx.get(name, {})
        ct = c_idx.get(name, {})
        fields = ("expected", "observed", "verdict", "duration_ms")
        changed: dict[str, Any] = {}
        for f in fields:
            bv = bt.get(f)
            cv = ct.get(f)
            if bv != cv:
                changed[f] = {"baseline": bv, "change": cv}
        if changed:
            test_diffs.append({"name": name, "changes": changed})

    # Scenario diffs (from results.json scenarios)
    def _idx_scen(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for s in results.get("scenarios", []) or []:
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or "").strip()
            if sid:
                out[sid] = s
        return out

    b_sidx = _idx_scen(b_results)
    c_sidx = _idx_scen(c_results)

    scen_diffs: list[dict[str, Any]] = []
    for (sid, _nsteps, _types) in b_scens:
        bs = b_sidx.get(sid, {})
        cs = c_sidx.get(sid, {})
        changed: dict[str, Any] = {}
        for f in ("verdict", "duration_ms"):
            if bs.get(f) != cs.get(f):
                changed[f] = {"baseline": bs.get(f), "change": cs.get(f)}

        # step verdict/duration diffs by index
        b_steps = bs.get("steps", []) or []
        c_steps = cs.get("steps", []) or []
        step_changes: list[dict[str, Any]] = []
        if isinstance(b_steps, list) and isinstance(c_steps, list):
            for i in range(min(len(b_steps), len(c_steps))):
                bst = b_steps[i] if isinstance(b_steps[i], dict) else {}
                cst = c_steps[i] if isinstance(c_steps[i], dict) else {}
                sc: dict[str, Any] = {}
                for f in ("type", "verdict", "duration_ms"):
                    if bst.get(f) != cst.get(f):
                        sc[f] = {"baseline": bst.get(f), "change": cst.get(f)}
                if sc:
                    step_changes.append({"step": i + 1, "changes": sc})
        if step_changes:
            changed["steps"] = step_changes

        if changed:
            scen_diffs.append({"id": sid, "changes": changed})

    summary = {
        "schema_version": "1",
        "authority": "supporting_evidence",
        "statement": "This diff is evidence-only and never determines verdicts.",
        "two_run": {
            "base_lab": base_name,
            "baseline": {"overall": (b_results.get("result") or ""), "topo_hash": topo_hash_b},
            "change": {"overall": (c_results.get("result") or ""), "topo_hash": topo_hash_c},
        },
        "comparability": {
            "ok": (len(comparability_errors) == 0),
            "errors": comparability_errors,
        },
        "diffs": {
            "tests": test_diffs,
            "scenarios": scen_diffs,
        },
    }

    # Deterministic human summary
    lines: list[str] = []
    lines.append("ai-netsim two-run diff (evidence-only)")
    lines.append(f"base_lab: {base_name}")
    lines.append(f"baseline_overall: {b_results.get('result')}")
    lines.append(f"change_overall: {c_results.get('result')}")
    lines.append(f"comparability_ok: {str(len(comparability_errors) == 0).lower()}")
    if comparability_errors:
        lines.append("comparability_errors:")
        for e in comparability_errors:
            lines.append(f" - {e}")

    lines.append(f"test_diffs: {len(test_diffs)}")
    for d in test_diffs[:25]:
        lines.append(f" - {d['name']}: {', '.join(sorted(d['changes'].keys()))}")
    if len(test_diffs) > 25:
        lines.append(f" - (+{len(test_diffs)-25} more)")

    lines.append(f"scenario_diffs: {len(scen_diffs)}")
    for d in scen_diffs[:25]:
        lines.append(f" - {d['id']}: changed")
    if len(scen_diffs) > 25:
        lines.append(f" - (+{len(scen_diffs)-25} more)")

    return summary, "\n".join(lines) + "\n"

def _cmd_test_two_run(args: argparse.Namespace) -> None:
    base_topo_path = _two_run_load_yaml_path(str(getattr(args, "two_run_topology")))
    topo = load_yaml(base_topo_path) or {}
    if not isinstance(topo, dict):
        die(f"two-run: invalid topology: {base_topo_path}")
    base_name = topo.get("name")
    if not isinstance(base_name, str) or not base_name.strip():
        die(f"two-run: topology has no valid 'name': {base_topo_path}")
    base_name = base_name.strip()

    # two-run requires candidate-config for the CHANGE run (even though baseline does not use it)
    cand_raw = getattr(args, "candidate_config", None)
    if cand_raw is None:
        die("two-run: missing required --candidate-config for CHANGE run")

    # Normalize candidate dir to an absolute, resolved path to avoid cwd ambiguity
    cand_dir = Path(str(cand_raw)).expanduser()
    if not cand_dir.is_absolute():
        cand_dir = (Path.cwd() / cand_dir)
    cand_dir = cand_dir.resolve()

    # Pre-validate candidate dir *before any runs* so we fail fast without deploying labs.
    # This enforces the "recognized inputs exist" invariant and gives a deterministic error.
    _candidate_parse_dir_or_die(topo, cand_dir)

    # Bundle root (stable)
    bundle_root = LABS_DIR / f"clab-{base_name}" / "two_run"
    tmp_dir = bundle_root / "_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    baseline_name = f"{base_name}-baseline"
    change_name = f"{base_name}-change"

    baseline_topo = tmp_dir / "baseline.topology.yaml"
    change_topo = tmp_dir / "change.topology.yaml"

    _two_run_make_temp_topology(base_topo_path=base_topo_path, new_name=baseline_name, out_path=baseline_topo)
    _two_run_make_temp_topology(base_topo_path=base_topo_path, new_name=change_name, out_path=change_topo)

    def run_one(*, topo_path: Path, lab_name: str, candidate: Path | None, label: str) -> tuple[int, str]:
        """
        Returns: (exit_code, overall_result_string)
        exit_code is for hard failure decisions; test failures are not treated as hard here.
        """
        # Always clean-state for this run
        up_args = argparse.Namespace(topology=str(topo_path), reconfigure=True)
        try:
            cmd_up(up_args)
        except SystemExit as e:
            die(f"{label}: deploy/provision failed")
        except Exception:
            die(f"{label}: deploy/provision failed")

        # If candidate is provided, re-validate it against the resolved topology
        # produced by THIS run (stronger than base YAML).
        if candidate is not None:
            rpath = LABS_DIR / f"clab-{lab_name}" / "topology.resolved.yaml"
            if not rpath.exists():
                die(f"{label}: missing resolved topology: {rpath}")
            rtopo = load_yaml(rpath) or {}
            if not isinstance(rtopo, dict):
                die(f"{label}: invalid resolved topology: {rpath}")
            ensure_valid_topology(rtopo)
            _candidate_parse_dir_or_die(rtopo, candidate)

        # Run tests (may fail normally)
        test_ns = argparse.Namespace(
            lab=lab_name,
            name=getattr(args, "name", None),
            kind=getattr(args, "kind", None),
            keep_going=bool(getattr(args, "keep_going", False)),
            json=bool(getattr(args, "json", False)),
            candidate_config=(str(candidate) if candidate is not None else None),
            scenario=getattr(args, "scenario", None),
            all_scenarios=bool(getattr(args, "all_scenarios", False)),
            scenario_verbose=bool(getattr(args, "scenario_verbose", False)),
            precheck_controlplane=bool(getattr(args, "precheck_controlplane", False)),
            list_scenarios=False,
        )
        try:
            cmd_test(test_ns)
        except SystemExit:
            # Normal test failure OR candidate apply failure. Decide later by inspecting results.json.
            pass

        # Collect best-effort (still deterministic)
        try:
            cmd_collect(argparse.Namespace(lab=lab_name))
        except SystemExit:
            pass
        except Exception:
            pass

        # Read overall result (if available)
        rpath = LABS_DIR / f"clab-{lab_name}" / "results.json"
        overall = ""
        if rpath.exists():
            overall = str((_two_run_load_json(rpath)).get("result") or "")

        # Always destroy for clean-state gate semantics
        try:
            cmd_down(argparse.Namespace(name=lab_name))
        except SystemExit:
            pass
        except Exception:
            pass

        return (0, overall)

    # Run baseline first
    run_one(topo_path=baseline_topo, lab_name=baseline_name, candidate=None, label="baseline")

    # If baseline artifacts missing, treat as hard failure
    baseline_dir = LABS_DIR / f"clab-{baseline_name}"
    if not (baseline_dir / "results.json").exists():
        die("baseline: hard failure (missing results.json)")

    # Run change second (with candidate apply)
    run_one(topo_path=change_topo, lab_name=change_name, candidate=cand_dir, label="change")

    change_dir = LABS_DIR / f"clab-{change_name}"
    if not (change_dir / "results.json").exists():
        die("change: hard failure (missing results.json)")

    # If candidate apply failed, treat as hard failure (per handover)
    cjson = _two_run_load_json(change_dir / "results.json")
    ca = cjson.get("candidate_apply") or {}
    if isinstance(ca, dict) and ca.get("enabled") and str(ca.get("verdict") or "") == "fail":
        # still proceed to bundle copy + diff if possible, but exit non-zero
        apply_failed = True
    else:
        apply_failed = False

    # Bundle placement (stable dirs)
    bdst = bundle_root / "baseline"
    cdst = bundle_root / "change"
    ddst = bundle_root / "diff"
    ddst.mkdir(parents=True, exist_ok=True)

    _two_run_copy_tree(baseline_dir, bdst)
    _two_run_copy_tree(change_dir, cdst)

    summary, txt = _two_run_compare(baseline_dir=bdst, change_dir=cdst, base_name=base_name)
    (ddst / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (ddst / "summary.txt").write_text(txt, encoding="utf-8")

    # Comparability broken => hard failure
    comp = summary.get("comparability") or {}
    if isinstance(comp, dict) and not bool(comp.get("ok")):
        die("comparison invalid: " + "; ".join(comp.get("errors") or []))

    # Candidate apply failure => hard failure
    if apply_failed:
        die("change: candidate apply failed (tests/scenarios did not run)")

    # Exit code reflects change verdict only
    if str(cjson.get("result") or "") != "pass":
        die("two-run: CHANGE verdict is FAIL", code=1)

    print(f"✅ two-run PASS: bundle at {bundle_root}")

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
    # -------------------------------------------------------------------------
    # Two-run gate orchestrator (v1.5): baseline vs change (evidence-only)
    # -------------------------------------------------------------------------
    if bool(getattr(args, "two_run", False)):
        topo_arg = getattr(args, "two_run_topology", None)
        cand_arg = getattr(args, "candidate_config", None)

        if not topo_arg:
            die("--two-run requires --two-run-topology <topology.yaml>")
        if not cand_arg:
            die("--two-run requires --candidate-config <dir> (used for the change run)")

        _cmd_test_two_run(args)
        return
    
    import json
    import time

    lab = args.lab
    # ------------------------------------------------------------
    # v1.x UX hardening: netsim test expects a LAB NAME, not a topology path
    # Deterministic heuristic only (no filesystem stat).
    # ------------------------------------------------------------
    lab_raw = str(lab or "").strip()

    def _looks_like_topology_path(s: str) -> bool:
        s2 = s.strip()
        s2_l = s2.lower()
        return (
            ("/" in s2)
            or ("\\" in s2)
            or s2_l.endswith(".yaml")
            or s2_l.endswith(".yml")
            or s2_l.startswith("topologies/")
            or s2_l.startswith("./")
        )

    if _looks_like_topology_path(lab_raw):
        die(
            "netsim test expects a LAB NAME, not a topology file path.\n\n"
            "You ran:\n"
            f"  netsim test {lab_raw}\n\n"
            "Try:\n"
            f"  netsim up {lab_raw}\n"
            "  netsim test <lab-name>\n\n"
            "Example:\n"
            "  netsim up topologies/change-context-hard.yaml\n"
            "  netsim test change-context-hard\n",
            code=2,
        )
    # ------------------------------------------------------------
    # v1.x UX: list scenarios from resolved topology (no execution)
    # ------------------------------------------------------------
    if bool(getattr(args, "list_scenarios", False)):
        adir = lab_dir(lab)
        if not adir.exists():
            die(
                f"ERROR: lab artifacts not found: {adir}\n"
                f"Expected: labs/clab-{lab}/\n"
                f"Tip: run 'netsim test {lab}' (or 'netsim up <topology.yaml>') to create artifacts."
            )

        rpath = adir / "topology.resolved.yaml"
        if not rpath.exists():
            die(
                f"ERROR: resolved topology missing: {rpath}\n"
                "Lab not provisioned / missing artifacts."
            )

        topo = load_yaml(rpath)
        scenarios = topo.get("scenarios") or []
        if not scenarios:
            print(f"No scenarios declared for lab '{lab}'.")
            return

        rows: list[tuple[str, str, int]] = []
        for s in scenarios:
            if not isinstance(s, dict):
                continue
            sid = s.get("id")
            if not isinstance(sid, str) or not sid.strip():
                continue
            desc = s.get("description") or ""
            if not isinstance(desc, str):
                desc = str(desc)
            steps = s.get("steps") or []
            steps_n = len(steps) if isinstance(steps, list) else 0
            rows.append((sid.strip(), desc.strip(), steps_n))

        rows.sort(key=lambda x: x[0])

        print(f"Scenarios for lab '{lab}':")
        print("Note: step counts are from the resolved topology (post-Resolve). Scenarios using 'run: { include: all }' will show expanded steps.")
        for sid, desc, steps_n in rows:
            if desc:
                print(f"- {sid}: {desc} (steps: {steps_n})")
            else:
                print(f"- {sid}: (steps: {steps_n})")
        return
    # v1.x UX hardening: users commonly try `netsim test topologies/foo.yaml`
    # `netsim test` is lab-driven by design, so fail early with an actionable message.
    if isinstance(lab, str):
        s = lab.strip()
        if s.endswith((".yaml", ".yml")) or "/" in s or s.startswith("topologies/") or s.startswith("./") or s.startswith("../"):
            die(
                "ERROR: netsim test expects a lab name, not a topology file.\n\n"
                f"You ran:\n  netsim test {lab}\n\n"
                "Did you mean:\n"
                f"  netsim up {lab} --reconfigure\n"
                f"  netsim test <lab-name>\n\n"
                "Tip: lab name usually matches the topology 'name:' field."
            )
    filter_name: str | None = getattr(args, "name", None)
    filter_kind: str | None = getattr(args, "kind", None)
    keep_going: bool = bool(getattr(args, "keep_going", False))
    print_json: bool = bool(getattr(args, "json", False))

    # Scenario CLI (opt-in)
    scenario_id: str | None = getattr(args, "scenario", None)
    all_scenarios: bool = bool(getattr(args, "all_scenarios", False))
    scenario_verbose: bool = bool(getattr(args, "scenario_verbose", False))
    want_scenarios = bool(scenario_id or all_scenarios)
    precheck_controlplane: bool = bool(getattr(args, "precheck_controlplane", False))

    started_at = time.time()

    # =============================================================================
    # 0) Load & validate the resolved topology that created this lab
    # =============================================================================
    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    # Candidate config fail-fast validation (no runtime actions required)
    # Normalize to absolute + resolved (same semantics as two-run)
    cand_dir_raw: str | None = getattr(args, "candidate_config", None)
    cand_dir: Path | None = None
    cand_plan: list[dict] | None = None

    if cand_dir_raw:
        cand_dir = Path(str(cand_dir_raw)).expanduser()
        if not cand_dir.is_absolute():
            cand_dir = (Path.cwd() / cand_dir)
        cand_dir = cand_dir.resolve()
        cand_plan = _candidate_parse_dir_or_die(topo, cand_dir)

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
            "keep_going": bool(keep_going),
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
        evidence: dict | None = None,
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
            "evidence": evidence,
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
        evidence: dict | None = None,
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
            "evidence": evidence,
        }
        if meta:
            rec["meta"] = meta
        results["events"].append(rec)

    def record_event_scenario_fault(
        *,
        scenario_id: str,
        step_index: int,
        verdict: str,
        duration_ms: int,
        error: str = "",
        meta: dict | None = None,
    ) -> None:
        """
        Persist a deterministic scenario fault event into results.json.
        This is the authoritative machine-consumable record for scenario fault steps.
        """
        rec = {
            "type": "scenario_fault",
            "scenario_id": str(scenario_id),
            "step": int(step_index),
            "verdict": str(verdict),
            "duration_ms": int(duration_ms),
            "error": str(error or ""),
        }
        if meta:
            rec["meta"] = meta

        # --- HARD DETERMINISTIC GUARD ---
        # Never allow more than one scenario_fault event
        # for the same scenario_id + step_index
        for e in results.get("events", []):
            if (
                e.get("type") == "scenario_fault"
                and e.get("scenario_id") == scenario_id
                and int(e.get("step") or -1) == int(step_index)
            ):
                return
        # --------------------------------

        results["events"].append(rec)

    def write_results() -> None:
        out = lab_dir(lab) / "results.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote: {out}")

        summary_path = write_test_summary_artifact(lab, results)
        print(f"Wrote: {summary_path}")

        if print_json:
            print(json.dumps(results, indent=2))

    # Use module-level retry_until() (authoritative)
    # (Do not re-define it here; keep behavior consistent everywhere.)

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
    def run_ping_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> dict:
        expected = (t.get("expect") or "pass").lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        # ---- destination resolution (v1-safe) ----
        dst_kind = t.get("_dst_kind")
        dst_value = t.get("_dst_value")

        if dst_kind and dst_value:
            dst_token = str(dst_value).strip()
        else:
            dst_token = (t.get("dst") or t.get("to") or t.get("to_ip") or "").strip()

        if not dst_token:
            die(f"test {test_name}: missing destination (need dst or to/to_ip)")

        if dst_kind == "ip" or is_ip_literal(dst_token):
            dst_ip = dst_token
            validate_ip_literal(dst_ip, f"test {test_name}")
        else:
            dst_ip = node_ip_or_die(dst_token)

        # ---- execution params ----
        count = int(t.get("count") or 2)

        # ICMP per-attempt timeout (-W). Keep it small and explicit.
        per_attempt_timeout_s = int(t.get("per_attempt_timeout_s") or 1)

        # Retry window applies only when we expect success (convergence)
        retry_timeout_s = int(t.get("timeout_s") or 15)
        retry_interval_s = float(t.get("retry_interval_s") or 1.0)

        # v1.x optional ping source selector (Tier-1 validation only)
        src_ip = t.get("src_ip")
        src_if = t.get("src_if")

        if src_ip is not None and src_if is not None:
            die(f"ERROR: ping test '{test_name}': specify only one of src_ip or src_if")

        if src_ip is not None:
            if not isinstance(src_ip, str) or not src_ip.strip():
                die(f"ERROR: ping test '{test_name}': src_ip must be a non-empty string")
            validate_ip_literal(src_ip.strip(), f"ping test '{test_name}' src_ip")

        if src_if is not None:
            if not isinstance(src_if, str) or not src_if.strip():
                die(f"ERROR: ping test '{test_name}': src_if must be a non-empty string")
            if any(ch.isspace() for ch in src_if):
                die(f"ERROR: ping test '{test_name}': src_if must not contain whitespace")

        def _format_ping_ctx(*, expected_s: str, observed_s: str) -> str:
            dst_part = str(dst_ip) if dst_ip else f"<unresolved: {dst_token}>"
            extras = []
            if src_if:
                extras.append(f"src_if={str(src_if).strip()}")
            if src_ip:
                extras.append(f"src_ip={str(src_ip).strip()}")
            extra_s = f" ({', '.join(extras)})" if extras else ""
            return f"ping mismatch: from={src} dst={dst_part} expected={expected_s} observed={observed_s}{extra_s}"

        def attempt():
            ping_cmd = ["ping", "-c", str(count), "-W", str(per_attempt_timeout_s)]
            if src_ip:
                ping_cmd += ["-I", str(src_ip).strip()]
            elif src_if:
                ping_cmd += ["-I", str(src_if).strip()]
            ping_cmd += [dst_ip]

            cp = rt.exec(
                lab,
                src,
                ping_cmd,
                check=False,
            )
            return (cp.returncode == 0), cp

        if expected == "fail":
            # v1 gate semantics: expected fail is fail-fast (single attempt)
            ok, last_cp = attempt()
            attempts = 1
            dur_ms = 0
        else:
            ok, last_cp, attempts, dur_ms = retry_until(retry_timeout_s, retry_interval_s, attempt)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        err = "" if verdict == "pass" else _format_ping_ctx(expected_s=expected, observed_s=observed)

        rec = {
            "name": test_name,
            "kind": "ping",
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": int(dur_ms),
            "error": err,
            "meta": {
                "dst_ip": dst_ip,
                "dst_raw": dst_token,
                "count": count,
                "per_attempt_timeout_s": per_attempt_timeout_s,
                "attempts": attempts,
                "retry_timeout_s": (retry_timeout_s if expected == "pass" else 0),
                "retry_interval_s": (retry_interval_s if expected == "pass" else 0),
                "last_rc": getattr(last_cp, "returncode", None),
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
            },
        }

        # Record once, always
        record_fn(
            name=rec["name"],
            kind=rec["kind"],
            src=rec["from"],
            dst=rec["to"],
            expected=rec["expected"],
            observed=rec["observed"],
            verdict=rec["verdict"],
            evidence={
                "cmd": "ping",
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
                "dst_ip": str(dst_ip),
            },
            duration_ms=rec["duration_ms"],
            error=rec["error"],
            meta=rec["meta"],
        )

        return rec

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
                evidence={"reason": "invalid_port"},
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
            evidence={"cmd": "nc -z"},
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

    def run_bgp_neighbor_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> str:
        """
        v1.x: binary control-plane health invariant.
        - src: node name (runs vtysh here)
        - dst: neighbor IPv4 literal (string)
        - expect: pass|fail (also accepts up|down synonyms)
        """

        raw_expect = (t.get("expect") or "pass")
        exp_s = str(raw_expect).strip().lower()

        # Normalize expected -> "up" or "down"
        if exp_s in ("pass", "up", "established", "true", "ok", "allow"):
            expected = "up"
        elif exp_s in ("fail", "down", "false", "drop", "deny"):
            expected = "down"
        else:
            expected = "up"

        neighbor = str(dst or "").strip()
        try:
            ip = ipaddress.ip_address(neighbor)
            if ip.version != 4:
                raise ValueError("neighbor must be IPv4")
        except Exception:
            record_fn(
                name=test_name,
                kind="bgp_neighbor",
                src=src,
                dst=dst,
                expected=expected,
                observed="down",
                verdict="fail",
                duration_ms=0,
                error="dst must be an IPv4 neighbor address",
                meta={"neighbor": neighbor},
                evidence={"reason": "invalid_neighbor_ip"},
            )
            return "fail"

        timeout_s = int(t.get("timeout_s") or (15 if expected == "up" else 0))
        interval_s = float(t.get("retry_interval_s") or 1.0)

        def attempt():
            # Prefer JSON for deterministic parsing
            cp = rt.exec(lab, src, ["vtysh", "-c", "show bgp summary json"], check=False)
            ok = (getattr(cp, "returncode", 1) == 0)
            out = (cp.stdout or "") if hasattr(cp, "stdout") else ""
            return ok, cp, out

        start = time.time()

        # Only retry when we expect "up" (deterministic + aligns with readiness semantics)
        if expected == "up" and timeout_s > 0:
            def try_once():
                ok, cp, out = attempt()
                return ok, (cp, out)

            ok, last_payload, attempts, dur_ms = retry_until(timeout_s, interval_s, try_once)
            last_cp, last_out = last_payload
        else:
            ok, last_cp, last_out = attempt()
            attempts = 1
            dur_ms = int((time.time() - start) * 1000)

        observed = "down"
        state = None
        parse_error = ""

        if ok:
            try:
                data = json.loads(last_out or "{}")

                def _extract_peers(obj: dict) -> dict | None:
                    # 1) Some FRR builds: peers at top-level
                    peers = obj.get("peers")
                    if isinstance(peers, dict):
                        return peers

                    # 2) Common FRR: peers under address-family key, e.g. ipv4Unicast.peers
                    v4u = obj.get("ipv4Unicast")
                    if isinstance(v4u, dict):
                        peers = v4u.get("peers")
                        if isinstance(peers, dict):
                            return peers

                    # 3) Defensive: scan 1 level deep for any dict that contains a peers dict
                    for _, v in obj.items():
                        if isinstance(v, dict):
                            peers = v.get("peers")
                            if isinstance(peers, dict):
                                return peers

                    return None

                peers = _extract_peers(data)
                if not isinstance(peers, dict):
                    peers = {}
                    parse_error = "peers not found in summary"

                p = peers.get(neighbor)

                if isinstance(p, dict):
                    # FRR fields vary; prefer "state" when present
                    state = p.get("state") or p.get("bgpState") or p.get("peerState")
                    st = (state or "").strip().lower()
                    observed = "up" if st == "established" else "down"
                else:
                    observed = "down"
                    if not parse_error:
                        parse_error = "neighbor not present in summary"

            except Exception as e:
                observed = "down"
                parse_error = f"json parse error: {e.__class__.__name__}"
        else:
            parse_error = "vtysh command failed"

        verdict = "pass" if observed == expected else "fail"

        meta = {
            "neighbor": neighbor,
            "state": state,
            "attempts": attempts,
            "timeout_s": timeout_s,
            "retry_interval_s": interval_s,
            "last_rc": getattr(last_cp, "returncode", None),
        }

        evidence = {
            "cmd": "vtysh -c 'show bgp summary json'",
            "parse_error": parse_error,
        }

        record_fn(
            name=test_name,
            kind="bgp_neighbor",
            src=src,
            dst=dst,
            expected=expected,
            observed=observed,
            verdict=verdict,
            duration_ms=int(dur_ms),
            error="" if verdict == "pass" else f"bgp neighbor mismatch (expected {expected}, observed {observed})",
            meta=meta,
            evidence=evidence,
        )

        return verdict

    def run_named_test(ref: str, *, scenario_ctx: tuple[str, int] | None = None) -> str:
        """
        Execute a declared atomic test by name (used by scenarios).
        Returns: "pass" | "fail"
        """
        if ref not in tests_by_name:
            # With fail-fast validation, this should never happen.
            die(f"INTERNAL ERROR: scenario referenced unknown test '{ref}' after pre-validation")

        t = tests_by_name[ref]

        kind = (t.get("kind") or t.get("type") or "").strip()

        src = t.get("src")
        dst = t.get("dst")

        if kind == "ping":
            if not src or not (dst or t.get("to") or t.get("to_ip")):
                record_test(
                    name=ref,
                    kind=kind or "ping",
                    src=src or "",
                    dst=(dst or t.get("to") or t.get("to_ip") or ""),
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
                    duration_ms=0,
                    error="missing src + (dst or to/to_ip)",
                )
                return "fail"

        elif kind == "bgp_neighbor":
            if not src or not dst:
                record_test(
                    name=ref,
                    kind=kind,
                    src=src or "",
                    dst=dst or "",
                    expected="up",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
                    duration_ms=0,
                    error="missing src/dst (neighbor IPv4 required)",
                )
                return "fail"

            if not isinstance(dst, str) or not is_ip_literal(dst.strip()):
                record_test(
                    name=ref,
                    kind=kind,
                    src=src or "",
                    dst=str(dst) if dst is not None else "",
                    expected="up",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "invalid_neighbor_ip"},
                    duration_ms=0,
                    error="dst must be an IPv4 neighbor address",
                )
                return "fail"

        else:
            if not src or not dst:
                record_test(
                    name=ref,
                    kind=kind or "unknown",
                    src=src or "",
                    dst=dst or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
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
                dst_label = dst or t.get("to") or t.get("to_ip") or ""
                rec = run_ping_test(test_name=ref, src=src, dst=dst_label, t=t, record_fn=record_fn)
                # In scenario mode, run_named_test must return a verdict string.
                if isinstance(rec, dict):
                    return str(rec.get("verdict") or "fail")
                return str(rec)
            # Non-scenario path preserves existing behavior (dict record)
            return run_ping_test(test_name=ref, src=src, dst=dst, t=t)

        if kind == "tcp":
            if record_fn:
                return run_tcp_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_tcp_test(test_name=ref, src=src, dst=dst, t=t)
        
        if kind == "bgp_neighbor":
            if record_fn:
                return run_bgp_neighbor_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_bgp_neighbor_test(test_name=ref, src=src, dst=dst, t=t)

        record_test(
            name=ref,
            kind=str(kind or "unknown"),
            src=src,
            dst=dst,
            expected="pass",
            observed="fail",
            verdict="fail",
            duration_ms=0,
            error=f"unsupported kind '{kind}' (supported: ping, tcp, bgp_neighbor)",

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

    def _find_link_interfaces_from_topology(
        topo: dict,
        a: str,
        b: str,
        *,
        a_if: str | None = None,
        b_if: str | None = None,
    ) -> tuple[str | None, str | None]:
        """
        Deterministically map node pair -> interface pair.

        If a_if/b_if provided:
        - must match a declared link exactly (order-insensitive, mapped to a->b direction)

        If not provided:
        - there must be exactly ONE link between a and b, otherwise fail fast.
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

        # Explicit disambiguation path
        if a_if is not None or b_if is not None:
            if not (isinstance(a_if, str) and isinstance(b_if, str)):
                die("fault link_down/link_up: a_if and b_if must be strings when provided")

            a_if_s = a_if.strip()
            b_if_s = b_if.strip()
            if not a_if_s or not b_if_s:
                die("fault link_down/link_up: a_if and b_if must be non-empty when provided")

            if (a_if_s, b_if_s) in matches:
                return a_if_s, b_if_s

            die(
                f"fault link_down/link_up: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                f"does not match any declared link between {a} and {b}"
            )

        # Implicit path: must be unambiguous
        if len(matches) == 0:
            die(f"fault link_down/link_up: no link found between {a} and {b}")
        if len(matches) > 1:
            die(
                f"fault link_down/link_up: ambiguous links between {a} and {b} "
                f"({len(matches)} found); provide a_if/b_if"
            )

        return matches[0]

    def _find_link_interfaces(
        a: str,
        b: str,
        *,
        a_if: str | None = None,
        b_if: str | None = None,
    ) -> tuple[str | None, str | None]:
        """
        Determine interface pair for a<->b.

        Deterministic rules:
        - If a_if/b_if provided: require topo["links"] to match exactly; fail fast otherwise.
        - If not provided: prefer topo["links"] unambiguous match; else fall back to links_by_node best-effort.
        """
        # Prefer authoritative topo["links"] parsing (most reliable)
        try:
            ta_if, tb_if = _find_link_interfaces_from_topology(topo, a, b, a_if=a_if, b_if=b_if)
            if ta_if and tb_if:
                return ta_if, tb_if
        except SystemExit:
            # If user explicitly disambiguated, do NOT fall back to guessing.
            if a_if is not None or b_if is not None:
                raise
            # Otherwise, allow fallback below.
            pass

        # Fallback: best-effort from build_node_links() if present (only when not explicitly disambiguated)
        fa_if: str | None = None
        fb_if: str | None = None

        for l in links_by_node.get(a, []) or []:
            if l.get("peer") == b:
                fa_if = l.get("ifname") or l.get("iface") or l.get("interface")
                fb_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                break

        if fb_if is None:
            for l in links_by_node.get(b, []) or []:
                if l.get("peer") == a:
                    fb_if = l.get("ifname") or l.get("iface") or l.get("interface")
                    if fa_if is None:
                        fa_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                    break

        return fa_if, fb_if

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

        # ----------------------------
        # link_down / link_up
        # Supports optional a_if/b_if for deterministic multi-link disambiguation.
        # ----------------------------
        if "link_down" in fault or "link_up" in fault:
            action = "link_down" if "link_down" in fault else "link_up"
            spec = fault.get(action) or {}
            a = spec.get("a")
            b = spec.get("b")
            if not a or not b:
                raise ValueError(f"{action}: requires a,b")

            # Optional explicit interface disambiguation (validated earlier in validate_scenarios)
            a_if_req = spec.get("a_if")
            b_if_req = spec.get("b_if")

            a_if, b_if = _find_link_interfaces(a, b, a_if=a_if_req, b_if=b_if_req)
            if not a_if or not b_if:
                raise ValueError(f"{action}: could not determine interfaces for link {a}<->{b}")

            if action == "link_down":
                _iface_down(a, a_if)
                _iface_down(b, b_if)
                return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": 0}

            ra = _iface_up(a, a_if)
            rb = _iface_up(b, b_if)
            return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": (ra + rb)}

        # ----------------------------
        # interface_down / interface_up
        # ----------------------------
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

        # ----------------------------
        # node_stop / node_start (future primitives)
        # ----------------------------
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

        # v1.x ping tuning (deterministic, explicit)
        count = int(wait_for.get("count") or 1)
        per_attempt_timeout_s = int(wait_for.get("per_attempt_timeout_s") or 1)

        # v1.x optional ping source selector (Tier-1 validation only)
        src_ip = wait_for.get("src_ip")
        src_if = wait_for.get("src_if")

        if src_ip is not None and src_if is not None:
            raise ValueError("wait_for ping: specify only one of src_ip or src_if")

        if src_ip is not None:
            if not isinstance(src_ip, str) or not src_ip.strip():
                raise ValueError("wait_for ping: src_ip must be a non-empty string")
            validate_ip_literal(src_ip.strip(), "wait_for ping src_ip")

        if src_if is not None:
            if not isinstance(src_if, str) or not src_if.strip():
                raise ValueError("wait_for ping: src_if must be a non-empty string")
            if any(ch.isspace() for ch in src_if):
                raise ValueError("wait_for ping: src_if must not contain whitespace")

        if count < 1:
            raise ValueError("wait_for ping: count must be >= 1")
        if per_attempt_timeout_s < 1:
            raise ValueError("wait_for ping: per_attempt_timeout_s must be >= 1")


        if expected not in ("pass", "fail"):
            raise ValueError("wait_for ping: expect must be pass|fail")
        if not src or not to:
            raise ValueError("wait_for ping: requires from + to")

        # If "to" looks like a node name, resolve to its first IPv4
        # v1-safe: "to" may be node name OR IP literal (fail-fast otherwise)
        if not isinstance(to, str) or not to.strip():
            raise ValueError("wait_for ping: to must be a non-empty string (node name or IP literal)")
        dst_ip = resolve_dst_to_ip(topo, to.strip())

        should_succeed = (expected == "pass")

        def attempt():
            ping_cmd = ["ping", "-c", str(count), "-W", str(per_attempt_timeout_s)]
            if src_ip:
                ping_cmd += ["-I", str(src_ip).strip()]
            elif src_if:
                ping_cmd += ["-I", str(src_if).strip()]
            ping_cmd += [str(dst_ip)]

            cp = rt.exec(
                lab,
                str(src),
                ping_cmd,
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
            "src_ip": (str(src_ip).strip() if src_ip else ""),
            "src_if": (str(src_if).strip() if src_if else ""),
            "attempts": attempts,
            "timeout_s": timeout_s,
            "interval_s": interval_s,
            "count": count,
            "per_attempt_timeout_s": per_attempt_timeout_s,
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
                verdict = run_named_test(ref, scenario_ctx=(sid, step_idx))
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

                    # deterministic event
                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error="fault must be a dict",
                        meta={"action": "invalid", "target": ""},
                    )

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

                    # keep existing scenario step trace
                    scen_step({
                        "type": "fault",
                        "action": action,
                        "target": target,
                        "verdict": "pass",
                        "duration_ms": dur_ms,
                        "step": step_idx,
                        "meta": meta,
                    })

                    # -------- deterministic artifact event --------
                    fmeta = dict(meta or {})
                    fmeta["action"] = action
                    fmeta["target"] = target

                    # normalize restored_routes to int if present
                    if "restored_routes" in fmeta:
                        try:
                            fmeta["restored_routes"] = int(fmeta.get("restored_routes") or 0)
                        except Exception:
                            fmeta["restored_routes"] = 0

                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="pass",
                        duration_ms=dur_ms,
                        error="",
                        meta=fmeta,
                    )
                    # ---------------------------------------------

                    note = ""
                    if action in ("link_up", "interface_up"):
                        rr = 0
                        try:
                            rr = int((meta or {}).get("restored_routes") or 0)
                        except Exception:
                            rr = 0
                        note = f" (restored_routes={rr})"

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

                    # deterministic event
                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error=str(e),
                        meta={"action": "error", "target": ""},
                    )

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

                    _sv(
                        f"[scenario {sid}] {step_idx:02d}. wait_for type={wtype} expected={expected} observed={observed} -> {verdict.upper()} ({dur_ms}ms)"
                    )

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
            # wait_for_bgp: { node: <frr>, timeout: N }
            # -------------------------
            if "wait_for_bgp" in step:
                wf = step.get("wait_for_bgp") or {}
                node = wf.get("node")
                timeout = int(wf.get("timeout") or 30)

                if not isinstance(node, str) or not node.strip():
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for_bgp",
                        "node": str(node),
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "wait_for_bgp.node must be a non-empty string",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> FAIL (invalid node)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                node = node.strip()
                _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp node={node} timeout={timeout}")

                try:
                    wait_for_bgp(rt, lab, node, timeout=timeout)

                    dur_ms = int((time.time() - step_started) * 1000)
                    meta = {"node": node, "timeout_s": timeout}

                    scen_step({
                        "type": "wait_for_bgp",
                        "node": node,
                        "verdict": "pass",
                        "duration_ms": dur_ms,
                        "meta": meta,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> PASS ({dur_ms}ms)")

                except SystemExit as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    meta = {"node": node, "timeout_s": timeout}

                    scen_step({
                        "type": "wait_for_bgp",
                        "node": node,
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "meta": meta,
                        "error": str(e),
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> FAIL ({e})")

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
            # v1.x UX hardening: lab exists but containers are stopped (common after reboot / manual clab destroy)
            hint_lines = [
                "Lab exists but one or more containers are not running.",
                "Try:",
                "  netsim up <topology.yaml> --reconfigure",
                "or (advanced):",
                f"  sudo containerlab deploy -t {tpath}",
            ]
            die(f"{name} is not running\n\n" + "\n".join(hint_lines))


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
    # 2.5) Candidate Config Apply (v1.5) - gate-only, atomic, evidenced
    # =============================================================================
    # IMPORTANT: this must run AFTER readiness and BEFORE any tests/scenarios.
    # Reuse normalized cand_dir + cand_plan from earlier fail-fast parse if present.
    # Fallback to parsing here only if older code path didn't create them.
    if "cand_dir" not in locals():
        cand_dir = None  # type: ignore[assignment]
    if "cand_plan" not in locals():
        cand_plan = None  # type: ignore[assignment]

    cand_dir_raw = getattr(args, "candidate_config", None)

    if cand_dir is None and cand_dir_raw:
        cand_dir = Path(str(cand_dir_raw)).expanduser()
        if not cand_dir.is_absolute():
            cand_dir = (Path.cwd() / cand_dir)
        cand_dir = cand_dir.resolve()
        cand_plan = _candidate_parse_dir_or_die(topo, cand_dir)

    # Only run apply when we actually have candidate inputs enabled
    if cand_dir is not None and cand_plan is not None:
        results["candidate_apply"] = {
            "enabled": True,
            "input_dir": str(cand_dir),
            "plan": [r["node"] for r in cand_plan],
            "verdict": "unknown",
            "failed_nodes": [],
            "duration_ms": None,
        }

        apply_started = time.time()
        failed: list[str] = []

        for item in cand_plan:
            node = item["node"]
            ntype = item["node_type"]
            src = Path(item["source_path"])

            # Always emit a per-node artifact for every attempted node.
            rec: dict[str, Any]
            try:
                if ntype == "frr":
                    rec = _candidate_apply_frr_generated_only(rt, lab, topo, node, src)
                elif ntype == "nft-fw":
                    rec = _candidate_apply_nft(rt, lab, node, src)
                else:
                    rec = {
                        "node": node,
                        "node_type": str(ntype),
                        "method": "unsupported",
                        "input": {
                            "source_path": str(src),
                            "sha256": _sha256_file(src) if src.exists() else "",
                        },
                        "attempt": {
                            "started_at_epoch_ms": int(time.time() * 1000),
                            "duration_ms": 0,
                        },
                        "result": {"applied_ok": False, "exit_code": 3},
                        "stdout": "",
                        "stderr": _safe_stdio(f"candidate apply: unsupported node_type '{ntype}'"),
                        "post_checks": [],
                    }
            except SystemExit as e:
                rec = {
                    "node": node,
                    "node_type": str(ntype),
                    "method": "exception",
                    "input": {
                        "source_path": str(src),
                        "sha256": _sha256_file(src) if src.exists() else "",
                    },
                    "attempt": {
                        "started_at_epoch_ms": int(time.time() * 1000),
                        "duration_ms": 0,
                    },
                    "result": {"applied_ok": False, "exit_code": 1},
                    "stdout": "",
                    "stderr": _safe_stdio(str(e)),
                    "post_checks": [],
                }

            _write_candidate_apply_artifact(lab, node, rec)

            if not bool(((rec.get("result") or {}).get("applied_ok"))):
                failed.append(node)
                # Atomic: stop further mutation after first failure.
                break

        apply_finished = time.time()
        results["candidate_apply"]["duration_ms"] = int((apply_finished - apply_started) * 1000)

        if failed:
            results["candidate_apply"]["verdict"] = "fail"
            results["candidate_apply"]["failed_nodes"] = failed

            # Hard rule: tests/scenarios MUST NOT run on candidate apply failure
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
            write_results()

            die("candidate apply failed for node(s): " + ", ".join(failed))

        results["candidate_apply"]["verdict"] = "pass"

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

    # Convergence semantics:
    # - Default tests: keep legacy behavior (precheck BGP if participants exist)
    # - Scenarios: skip global precheck unless user explicitly requests it
    do_global_cp_precheck = (not want_scenarios) or precheck_controlplane
    results["summary"]["precheck_controlplane"] = bool(do_global_cp_precheck)

    if do_global_cp_precheck and bgp_participants:
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

                if kind not in ("ping", "tcp", "bgp_neighbor"):
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
                    fail_or_continue(f"tests[{i}]: unsupported kind '{kind}' (supported: ping, tcp, bgp_neighbor)")
                    continue

                if filter_kind and kind != filter_kind:
                    continue

                matched += 1

                src = t.get("src")
                dst = t.get("dst")

                if kind == "ping":
                    # v1: ping supports dst (node) OR to/to_ip (ip literal)
                    if not src or not (dst or t.get("to") or t.get("to_ip")):
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=(dst or t.get("to") or t.get("to_ip") or ""),
                            expected="pass",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src/dst(to)",
                        )
                        fail_or_continue(f"tests[{i}]: missing src + (dst or to/to_ip)")
                        continue

                elif kind == "bgp_neighbor":
                    # v1.x: bgp_neighbor requires src node + dst neighbor IPv4 literal
                    if not src or not dst:
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=dst or "",
                            expected="up",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src/dst (neighbor IPv4 required)",
                        )
                        fail_or_continue(f"tests[{i}]: missing src/dst (neighbor IPv4 required)")
                        continue

                    if not isinstance(dst, str) or not is_ip_literal(dst.strip()):
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=str(dst) if dst is not None else "",
                            expected="up",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="dst must be an IPv4 neighbor address",
                        )
                        fail_or_continue(f"tests[{i}]: bgp_neighbor dst must be an IPv4 literal")
                        continue

                else:
                    # tcp (and future kinds) keep legacy requirement
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
                    dst_label = (
                        t.get("dst")
                        or t.get("to")
                        or t.get("to_ip")
                        or t.get("to_ip4")
                        or t.get("to_ip6")
                        or dst
                        or ""
                    )

                    r = run_ping_test(test_name=test_name, src=src, dst=dst_label, t=t)

                    if r.get("verdict") != "pass":
                        dst_ip = None
                        meta = r.get("meta")
                        if isinstance(meta, dict):
                            dst_ip = meta.get("dst_ip")
                        extra = f" ({dst_ip})" if dst_ip else ""
                        fail_or_continue(
                            f"tests[{i}] ping mismatch: {src} -> {dst_label}{extra} expected {r.get('expected')}, observed {r.get('observed')}"
                        )
                    continue

                if kind == "bgp_neighbor":
                    verdict = run_bgp_neighbor_test(test_name=test_name, src=src, dst=dst, t=t)
                    if verdict != "pass":
                        fail_or_continue(
                            f"tests[{i}] bgp_neighbor mismatch: {src} -> {dst} expected {t.get('expect','pass')}"
                        )
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

    if bgp_participants and results["summary"].get("precheck_controlplane"):
        print(f"✅ Control-plane PASS: BGP established ({len(bgp_participants)} participants)")
    elif bgp_participants and want_scenarios:
        print("ℹ️ Control-plane precheck skipped for scenarios (use --precheck-controlplane to enable)")

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

def cmd_gen(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    out = write_containerlab_file(topo_path)
    print(f"Generated containerlab file: {out}")

def cmd_validate(args: argparse.Namespace) -> None:
    """
    Validate topology + scenarios without deploying anything.

    CI-friendly semantics:
      - exit 0 on pass, exit 1 on fail
      - with --json: emit exactly ONE JSON object and no extra "ERROR:" prefix
      - without --json: keep human output (✅ / die(...))

    NOTE: This relies on die() honoring a module-global `_QUIET_DIE` flag:
      - when _QUIET_DIE is True, die() must NOT print "ERROR:" and must raise SystemExit(<message>)
        (so str(SystemExit) is the message, not "1").
    """
    import json
    import sys  # keep (often used elsewhere)

    global _QUIET_DIE  # module-global flag used by die()

    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    want_json: bool = bool(getattr(args, "json", False))

    def emit(result: str, error: str = "") -> None:
        payload = {
            "schema_version": "1",
            "command": "validate",
            "topology": str(topo_path),
            "result": result,
            "error": error or "",
        }
        if want_json:
            print(json.dumps(payload, indent=2))
        else:
            if result == "pass":
                print(f"✅ VALIDATE PASS: {topo_path}")
            else:
                die(error or "validation failed")

    prev_quiet = bool(globals().get("_QUIET_DIE", False))
    _QUIET_DIE = want_json
    try:
        topo = load_yaml(topo_path)
        ensure_valid_topology(topo)

        resolved = resolve_topology(topo)
        validate_scenarios(resolved)

        emit("pass", "")
        return  # do not fall through

    except SystemExit as e:
        # In --json mode, die() should have raised SystemExit(<message>), so str(e) is the real error.
        msg = str(e).strip() or "validation failed"
        if want_json:
            emit("fail", msg)
            raise SystemExit(1)
        raise

    except Exception as e:
        msg = str(e).strip() or "validation failed"
        if want_json:
            emit("fail", msg)
            raise SystemExit(1)
        die(msg)

    finally:
        _QUIET_DIE = prev_quiet

def cmd_up(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # If --reconfigure: destroy + remove root-owned lab dir FIRST.
    # Pre-validate topology BEFORE any destructive action (v1 deterministic, fail-fast)
    topo_preview = load_yaml(topo_path)
    ensure_valid_topology(topo_preview)
    resolved_preview = resolve_topology(topo_preview)
    validate_scenarios(resolved_preview)

    # If --reconfigure: destroy + remove root-owned lab dir AFTER validation passes.
    if getattr(args, "reconfigure", False):
        lab_name: str | None = None
        try:
            lab_name = (resolved_preview or {}).get("name")
        except Exception:
            lab_name = None

        if isinstance(lab_name, str) and lab_name.strip():
            lab_name = lab_name.strip()
            existing_clab = LABS_DIR / f"{lab_name}.clab.yaml"
            if existing_clab.exists():
                run(["sudo", "containerlab", "destroy", "-t", str(existing_clab)], check=False)
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

def cmd_down(args: argparse.Namespace) -> None:
    out = lab_file_from_name(args.name)
    if not out.exists():
        die(f"Lab file not found: {out} (did you run gen/up first?)")
    run(["sudo", "containerlab", "destroy", "-t", str(out)])

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

def cmd_cleanup(args: argparse.Namespace) -> None:
    """
    v1.x ops helper (non-authoritative):
      netsim cleanup --all [--yes]

    Safety:
      - ONLY targets ai-netsim labs that have artifacts under labs/clab-*
      - Dry-run by default; --yes required to destroy
      - Never touches labs not present in labs/
      - Does NOT delete artifacts
    """
    if not getattr(args, "all", False):
        die("cleanup requires --all. This command only targets ai-netsim labs present in labs/ (labs/clab-*).")

    candidates = list_owned_labs_from_artifacts()

    print("Cleanup plan (dry-run):" if not getattr(args, "yes", False) else "Cleanup plan (execute):")
    if not candidates:
        print("- (none)  No ai-netsim lab artifacts found under labs/clab-*")
        return

    for lab, artifact_dir in candidates:
        print(f"- {lab}   ({artifact_dir})")

    if not getattr(args, "yes", False):
        print("Run with --yes to destroy these labs. (Artifacts under labs/clab-* are not deleted automatically.)")
        return

    # Execute: best-effort, deterministic order, never stops on per-lab failure
    failures: list[str] = []

    for lab, artifact_dir in candidates:
        clab_yaml = lab_file_from_name(lab)

        # If the generated containerlab file is missing, we still keep safety:
        # we DO NOT scan Docker; we treat this as a safe no-op attempt.
        if not clab_yaml.exists():
            print(f"OK  {lab}: no {clab_yaml.name} found (treating as already down; artifacts kept)")
            continue

        cp = run(
            ["sudo", "containerlab", "destroy", "-t", str(clab_yaml)],
            check=False,
            capture_output=True,
        )

        if cp.returncode == 0:
            print(f"OK  {lab}: destroyed")
            continue

        # Best-effort classification: containerlab may say "not found" if already down.
        combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        low = combined.lower()
        if "not found" in low or "no such" in low:
            print(f"OK  {lab}: already down / not found (artifacts kept)")
            continue

        # Otherwise warn and continue
        summary = combined.splitlines()[-1].strip() if combined else f"exit {cp.returncode}"
        print(f"WARN {lab}: destroy failed: {summary}")
        failures.append(f"{lab}: {summary}")

    if failures:
        print("Cleanup completed with warnings:")
        for f in failures:
            print(f"- {f}")
    else:
        print("Cleanup completed successfully. (Artifacts were not deleted.)")

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

# --- Assistive AI (v1: advisory-only, artifact-only, post-exec, BYO-key online optional) ---

def _ai_resolve_lab_and_dir(arg: str) -> tuple[str, str]:
    """
    If 'arg' looks like a topology file (*.yaml|*.yml), load it and use its 'name' as the lab.
    Otherwise treat it as a lab name directly.
    Returns (lab, lab_dir).
    """
    from pathlib import Path
    import yaml

    p = Path(arg)
    if p.suffix in (".yaml", ".yml") and p.exists():
        with p.open("r", encoding="utf-8") as f:
            topo = yaml.safe_load(f) or {}
        lab = str((topo.get("name") or "").strip())
        if not lab:
            print("AI usage error: topology must define 'name' to resolve lab.", file=sys.stderr)
            sys.exit(2)
    else:
        lab = arg.strip()
        if not lab:
            print("AI usage error: lab name is empty.", file=sys.stderr)
            sys.exit(2)

    return lab, os.path.join("labs", f"clab-{lab}")


def _ai_read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _ai_file_exists(path: str) -> bool:
    try:
        st = os.stat(path)
        return st.st_size >= 0
    except Exception:
        return False


def _ai_advisory_headers() -> dict[str, Any]:
    return {
        "authority": "advisory",
        "non_authoritative": True,
        "disclaimer": "Assistive AI is advisory-only. Tests & scenarios are authoritative.",
    }


def _ai_print_json(payload: dict[str, Any], ensure_ascii: bool = False) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=ensure_ascii))


def _ai_env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def _ai_default_bundle_out_path(bundle: dict[str, Any]) -> str | None:
    """
    Default bundle location:
      - explain: labs/<labdir>/ai/ai_bundle.json (uses bundle["lab"]["labdir"])
      - review: no default (no labdir) -> only writes if --bundle-out is provided
      - coach: no default (no labdir) -> only writes if --bundle-out is provided
    """
    lab = bundle.get("lab")
    if isinstance(lab, dict):
        labdir = lab.get("labdir")
        if isinstance(labdir, str) and labdir.strip():
            return os.path.join(labdir.strip(), "ai", "ai_bundle.json")
    return None


def _ai_write_bundle(path: str, bundle: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True, ensure_ascii=False)


def _ai_online_config(args) -> dict[str, Any]:
    """
    BYO key contract:
      - provider: AI_NETSIM_AI_PROVIDER (currently only 'openai' supported)
      - api_key: AI_NETSIM_AI_API_KEY or OPENAI_API_KEY
      - model:   --model or AI_NETSIM_AI_MODEL (fallback safe default inside _ai_try_online)
      - base_url: optional AI_NETSIM_AI_BASE_URL (for proxies/self-hosting)
    """
    provider = _ai_env("AI_NETSIM_AI_PROVIDER").lower()
    api_key = _ai_env("AI_NETSIM_AI_API_KEY") or _ai_env("OPENAI_API_KEY")
    model = (getattr(args, "model", None) or _ai_env("AI_NETSIM_AI_MODEL") or "").strip()
    base_url = _ai_env("AI_NETSIM_AI_BASE_URL") or ""
    if base_url == "":
        base_url = None
    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
    }

def _ai_sanitize_error(msg: str) -> str:
    """
    Sanitize provider error messages so they are safe to emit:
      - remove API keys
      - trim excessive length
    """
    if not msg:
        return ""

    # Never leak anything that looks like an API key
    msg = re.sub(r"sk-[A-Za-z0-9]{10,}", "sk-REDACTED", msg)

    # Bound size (CI / logs safety)
    MAX = 500
    if len(msg) > MAX:
        msg = msg[:MAX] + "...(truncated)"

    return msg

def _ai_validate_output_schema(out: Any) -> tuple[bool, str]:
    """
    Validate the v1 AI output schema.

    Required:
      - summary: string

    Optional (but if present must match shape):
      - findings: list of {title,evidence,suggestion} strings
      - suggested_next_tests: list of {id,title,why,yaml} strings

    Returns: (ok, error_string)
    """
    if not isinstance(out, dict):
        return (False, "AI output must be a JSON object")

    summary = out.get("summary")
    if not isinstance(summary, str):
        return (False, "AI output schema error: 'summary' must be a string")

    findings = out.get("findings", [])
    if findings is None:
        findings = []
    if not isinstance(findings, list):
        return (False, "AI output schema error: 'findings' must be a list")

    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            return (False, f"AI output schema error: findings[{i}] must be an object")
        for k in ("title", "evidence", "suggestion"):
            if k not in f or not isinstance(f.get(k), str):
                return (False, f"AI output schema error: findings[{i}].{k} must be a string")

    nxt = out.get("suggested_next_tests")
    if nxt is not None:
        if not isinstance(nxt, list):
            return (False, "AI output schema error: 'suggested_next_tests' must be a list")
        for i, item in enumerate(nxt):
            if not isinstance(item, dict):
                return (False, f"AI output schema error: suggested_next_tests[{i}] must be an object")
            for k in ("id", "title", "why", "yaml"):
                if k not in item or not isinstance(item.get(k), str):
                    return (False, f"AI output schema error: suggested_next_tests[{i}].{k} must be a string")

    return (True, "")

def _ai_parse_and_validate_model_json(text: str) -> tuple[dict[str, Any], str]:
    """
    JSON-only contract:
      - Must be valid JSON
      - Must be a dict matching the required schema
    Returns: (parsed_dict_or_empty, error_string_or_empty)
    """
    text = (text or "").strip()
    if not text:
        return ({}, "empty model response")

    try:
        out = json.loads(text)
    except Exception as e:
        return ({}, f"non-JSON model response: {e!s}")

    ok, err = _ai_validate_output_schema(out)
    if not ok:
        return ({}, err)

    # Safe: schema-validated dict. Keep as-is (do not rewrite content).
    return (out, "")

def _ai_sanitize_output_for_fixture(ai_output: Any) -> dict[str, Any]:
    """
    Convert schema-valid ai_output into a stable, content-free structure for fixtures.

    This is a structural contract sanitizer:
      - does NOT validate correctness of content
      - does NOT pin wording
      - only preserves schema shape + required keys
    """
    # If it's not schema-valid, return empty dict (caller should already validate schema).
    if not isinstance(ai_output, dict):
        return {}

    # Enforce only the allowed schema keys in the sanitized fixture
    allowed_top = {"summary", "findings", "suggested_next_tests"}
    out: dict[str, Any] = {}

    # summary
    if "summary" in ai_output and isinstance(ai_output.get("summary"), str):
        out["summary"] = "<string>"
    else:
        out["summary"] = "<missing>"

    # findings
    findings = ai_output.get("findings")
    san_findings: list[dict[str, str]] = []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                san_findings.append({
                    "title": "<string>" if isinstance(f.get("title"), str) else "<missing>",
                    "evidence": "<string>" if isinstance(f.get("evidence"), str) else "<missing>",
                    "suggestion": "<string>" if isinstance(f.get("suggestion"), str) else "<missing>",
                })
            else:
                san_findings.append({
                    "title": "<invalid>",
                    "evidence": "<invalid>",
                    "suggestion": "<invalid>",
                })
    out["findings"] = san_findings

    # suggested_next_tests
    nxt = ai_output.get("suggested_next_tests")
    san_nxt: list[dict[str, str]] = []
    if isinstance(nxt, list):
        for item in nxt:
            if isinstance(item, dict):
                san_nxt.append(
                    {
                        "id": "<string>" if isinstance(item.get("id"), str) else "<missing>",
                        "title": "<string>" if isinstance(item.get("title"), str) else "<missing>",
                        "why": "<string>" if isinstance(item.get("why"), str) else "<missing>",
                        "yaml": "<string>" if isinstance(item.get("yaml"), str) else "<missing>",
                    }
                )
            else:
                san_nxt.append({"id": "<invalid>", "title": "<invalid>", "why": "<invalid>", "yaml": "<invalid>"})
    out["suggested_next_tests"] = san_nxt

    # If additional keys exist, record them explicitly (so fixtures can guard expansion).
    extras = sorted([k for k in ai_output.keys() if k not in allowed_top])
    out["_extra_keys"] = extras  # must be [] in fixtures

    return out

def _ai_provider_openai(
    bundle: dict[str, Any],
    model: str,
    api_key: str,
    base_url: str | None
) -> tuple[str, dict[str, Any], str]:
    """
    Returns (ai_status, ai_output, ai_error)

    ai_output:
      - parsed JSON dict if the model returns JSON
      - else {"raw_text": "..."} if non-JSON
    """
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(f"openai sdk not importable: {e!s}")
        )

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)

        # Deterministic prompt object: bundle-only input.
        prompt_obj = {
            "task": "ai-netsim advisory analysis",
            "rules": {
                "authority": "advisory",
                "non_authoritative": True,
                "do_not_change_verdicts_or_exit_codes": True,
                "artifact_only": True,
                "no_runtime_calls": True,
            },
            "bundle": bundle,
            "output_contract": {
                "json_only": True,
                "no_markdown": True,
                "no_prose_outside_json": True,
                "rules": [
                    "Return JSON only. No YAML, no markdown, no prose outside the JSON object.",
                    "Never claim correctness or safety. Do NOT use words like: validated, correct, safe, approved, guaranteed.",
                    "Anchor claims to observed evidence (tests/scenarios/results pointers) where possible. Config text is context only.",
                    "Candidate changes are context-only and are never executed/simulated/validated by ai-netsim.",
                    "Suggested tests MUST be actionable: include a copy-paste YAML snippet that fits ai-netsim v1 schema.",
                ],
                "schema": {
                    "summary": "string",
                    "findings": [{"title": "string", "evidence": "string", "suggestion": "string"}],
                    "suggested_next_tests": [
                        {"id": "string", "title": "string", "why": "string", "yaml": "string"},
                    ],
                },
            },
        }

        resp = client.responses.create(
            model=model,
            input=[
                {
                    "role": "user",
                    "content": json.dumps(prompt_obj, sort_keys=True),
                }
            ],
        )

        # Defensive extraction (Responses API)
        text = ""
        try:
            # Preferred: SDK convenience field
            text = getattr(resp, "output_text", "") or ""
        except Exception:
            text = ""

        # Fallback: scan structured output for message content
        if not text:
            try:
                for item in getattr(resp, "output", []) or []:
                    if getattr(item, "type", "") == "message":
                        for part in getattr(item, "content", []) or []:
                            if getattr(part, "type", "") == "output_text":
                                text += getattr(part, "text", "") or ""
                            elif getattr(part, "type", "") == "text":
                                # Some SDKs use "text" parts
                                text += getattr(part, "text", "") or ""
            except Exception:
                text = ""

        if not text:
            # Last resort: string form (usually not useful, but keep deterministic behavior)
            try:
                text = str(resp)
            except Exception:
                text = ""

        text = (text or "").strip()
        if not text:
            return ("unavailable", {}, "empty model response")

        out, perr = _ai_parse_and_validate_model_json(text)
        if perr:
            return ("unavailable", {}, _ai_sanitize_error(perr))
        return ("ok", out, "")

    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(str(e))
        )

def _ai_try_online(bundle: dict[str, Any], args) -> dict[str, Any]:
    """
    Never raises. Never gates.
    Returns:
      {ai_status, ai_error, model_used, ai_output}
    """
    if not bool(getattr(args, "online", False)):
        return {"ai_status": "unavailable", "ai_error": "online not requested", "model_used": None, "ai_output": {}}

    cfg = _ai_online_config(args)

    if not cfg["provider"]:
        return {"ai_status": "unavailable", "ai_error": "AI_NETSIM_AI_PROVIDER not set", "model_used": None, "ai_output": {}}

    if cfg["provider"] != "openai":
        return {"ai_status": "unavailable", "ai_error": f"unsupported provider '{cfg['provider']}'", "model_used": None, "ai_output": {}}

    if not cfg["api_key"]:
        return {
            "ai_status": "unavailable",
            "ai_error": "AI_NETSIM_AI_API_KEY/OPENAI_API_KEY not set",
            "model_used": None,
            "ai_output": {},
        }

    # Safe default (can change later). Keep deterministic behavior regardless.
    model = cfg["model"] or "gpt-4.1-mini"

    st, out, err = _ai_provider_openai(bundle=bundle, model=model, api_key=cfg["api_key"], base_url=cfg["base_url"])
    return {"ai_status": st, "ai_error": err, "model_used": model, "ai_output": out}


def _ai_finalize_and_emit(command_name: str, bundle: dict[str, Any], args) -> None:
    """
    Single enforcement point for v1 AI CLI contract.

    Rules:
      - Bundle is deterministic and always exists.
      - --bundle: print bundle JSON (no online), exit 0
      - --bundle-out: write bundle to path (no online), exit 0
      - default: write bundle to default path if available (explain only)
      - --online: attempt provider call; failures never gate; exit 0
      - output controlled by --format json|text (default json per argparse)
    """

    def _cc_summary_text(bundle_in: dict[str, Any]) -> str | None:
        # Support legacy keys + current key.
        cc = bundle_in.get("change_context") or bundle_in.get("change_review") or bundle_in.get("change_explain")
        if not isinstance(cc, dict):
            return None

        present = bool(cc.get("present", False))
        if not present:
            return None

        counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
        items = int(counts.get("items", 0) or 0)
        included = int(counts.get("included", 0) or 0)
        missing = int(counts.get("missing", 0) or 0)
        blocked = int(counts.get("blocked", 0) or 0)
        too_large = int(counts.get("too_large", 0) or 0)

        # One-line banner: explicit non-execution + non-authority (v1 contract).
        return (
            f"change_context: present (items={items} included={included} missing={missing} "
            f"blocked={blocked} too_large={too_large}) — context-only, NOT executed, does not affect verdicts"
        )


    def _ai_contains_forbidden_correctness_language(obj: Any) -> bool:
        # Non-blocking lint: warn in text mode (never gate).
        # Expand list to cover common implied authority / safety claims.
        forbidden = (
            "validated",
            "correct",
            "safe",
            "approved",
            "guaranteed",
            "compliant",
            "secure",
            "certified",
            "verified",
        )
        try:
            s = json.dumps(obj, ensure_ascii=True).lower()
            return any(w in s for w in forbidden)
        except Exception:
            return False


    def _render_ai_output_text(ai_out: Any) -> None:
        """
        Human-friendly rendering for engineers.

        Expected ai_out schema:
          {
            "summary": str,
            "findings": [{title,evidence,suggestion}],
            "suggested_next_tests": [{id,title,why,yaml}]
          }
        Backward compatible: if suggested_next_tests is list[str], print as generic.
        """
        if not ai_out:
            return

        if not isinstance(ai_out, dict):
            print(str(ai_out))
            return

        summary = ai_out.get("summary")
        if isinstance(summary, str) and summary.strip():
            print("summary:")
            print(f"  {summary.strip()}")
            print("  (Informational only. Only tests & scenarios prove behavior.)")
            print()

        findings = ai_out.get("findings")
        if isinstance(findings, list) and findings:
            print("findings:")
            n = 0
            for f in findings:
                if not isinstance(f, dict):
                    continue
                title = str(f.get("title") or "").strip()
                suggestion = str(f.get("suggestion") or "").strip()
                evidence = str(f.get("evidence") or "").strip()
                if not (title or suggestion or evidence):
                    continue
                n += 1
                head = title if title else f"finding {n}"
                print(f"  {n}. {head}")
                if suggestion:
                    print(f"     suggestion: {suggestion}")
                if evidence:
                    print(f"     evidence: {evidence}")
            print()

        nxt = ai_out.get("suggested_next_tests")
        if isinstance(nxt, list) and nxt:
            print("suggested_next_tests (copy/paste):")
            for item in nxt:
                if isinstance(item, str):
                    # Backward-compat: older models may still return strings.
                    print(f"  - {item} (generic; no YAML provided)")
                    continue
                if not isinstance(item, dict):
                    continue

                tid = str(item.get("id") or "").strip()
                title = str(item.get("title") or "").strip()
                why = str(item.get("why") or "").strip()
                yaml_snip = str(item.get("yaml") or "").rstrip()

                head = ""
                if tid and title:
                    head = f"{tid}: {title}"
                elif title:
                    head = title
                elif tid:
                    head = tid
                else:
                    head = "test"

                print(f"  - {head}")
                if why:
                    print(f"    why: {why}")
                if yaml_snip:
                    print("    add to topology:")
                    for line in yaml_snip.splitlines():
                        print(f"      {line}")
            print()

    # Ensure mandatory deterministic headers exist (do NOT overwrite if already set)
    bundle.setdefault("schema_version", "1")
    for k, v in _ai_advisory_headers().items():
        bundle.setdefault(k, v)

    # Determine requested output mode flags
    want_bundle = bool(getattr(args, "bundle", False))
    bundle_out = getattr(args, "bundle_out", None)

    fmt = (getattr(args, "format", None) or "json").strip().lower()
    if fmt not in ("json", "text"):
        fmt = "json"

    # 1) --bundle-out: write bundle and exit (no online)
    if bundle_out:
        _ai_write_bundle(str(bundle_out), bundle)
        bundle_with_ptr = dict(bundle)
        bundle_with_ptr["bundle_path"] = str(bundle_out)

        if fmt == "json":
            _ai_print_json(bundle_with_ptr)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle_with_ptr.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(f"bundle_path: {bundle_with_ptr['bundle_path']}")
        return

    # 2) --bundle: print bundle and exit (no online)
    if want_bundle:
        if fmt == "json":
            _ai_print_json(bundle)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(json.dumps(bundle, indent=2, sort_keys=True))
        return

    # 3) Default bundle write (best practice): only if we can infer a default path (explain has labdir)
    default_path = _ai_default_bundle_out_path(bundle)
    if default_path:
        try:
            _ai_write_bundle(default_path, bundle)
        except Exception:
            default_path = None

    # 4) Optional online call
    online_res = {
        "ai_status": "unavailable",
        "ai_error": "online not requested",
        "model_used": None,
        "ai_output": {},
    }
    if bool(getattr(args, "online", False)):
        try:
            online_res = _ai_try_online(bundle=bundle, args=args)
        except Exception as e:
            online_res = {"ai_status": "unavailable", "ai_error": str(e), "model_used": None, "ai_output": {}}

    # 5) Final advisory output (stable, CI-safe)
    out: dict[str, Any] = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": command_name,
        "inputs": {"bundle_path": default_path},
        "ai_status": online_res.get("ai_status"),
        "ai_error": online_res.get("ai_error") or "",
        "model_used": online_res.get("model_used"),
        "ai_output": online_res.get("ai_output") or {},
        # always include the deterministic bundle for audit/debug
        "bundle": bundle,
    }

    if fmt == "json":
        _ai_print_json(out)
        return

    # text mode (human-friendly)
    print(f"[advisory] ai {command_name}")
    print(out.get("disclaimer"))

    cc_line = _cc_summary_text(bundle)
    if cc_line:
        print(cc_line)

    if out["inputs"].get("bundle_path"):
        print(f"bundle_path: {out['inputs']['bundle_path']}")

    print(f"ai_status: {out.get('ai_status')}")

    if out.get("ai_error"):
        print(f"ai_error: {out.get('ai_error')}")

    if out.get("model_used"):
        print(f"model_used: {out.get('model_used')}")

    if out.get("ai_output"):
        if _ai_contains_forbidden_correctness_language(out["ai_output"]):
            print("warning: AI output contained correctness/safety language. Treat as advisory and prove via tests.")
        _render_ai_output_text(out["ai_output"])

def _ai_explain_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Step 4 (v1): Change-aware explain scaffold.

    Rules:
      - deterministic
      - vendor-agnostic (no parsing)
      - advisory-only
      - no remediation instructions
      - links failures to "affected areas" based on declared candidate_changes metadata only
    """
    cc = bundle.get("change_context") or {}
    items = list(cc.get("items") or [])

    # deterministic ordering
    def _k_item(it: dict) -> tuple:
        return (str(it.get("id") or ""), str(it.get("node") or ""), str(it.get("description") or ""))

    items = sorted([it for it in items if isinstance(it, dict)], key=_k_item)

    # Build a light-weight index: node -> change ids
    node_to_changes: dict[str, list[str]] = {}
    change_ids: list[str] = []
    for it in items:
        cid = str(it.get("id") or "").strip()
        if cid:
            change_ids.append(cid)
        node = it.get("node")
        if isinstance(node, str) and node.strip() and cid:
            node_to_changes.setdefault(node.strip(), []).append(cid)

    for k in list(node_to_changes.keys()):
        node_to_changes[k] = sorted(set(node_to_changes[k]))

    change_ids = sorted(set(change_ids))

    verdict = bundle.get("verdict") or {}
    failed_tests = list(verdict.get("failed_tests") or [])
    failed_steps = list(verdict.get("failed_scenarios") or [])
    wait_failures = list(verdict.get("wait_failures") or [])

    # Helper: try to extract node-ish strings from a failure record without guessing too hard
    def _extract_nodes_from_failure(rec: dict) -> set[str]:
        out: set[str] = set()
        if not isinstance(rec, dict):
            return out

        # Common spots
        for key in ("name", "reason", "error"):
            v = rec.get(key)
            if isinstance(v, str):
                # light heuristic: if a node name appears exactly as a token in the string, match it
                # (still deterministic, but best-effort)
                for n in node_to_changes.keys():
                    if n and (f" {n} " in f" {v} " or v.strip() == n):
                        out.add(n)

        meta = rec.get("meta")
        if isinstance(meta, dict):
            for key in ("node", "src", "dst", "from", "to"):
                v = meta.get(key)
                if isinstance(v, str) and v.strip() in node_to_changes:
                    out.add(v.strip())

        return out

    affected_nodes: set[str] = set()
    for rec in failed_tests:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in failed_steps:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in wait_failures:
        affected_nodes |= _extract_nodes_from_failure(rec)

    affected_nodes = set(sorted(affected_nodes))

    affected_changes: list[str] = []
    for n in affected_nodes:
        affected_changes.extend(node_to_changes.get(n) or [])
    affected_changes = sorted(set(affected_changes))

    # Calm, on-call friendly notes (no remediation)
    notes: list[str] = []
    present = bool(cc.get("present"))
    if not present:
        notes.append("No candidate change context was provided, so this explanation is based on test/scenario evidence only.")
    else:
        if cc.get("counts", {}).get("missing"):
            notes.append("Some change_context files were missing at bundle time; affected-area mapping may be incomplete.")
        if cc.get("counts", {}).get("blocked"):
            notes.append("Some change_context items were blocked for safety (path rules); mapping may be incomplete.")
        if cc.get("counts", {}).get("too_large"):
            notes.append("Some change_context items were too large and were not included; mapping may be incomplete.")

    mapping = {
        "affected_nodes": sorted(list(affected_nodes)),
        "affected_change_ids": affected_changes,
        "node_to_change_ids": {k: node_to_changes[k] for k in sorted(node_to_changes)},
    }

    # Minimal structured output required by Step 4
    out = {
        "present": bool(cc.get("present")),
        "summary": {
            "change_ids": change_ids,
            "affected_nodes": mapping["affected_nodes"],
            "affected_change_ids": mapping["affected_change_ids"],
        },
        "mapping": mapping,
        "notes": notes,
        "reminders": [
            "This is advisory context only. Tests & scenarios are authoritative.",
            "No vendor parsing was performed; mapping uses declared metadata only.",
            "No remediation instructions are provided.",
        ],
    }

    return out

def cmd_ai_explain(args) -> None:
    """
    Explain a prior run using artifacts only.

    v1 contract:
      - always builds a deterministic bundle
      - --bundle prints bundle JSON and exits 0
      - --bundle-out writes bundle and exits 0
      - --online attempts optional model layer; failures never gate (exit 0)

    Exit codes:
      0 = success (including AI unavailable)
      2 = CLI usage / missing required artifacts when --strict-inputs
    """
    lab, labdir = _ai_resolve_lab_and_dir(args.target)
    res_path = os.path.join(labdir, "results.json")
    topo_resolved_path = os.path.join(labdir, "topology.resolved.yaml")
    summary_path = os.path.join(labdir, "results.summary.txt")

    strict = bool(getattr(args, "strict_inputs", False))

    # Required artifacts for v1 explain
    missing: list[str] = []
    if not _ai_file_exists(res_path):
        missing.append("results.json")
    if not _ai_file_exists(topo_resolved_path):
        missing.append("topology.resolved.yaml")

    if missing and strict:
        print(
            f"AI usage error: missing required artifacts in {labdir}: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "explain",
        "lab": {"name": lab, "labdir": labdir},
        "artifacts": {
            "results_json": os.path.join(labdir, "results.json"),
            "resolved_topology": os.path.join(labdir, "topology.resolved.yaml"),
            "summary_txt": os.path.join(labdir, "results.summary.txt"),
            "present": {
                "results_json": _ai_file_exists(res_path),
                "resolved_topology": _ai_file_exists(topo_resolved_path),
                "summary_txt": _ai_file_exists(summary_path),
            },
        },
        "verdict": {
            "overall": None,
            "failed_tests": [],
            "failed_scenarios": [],
            "wait_failures": [],
        },
        "notes": [],
    }

    # Change Context (bundle-time only): pull from resolved topology if present
    # Use labdir as the deterministic base_dir so explain works from artifacts alone.
    cc_base_dir = Path(labdir)

    if _ai_file_exists(topo_resolved_path):
        try:
            topo_resolved = _ai_read_yaml(topo_resolved_path)
            bundle["change_context"] = _ai_cc_build_change_context(topo_resolved, base_dir=cc_base_dir)
        except Exception as e:
            bundle["change_context"] = {
                "present": False,
                "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 1, "too_large": 0},
                "limits": {
                    "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
                    "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
                    "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
                    "max_items": _AI_CC_MAX_ITEMS,
                },
                "items": [],
                "notes": [f"Failed to parse topology.resolved.yaml for change_context: {e!s}"],
            }
    else:
        bundle["change_context"] = _ai_cc_build_change_context({}, base_dir=cc_base_dir)

    # Deterministic scaffold: extract stable evidence pointers
    if _ai_file_exists(res_path):
        try:
            r = _ai_read_json(res_path)
            bundle["verdict"]["overall"] = r.get("result")
            results_ptr = f"{labdir}/results.json"

            tests = list(r.get("tests") or [])
            for i, t in enumerate(tests):
                if not isinstance(t, dict):
                    continue
                if (t.get("verdict") or "").lower() == "fail":
                    bundle["verdict"]["failed_tests"].append(
                        {
                            "name": t.get("name"),
                            "type": t.get("type"),
                            "reason": t.get("reason"),
                            "evidence": {"artifact": results_ptr, "path": f"tests[{i}]"},
                        }
                    )

            scenarios = list(r.get("scenarios") or [])
            for si, s in enumerate(scenarios):
                if not isinstance(s, dict):
                    continue
                sid = s.get("id")
                steps = list(s.get("steps") or [])
                for st_i, st in enumerate(steps):
                    if not isinstance(st, dict):
                        continue

                    if (st.get("verdict") or "").lower() == "fail":
                        bundle["verdict"]["failed_scenarios"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st.get("type"),
                                "error": st.get("error"),
                                "meta": st.get("meta"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

                    st_type = st.get("type")
                    st_verdict = (st.get("verdict") or "").lower()
                    if st_type in ("wait_for", "wait_for_bgp") and st_verdict != "pass":
                        bundle["verdict"]["wait_failures"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st_type,
                                "expected": st.get("expected"),
                                "observed": st.get("observed"),
                                "error": st.get("error"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

            # Deterministic sorting
            def _k_test(x: dict) -> tuple:
                ev = x.get("evidence", {}) or {}
                return (
                    str(x.get("name") or ""),
                    str(x.get("type") or ""),
                    str(ev.get("path") or ""),
                )

            def _k_step(x: dict) -> tuple:
                step_v = x.get("step")
                step_i = step_v if isinstance(step_v, int) else 10**9
                return (str(x.get("scenario_id") or ""), step_i, str(x.get("type") or ""))

            bundle["verdict"]["failed_tests"] = sorted(bundle["verdict"]["failed_tests"], key=_k_test)
            bundle["verdict"]["failed_scenarios"] = sorted(bundle["verdict"]["failed_scenarios"], key=_k_step)
            bundle["verdict"]["wait_failures"] = sorted(bundle["verdict"]["wait_failures"], key=_k_step)

        except Exception as e:
            bundle["notes"].append(f"Failed to parse results.json: {e!s}")

    # IMPORTANT: all output logic lives in the shared finalizer
    bundle["change_explain"] = _ai_explain_change_sections(bundle)
    _ai_finalize_and_emit("explain", bundle, args)

# ----------------------------
# v1: Change Context (Step 2) — AI bundle-only packaging helpers
#   - best-effort, deterministic
#   - size-limited, redacted
#   - NEVER affects runtime / verdicts / exit codes
# ----------------------------

_AI_CC_ITEM_MAX_BYTES = 64 * 1024        # 64 KiB per item read cap
_AI_CC_TOTAL_MAX_BYTES = 256 * 1024      # 256 KiB total cap across items
_AI_CC_PREVIEW_MAX_CHARS = 4096          # preview chars per item (after redaction)
_AI_CC_MAX_ITEMS = 50                    # hard cap for safety


def _ai_cc_redact(text: str) -> str:
    """
    Deterministic, conservative redaction for common secret-like patterns.
    Not a security guarantee; just hygiene to reduce accidental leakage.
    """
    if not text:
        return text

    out_lines: list[str] = []
    keys = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")

    for line in text.splitlines(True):  # keep newlines
        low = line.lower()
        if any(k in low for k in keys):
            # redact value after common separators
            for sep in (":", "=", " "):
                if sep in line:
                    left, right = line.split(sep, 1)
                    # keep left + sep, replace remainder
                    line = f"{left}{sep} <redacted>\n" if line.endswith("\n") else f"{left}{sep} <redacted>"
                    break
        out_lines.append(line)

    return "".join(out_lines)


def _ai_cc_safe_read_text_file(base_dir: Path, rel_path: str, max_bytes: int) -> tuple[str, dict]:
    """
    Best-effort safe read:
      - only allows paths within base_dir (no traversal)
      - blocks absolute paths
      - reads at most max_bytes
    Returns: (text, meta)
    """
    meta: dict[str, Any] = {
        "source_kind": "file",
        "path": rel_path,
        "status": "unavailable",
        "bytes": 0,
        "truncated": False,
        "reason": "",
    }

    try:
        if not isinstance(rel_path, str) or not rel_path.strip():
            meta["status"] = "invalid"
            meta["reason"] = "empty path"
            return "", meta

        rp = rel_path.strip()
        p = Path(rp)

        if p.is_absolute():
            meta["status"] = "blocked"
            meta["reason"] = "absolute paths are blocked"
            return "", meta

        # Resolve under base_dir and prevent traversal
        base = base_dir.resolve()
        full = (base / p).resolve()
        if str(full) == str(base) or (not str(full).startswith(str(base) + os.sep)):
            meta["status"] = "blocked"
            meta["reason"] = "path traversal / outside base_dir blocked"
            return "", meta

        if not full.exists() or not full.is_file():
            meta["status"] = "missing"
            meta["reason"] = "file not found"
            return "", meta

        # bounded read
        with full.open("rb") as f:
            raw = f.read(max_bytes + 1)

        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
            meta["truncated"] = True

        # decode best-effort as utf-8; replace errors deterministically
        txt = raw.decode("utf-8", errors="replace")
        meta["status"] = "ok"
        meta["bytes"] = len(raw)
        return txt, meta

    except Exception as e:
        meta["status"] = "error"
        meta["reason"] = str(e)
        return "", meta


def _ai_cc_build_change_context(topo_obj: dict, base_dir: Path) -> dict[str, Any]:
    """
    Build deterministic change_context bundle payload from topo candidate_changes.
    Reads candidate content ONLY here (bundle-time), size-limited.
    """
    cc = topo_obj.get("candidate_changes")
    out: dict[str, Any] = {
        "present": bool(cc),
        "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 0, "too_large": 0},
        "limits": {
            "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
            "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
            "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
            "max_items": _AI_CC_MAX_ITEMS,
        },
        "items": [],
        "notes": [],
    }

    if not isinstance(cc, list) or not cc:
        return out

    total_budget = _AI_CC_TOTAL_MAX_BYTES
    included = 0

    # Preserve declared ordering (author intent), but cap number of items deterministically
    for idx, item in enumerate(cc[:_AI_CC_MAX_ITEMS], start=1):
        if not isinstance(item, dict):
            continue

        cid = item.get("id")
        cid = cid.strip() if isinstance(cid, str) else f"candidate_changes[{idx}]"

        entry: dict[str, Any] = {
            "id": cid,
            "description": (item.get("description").strip() if isinstance(item.get("description"), str) else ""),
            "format": (item.get("format").strip() if isinstance(item.get("format"), str) else ""),
            "scope": (item.get("scope") if isinstance(item.get("scope"), list) else []),
            "source": {},
            "preview": {"text": "", "redacted": True},
        }

        # inline wins only if present (Step 1 enforces exactly one)
        if item.get("inline") is not None:
            s = item.get("inline")
            if not isinstance(s, str):
                s = str(s)
            raw = s
            # enforce per-item cap via bytes
            b = raw.encode("utf-8", errors="replace")
            meta = {
                "source_kind": "inline",
                "status": "ok",
                "bytes": min(len(b), _AI_CC_ITEM_MAX_BYTES),
                "truncated": len(b) > _AI_CC_ITEM_MAX_BYTES,
                "reason": "",
            }
            if len(b) > _AI_CC_ITEM_MAX_BYTES:
                raw = b[:_AI_CC_ITEM_MAX_BYTES].decode("utf-8", errors="replace")
            # total budget enforcement
            if meta["bytes"] > total_budget:
                meta["status"] = "too_large"
                meta["reason"] = "exceeds remaining total budget"
                out["counts"]["too_large"] += 1
                entry["source"] = meta
                out["items"].append(entry)
                continue

            total_budget -= meta["bytes"]
            red = _ai_cc_redact(raw)
            entry["source"] = meta
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
            included += 1
            out["items"].append(entry)
            continue

        # file path
        rel_path = item.get("file")
        rel_path = rel_path.strip() if isinstance(rel_path, str) else str(rel_path)

        # if no budget left, record deterministically
        if total_budget <= 0:
            entry["source"] = {
                "source_kind": "file",
                "path": rel_path,
                "status": "too_large",
                "bytes": 0,
                "truncated": False,
                "reason": "no remaining total budget",
            }
            out["counts"]["too_large"] += 1
            out["items"].append(entry)
            continue

        max_bytes = min(_AI_CC_ITEM_MAX_BYTES, total_budget)
        txt, meta = _ai_cc_safe_read_text_file(base_dir, rel_path, max_bytes=max_bytes)

        # update counters
        st = meta.get("status")
        if st == "ok":
            included += 1
        elif st == "blocked":
            out["counts"]["blocked"] += 1
        elif st == "missing":
            out["counts"]["missing"] += 1
        elif st == "error":
            out["counts"]["errors"] += 1
        elif st == "too_large":
            out["counts"]["too_large"] += 1

        # budget accounting only if we actually read bytes
        if st == "ok":
            total_budget -= int(meta.get("bytes") or 0)

        entry["source"] = meta
        if st == "ok":
            red = _ai_cc_redact(txt)
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
        out["items"].append(entry)

    out["counts"]["items"] = min(len(cc), _AI_CC_MAX_ITEMS)
    out["counts"]["included"] = included
    if len(cc) > _AI_CC_MAX_ITEMS:
        out["notes"].append(f"candidate_changes truncated to first {_AI_CC_MAX_ITEMS} items (safety cap)")

    return out

def _ai_read_yaml(path: str) -> Any:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
    
def _ai_review_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministic, vendor-agnostic offline review sections for Change Context.
    No remediation. No vendor parsing. Advisory only.
    """
    cc = (bundle.get("change_context") or {}) if isinstance(bundle, dict) else {}
    items = cc.get("items") if isinstance(cc.get("items"), list) else []
    counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
    present = bool(cc.get("present"))

    # ---- 1) What Changed? ----
    what_changed: list[dict[str, Any]] = []
    if not present:
        what_changed.append(
            {"type": "no_change_context", "summary": "No candidate_changes declared in topology."}
        )
    else:
        for it in items:
            if not isinstance(it, dict):
                continue
            src = it.get("source") or {}
            what_changed.append(
                {
                    "id": it.get("id"),
                    "format": it.get("format") or "",
                    "scope": it.get("scope") or [],
                    "source_status": src.get("status"),
                    "source_kind": src.get("source_kind"),
                    "summary": it.get("description") or "",
                }
            )

    # ---- 2) Am I Missing Something? ----
    missing: list[dict[str, Any]] = []

    if present and int(counts.get("included") or 0) == 0:
        missing.append(
            {
                "type": "change_context_not_included",
                "hint": "Candidate changes were declared but none could be included in the bundle (missing/blocked/too_large).",
            }
        )

    # scope hygiene: if any item has empty scope, nudge to add it (still optional)
    if present:
        any_empty_scope = False
        any_has_scope = False
        for it in items:
            if not isinstance(it, dict):
                continue
            sc = it.get("scope")
            if isinstance(sc, list) and sc:
                any_has_scope = True
            else:
                any_empty_scope = True
        if any_empty_scope:
            missing.append(
                {
                    "type": "scope_not_specified",
                    "hint": "Some candidate changes have no scope. Consider adding scope: [node1, node2] to clarify what should be proven.",
                }
            )
        if not any_has_scope:
            missing.append(
                {
                    "type": "no_scopes_present",
                    "hint": "No candidate changes specify scope. Proof suggestions will be generic (still safe).",
                }
            )

    # deterministic checklist reminders (generic, not vendor-specific)
    missing.extend(
        [
            {"type": "pre_change_baseline", "hint": "Do you have steady-state tests that pass before the change? (baseline proof)"},
            {"type": "negative_tests", "hint": "If a firewall/policy exists, do you have at least one expected-fail (blocked) test?"},
            {"type": "failover_scenarios", "hint": "If the change could affect failover, do you have a scenario with fault + wait_for + post-fault revalidation?"},
        ]
    )

    # ---- 3) Minimal Proof Set (template-level) ----
    proof: list[dict[str, Any]] = []

    # Always include a tiny deterministic proof set template (does not claim correctness)
    proof.append(
        {
            "name": "baseline_reachability",
            "purpose": "Prove the network still forwards the intended steady-state traffic.",
            "templates": [
                {"kind": "ping", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>"},
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>", "port": 443},
            ],
        }
    )
    proof.append(
        {
            "name": "control_plane_convergence",
            "purpose": "Prove routing converges to the expected state after events (if applicable).",
            "templates": [
                {"scenario_step": "wait_for_bgp", "node": "<frr_node>", "timeout": 60},
                {"scenario_step": "wait_for", "type": "ping", "from": "<src_node>", "to": "<dst_node_or_ip>", "expect": "pass", "timeout": 30},
            ],
        }
    )
    proof.append(
        {
            "name": "policy_negative",
            "purpose": "Prove must-not traffic is still blocked (if policy/firewall is in path).",
            "templates": [
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip>", "port": 22, "expected": "fail"},
            ],
        }
    )

    return {
        "what_changed": what_changed,
        "missing_something": missing,
        "minimal_proof_set": proof,
        "notes": [
            "Change context is advisory-only; tests and scenarios remain authoritative.",
            "This section is vendor-agnostic and does not interpret configs.",
        ],
    }

def cmd_ai_review(args) -> None:
    """
    Review topology-only (no execution). Deterministic coverage sketch + bounded snippets.
    Exit codes: 0 success, 2 usage error.
    """
    from pathlib import Path
    import yaml

    topo_path = Path(args.topology)
    if not topo_path.exists():
        print(f"AI usage error: topology not found: {topo_path}", file=sys.stderr)
        sys.exit(2)

    with topo_path.open("r", encoding="utf-8") as f:
        topo = yaml.safe_load(f) or {}

    nodes = topo.get("nodes") or []
    tests = topo.get("tests") or []
    scenarios = topo.get("scenarios") or []

    max_items = max(0, int(getattr(args, "max_items", 50) or 50))

    # ---- Deterministic inventory ----
    node_names: list[str] = []
    node_types: dict[str, str] = {}
    for n in nodes:
        if isinstance(n, dict):
            nm = n.get("name")
            tp = n.get("type")
            if isinstance(nm, str) and nm.strip():
                nm2 = nm.strip()
                node_names.append(nm2)
                if isinstance(tp, str) and tp.strip():
                    node_types[nm2] = tp.strip()
    node_names = sorted(set(node_names))

    frr_nodes = sorted([n for n in node_names if node_types.get(n) == "frr"])
    host_nodes = sorted([n for n in node_names if node_types.get(n) == "host"])
    fw_nodes = sorted([n for n in node_names if node_types.get(n) in ("fw", "fw-routed", "firewall")])

    test_names: list[str] = []
    covered_dst: set[str] = set()
    kinds: set[str] = set()

    for t in (tests or []):
        if not isinstance(t, dict):
            continue
        nm = t.get("name")
        if isinstance(nm, str) and nm.strip():
            test_names.append(nm.strip())

        kd = t.get("type") or t.get("kind")
        if isinstance(kd, str) and kd.strip():
            kinds.add(kd.strip())

        if "to" in t and isinstance(t.get("to"), str) and t.get("to").strip():
            covered_dst.add(t.get("to").strip())
        if "to_ip" in t and isinstance(t.get("to_ip"), str) and t.get("to_ip").strip():
            covered_dst.add(t.get("to_ip").strip())

    test_names = sorted(set(test_names))
    kinds = set(sorted(kinds))

    has_faults = False
    has_postfault_revalidate = False
    scenario_ids: list[str] = []
    for s in (scenarios or []):
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        if isinstance(sid, str) and sid.strip():
            scenario_ids.append(sid.strip())

        for st in (s.get("steps") or []):
            if not isinstance(st, dict):
                continue
            if "fault" in st:
                has_faults = True
            if "run_tests" in st:
                has_postfault_revalidate = True

    scenario_ids = sorted(set(scenario_ids))

    gaps: list[dict[str, Any]] = []
    for nn in node_names:
        if nn not in covered_dst:
            gaps.append({"type": "node_uncovered_as_dst", "node": nn})

    if fw_nodes:
        gaps.append({"type": "firewall_present_consider_negative_tests", "nodes": fw_nodes})

    if has_faults and not has_postfault_revalidate:
        gaps.append(
            {
                "type": "scenario_faults_without_postfault_revalidation",
                "hint": "Add a run_tests step after faults",
            }
        )

    evpn_present = False
    if isinstance(topo.get("evpn"), dict):
        evpn_present = True
    else:
        for n in nodes:
            if isinstance(n, dict) and "evpn" in n:
                evpn_present = True
                break
    if evpn_present:
        gaps.append({"type": "evpn_present_add_east_west_tests", "hint": "Add host-to-host reachability tests across VNIs/VLANs"})

    gaps = sorted(gaps, key=lambda g: (str(g.get("type") or ""), json.dumps(g, sort_keys=True)))

    # snippets
    snippets: list[dict[str, str]] = []
    src_host = host_nodes[0] if host_nodes else (node_names[0] if node_names else "src")
    dst_host = host_nodes[1] if len(host_nodes) > 1 else (host_nodes[0] if host_nodes else (node_names[0] if node_names else "dst"))

    snippets.append(
        {
            "title": "Add steady-state ping reachability test (IP target)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "tests:",
                    "  - name: ping_host_to_host",
                    "    type: ping",
                    f"    from: {src_host}",
                    "    to_ip: 192.0.2.1  # replace with real destination IP",
                ]
            ),
        }
    )

    snippets.append(
        {
            "title": "Add steady-state TCP port test (IP target)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "tests:",
                    "  - name: tcp_service_reachability",
                    "    type: tcp",
                    f"    from: {src_host}",
                    "    to_ip: 192.0.2.1  # replace with real destination IP",
                    "    port: 443",
                ]
            ),
        }
    )

    snippets.append(
        {
            "title": "Add post-fault revalidation in a scenario (run_tests after faults)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "scenarios:",
                    "  - id: example_failover_check",
                    "    steps:",
                    "      - fault:",
                    "          interface_down:",
                    "            node: r1",
                    "            interface: eth1",
                    "      - wait_for:",
                    "          type: ping",
                    f"          from: {src_host}",
                    f"          to: {dst_host}  # or an IP literal",
                    "          expect: pass",
                    "          timeout: 30",
                    "      - run_tests:",
                    "          include: all  # syntactic sugar expands deterministically",
                ]
            ),
        }
    )

    snippets = snippets[:max_items]

    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "review",
        "topology": str(topo_path),
        "counts": {"nodes": len(nodes), "tests": len(tests), "scenarios": len(scenarios)},
        "inventory": {
            "node_names": node_names,
            "node_types": {k: node_types[k] for k in sorted(node_types)},
            "frr_nodes": frr_nodes,
            "host_nodes": host_nodes,
            "fw_nodes": fw_nodes,
            "scenario_ids": scenario_ids,
            "test_names": test_names,
            "test_kinds": sorted(list(kinds)),
            "has_faults": has_faults,
            "has_postfault_revalidate": has_postfault_revalidate,
        },
        "gaps": gaps[:max_items],
        "suggested_snippets": snippets,
        "non_goals": [
            "No lab execution from ai review.",
            "No protocol sprawl or feature-parity assumptions.",
            "Suggestions are advisory-only; tests/scenarios remain authoritative.",
        ],
    }

    bundle["change_context"] = _ai_cc_build_change_context(topo, base_dir=topo_path.parent)
    bundle["change_review"] = _ai_review_change_sections(bundle)

    _ai_finalize_and_emit("review", bundle, args)

def cmd_ai_coach(args) -> None:
    """
    Coach/onboarding: deterministic, static guidance (no YAML emission).
    Exit codes: 0 success, 2 usage error (none expected here).
    """
    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "coach",
        "model": "v1 onboarding",
        "topics": [
            "run vs test (explore vs gate)",
            "atomic tests vs scenarios",
            "artifacts: results.json, topology.resolved.yaml, results.summary.txt",
            "negative tests and fail-fast philosophy",
        ],
        "what_to_validate_next": [
            "Steady-state reachability (ping/tcp)",
            "Control-plane convergence (wait_for_bgp)",
            "Failure choreography (interface/link down/up + revalidation)",
        ],
    }

    _ai_finalize_and_emit("coach", bundle, args)

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

    # validate
    p_val = sub.add_parser("validate", help="Validate topology + scenarios (no lab, no containers)")
    p_val.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_val.add_argument("--json", action="store_true", help="Emit machine-readable JSON (CI-friendly)")
    p_val.set_defaults(func=cmd_validate)

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

    # cleanup
    p_cleanup = sub.add_parser(
        "cleanup",
        help="Safely clean up ai-netsim-owned labs found under labs/ (dry-run unless --yes)",
    )
    p_cleanup.add_argument(
        "--all",
        action="store_true",
        help="Required. Only targets ai-netsim labs with artifact dirs under labs/clab-* (never scans Docker).",
    )
    p_cleanup.add_argument(
        "--yes",
        action="store_true",
        help="Actually destroy labs listed in the plan (artifacts are NOT deleted).",
    )
    p_cleanup.set_defaults(func=cmd_cleanup)

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
    p_test = sub.add_parser("test", help="Run declared tests against an existing lab by name")
    p_test.add_argument(
        "lab",
        nargs="?",
        help="Lab name (topology 'name', e.g. three-frr-two-hosts-fw-routed). "
             "Optional when using --two-run (then provide --two-run-topology).",
    )
    p_test.add_argument(
        "--two-run",
        action="store_true",
        help="Run the authoritative gate twice (baseline then change) and write an evidence-only diff bundle. "
             "Requires --two-run-topology and --candidate-config.",
    )
    p_test.add_argument(
        "--two-run-topology",
        dest="two_run_topology",
        help="Topology YAML filename under ./topologies or a full path (used only with --two-run).",
    )
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
    p_test.add_argument(
    "--precheck-controlplane",
    action="store_true",
    help="Run global control-plane prechecks (e.g., BGP wait) before executing scenarios. "
         "Default: off when --scenario/--all-scenarios is used.",
    )
    p_test.add_argument(
    "--list-scenarios",
    action="store_true",
    help="List scenarios from labs/clab-<lab>/topology.resolved.yaml (no deploy/execute).",
    )
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

    # ai (group)
    p_ai = sub.add_parser("ai", help="Assistive, non-authoritative AI (post-exec, artifact-only)")
    ai_sub = p_ai.add_subparsers(dest="ai_cmd", required=True)

    def _ai_add_common_flags(p) -> None:
        p.add_argument("--bundle", action="store_true", help="Emit deterministic JSON bundle (no model) and exit 0")
        p.add_argument("--bundle-out", dest="bundle_out", help="Write bundle JSON to this path and exit 0")
        p.add_argument("--online", action="store_true", help="Attempt online model call (BYO key). Never gates; exit 0 on failure.")
        p.add_argument("--model", help="Override model name (else AI_NETSIM_AI_MODEL)")
        p.add_argument("--format", choices=["json", "text"], default="json", help="Output format (json is CI-safe)")

    # ai explain
    p_ai_explain = ai_sub.add_parser("explain", help="Explain a prior run using artifacts only")
    p_ai_explain.add_argument("target", help="Lab name or topology file (to resolve lab)")
    _ai_add_common_flags(p_ai_explain)
    p_ai_explain.add_argument(
        "--strict-inputs",
        dest="strict_inputs",
        action="store_true",
        help="Usage error (exit 2) if required artifacts are missing.",
    )
    p_ai_explain.add_argument("--max-items", type=int, default=50, help="Bound findings/suggestions deterministically")
    p_ai_explain.set_defaults(func=cmd_ai_explain)

    # ai review
    p_ai_review = ai_sub.add_parser("review", help="Review topology tests/scenarios coverage (no execution)")
    p_ai_review.add_argument("topology", help="Topology YAML file")
    _ai_add_common_flags(p_ai_review)
    p_ai_review.add_argument("--max-items", type=int, default=50, help="Bound gaps/snippets deterministically")
    p_ai_review.set_defaults(func=cmd_ai_review)

    # ai coach
    p_ai_coach = ai_sub.add_parser("coach", help="Onboarding and guidance (no YAML generation)")
    _ai_add_common_flags(p_ai_coach)
    p_ai_coach.set_defaults(func=cmd_ai_coach)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
