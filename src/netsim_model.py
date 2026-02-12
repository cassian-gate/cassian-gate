#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

import ipaddress
import yaml

from netsim_common import (
    DEFAULT_IMAGES,
    assert_vm_runtime_supported,
    die,
    is_ip_literal,
    validate_ip_literal,
)

from netsim_artifacts import (
    node_cfg_dir,
    write_file,
)

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

def _validate_fabric_evpn_presence_only(topo: dict) -> dict[str, Any] | None:
    """
    v1.5 EVPN Awareness (presence-only):
      - Only allowed declaration location: fabric.evpn
      - Allowed keys under fabric.evpn: enabled (bool, optional), mode ("evpn", optional)
      - Everything else is rejected (fail-fast) to prevent scope creep.
      - EVPN presence MUST NOT be inferred from candidate config, runtime state, or other keys.
    Returns:
      - normalized evpn dict if present and enabled
      - None if not present or explicitly disabled
    """

    # Guard: reject any "evpn" keys outside fabric.evpn (canonical shape only).
    # Deterministic: shallow + common nested scans; avoids heuristics and prevents alternate schema.
    def _scan_for_evpn_keys(obj: Any, path: str) -> list[str]:
        hits: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                p = f"{path}.{k_str}" if path else k_str
                # The ONLY allowed path prefix is fabric.evpn.*
                if "evpn" in k_str.lower():
                    if not (p == "fabric.evpn" or p.startswith("fabric.evpn.")):
                        hits.append(p)
                # Recurse a bit to catch obvious alternates (nodes[*].evpn, etc.)
                hits.extend(_scan_for_evpn_keys(v, p))
        elif isinstance(obj, list):
            for i, it in enumerate(obj, start=0):
                hits.extend(_scan_for_evpn_keys(it, f"{path}[{i}]"))
        return hits

    hits = _scan_for_evpn_keys(topo, "")
    if hits:
        hits_sorted = sorted(set(hits))
        die(
            "Topology invalid: EVPN must be declared only at 'fabric.evpn' (v1.5 presence-only). "
            f"Found evpn-shaped keys at: {', '.join(hits_sorted)}"
        )

    fabric = topo.get("fabric")
    if fabric is None:
        return None
    if not isinstance(fabric, dict):
        die("Topology invalid: 'fabric' must be a dict when provided")

    evpn = fabric.get("evpn")
    if evpn is None:
        return None
    if not isinstance(evpn, dict):
        die("Topology invalid: 'fabric.evpn' must be a dict when provided")

    # Allowed keys only (presence-only schema)
    allowed = {"enabled", "mode"}
    unknown = sorted([k for k in evpn.keys() if str(k) not in allowed])
    if unknown:
        die(
            "Topology invalid: fabric.evpn contains unsupported key(s): "
            + ", ".join(unknown)
            + ". v1.5 supports presence-only: allowed keys are {enabled, mode}."
        )

    enabled = evpn.get("enabled", True)
    if not isinstance(enabled, bool):
        die("Topology invalid: fabric.evpn.enabled must be boolean if provided")

    if not enabled:
        return None

    mode = evpn.get("mode", "evpn")
    if not isinstance(mode, str) or mode.strip() != "evpn":
        die("Topology invalid: fabric.evpn.mode must be 'evpn' if provided")

    # Normalized minimal dict
    return {"enabled": True, "mode": "evpn"}

def ensure_valid_topology(topo: dict) -> None:
    if not isinstance(topo, dict):
        die("Topology YAML must be a mapping.")
    for k in ("name", "nodes", "links"):
        if k not in topo:
            die(f"Missing required key: '{k}'")

    # v1.5 EVPN Awareness (presence-only): validate canonical fabric.evpn shape (fail-fast).
    # This MUST NOT change execution semantics; it only validates declared intent.
    _validate_fabric_evpn_presence_only(topo)

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

        # v1.5 VM Runtime Backend (foundational):
        # - runtime is execution substrate only; must not change authority model.
        # - runtime must be explicit in resolved topology; defaulting happens in resolve_topology().
        runtime = (n.get("runtime") or "").strip().lower()
        if runtime and runtime not in ("container", "vm"):
            die(
                f"Topology invalid: node '{n.get('name')}': "
                f"runtime must be 'container' or 'vm' if provided"
            )

        if runtime == "vm":
            # For v1.5 foundation, support SONiC VM via containerlab's 'sonic-vm' kind.
            # Node image must be explicit (user-provided container image that packages the VM via vrnetlab).
            if (n.get("type") or "").strip().lower() != "sonic-vm":
                die(
                    f"Topology invalid: node '{n.get('name')}': "
                    f"runtime: vm currently requires type: sonic-vm (v1.5 foundation)"
                )
            img = n.get("image")
            if not isinstance(img, str) or not img.strip():
                die(
                    f"Topology invalid: node '{n.get('name')}': "
                    f"runtime: vm requires an explicit node.image (no implicit download)"
                )

    # v1.x guardrail hardening (clarified):
    # - Topology MUST NOT encode routing mechanics (protocols/metrics/policy).
    # - FRR nodes MAY include metadata like asn/router_id, but these do not imply routing.
    # - If present, validate types deterministically.
    # VM runtime availability gate (fail-fast before deploy).
    # If any node requests runtime: vm, enforce deterministic host requirements now.
    if any((str(n.get("runtime") or "").strip().lower() == "vm") for n in topo.get("nodes", []) if isinstance(n, dict)):
        assert_vm_runtime_supported()

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

def topo_to_containerlab(topo: dict) -> dict:
    clab = {
        "name": topo["name"],
        "topology": {"nodes": {}, "links": []},
    }

    # Hard defaults for core node types (deterministic + first-time UX safe).
    # node.image always overrides these.
    hard_defaults = {
        "host": "wbitt/network-multitool:latest",
        "nft-fw": "ghcr.io/andrew-ai-netsim/nft-fw:latest",
        "frr": "frrouting/frr:latest",
    }

    for n in topo["nodes"]:
        ntype = n["type"]

        # Resolve image once (node.image overrides defaults)
        image = n.get("image") or hard_defaults.get(ntype) or DEFAULT_IMAGES.get(ntype)
        if not image:
            die(f"No default image for node type '{ntype}'. Set node.image explicitly.")

        # Runtime-aware kind selection (backend mapping; topology remains runtime-agnostic).
        # v1.5 foundation: runtime: vm is supported for SONiC via containerlab 'sonic-vm' kind.
        rt = (n.get("runtime") or "container").strip().lower()

        if rt == "vm":
            if ntype != "sonic-vm":
                die(f"VM runtime currently supports only type 'sonic-vm' (got {ntype!r})")
            node_def = {"kind": "sonic-vm", "image": image}
        else:
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
    # 0a) Normalize node runtime (resolved output must be explicit)
    # ----------------------------
    for n in resolved.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue

        ntype = str(n.get("type") or "").strip().lower()

        # Default runtime stays container (existing behavior).
        rt = str(n.get("runtime") or "").strip().lower()

        # v1.5 foundation default: sonic-vm implies runtime vm if omitted (visible in resolved output).
        if not rt and ntype == "sonic-vm":
            rt = "vm"

        if not rt:
            rt = "container"

        if rt not in ("container", "vm"):
            die(f"Topology invalid: node '{n.get('name')}': runtime must be 'container' or 'vm'")

        n["runtime"] = rt
        n["_runtime"] = rt

    # ----------------------------
    # 0) v1.5 EVPN Awareness (presence-only): normalize fabric.evpn into resolved output
    # ----------------------------
    evpn_norm = _validate_fabric_evpn_presence_only(resolved)
    if evpn_norm is not None:
        fabric = resolved.get("fabric")
        if fabric is None or not isinstance(fabric, dict):
            fabric = {}
            resolved["fabric"] = fabric
        fabric["evpn"] = dict(evpn_norm)

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
        # v1.5: route_prefix alias normalization
        # Accept 'on' as an alias for 'src' (vantage node), with strict disagreement checks.
        # ----------------------------
        if "on" in t and "src" in t:
            a = str(t.get("on") or "").strip()
            b = str(t.get("src") or "").strip()
            if a and b and a != b:
                die(f"tests[{i}]: 'on' and 'src' disagree ({a!r} vs {b!r})")

        if "src" not in t and "on" in t:
            t["src"] = t.get("on")

        # ----------------------------
        # v1.5: route_prefix schema validation (fail-fast, deterministic)
        # Required: kind=route_prefix, name, src(vantage), prefix(CIDR), expect(pass|fail optional)
        # ----------------------------
        if (t.get("kind") or "").strip() == "route_prefix":
            ctx = f"tests[{i}] ({t.get('name', '<unnamed>')})"

            src = t.get("src")
            if not isinstance(src, str) or not src.strip():
                die(f"{ctx}: route_prefix test requires 'on/src' as a node name")

            pfx = t.get("prefix")
            if not isinstance(pfx, str) or not pfx.strip():
                die(f"{ctx}: route_prefix test requires 'prefix' as CIDR (e.g. 10.0.0.0/24)")

            try:
                _ = ipaddress.ip_network(pfx.strip(), strict=False)
            except Exception:
                die(f"{ctx}: route_prefix.prefix must be a valid CIDR (e.g. 10.0.0.0/24)")

            exp = t.get("expect")
            if exp is None:
                exp = "pass"
            exp_s = str(exp).strip().lower()
            if exp_s not in ("pass", "fail"):
                die(f"{ctx}: route_prefix.expect must be pass|fail if provided")
            t["expect"] = exp_s

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
