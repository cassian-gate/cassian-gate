#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

import hashlib
import json
from pathlib import Path
import re

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
# Input adapters (read-only, advisory-only)
# -------------------------

def adapt_terraform_plan_json(plan_path: Path) -> dict[str, Any]:
    """
    Read-only adapter: Terraform plan JSON (terraform show -json).
    Contract:
      - advisory-only (no authority transfer)
      - offline-only (no subprocess, no network)
      - deterministic ordering and IDs
      - no timestamps in output
    """
    out: dict[str, Any] = {
        "schema_version": "adapters.v1",
        "authority": "advisory",
        "source_type": "terraform_plan_json",
        "source_path": str(plan_path),
        "summary": {
            "items_total": 0,
            "items_changed": 0,
            "items_added": 0,
            "items_removed": 0,
        },
        "items": [],
        "parse_warnings": [],
        "parse_errors": [],
    }

    try:
        raw = plan_path.read_text(encoding="utf-8", errors="strict")
    except Exception as e:
        out["parse_errors"].append(f"read_error: {e}")
        return out

    try:
        doc = json.loads(raw)
    except Exception as e:
        out["parse_errors"].append(f"json_error: {e}")
        return out

    rc = doc.get("resource_changes")
    if rc is None:
        out["parse_warnings"].append("missing: resource_changes (no resources discovered)")
        rc = []
    if not isinstance(rc, list):
        out["parse_errors"].append("invalid: resource_changes must be a list")
        rc = []

    items: list[dict[str, Any]] = []

    for idx, r in enumerate(rc, start=1):
        if not isinstance(r, dict):
            out["parse_warnings"].append(f"resource_changes[{idx}]: not a dict (skipped)")
            continue

        addr = r.get("address")
        if not isinstance(addr, str) or not addr.strip():
            out["parse_warnings"].append(f"resource_changes[{idx}]: missing/invalid address (skipped)")
            continue
        addr = addr.strip()

        # action
        action = "unknown"
        change = r.get("change")
        actions = None
        if isinstance(change, dict):
            actions = change.get("actions")
        if isinstance(actions, list) and actions and all(isinstance(a, str) for a in actions):
            # Terraform commonly uses ["create"], ["update"], ["delete"], or ["delete","create"] (replace).
            # Deterministic mapping: if single action, use it; else unknown (do not infer).
            if len(actions) == 1:
                a0 = actions[0].strip().lower()
                if a0 in ("create", "update", "delete"):
                    action = a0
                else:
                    action = "unknown"
            else:
                action = "unknown"
                out["parse_warnings"].append(f"{addr}: actions={actions} treated as unknown (no inference)")
        else:
            out["parse_warnings"].append(f"{addr}: missing/invalid change.actions (unknown)")

        details: dict[str, Any] = {}
        rtype = r.get("type")
        if isinstance(rtype, str) and rtype.strip():
            details["resource_type"] = rtype.strip()
        mpath = r.get("module_address")
        if isinstance(mpath, str) and mpath.strip():
            details["module_path"] = mpath.strip()

        item = {
            "id": f"terraform:resource:{addr}:{action}",
            "kind": "resource",
            "action": action,
            "address": addr,
            "provider": "terraform",
            "details": details,
        }
        items.append(item)

    # Stable ordering: kind, address, action
    items.sort(key=lambda it: (str(it.get("kind")), str(it.get("address")), str(it.get("action"))))

    # Summary counts
    added = sum(1 for it in items if it.get("action") == "create")
    removed = sum(1 for it in items if it.get("action") == "delete")
    changed = sum(1 for it in items if it.get("action") in ("create", "update", "delete"))

    out["items"] = items
    out["summary"]["items_total"] = len(items)
    out["summary"]["items_changed"] = changed
    out["summary"]["items_added"] = added
    out["summary"]["items_removed"] = removed

    # Deterministic ordering for warnings/errors
    out["parse_warnings"] = sorted([str(x) for x in out.get("parse_warnings", [])])
    out["parse_errors"] = sorted([str(x) for x in out.get("parse_errors", [])])

    return out

def adapt_ansible_rendered_dir(root_dir: Path) -> dict[str, Any]:
    """
    Read-only adapter: rendered Ansible output directory -> normalized advisory JSON.
    Contract:
      - advisory-only (no authority transfer)
      - offline-only (no subprocess, no network)
      - deterministic ordering and IDs
      - no timestamps in output
      - explicit allowlist (no heuristics)
    """
    out: dict[str, Any] = {
        "schema_version": "adapters.v1",
        "authority": "advisory",
        "source_type": "ansible_rendered_dir",
        "source_path": str(root_dir),
        "summary": {
            "items_total": 0,
            "items_changed": 0,
            "items_added": 0,
            "items_removed": 0,
        },
        "items": [],
        "parse_warnings": [],
        "parse_errors": [],
    }

    # Explicit allowlist (deterministic; no heuristics)
    allow_ext = {
        ".conf", ".cfg", ".ini",
        ".yaml", ".yml", ".json",
        ".txt", ".j2",
    }

    items: list[dict[str, Any]] = []

    try:
        all_files = [p for p in root_dir.rglob("*") if p.is_file()]
    except Exception as e:
        out["parse_errors"].append(f"walk_error: {e}")
        all_files = []

    # Deterministic traversal order: stable relative POSIX path
    def relposix(p: Path) -> str:
        try:
            return p.relative_to(root_dir).as_posix()
        except Exception:
            return p.as_posix()

    all_files.sort(key=lambda p: relposix(p))

    matched = 0
    for p in all_files:
        rel = relposix(p)
        ext = p.suffix.lower()

        if ext not in allow_ext:
            continue

        matched += 1

        # role inference (deterministic, layout-based only)
        role: str | None = None
        parts = [x for x in rel.split("/") if x]
        if "roles" in parts:
            i = parts.index("roles")
            if i + 1 < len(parts):
                maybe = parts[i + 1].strip()
                if maybe:
                    role = maybe

        file_hash = ""
        try:
            file_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        except Exception as e:
            out["parse_errors"].append(f"{rel}: read_error: {e}")
            file_hash = ""

        details: dict[str, Any] = {}
        if role:
            details["role"] = role
        if file_hash:
            details["file_hash"] = file_hash

        item = {
            "id": f"ansible:file:{rel}:unknown",
            "kind": "file",
            "action": "unknown",
            "address": rel,
            "provider": "ansible",
            "details": details,
        }
        items.append(item)

    if matched == 0:
        out["parse_warnings"].append("no matching files found (allowlist filtered everything)")

    # Stable ordering: kind, address, action
    items.sort(key=lambda it: (str(it.get("kind")), str(it.get("address")), str(it.get("action"))))

    out["items"] = items
    out["summary"]["items_total"] = len(items)

    # Deterministic ordering for warnings/errors
    out["parse_warnings"] = sorted([str(x) for x in out.get("parse_warnings", [])])
    out["parse_errors"] = sorted([str(x) for x in out.get("parse_errors", [])])

    return out

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
    v2 EVPN topology/config generation support:
      - Only allowed declaration location: fabric.evpn
      - Allowed keys under fabric.evpn: enabled, mode, asn
      - Supported mode: vlan-aware
      - Validates deterministic leaf/spine RR shape, VLAN↔VNI mapping, and
        explicit host attachment semantics required for MAC learning proof.
    Returns:
      - normalized evpn dict if present and enabled
      - None if not present or explicitly disabled
    """

    def _scan_for_evpn_keys(obj: Any, path: str) -> list[str]:
        hits: list[str] = []
        allowed_node_keys = {"evpn_rr"}
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                p = f"{path}.{k_str}" if path else k_str
                if "evpn" in k_str.lower():
                    if not (
                        p == "fabric.evpn"
                        or p.startswith("fabric.evpn.")
                        or k_str in allowed_node_keys
                    ):
                        hits.append(p)
                hits.extend(_scan_for_evpn_keys(v, p))
        elif isinstance(obj, list):
            for i, it in enumerate(obj, start=0):
                hits.extend(_scan_for_evpn_keys(it, f"{path}[{i}]"))
        return hits

    def _parse_vlan_id(raw: Any, field: str) -> int:
        try:
            vlan_id = int(str(raw).strip())
        except Exception:
            die(f"Topology invalid: {field} must be an integer VLAN id")
        if vlan_id < 1 or vlan_id > 4094:
            die(f"Topology invalid: {field} must be in range 1..4094")
        return vlan_id

    def _parse_vni(raw: Any, field: str) -> int:
        try:
            vni = int(raw)
        except Exception:
            die(f"Topology invalid: {field} must be an integer VNI")
        if vni < 1 or vni > 16777215:
            die(f"Topology invalid: {field} must be in range 1..16777215")
        return vni

    def _valid_mac(raw: Any) -> bool:
        if not isinstance(raw, str):
            return False
        parts = raw.split(":")
        if len(parts) != 6:
            return False
        for part in parts:
            if len(part) != 2:
                return False
            try:
                int(part, 16)
            except Exception:
                return False
        return True

    def _link_interfaces(links: list[Any], left: str, right: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for link in links:
            if not isinstance(link, dict):
                continue
            eps = link.get("endpoints") or []
            if not isinstance(eps, list) or len(eps) != 2:
                continue
            try:
                n1, if1 = str(eps[0]).split(":", 1)
                n2, if2 = str(eps[1]).split(":", 1)
            except ValueError:
                continue
            if n1 == left and n2 == right:
                pairs.append((if1, if2))
            elif n1 == right and n2 == left:
                pairs.append((if2, if1))
        return pairs

    hits = _scan_for_evpn_keys(topo, "")
    if hits:
        hits_sorted = sorted(set(hits))
        die(
            "Topology invalid: EVPN must be declared only at 'fabric.evpn'. "
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

    allowed = {"enabled", "mode", "asn", "rr_nodes", "leaf_nodes", "vlans", "host_attachments"}
    unknown = sorted([k for k in evpn.keys() if str(k) not in allowed])
    if unknown:
        die(
            "Topology invalid: fabric.evpn contains unsupported key(s): "
            + ", ".join(unknown)
            + ". Supported keys are {enabled, mode, asn, rr_nodes, leaf_nodes, vlans, host_attachments}."
        )

    enabled = evpn.get("enabled", True)
    if not isinstance(enabled, bool):
        die("Topology invalid: fabric.evpn.enabled must be boolean if provided")
    if not enabled:
        return None

    mode = evpn.get("mode")
    if not isinstance(mode, str) or mode.strip() != "vlan-aware":
        die("Topology invalid: fabric.evpn.mode must be 'vlan-aware'")

    asn = evpn.get("asn")
    if not isinstance(asn, int) or asn < 1 or asn > 4294967295:
        die("Topology invalid: fabric.evpn.asn must be an integer in range 1..4294967295")

    vlans = topo.get("vlans")
    if not isinstance(vlans, dict) or not vlans:
        die("Topology invalid: EVPN requires a non-empty top-level 'vlans' mapping")

    vlan_to_vni: dict[int, int] = {}
    seen_vnis: dict[int, int] = {}
    for raw_vlan, raw_cfg in vlans.items():
        vlan_id = _parse_vlan_id(raw_vlan, f"vlans.{raw_vlan}")
        if not isinstance(raw_cfg, dict):
            die(f"Topology invalid: vlans.{vlan_id} must be a mapping")
        unknown_vlan_keys = sorted([k for k in raw_cfg.keys() if str(k) not in {"vni"}])
        if unknown_vlan_keys:
            die(
                f"Topology invalid: vlans.{vlan_id} contains unsupported key(s): "
                + ", ".join(unknown_vlan_keys)
            )
        if "vni" not in raw_cfg:
            die(f"Topology invalid: vlans.{vlan_id}.vni is required")
        vni = _parse_vni(raw_cfg.get("vni"), f"vlans.{vlan_id}.vni")
        if vni in seen_vnis:
            die(
                "Topology invalid: duplicate VNI mapping is not allowed: "
                f"VNI {vni} used by VLAN {seen_vnis[vni]} and VLAN {vlan_id}"
            )
        vlan_to_vni[vlan_id] = vni
        seen_vnis[vni] = vlan_id

    nodes = topo.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        die("Topology invalid: EVPN requires a non-empty 'nodes' list")

    links = topo.get("links")
    if not isinstance(links, list):
        die("Topology invalid: EVPN requires 'links' to be a list")

    nodes_by_name: dict[str, dict[str, Any]] = {}
    rr_names: list[str] = []
    leaf_names: list[str] = []

    for idx, node in enumerate(nodes, start=0):
        if not isinstance(node, dict):
            die(f"Topology invalid: nodes[{idx}] must be a mapping")
        name = node.get("name")
        ntype = node.get("type")
        if not isinstance(name, str) or not name.strip():
            die(f"Topology invalid: nodes[{idx}].name is required for EVPN")
        if not isinstance(ntype, str) or not ntype.strip():
            die(f"Topology invalid: nodes[{idx}].type is required for EVPN")
        nodes_by_name[name] = node

        role = node.get("role")
        evpn_rr = node.get("evpn_rr", False)
        if evpn_rr not in (True, False):
            die(f"Topology invalid: node '{name}': evpn_rr must be boolean if provided")

        if role is None:
            if evpn_rr:
                die(f"Topology invalid: node '{name}': evpn_rr requires role: spine")
            continue

        if not isinstance(role, str) or role not in {"spine", "leaf"}:
            die(f"Topology invalid: node '{name}': role must be 'spine' or 'leaf'")
        if ntype != "frr":
            die(f"Topology invalid: node '{name}': EVPN participant nodes must use type: frr")

        router_id = node.get("router_id")
        if not isinstance(router_id, str) or not router_id.strip():
            die(f"Topology invalid: node '{name}': router_id is required for EVPN participants")
        try:
            ipaddress.ip_address(router_id.strip())
        except Exception:
            die(f"Topology invalid: node '{name}': router_id must be a valid IP literal")

        if role == "spine":
            if not evpn_rr:
                die(f"Topology invalid: node '{name}': spine nodes must set evpn_rr: true")
            rr_names.append(name)
        else:
            if evpn_rr:
                die(f"Topology invalid: node '{name}': evpn_rr is only allowed on spine nodes")
            leaf_names.append(name)

    rr_names = sorted(rr_names)
    leaf_names = sorted(leaf_names)

    if not rr_names:
        die("Topology invalid: EVPN requires at least one spine node with evpn_rr: true")
    if not leaf_names:
        die("Topology invalid: EVPN requires at least one leaf node")

    for leaf in leaf_names:
        linked_rrs = [rr for rr in rr_names if _link_interfaces(links, leaf, rr)]
        if not linked_rrs:
            die(
                f"Topology invalid: EVPN leaf '{leaf}' must have an explicit direct link to at least one EVPN RR spine"
            )

    host_attachments: list[dict[str, Any]] = []
    for name, node in sorted(nodes_by_name.items()):
        if node.get("type") != "host":
            continue

        attach = node.get("attach")
        if not isinstance(attach, str) or not attach.strip():
            die(f"Topology invalid: host '{name}': attach is required for EVPN MAC-route proof")
        attach = attach.strip()
        if attach not in leaf_names:
            die(f"Topology invalid: host '{name}': attach must reference an EVPN leaf")

        vlan_id = _parse_vlan_id(node.get("vlan"), f"host '{name}' vlan")
        if vlan_id not in vlan_to_vni:
            die(f"Topology invalid: host '{name}': vlan {vlan_id} has no declared VLAN↔VNI mapping")

        mac = node.get("mac")
        if not _valid_mac(mac):
            die(f"Topology invalid: host '{name}': mac must be an explicit 6-octet MAC address")

        host_ip = node.get("ip")
        if not isinstance(host_ip, str) or not host_ip.strip():
            die(f"Topology invalid: host '{name}': ip is required for deterministic host presence")
        try:
            ipaddress.ip_interface(host_ip.strip())
        except Exception:
            die(f"Topology invalid: host '{name}': ip must be a valid interface literal")

        host_links = _link_interfaces(links, name, attach)
        if len(host_links) != 1:
            die(
                f"Topology invalid: host '{name}' must have exactly one explicit link to attached leaf '{attach}'"
            )

        host_attachments.append(
            {
                "host": name,
                "attach": attach,
                "vlan": vlan_id,
                "mac": str(mac).lower(),
                "ip": host_ip.strip(),
                "leaf_iface": host_links[0][1],
                "host_iface": host_links[0][0],
            }
        )

    if not host_attachments:
        die("Topology invalid: EVPN MAC-route proof requires at least one explicitly attached host")

    host_attachments.sort(key=lambda item: (item["attach"], item["leaf_iface"], item["host"]))

    return {
        "enabled": True,
        "mode": "vlan-aware",
        "asn": asn,
        "rr_nodes": rr_names,
        "leaf_nodes": leaf_names,
        "vlans": {str(k): {"vni": vlan_to_vni[k]} for k in sorted(vlan_to_vni)},
        "host_attachments": host_attachments,
    }

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
            # Contract: node.image MUST be an explicit container image reference (vrnetlab-built or equivalent).
            # Contract: filesystem paths are forbidden; ai-netsim does not auto-build/convert/import VM images.
            node_name = str(n.get("name") or "<unnamed>").strip()

            if (n.get("type") or "").strip().lower() != "sonic-vm":
                die(
                    "VM runtime contract violation\n"
                    f"node: {node_name}\n"
                    "reason: unsupported VM node type\n"
                    f"detail: type={str(n.get('type') or '').strip()!r} (runtime=vm)\n"
                    "required: set node.type to 'sonic-vm' for runtime: vm (v1.5 foundation)\n"
                    "notes: VM runtime must use an explicit user-supplied VM container image (vrnetlab-built)."
                )

            img = n.get("image")
            img_s = str(img).strip() if isinstance(img, str) else ""

            if not img_s:
                die(
                    "VM runtime contract violation\n"
                    f"node: {node_name}\n"
                    "reason: missing required image reference\n"
                    "detail: image is missing or empty\n"
                    "required: set node.image to a container image reference (vrnetlab-built or equivalent)\n"
                    "notes: Filesystem paths are not supported for VM node.image. ai-netsim will not auto-build or convert VM images."
                )

            # Reject filesystem paths (absolute/relative/file:///tilde/Windows drive forms) deterministically.
            is_path = False
            if img_s.startswith(("/", "./", "../", "~", "file://")):
                is_path = True
            if len(img_s) >= 2 and img_s[1] == ":" and img_s[0].isalpha():
                # Windows drive path (e.g., C:\...)
                is_path = True
            if "\\" in img_s:
                # Common Windows path separator; treat as filesystem path
                is_path = True

            if is_path:
                die(
                    "VM runtime contract violation\n"
                    f"node: {node_name}\n"
                    "reason: image must be a container image reference (not a filesystem path)\n"
                    f"detail: image={img_s!r}\n"
                    "required: set node.image to a vrnetlab-built container image reference (e.g., ghcr.io/org/sonic-vm:tag)\n"
                    "notes: Filesystem paths are not supported for VM node.image. ai-netsim will not auto-build or convert VM images."
                )

            # Plausible container image reference check (format gate only; do NOT probe pull/existence).
            # Deterministic minimal rule: no whitespace; only common OCI reference characters.
            if any(ch.isspace() for ch in img_s):
                die(
                    "VM runtime contract violation\n"
                    f"node: {node_name}\n"
                    "reason: invalid container image reference (whitespace)\n"
                    f"detail: image={img_s!r}\n"
                    "required: set node.image to a valid OCI image reference (no whitespace)\n"
                    "notes: ai-netsim validates format only; image pull/existence is handled by the runtime."
                )

            allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/:@")
            bad = sorted({ch for ch in img_s if ch not in allowed_chars})
            if bad:
                die(
                    "VM runtime contract violation\n"
                    f"node: {node_name}\n"
                    "reason: invalid container image reference (unsupported characters)\n"
                    f"detail: image={img_s!r} bad_chars={bad!r}\n"
                    "required: set node.image to a valid OCI image reference using only [A-Za-z0-9._-/:@]\n"
                    "notes: ai-netsim does not auto-fix or rewrite image references."
                )

            # Reject any fields that would imply auto-build/import/conversion (if present).
            forbidden_build_keys = {
                "build", "qcow2", "disk", "disk_path", "image_path", "download", "url", "source",
            }
            for k in sorted(forbidden_build_keys):
                if k in n and n.get(k) not in (None, "", [], {}):
                    die(
                        "VM runtime contract violation\n"
                        f"node: {node_name}\n"
                        "reason: implicit VM image build/import is not supported\n"
                        f"detail: forbidden_field={k!r} value={n.get(k)!r}\n"
                        "required: provide a pre-built VM container image and reference it via node.image\n"
                        "notes: ai-netsim must never auto-build, download, convert, or import VM images during deploy."
                    )

    # v1.x guardrail hardening (clarified):
    # - Topology MUST NOT encode routing mechanics (protocols/metrics/policy).
    # - FRR nodes MAY include metadata like asn/router_id, but these do not imply routing.
    # - If present, validate types deterministically.
    # VM runtime availability gate (fail-fast before deploy).
    # If any node requests runtime: vm, enforce deterministic host requirements now.
    vm_nodes = [
        n for n in topo.get("nodes", [])
        if isinstance(n, dict) and (str(n.get("runtime") or "").strip().lower() == "vm")
    ]
    if vm_nodes:
        first_vm = vm_nodes[0]
        first_name = str(first_vm.get("name") or "<unnamed>").strip()
        assert_vm_runtime_supported(first_name)

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
    Generate FRR integrated config.

    Default behavior remains routing-neutral for non-EVPN nodes.
    When fabric.evpn is enabled and the node is an EVPN participant, render a
    deterministic iBGP EVPN configuration for the supported leaf/spine RR shape.
    """
    name = node["name"]

    rid = node.get("router_id")
    rid = str(rid).strip() if rid is not None else ""

    evpn = _validate_fabric_evpn_presence_only(topo)
    role = node.get("role")
    is_evpn_participant = bool(
        evpn
        and node.get("type") == "frr"
        and isinstance(role, str)
        and role in {"spine", "leaf"}
    )

    nodes_by_name: dict[str, dict[str, Any]] = {}
    for topo_node in topo.get("nodes", []) or []:
        if isinstance(topo_node, dict):
            topo_name = topo_node.get("name")
            if isinstance(topo_name, str) and topo_name:
                nodes_by_name[topo_name] = topo_node

    links_by_node = build_node_links(topo)
    node_links = links_by_node.get(name, [])

    access_ifaces: set[str] = set()
    if is_evpn_participant and role == "leaf":
        for topo_node in topo.get("nodes", []) or []:
            if not isinstance(topo_node, dict):
                continue
            if topo_node.get("type") != "host":
                continue
            if str(topo_node.get("attach") or "").strip() != name:
                continue
            host_name = topo_node.get("name")
            if not isinstance(host_name, str) or not host_name:
                continue
            for link in topo.get("links", []) or []:
                if not isinstance(link, dict):
                    continue
                eps = link.get("endpoints") or []
                if not isinstance(eps, list) or len(eps) != 2:
                    continue
                try:
                    n1, if1 = str(eps[0]).split(":", 1)
                    n2, if2 = str(eps[1]).split(":", 1)
                except ValueError:
                    continue
                if n1 == host_name and n2 == name:
                    access_ifaces.add(if2)
                elif n1 == name and n2 == host_name:
                    access_ifaces.add(if1)

    bgp = node.get("bgp") if isinstance(node.get("bgp"), dict) else {}
    asn = node.get("asn")
    neighbors = bgp.get("neighbors") if isinstance(bgp.get("neighbors"), list) else []
    route_maps = bgp.get("route_maps") if isinstance(bgp.get("route_maps"), list) else []
    is_generic_bgp_participant = bool(
        node.get("type") == "frr"
        and not is_evpn_participant
        and asn is not None
        and rid
        and (neighbors or route_maps or (node.get("networks") if isinstance(node.get("networks"), list) else []))
    )

    cfg: list[str] = []
    cfg.append("frr version 8")
    cfg.append("frr defaults traditional")
    cfg.append(f"hostname {name}")
    cfg.append("no ipv6 forwarding")
    cfg.append("service integrated-vtysh-config")
    cfg.append("!")

    if rid:
        cfg.append("interface lo")
        cfg.append(f" ip address {rid}/32")
        cfg.append("!")

    for l in node_links:
        cfg.append(f"interface {l['iface']}")
        if l["iface"] in access_ifaces:
            cfg.append(" no ip address")
        else:
            cfg.append(f" ip address {l['ip']}")
        cfg.append("!")

    if is_evpn_participant:
        peer_entries: list[tuple[str, str, bool]] = []
        for l in node_links:
            peer_name = l["peer"]
            peer_node = nodes_by_name.get(peer_name) or {}
            peer_role = peer_node.get("role")
            if role == "leaf":
                if peer_role == "spine" and bool(peer_node.get("evpn_rr")):
                    peer_entries.append((peer_name, l["peer_ip"], False))
            elif role == "spine" and bool(node.get("evpn_rr")):
                if peer_role == "leaf":
                    peer_entries.append((peer_name, l["peer_ip"], True))

        peer_entries.sort(key=lambda item: (item[0], item[1]))

        cfg.append(f"router bgp {evpn['asn']}")
        cfg.append(f" bgp router-id {rid}")
        cfg.append(" no bgp ebgp-requires-policy")
        cfg.append(" no bgp default ipv4-unicast")
        cfg.append(" bgp retain route-target all")
        cfg.append(" neighbor EVPN peer-group")
        cfg.append(f" neighbor EVPN remote-as {evpn['asn']}")
        for peer_name, peer_ip, rr_client in peer_entries:
            cfg.append(f" neighbor {peer_ip} peer-group EVPN")
        cfg.append(" !")
        cfg.append(" address-family ipv4 unicast")
        for peer_name, peer_ip, rr_client in peer_entries:
            cfg.append(f"  neighbor {peer_ip} activate")
            if rr_client:
                cfg.append(f"  neighbor {peer_ip} route-reflector-client")
        cfg.append(f"  network {rid}/32")
        cfg.append(" exit-address-family")
        cfg.append(" !")
        cfg.append(" address-family l2vpn evpn")
        cfg.append("  neighbor EVPN activate")
        for peer_name, peer_ip, rr_client in peer_entries:
            if rr_client:
                cfg.append(f"  neighbor {peer_ip} route-reflector-client")
        cfg.append("  advertise-all-vni")
        if role == "leaf":
            for vlan_id, vlan_data in sorted((evpn.get("vlans") or {}).items(), key=lambda item: int(str(item[0]))):
                vni = int(vlan_data["vni"])
                cfg.append(f"  vni {vni}")
                cfg.append("   advertise-svi-ip")
                cfg.append("  exit-vni")
        cfg.append(" exit-address-family")
        cfg.append("!")

    elif is_generic_bgp_participant:
        neighbor_entries: list[tuple[str, str, int, str]] = []
        for nbr in neighbors:
            if not isinstance(nbr, dict):
                continue
            peer_name = str(nbr.get("peer") or "").strip()
            if not peer_name:
                continue
            link_match = None
            for l in node_links:
                if l["peer"] == peer_name:
                    link_match = l
                    break
            if not link_match:
                continue
            try:
                remote_as = int(nbr.get("remote_as"))
            except Exception:
                continue
            route_map_in = ""
            ipv4u = nbr.get("ipv4_unicast")
            if isinstance(ipv4u, dict):
                route_map_in = str(ipv4u.get("route_map_in") or "").strip()
            neighbor_entries.append((peer_name, link_match["peer_ip"], remote_as, route_map_in))

        neighbor_entries.sort(key=lambda item: (item[0], item[1], item[2], item[3]))

        cfg.append(f"router bgp {int(asn)}")
        cfg.append(f" bgp router-id {rid}")
        cfg.append(" no bgp ebgp-requires-policy")
        for peer_name, peer_ip, remote_as, route_map_in in neighbor_entries:
            cfg.append(f" neighbor {peer_ip} remote-as {remote_as}")
        cfg.append(" !")
        cfg.append(" address-family ipv4 unicast")
        for peer_name, peer_ip, remote_as, route_map_in in neighbor_entries:
            cfg.append(f"  neighbor {peer_ip} activate")
            if route_map_in:
                cfg.append(f"  neighbor {peer_ip} route-map {route_map_in} in")
        for network in node.get("networks", []) or []:
            if isinstance(network, str) and network.strip():
                cfg.append(f"  network {network.strip()}")
        cfg.append(" exit-address-family")
        cfg.append("!")

        for rm in route_maps:
            if not isinstance(rm, dict):
                continue
            rm_name = str(rm.get("name") or "").strip()
            if not rm_name:
                continue
            entries = rm.get("entries") if isinstance(rm.get("entries"), list) else []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                try:
                    seq = int(entry.get("seq"))
                except Exception:
                    continue
                action = str(entry.get("action") or "").strip()
                if action not in ("permit", "deny"):
                    continue
                cfg.append(f"route-map {rm_name} {action} {seq}")
                set_block = entry.get("set") if isinstance(entry.get("set"), dict) else {}
                if "med" in set_block:
                    try:
                        cfg.append(f" set metric {int(set_block.get('med'))}")
                    except Exception:
                        pass
                if "localpref" in set_block:
                    try:
                        cfg.append(f" set local-preference {int(set_block.get('localpref'))}")
                    except Exception:
                        pass
        if route_maps:
            cfg.append("!")

    cfg.append("line vty")
    cfg.append("!")
    return "\n".join(cfg) + "\n"

def topo_to_containerlab(topo: dict) -> dict:
    clab = {
        "name": topo["name"],
        "topology": {"nodes": {}, "links": []},
    }

    hard_defaults = {
        "host": "wbitt/network-multitool:latest",
        "nft-fw": "ghcr.io/andrew-ai-netsim/nft-fw:latest",
        "frr": "frrouting/frr:latest",
    }

    evpn = _validate_fabric_evpn_presence_only(topo)
    evpn_leaf_access: dict[str, dict[str, Any]] = {}
    if isinstance(evpn, dict):
        for item in evpn.get("host_attachments", []) or []:
            if not isinstance(item, dict):
                continue
            key = f"{item['attach']}:{item['leaf_iface']}"
            evpn_leaf_access[key] = item

    for n in topo["nodes"]:
        ntype = n["type"]

        image = n.get("image") or hard_defaults.get(ntype) or DEFAULT_IMAGES.get(ntype)
        if not image:
            die(f"No default image for node type '{ntype}'. Set node.image explicitly.")

        rt = (n.get("runtime") or "container").strip().lower()

        if rt == "vm":
            if ntype != "sonic-vm":
                die(f"VM runtime currently supports only type 'sonic-vm' (got {ntype!r})")
            node_def = {"kind": "sonic-vm", "image": image}
        else:
            node_def = {"kind": "linux", "image": image}

        binds: list[str] = []

        if ntype == "frr":
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
                binds = []

        if ntype == "host":
            node_def["cmd"] = "sleep infinity"

        if ntype == "nft-fw":
            node_def["cmd"] = "sleep infinity"
            node_def["sysctls"] = {
                "net.ipv4.ip_forward": "1",
                "net.ipv4.conf.all.rp_filter": "0",
                "net.ipv4.conf.default.rp_filter": "0",
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
    # 0b) Deterministic host<->nft-fw link ipv4 synthesis (explicit intent precedence)
    #
    # If the user omits link.ipv4 for a host<->nft-fw point-to-point link, but declares:
    #   - host: ip + gw
    #   - nft-fw: interfaces[<ifname>]
    # then synthesize link.ipv4 deterministically in Resolve, preserving endpoint order.
    #
    # Fail-fast (no silent defaults):
    #   - host has ip/gw but fw.interfaces[if] missing -> die
    #   - fw.interfaces[if] present but host.ip missing -> die
    # ----------------------------
    nodes_by_name = {}
    for n in (resolved.get("nodes") or []):
        if isinstance(n, dict):
            nm = n.get("name")
            if isinstance(nm, str) and nm:
                nodes_by_name[nm] = n

    for link in (resolved.get("links") or []):
        if not isinstance(link, dict):
            continue
        if link.get("ipv4"):
            continue  # explicit link intent always wins
        eps = link.get("endpoints") or []
        if not (isinstance(eps, list) and len(eps) == 2):
            continue

        def _split(ep: str):
            if not (isinstance(ep, str) and ":" in ep):
                return None, None
            return ep.split(":", 1)

        a_ep, b_ep = eps
        a_node, a_if = _split(a_ep)
        b_node, b_if = _split(b_ep)
        if not a_node or not b_node:
            continue

        a = nodes_by_name.get(a_node) or {}
        b = nodes_by_name.get(b_node) or {}
        a_type = str(a.get("type") or "").strip().lower()
        b_type = str(b.get("type") or "").strip().lower()

        def _synth(host_node: str, host_if: str, host_rec: dict, fw_node: str, fw_if: str, fw_rec: dict):
            hip = host_rec.get("ip")
            hgw = host_rec.get("gw")
            fw_intfs = fw_rec.get("interfaces") or {}
            fip = fw_intfs.get(fw_if) if isinstance(fw_intfs, dict) else None

            host_has = isinstance(hip, str) and hip.strip() and isinstance(hgw, str) and hgw.strip()
            fw_has = isinstance(fip, str) and fip.strip()

            if host_has and not fw_has:
                die(
                    f"Topology invalid: link {host_node}:{host_if} <-> {fw_node}:{fw_if}: "
                    f"host has ip/gw but {fw_node}.interfaces missing '{fw_if}'"
                )
            if fw_has and not (isinstance(hip, str) and hip.strip()):
                die(
                    f"Topology invalid: link {host_node}:{host_if} <-> {fw_node}:{fw_if}: "
                    f"{fw_node}.interfaces has '{fw_if}' but host '{host_node}' is missing node.ip"
                )

            if host_has and fw_has:
                # Preserve the original endpoint order for link['ipv4']
                if eps[0].startswith(host_node + ":"):
                    link["ipv4"] = [hip.strip(), fip.strip()]
                else:
                    link["ipv4"] = [fip.strip(), hip.strip()]

        if a_type == "host" and b_type == "nft-fw":
            _synth(a_node, a_if, a, b_node, b_if, b)
        elif b_type == "host" and a_type == "nft-fw":
            _synth(b_node, b_if, b, a_node, a_if, a)

    # ----------------------------
    # 1) Auto-address point-to-point links (10.0.0.0/16, sequential /31s)
    # ----------------------------
    evpn_host_links = set()
    fabric_evpn = (((resolved.get("fabric") or {}).get("evpn")) or {})
    if fabric_evpn.get("enabled"):
        for att in list((fabric_evpn.get("host_attachments") or [])):
            leaf = str(att.get("attach") or att.get("leaf") or att.get("node") or "").strip()
            host = str(att.get("host") or "").strip()
            if leaf and host:
                evpn_host_links.add(tuple(sorted((f"{host}:eth1", att.get("leaf_iface") and f"{leaf}:{att.get('leaf_iface')}" or f"{leaf}:eth2"))))

    next_host = 0  # host index inside 10.0.0.0/16
    for link in resolved.get("links", []):
        if "ipv4" in link and link["ipv4"]:
            continue  # user already specified

        eps = link["endpoints"]
        if len(eps) != 2:
            die("Auto-IP currently supports only point-to-point links with 2 endpoints")

        if tuple(sorted(eps)) in evpn_host_links:
            host_name = None
            for ep in eps:
                node_name = ep.split(":", 1)[0].strip()
                for n in resolved.get("nodes", []):
                    if str(n.get("name") or "").strip() == node_name:
                        if str(n.get("type") or "").strip() == "host":
                            host_name = node_name
                        break

            host_node = {}
            for n in resolved.get("nodes", []):
                if str(n.get("name") or "").strip() == str(host_name or "").strip():
                    host_node = n
                    break

            host_ip = str(host_node.get("ip") or "").strip()
            host_gw = str(host_node.get("gw") or "").strip()
            if not host_ip or not host_gw:
                die("EVPN host attachment requires host ip and gw for resolved access-link addressing")
            link["ipv4"] = [host_ip, f"{host_gw}/24"]
            continue  # EVPN access-side attachment: preserve non-/31 access-link addressing

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

        kind_raw = t.get("kind")
        type_raw = t.get("type")

        # v2 routing invariants reserve:
        #   kind: invariant
        #   type: <invariant subtype>
        # For all other tests, legacy type->kind aliasing remains unchanged.
        if kind_raw is not None:
            kind_norm = str(kind_raw).strip().lower()
            t["kind"] = kind_norm
        else:
            kind_norm = ""

        if kind_norm == "invariant":
            if type_raw is None:
                die(f"tests[{i}]: invariant test requires 'type'")
            inv_type = str(type_raw).strip().lower()
            if not inv_type:
                die(f"tests[{i}]: invariant test requires non-empty 'type'")
            if inv_type not in (
                "bgp_session_up",
                "route_present",
                "route_absent",
                "bgp_med_equals",
                "bgp_localpref_equals",
                "route_advertised_to",
                "evpn_mac_route_present",
                "evpn_mac_route_absent",
                "evpn_vni_route_present",
                "evpn_bgp_session_up",
            ):
                die(
                    f"tests[{i}]: invariant.type unsupported ({inv_type!r}) "
                    f"(supported: bgp_session_up, route_present, route_absent, "
                    f"bgp_med_equals, bgp_localpref_equals, route_advertised_to, "
                    f"evpn_mac_route_present, evpn_mac_route_absent, "
                    f"evpn_vni_route_present, evpn_bgp_session_up)"
                )
            t["type"] = inv_type
        else:
            if "kind" in t and "type" in t:
                die(f"tests[{i}]: has both 'kind' and 'type' (use only 'kind')")

            if "type" in t and "kind" not in t:
                t["kind"] = str(t.pop("type")).strip().lower()

        # ----------------------------
        # v2: invariant alias normalization + schema validation (resolve-time only)
        # Canonical form:
        #   kind: invariant
        #   type: bgp_session_up|route_present|route_absent
        #   node: <node name>
        # Normalized aliases:
        #   node -> src
        #   neighbor -> dst   (bgp_session_up only)
        # ----------------------------
        if (t.get("kind") or "").strip() == "invariant":
            ctx = f"tests[{i}] ({t.get('name', '<unnamed>')})"

            if "node" in t and "src" in t:
                a = str(t.get("node") or "").strip()
                b = str(t.get("src") or "").strip()
                if a and b and a != b:
                    die(f"{ctx}: 'node' and 'src' disagree ({a!r} vs {b!r})")

            if "src" not in t and "node" in t:
                t["src"] = t.get("node")

            inv_type = str(t.get("type") or "").strip().lower()
            src = t.get("src")
            if not isinstance(src, str) or not src.strip():
                die(f"{ctx}: invariant test requires 'node/src' as a node name")

            exp = t.get("expect")
            if exp is None:
                exp = "pass"
            exp_s = str(exp).strip().lower()
            if exp_s not in ("pass", "fail"):
                die(f"{ctx}: invariant.expect must be pass|fail if provided")
            t["expect"] = exp_s

            if inv_type in ("route_present", "route_absent", "bgp_med_equals", "bgp_localpref_equals", "route_advertised_to"):
                pfx = t.get("prefix")
                if not isinstance(pfx, str) or not pfx.strip():
                    die(f"{ctx}: {inv_type} requires 'prefix' as CIDR (e.g. 10.0.0.0/24)")
                try:
                    _ = ipaddress.ip_network(pfx.strip(), strict=False)
                except Exception:
                    die(f"{ctx}: {inv_type}.prefix must be a valid CIDR (e.g. 10.0.0.0/24)")

                if inv_type == "route_advertised_to":
                    peer = t.get("peer")
                    if not isinstance(peer, str) or not peer.strip():
                        die(f"{ctx}: {inv_type} requires 'peer'")

                if inv_type in ("bgp_med_equals", "bgp_localpref_equals"):
                    expv = t.get("expected")
                    if expv is None or str(expv).strip() == "":
                        die(f"{ctx}: {inv_type} requires 'expected'")
                    try:
                        t["expected"] = int(expv)
                    except Exception:
                        die(f"{ctx}: {inv_type}.expected must be an integer")

            elif inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent"):
                mac = t.get("mac")
                if not isinstance(mac, str) or not mac.strip():
                    die(f"{ctx}: {inv_type} requires 'mac'")
                mac_s = mac.strip().lower()
                if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac_s):
                    die(f"{ctx}: {inv_type}.mac must be a valid MAC address")
                t["mac"] = mac_s

                vni = t.get("vni")
                if vni is None or str(vni).strip() == "":
                    die(f"{ctx}: {inv_type} requires 'vni'")
                try:
                    vni_i = int(vni)
                except Exception:
                    die(f"{ctx}: {inv_type}.vni must be an integer")
                if vni_i < 1:
                    die(f"{ctx}: {inv_type}.vni must be >= 1")
                t["vni"] = vni_i

            elif inv_type == "evpn_vni_route_present":
                vni = t.get("vni")
                if vni is None or str(vni).strip() == "":
                    die(f"{ctx}: {inv_type} requires 'vni'")
                try:
                    vni_i = int(vni)
                except Exception:
                    die(f"{ctx}: {inv_type}.vni must be an integer")
                if vni_i < 1:
                    die(f"{ctx}: {inv_type}.vni must be >= 1")
                t["vni"] = vni_i

            elif inv_type == "evpn_bgp_session_up":
                peer = t.get("peer")
                if not isinstance(peer, str) or not peer.strip():
                    die(f"{ctx}: evpn_bgp_session_up requires non-empty 'peer'")
                t["peer"] = peer.strip()

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
