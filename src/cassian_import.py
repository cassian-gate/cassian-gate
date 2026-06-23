"""Cassian Gate — Brownfield First-Importer (§4.14).

A backend-pluggable importer that converts committed brownfield sources into an
authoritative, deterministic ``(topology, starter_invariants)`` pair conformant
to DC v2.1 §2. The emitted pair is **authoritative gate input** — categorically
distinct from the advisory ``adapt``/``adapters.v1`` surface (LD-3). This module
shares NO code with that path; the minimal rendered-config parse below is a
deliberate duplicate (REQ-414-PRES-2, BR-5).

Phase 1b subset (LD-1 / LD-6): a committed NetBox export fixture plus rendered
device configs, parsed offline. The live NetBox API and the Git-Ansible /
CloudVision / live backends are defined-not-implemented seams (REQ-414-IF-3).
End-to-end deploy (PO-7) is Phase 2 — this module produces input, not evidence.

Reuse-by-import (LD-4): this module imports the existing ``cassian_model``
validators and never edits them, so ``cassian_model.py`` stays byte-unchanged
and PBE-1b-9 remains untriggered. Importing an existing validator is not the
creation of a new shared helper.

Determinism (REQ-414-IF-4): identical brownfield input yields a byte-identical
pair. All source iteration is sorted (D02/D04); serialization is canonical
(sorted keys, block style); run-variant provenance (timestamps, host paths) is
never written (D03).

Authoritative-input hard-fail (REQ-414-VAL-1/-2/-3): invalid, ambiguous, or
unsupported import input hard-fails at the exit-2 band via ``die(..., code=2)``
with a §13(a)-sufficient message (offending field/source, the issue, the
corrective action). The importer never emits a pair the gate would reject;
ambiguity is rejected at import, never deferred downstream.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

# Reuse-by-import (LD-4): cassian_model stays byte-unchanged. No advisory
# (adapt/adapters.v1) import; no cassian_ai import (REQ-414-PRES-2, 4.1 AI=N/A).
from cassian_common import die
from cassian_model import (
    ensure_valid_topology,
    resolve_topology,
    _validate_exec_assertion,
)

# --------------------------------------------------------------------------- #
# Allowlists (explicit, no heuristics — REQ-414-NB-1, BR-3)                    #
# --------------------------------------------------------------------------- #

# Device platforms admitted in the Phase 1b subset. Anything else is an
# unsupported authoritative-input source and is hard-failed (REQ-414-VAL-1).
SUPPORTED_PLATFORMS = ("frr",)

# Declaration -> invariant-type mapping. Each emitted type is a member of the
# gate's recognized invariant set (cassian_model:2210) and is generated only
# from an unambiguous declaration (REQ-414-INV-1, LD-5). Ambiguous or
# unsupported declarations are omitted, never synthesized.
INVARIANT_ALLOWLIST = {
    "bgp_session": "bgp_session_up",   # session-up for a declared BGP peer
    "interface": "interface_state",    # interface-state for a declared interface
    "static_route": "route_present",   # route-presence for a declared static
}

# Future backends are defined here as named seams but NOT implemented in Phase 1b
# (REQ-414-IF-3). Selecting one hard-fails with a clear, corrective message.
FUTURE_BACKENDS = ("git-ansible", "cloudvision", "live-netbox")


# --------------------------------------------------------------------------- #
# Backend contract (open/closed — REQ-414-IF-1)                               #
# --------------------------------------------------------------------------- #

class ImporterBackend:
    """Backend contract.

    A backend converts a committed brownfield source directory into a
    ``(topology_dict, starter_invariants_list)`` pair. Adding a backend requires
    subclassing this and registering it in :data:`BACKENDS` — with no change to
    this contract or to any consumer (open/closed, REQ-414-IF-1).
    """

    name = "base"

    def produce(self, source_dir: Path) -> tuple[dict, list]:
        raise NotImplementedError(
            f"backend {self.name!r} does not implement produce()"
        )


class NetBoxBackend(ImporterBackend):
    """First concrete backend: a committed NetBox export fixture plus rendered
    device configs, parsed offline (REQ-414-NB-1/-2/-4, LD-6)."""

    name = "netbox"

    EXPORT_FILENAME = "netbox_export.json"
    RENDERED_SUBDIR = "rendered"

    # ---- source loading ---------------------------------------------------- #

    def _load_export(self, source_dir: Path) -> dict:
        export_path = source_dir / self.EXPORT_FILENAME
        if not export_path.is_file():
            die(
                f"Invalid NetBox import: export file "
                f"'{self.EXPORT_FILENAME}' not found under '{source_dir}' "
                f"(expected a committed NetBox export). "
                f"Add the export and re-run.",
                code=2,
            )
        try:
            data = json.loads(export_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            die(
                f"Invalid NetBox import: export '{self.EXPORT_FILENAME}' is not "
                f"valid JSON ({exc}). Correct the export and re-run.",
                code=2,
            )
        if not isinstance(data, dict):
            die(
                "Invalid NetBox import: export root must be a JSON object "
                "(got a non-object). Correct the export and re-run.",
                code=2,
            )
        return data

    def _parse_rendered_configs(self, source_dir: Path) -> dict:
        """Duplicated minimal frr-config parse (LD-3 — no advisory code-sharing).

        Returns ``{device_name: {"asn": int|None, "router_id": str|None}}`` for
        corroboration. Directory traversal is sorted (D04). Offline only.
        """
        rendered_dir = source_dir / self.RENDERED_SUBDIR
        out: dict = {}
        if not rendered_dir.is_dir():
            return out
        for conf in sorted(rendered_dir.glob("*.conf")):
            device = conf.stem
            asn = None
            router_id = None
            for raw in conf.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line.startswith("router bgp "):
                    tail = line[len("router bgp "):].strip()
                    if tail.isdigit():
                        asn = int(tail)
                elif line.startswith("bgp router-id "):
                    router_id = line[len("bgp router-id "):].strip() or None
            out[device] = {"asn": asn, "router_id": router_id}
        return out

    # ---- topology construction (allowlist, no heuristics) ------------------ #

    def _build_nodes(self, export: dict, rendered: dict) -> tuple[list, set]:
        devices = export.get("devices") or []
        if not isinstance(devices, list) or not devices:
            die(
                "Invalid NetBox import: 'devices' must be a non-empty list. "
                "Correct the export and re-run.",
                code=2,
            )
        nodes = []
        names: set = set()
        for dev in sorted(devices, key=lambda d: str((d or {}).get("name") or "")):
            if not isinstance(dev, dict):
                die(
                    "Invalid NetBox import: each entry in 'devices' must be an "
                    "object. Correct the export and re-run.",
                    code=2,
                )
            name = str(dev.get("name") or "").strip()
            if not name:
                die(
                    "Invalid NetBox import: a device is missing 'name'. "
                    "Every device requires a name. Correct the export and re-run.",
                    code=2,
                )
            if name in names:
                die(
                    f"Invalid NetBox import: duplicate device name {name!r}. "
                    f"Device names must be unique. Correct the export and re-run.",
                    code=2,
                )
            platform = str(dev.get("platform") or "").strip().lower()
            if platform not in SUPPORTED_PLATFORMS:
                die(
                    f"Invalid NetBox import: device {name!r} platform "
                    f"{platform!r} unsupported "
                    f"(allowed: {', '.join(SUPPORTED_PLATFORMS)}). "
                    f"Correct the export and re-run.",
                    code=2,
                )
            # router_id: export field, corroborated by rendered config (NB-2).
            export_rid = str(dev.get("router_id") or "").strip() or None
            rendered_rid = (rendered.get(name) or {}).get("router_id")
            router_id = self._corroborate(
                name, "router_id", export_rid, rendered_rid
            )
            # asn: export field, corroborated by rendered config (NB-2).
            export_asn = dev.get("asn")
            export_asn = int(export_asn) if isinstance(export_asn, int) else None
            rendered_asn = (rendered.get(name) or {}).get("asn")
            asn = self._corroborate(name, "asn", export_asn, rendered_asn)

            node: dict = {"name": name, "type": platform}
            if asn is not None:
                node["asn"] = asn
            if router_id is not None:
                node["router_id"] = router_id
            nodes.append(node)
            names.add(name)
        return nodes, names

    @staticmethod
    def _corroborate(device: str, field: str, export_val, rendered_val):
        """Prefer the export value; corroborate with rendered config. A genuine
        conflict between the two unambiguous sources is rejected (REQ-414-VAL-1)."""
        if export_val is not None and rendered_val is not None:
            if export_val != rendered_val:
                die(
                    f"Invalid NetBox import: device {device!r} {field} conflicts "
                    f"between export ({export_val!r}) and rendered config "
                    f"({rendered_val!r}). Reconcile the sources and re-run.",
                    code=2,
                )
            return export_val
        return export_val if export_val is not None else rendered_val

    def _build_links(self, export: dict, node_names: set) -> tuple[list, list]:
        cables = export.get("cables") or []
        if not isinstance(cables, list):
            die(
                "Invalid NetBox import: 'cables' must be a list. "
                "Correct the export and re-run.",
                code=2,
            )
        links = []
        interfaces: list = []  # (device, interface) declared via cable endpoints
        rows = []
        for cable in cables:
            if not isinstance(cable, dict):
                die(
                    "Invalid NetBox import: each entry in 'cables' must be an "
                    "object. Correct the export and re-run.",
                    code=2,
                )
            a = cable.get("a") or {}
            b = cable.get("b") or {}
            ad, ai = str(a.get("device") or "").strip(), str(a.get("interface") or "").strip()
            bd, bi = str(b.get("device") or "").strip(), str(b.get("interface") or "").strip()
            for dev, iface, side in ((ad, ai, "a"), (bd, bi, "b")):
                if not dev or not iface:
                    die(
                        f"Invalid NetBox import: a cable endpoint '{side}' is "
                        f"missing 'device' or 'interface'. "
                        f"Correct the export and re-run.",
                        code=2,
                    )
                if dev not in node_names:
                    die(
                        f"Invalid NetBox import: cable '{ad}:{ai}<->{bd}:{bi}' "
                        f"references undefined node {dev!r} "
                        f"(allowed: declared nodes {', '.join(sorted(node_names))}). "
                        f"Correct the source and re-run.",
                        code=2,
                    )
                interfaces.append((dev, iface))
            endpoints = [f"{ad}:{ai}", f"{bd}:{bi}"]
            ipv4 = []
            for ip_key in ("a_ip", "b_ip"):
                v = cable.get(ip_key)
                if v:
                    ipv4.append(str(v).strip())
            rows.append((tuple(endpoints), tuple(ipv4)))
        # Deterministic ordering of links by canonical endpoint tuple (D02).
        for endpoints, ipv4 in sorted(rows):
            link = {"endpoints": list(endpoints)}
            if ipv4:
                link["ipv4"] = list(ipv4)
            links.append(link)
        return links, interfaces

    def _attach_bgp(self, export: dict, nodes: list, node_names: set) -> list:
        """Map declared BGP sessions onto node bgp.neighbors and return the list
        of (local_device, peer_ip) pairs usable for bgp_session_up invariants."""
        sessions = export.get("bgp_sessions") or []
        if not isinstance(sessions, list):
            die(
                "Invalid NetBox import: 'bgp_sessions' must be a list. "
                "Correct the export and re-run.",
                code=2,
            )
        by_name = {n["name"]: n for n in nodes}
        pairs = []
        for sess in sorted(
            sessions,
            key=lambda s: (
                str((s or {}).get("local_device") or ""),
                str((s or {}).get("peer_ip") or ""),
            ),
        ):
            if not isinstance(sess, dict):
                die(
                    "Invalid NetBox import: each entry in 'bgp_sessions' must be "
                    "an object. Correct the export and re-run.",
                    code=2,
                )
            local = str(sess.get("local_device") or "").strip()
            peer_ip = str(sess.get("peer_ip") or "").strip()
            remote_asn = sess.get("remote_asn")
            if local not in node_names:
                die(
                    f"Invalid NetBox import: bgp_session references undefined "
                    f"local_device {local!r} "
                    f"(allowed: declared nodes {', '.join(sorted(node_names))}). "
                    f"Correct the export and re-run.",
                    code=2,
                )
            if not peer_ip:
                # Ambiguous: no unambiguous peer IP -> omit (no synthesis, LD-5).
                continue
            neighbor: dict = {"peer": peer_ip}
            if isinstance(remote_asn, int):
                neighbor["remote_as"] = remote_asn
            node = by_name[local]
            node.setdefault("bgp", {}).setdefault("neighbors", []).append(neighbor)
            pairs.append((local, peer_ip))
        # Keep neighbor lists deterministic.
        for node in nodes:
            if "bgp" in node and "neighbors" in node["bgp"]:
                node["bgp"]["neighbors"] = sorted(
                    node["bgp"]["neighbors"], key=lambda nb: str(nb.get("peer") or "")
                )
        return sorted(pairs)

    # ---- produce ----------------------------------------------------------- #

    def produce(self, source_dir: Path) -> tuple[dict, list]:
        export = self._load_export(source_dir)
        rendered = self._parse_rendered_configs(source_dir)

        site = export.get("site") or {}
        name = str(site.get("name") or "").strip()
        if not name:
            die(
                "Invalid NetBox import: 'site.name' is required as the topology "
                "name. Correct the export and re-run.",
                code=2,
            )

        nodes, node_names = self._build_nodes(export, rendered)
        links, declared_ifaces = self._build_links(export, node_names)
        bgp_pairs = self._attach_bgp(export, nodes, node_names)

        topo = {"name": name, "nodes": nodes, "links": links}

        declarations = {
            "bgp_session": bgp_pairs,
            "interface": sorted(set(declared_ifaces)),
            "static_route": _collect_static_routes(export, node_names),
        }
        invariants = generate_starter_invariants(declarations)
        return topo, invariants


# Backend registry. Adding a backend = one entry; no consumer change (IF-1).
BACKENDS = {NetBoxBackend.name: NetBoxBackend}


# --------------------------------------------------------------------------- #
# Static-route collection (allowlist source helper)                           #
# --------------------------------------------------------------------------- #

def _collect_static_routes(export: dict, node_names: set) -> list:
    routes = export.get("static_routes") or []
    if not isinstance(routes, list):
        die(
            "Invalid NetBox import: 'static_routes' must be a list. "
            "Correct the export and re-run.",
            code=2,
        )
    out = []
    for r in routes:
        if not isinstance(r, dict):
            die(
                "Invalid NetBox import: each entry in 'static_routes' must be an "
                "object. Correct the export and re-run.",
                code=2,
            )
        dev = str(r.get("device") or "").strip()
        prefix = str(r.get("prefix") or "").strip()
        if dev not in node_names:
            die(
                f"Invalid NetBox import: static_route references undefined device "
                f"{dev!r} (allowed: declared nodes {', '.join(sorted(node_names))}). "
                f"Correct the export and re-run.",
                code=2,
            )
        if not prefix:
            # Ambiguous: no prefix -> omit (no synthesis, LD-5).
            continue
        out.append((dev, prefix))
    return sorted(set(out))


# --------------------------------------------------------------------------- #
# Starter-invariant generation (bounded, deterministic, allowlist-only)       #
# REQ-414-INV-1/-2/-3, BR-3, LD-5                                              #
# --------------------------------------------------------------------------- #

def generate_starter_invariants(declarations: dict) -> list:
    """Generate a bounded, deterministic starter-invariant set from unambiguous
    declarations only. Nothing is synthesized; an ambiguous or unsupported
    declaration produces no invariant (REQ-414-INV-1)."""
    invs = []

    for local, peer_ip in declarations.get("bgp_session", []):
        invs.append({
            "name": f"starter_bgp_session_up_{local}_{_slug(peer_ip)}",
            "kind": "invariant",
            "type": INVARIANT_ALLOWLIST["bgp_session"],
            "node": local,
            "dst": peer_ip,
            "expect": "pass",
        })

    for device, iface in declarations.get("interface", []):
        invs.append({
            "name": f"starter_interface_state_{device}_{_slug(iface)}",
            "kind": "invariant",
            "type": INVARIANT_ALLOWLIST["interface"],
            "node": device,
            "interface": iface,
            "state": "up",
            "expect": "pass",
        })

    for device, prefix in declarations.get("static_route", []):
        invs.append({
            "name": f"starter_route_present_{device}_{_slug(prefix)}",
            "kind": "invariant",
            "type": INVARIANT_ALLOWLIST["static_route"],
            "node": device,
            "prefix": prefix,
            "expect": "pass",
        })

    # Deterministic ordering by stable invariant name (D01).
    return sorted(invs, key=lambda t: t["name"])


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in str(value))


# --------------------------------------------------------------------------- #
# Orchestration + deterministic emission                                      #
# --------------------------------------------------------------------------- #

def _select_backend(backend: str) -> ImporterBackend:
    key = (backend or "").strip().lower()
    if key in BACKENDS:
        return BACKENDS[key]()
    if key in FUTURE_BACKENDS:
        die(
            f"Invalid import backend: {key!r} is a defined-but-not-implemented "
            f"backend (Phase 2). Use one of: {', '.join(sorted(BACKENDS))}. ",
            code=2,
        )
    die(
        f"Invalid import backend: {key!r} is unknown "
        f"(supported: {', '.join(sorted(BACKENDS))}). "
        f"Select a supported backend and re-run.",
        code=2,
    )


def produce_pair(source_dir, backend: str = "netbox") -> tuple[dict, list]:
    """Produce the authoritative ``(topology, starter_invariants)`` pair."""
    src = Path(source_dir)
    if not src.is_dir():
        die(
            f"Invalid import: source '{source_dir}' is not a directory. "
            f"Point to a committed brownfield source directory and re-run.",
            code=2,
        )
    impl = _select_backend(backend)
    return impl.produce(src)


def _validate_emitted_pair(topo: dict) -> None:
    """Reuse-by-import safety net: the importer never emits a pair the gate would
    reject (REQ-414-VAL-2). Re-validates own output via the existing validators;
    a failure here is an importer defect, surfaced with importer context so the
    import-rejection path stays distinct from gate rejection (REQ-414-VAL-3)."""
    for t in topo.get("tests") or []:
        if isinstance(t, dict) and str(t.get("kind") or "").lower() == "exec":
            _validate_exec_assertion(t.get("assertion"), f"importer:{t.get('name')}")
    try:
        ensure_valid_topology(topo)
        resolve_topology(topo)
    except SystemExit as exc:
        die(
            f"Invalid import: the importer produced a non-conformant pair "
            f"({exc}). This is an importer defect; do not hand-edit the export "
            f"to work around it.",
            code=2,
        )


def _dump_yaml(obj) -> str:
    """Canonical, deterministic YAML: sorted keys, block style, no provenance."""
    return yaml.safe_dump(
        obj, sort_keys=True, default_flow_style=False, allow_unicode=True
    )


def run_import(source_dir, out_dir, backend: str = "netbox") -> None:
    """Produce and emit the authoritative pair deterministically to ``out_dir``.

    Emits ``<out_dir>/topology.yaml`` (gate-ready: name/nodes/links/tests) and
    ``<out_dir>/tests/starter_invariants.yaml`` (a standalone, operator-readable
    copy of the generated invariants). Success prints both paths and returns
    (exit 0); any invalid/ambiguous/unsupported input hard-fails at exit 2.
    """
    topo, invariants = produce_pair(source_dir, backend=backend)

    # Embed the starter invariants as the gate-consumed ``tests`` block.
    if invariants:
        topo["tests"] = invariants

    _validate_emitted_pair(topo)

    out = Path(out_dir)
    (out / "tests").mkdir(parents=True, exist_ok=True)
    topo_path = out / "topology.yaml"
    inv_path = out / "tests" / "starter_invariants.yaml"

    topo_path.write_text(_dump_yaml(topo), encoding="utf-8")
    inv_path.write_text(_dump_yaml({"tests": invariants}), encoding="utf-8")

    # Quiet success: name the two emitted artifacts; provenance-free (D03).
    print(f"✅ IMPORT OK (authoritative input): wrote {topo_path}")
    print(f"   starter invariants ({len(invariants)}): wrote {inv_path}")
