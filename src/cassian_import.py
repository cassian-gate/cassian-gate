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

import ipaddress
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
# Import-side checks and messages (§4.6: DC v2.1 §2 hard-fail, §13 messages)   #
# --------------------------------------------------------------------------- #

# The contract's allowed keys, per object (§4.6 REQ-46-7, IR-39). These are
# exactly the keys the build path reads. Any other key is rejected at load,
# naming the file, the object and the key; it is never ignored.
CONTRACT_ALLOWED_KEYS = {
    "top level": ("bgp_sessions", "cables", "devices", "site", "static_routes"),
    "site": ("name",),
    "device": ("asn", "name", "platform", "router_id"),
    "cable": ("a", "a_ip", "b", "b_ip"),
    "cable end": ("device", "interface"),
    "bgp session": ("local_device", "peer_ip", "remote_asn"),
    "static route": ("device", "prefix"),
}

# The starter file's set-aside section (§4.6 REQ-46-26, IR-10, IR-36). Cassian
# Gate does not configure static routes on the nodes it generates, so the
# route_present starter checks are written here, not embedded in topology.yaml.
NEEDS_DEVICE_CONFIGURATION_KEY = "needs_device_configuration"
NEEDS_DEVICE_CONFIGURATION_REASON = (
    "route_present checks for declared static routes. Cassian Gate does not "
    "configure static routes on the nodes it generates, so these pass only "
    "where routing comes from device configuration. They are not in "
    "topology.yaml."
)


def _text(value) -> str:
    """A declared name or address as the importer reads it (shipped form)."""
    return str(value or "").strip()


def _end_text(end) -> str:
    """A cable end as ``<device>:<interface>``, for a rejection's locator."""
    if not isinstance(end, dict):
        return ":"
    return f"{_text(end.get('device'))}:{_text(end.get('interface'))}"


def _reject(where: tuple, issue: str, action: str) -> None:
    """Reject the import source's content at exit 2 (§4.6 REQ-46-13, B-13):
    ``Invalid NetBox import: <file>: <object>: <issue>. <action> and re-run.``
    A whole-file issue carries no object. Nothing has been written."""
    file, obj = where
    located = f"{file}: {obj}: " if obj else f"{file}: "
    end = " " if issue.endswith("?") else ". "  # an issue may end in a question
    die(f"Invalid NetBox import: {located}{issue}{end}{action} and re-run.", code=2)


def _value_text(entry: dict, key: str) -> str:
    """A field's value as a rejection prints it (§4.6 §6.6): ``json.dumps`` of
    the parsed value, or ``missing`` when the key is absent."""
    if key not in entry:
        return "missing"
    return json.dumps(entry[key])


def _valid_interface_name(name: str) -> bool:
    """A Linux interface name (§4.6 REQ-46-10, B-10): 1 to 15 bytes in UTF-8,
    no '/', ':' or whitespace, and not '.' or '..'. No name is rewritten."""
    if name in (".", ".."):
        return False
    if not 1 <= len(name.encode("utf-8")) <= 15:
        return False
    return not any(c in "/:" or c.isspace() for c in name)


class _ContractLocator:
    """The locator table (§4.6 §13): for each contract entry, the file and the
    object text a rejection names (REQ-46-13). The contract backend's entries
    all come from ``netbox_export.json``; ``i`` is the entry's position in its
    list in that file, from 0."""

    def __init__(self, file: str, export: dict):
        self.file = file
        self.export = export

    def whole(self) -> tuple:
        return (self.file, "")

    def section(self, key: str) -> tuple:
        return (self.file, key)

    def item(self, key: str, i: int) -> tuple:
        return (self.file, f"{key}[{i}]")

    def _entry(self, key: str, i: int) -> dict:
        items = self.export.get(key)
        entry = items[i] if isinstance(items, list) and 0 <= i < len(items) else {}
        return entry if isinstance(entry, dict) else {}

    def device(self, i: int) -> tuple:
        name = _text(self._entry("devices", i).get("name"))
        return (self.file, f"devices[{i}] '{name}'")

    def cable(self, i: int) -> tuple:
        c = self._entry("cables", i)
        return (self.file, f"cables[{i}] '{_end_text(c.get('a'))}<->{_end_text(c.get('b'))}'")

    def cable_end(self, i: int, side: str) -> tuple:
        file, obj = self.cable(i)
        return (file, f"{obj} end '{side}'")

    def session(self, i: int, peer: bool = True) -> tuple:
        s = self._entry("bgp_sessions", i)
        local = _text(s.get("local_device"))
        if not peer:
            return (self.file, f"bgp_sessions[{i}] (local_device '{local}')")
        return (
            self.file,
            f"bgp_sessions[{i}] (local_device '{local}', "
            f"peer_ip '{_text(s.get('peer_ip'))}')",
        )

    def route(self, i: int) -> tuple:
        device = _text(self._entry("static_routes", i).get("device"))
        return (self.file, f"static_routes[{i}] (device '{device}')")


def _check_contract_keys(export: dict, loc: _ContractLocator) -> None:
    """Unknown-key strictness for the contract (§4.6 REQ-46-7, B-7; DC v2.1 §2).
    Objects are checked in file order, top level first; the first unknown key
    of an object, in sorted order, is reported. An entry that is not an object
    is left to the build path's shipped type checks."""

    def check(where: tuple, obj, row: str) -> None:
        if not isinstance(obj, dict):
            return
        allowed = CONTRACT_ALLOWED_KEYS[row]
        unknown = sorted(k for k in obj if k not in allowed)
        if unknown:
            _reject(
                where,
                f"unknown key '{unknown[0]}' (allowed: {', '.join(sorted(allowed))})",
                "Remove or correct the key",
            )

    check(loc.section("top level"), export, "top level")
    check(loc.section("site"), export.get("site"), "site")
    for key, row in (
        ("devices", "device"),
        ("cables", "cable"),
        ("bgp_sessions", "bgp session"),
        ("static_routes", "static route"),
    ):
        items = export.get(key)
        if not isinstance(items, list):
            continue
        for i, entry in enumerate(items):
            where = {
                "devices": loc.device,
                "cables": loc.cable,
                "bgp_sessions": loc.session,
                "static_routes": loc.route,
            }[key](i)
            check(where, entry, row)
            if key == "cables" and isinstance(entry, dict):
                for side in ("a", "b"):
                    check(loc.cable_end(i, side), entry.get(side), "cable end")


def _link_text(link: dict) -> str:
    """A link as a message names it: ``<ep0><-><ep1>``, in the link's order."""
    return f"{link['endpoints'][0]}<->{link['endpoints'][1]}"


def _classify_peer(local: str, x, links: list) -> list:
    """Direction A's five cases (§4.6 D-16) for a session (L, X): every
    ``(case, link)`` match over all addressed links, in link order. Cases 1 and
    2 are on links of L; cases 3 and 4 on links L is not on; no match is case
    5. A link with both ends on L is a link of L; X on it is case 2."""
    matches = []
    for link in links:
        ifaces = link.get("_ifaces")
        if not ifaces:
            continue  # a link without addresses contributes nothing
        devices = link["_devices"]
        network = ifaces[0].network
        if local in devices:
            if devices[0] == devices[1]:
                far = None
            elif devices[0] == local:
                far = ifaces[1]
            else:
                far = ifaces[0]
            if far is not None and x == far.ip:
                matches.append((1, link))
            elif x in network:
                matches.append((2, link))
        else:
            if x in (ifaces[0].ip, ifaces[1].ip):
                matches.append((3, link))
            elif x in network:
                matches.append((4, link))
    return matches


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
        where = (str(export_path), "")
        if not export_path.is_file():
            _reject(
                where,
                "export file not found (expected a committed NetBox export "
                "in Cassian's contract)",
                "Add the export",
            )
        try:
            data = json.loads(export_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            _reject(where, f"not valid JSON ({exc})", "Correct the export")
        if not isinstance(data, dict):
            _reject(
                where,
                "the export root must be a JSON object (got a non-object)",
                "Correct the export",
            )
        return data

    def _load(self, source_dir: Path) -> tuple[dict, _ContractLocator]:
        """Load: read ``netbox_export.json`` and check every object's keys
        (§4.6 REQ-46-7). Returns the contract and its locator table (§13)."""
        export = self._load_export(source_dir)
        loc = _ContractLocator(str(source_dir / self.EXPORT_FILENAME), export)
        _check_contract_keys(export, loc)
        return export, loc

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
    # The build path (§4.6 §13): it takes the contract as a dict plus its
    # locator table, checks in §8's pass order, and stops at the first
    # rejection. Out-of-scope sessions are excluded and recorded on the
    # instance as ``(kind, device, object, reason)`` for run_import to name.

    def _build_nodes(self, export: dict, rendered: dict, loc, rendered_dir: Path):
        devices = export.get("devices") or []
        if not isinstance(devices, list) or not devices:
            _reject(
                loc.section("devices"),
                "'devices' must be a non-empty list",
                "Correct the export",
            )
        nodes = []
        names: set = set()
        index: dict = {}  # device name -> its position in 'devices'
        for i, dev in sorted(
            enumerate(devices), key=lambda p: str((p[1] or {}).get("name") or "")
        ):
            if not isinstance(dev, dict):
                _reject(
                    loc.item("devices", i),
                    "each entry in 'devices' must be an object",
                    "Correct the export",
                )
            name = _text(dev.get("name"))
            if not name:
                _reject(
                    loc.device(i),
                    "a device is missing 'name'",
                    "Every device requires a name. Correct the export",
                )
            if name in names:
                _reject(
                    loc.device(i),
                    f"duplicate device name '{name}' "
                    f"(also devices[{index[name]}])",
                    "Device names must be unique. Correct the export",
                )
            platform = str(dev.get("platform") or "").strip().lower()
            if platform not in SUPPORTED_PLATFORMS:
                _reject(
                    loc.device(i),
                    f"platform '{platform}' unsupported "
                    f"(allowed: {', '.join(SUPPORTED_PLATFORMS)})",
                    "Correct the export",
                )
            conf = str(rendered_dir / f"{name}.conf")
            # router_id: export field, corroborated by rendered config (NB-2).
            export_rid = _text(dev.get("router_id")) or None
            rendered_rid = (rendered.get(name) or {}).get("router_id")
            router_id = self._corroborate(
                loc.device(i), conf, "router_id", export_rid, rendered_rid
            )
            # asn: a JSON integer or absent, never coerced (§4.6 REQ-46-3, B-3);
            # corroborated by rendered config (NB-2).
            if "asn" in dev and type(dev["asn"]) is not int:
                _reject(
                    loc.device(i),
                    f"'asn' must be an integer (got {_value_text(dev, 'asn')})",
                    "Correct the export",
                )
            export_asn = dev.get("asn")
            rendered_asn = (rendered.get(name) or {}).get("asn")
            asn = self._corroborate(loc.device(i), conf, "asn", export_asn, rendered_asn)

            node: dict = {"name": name, "type": platform}
            if asn is not None:
                node["asn"] = asn
            if router_id is not None:
                node["router_id"] = router_id
            nodes.append(node)
            names.add(name)
            index[name] = i
        return nodes, names, index

    @staticmethod
    def _corroborate(where: tuple, conf: str, field: str, export_val, rendered_val):
        """Prefer the export value; corroborate with rendered config. A genuine
        conflict between the two unambiguous sources is rejected (REQ-414-VAL-1)."""
        if export_val is not None and rendered_val is not None:
            if export_val != rendered_val:
                _reject(
                    where,
                    f"{field} conflicts between the export ({export_val!r}) and "
                    f"the rendered config {conf} ({rendered_val!r})",
                    "Reconcile the sources",
                )
            return export_val
        return export_val if export_val is not None else rendered_val

    def _build_links(self, export: dict, node_names: set, loc) -> tuple[list, list, list]:
        cables = export.get("cables") or []
        if not isinstance(cables, list):
            _reject(loc.section("cables"), "'cables' must be a list", "Correct the export")
        links = []
        interfaces: list = []  # (device, interface) declared via cable endpoints
        rows = []
        for i, cable in enumerate(cables):
            if not isinstance(cable, dict):
                _reject(
                    loc.item("cables", i),
                    "each entry in 'cables' must be an object",
                    "Correct the export",
                )
            a = cable.get("a") or {}
            b = cable.get("b") or {}
            ad, ai = _text(a.get("device")), _text(a.get("interface"))
            bd, bi = _text(b.get("device")), _text(b.get("interface"))
            for dev, iface, side in ((ad, ai, "a"), (bd, bi, "b")):
                if not dev or not iface:
                    _reject(
                        loc.cable(i),
                        f"endpoint '{side}' is missing 'device' or 'interface'",
                        "Correct the export",
                    )
                if dev not in node_names:
                    _reject(
                        loc.cable(i),
                        f"references undefined node '{dev}' "
                        f"(allowed: declared nodes {', '.join(sorted(node_names))})",
                        "Correct the source",
                    )
                interfaces.append((dev, iface))
            # §4.6 checks, in the order REQ-46-10, -5, -12, -6 (§8 pass 4).
            for iface in (ai, bi):
                if not _valid_interface_name(iface):
                    _reject(
                        loc.cable(i),
                        f"interface name '{iface}' is not a valid Linux interface "
                        f"name (1 to 15 bytes; no '/', ':' or whitespace; not '.' "
                        f"or '..')",
                        "Cassian Gate does not rename interfaces; use the name the "
                        "device has in its namespace, for example 'eth1'",
                    )
            declared = [k for k in ("a_ip", "b_ip") if cable.get(k)]
            if len(declared) == 1:
                _reject(
                    loc.cable(i),
                    f"declares {declared[0]} without the other; a link needs "
                    f"both addresses or neither",
                    "Correct the export",
                )
            ipv4 = []
            ifaces = []
            for ip_key in declared:
                v = str(cable.get(ip_key)).strip()
                try:
                    iface_addr = ipaddress.IPv4Interface(v) if "/" in v else None
                except ValueError:
                    iface_addr = None
                if iface_addr is None:
                    _reject(
                        loc.cable(i),
                        f"{ip_key} '{v}' is not an IPv4 interface address "
                        f"(address/length, for example '10.0.0.1/30')",
                        "Correct the export",
                    )
                ipv4.append(v)
                ifaces.append(iface_addr)
            if ifaces and (
                ifaces[0].network != ifaces[1].network or ifaces[0].ip == ifaces[1].ip
            ):
                _reject(
                    loc.cable(i),
                    f"addresses {ipv4[0]} and {ipv4[1]} are not two distinct "
                    f"addresses of one IPv4 subnet",
                    "Correct the export",
                )
            endpoints = [f"{ad}:{ai}", f"{bd}:{bi}"]
            rows.append((tuple(endpoints), tuple(ipv4), (ad, bd), tuple(ifaces)))
        # Deterministic ordering of links by canonical endpoint tuple (D02).
        for endpoints, ipv4, devices, ifaces in sorted(rows, key=lambda r: (r[0], r[1])):
            link = {"endpoints": list(endpoints)}
            if ipv4:
                link["ipv4"] = list(ipv4)
            links.append(link)
        return links, interfaces, [
            {"endpoints": list(r[0]), "_devices": r[2], "_ifaces": r[3]}
            for r in sorted(rows, key=lambda r: (r[0], r[1]))
        ]

    def _attach_bgp(self, export: dict, nodes: list, node_names: set, loc,
                    resolve_links: list) -> tuple[list, list]:
        """Map declared BGP sessions onto node bgp.neighbors, each resolved to its
        far-end node through the links (§4.6 IR-41, direction A), and return the
        (local_device, peer_ip) pairs usable for bgp_session_up invariants, with
        the local devices of every session that reached this path."""
        sessions = export.get("bgp_sessions") or []
        if not isinstance(sessions, list):
            _reject(
                loc.section("bgp_sessions"),
                "'bgp_sessions' must be a list",
                "Correct the export",
            )
        by_name = {n["name"]: n for n in nodes}
        pairs = []
        locals_seen: set = set()
        seen: dict = {}  # (local_device, peer address) -> position
        for i, sess in sorted(
            enumerate(sessions),
            key=lambda p: (
                str((p[1] or {}).get("local_device") or ""),
                str((p[1] or {}).get("peer_ip") or ""),
            ),
        ):
            if not isinstance(sess, dict):
                _reject(
                    loc.item("bgp_sessions", i),
                    "each entry in 'bgp_sessions' must be an object",
                    "Correct the export",
                )
            local = _text(sess.get("local_device"))
            peer_ip = _text(sess.get("peer_ip"))
            if local not in node_names:
                _reject(
                    loc.session(i),
                    f"references undefined local_device '{local}' "
                    f"(allowed: declared nodes {', '.join(sorted(node_names))})",
                    "Correct the export",
                )
            # §4.6 checks, in the order REQ-46-1, -4, -23, -9 (§8 pass 5).
            try:
                x = ipaddress.IPv4Address(peer_ip) if peer_ip else None
            except ValueError:
                x = None
            if x is None:
                _reject(
                    loc.session(i, peer=False),
                    f"'peer_ip' is missing, empty or not an IPv4 address "
                    f"({_value_text(sess, 'peer_ip')})",
                    "A session needs its peer's IPv4 address. Correct the export",
                )
            if "remote_asn" in sess and type(sess["remote_asn"]) is not int:
                _reject(
                    loc.session(i),
                    f"'remote_asn' must be an integer "
                    f"(got {_value_text(sess, 'remote_asn')})",
                    "Correct the export",
                )
            if "remote_asn" not in sess:
                _reject(
                    loc.session(i),
                    "'remote_asn' is required; the generated configuration "
                    "cannot render a neighbour without it",
                    "Add 'remote_asn'",
                )
            if (local, x) in seen:
                first = seen[(local, x)]
                _reject(
                    loc.section("bgp_sessions"),
                    f"local_device '{local}' declares a session to '{peer_ip}' "
                    f"more than once (entries [{min(first, i)}] and "
                    f"[{max(first, i)}])",
                    "Remove the duplicate",
                )
            seen[(local, x)] = i
            locals_seen.add(local)

            # Direction A's five cases (§4.6 REQ-46-15 to -22, D-16).
            matches = _classify_peer(local, x, resolve_links)
            cases = sorted({case for case, _ in matches})
            if not matches:  # case 5 (REQ-46-21): excluded and named
                self.exclusions.append((
                    "bgp-session", local, f"{local} -> {peer_ip}",
                    f"peer outside the declared topology: {peer_ip} lies "
                    f"outside every declared link's subnet",
                ))
                continue
            if len(cases) > 1:  # REQ-46-22
                _reject(
                    loc.session(i),
                    f"{peer_ip} matches more than one declared link in different "
                    f"ways ("
                    + "; ".join(f"{_link_text(k)}: case {c}" for c, k in matches)
                    + "); the link addressing overlaps",
                    "Correct the export",
                )
            case = cases[0]
            matched = [k for _, k in matches]
            if case == 1:
                if len(matched) > 1:  # REQ-46-16
                    _reject(
                        loc.session(i),
                        f"{peer_ip} is the far-end address of more than one of "
                        f"{local}'s links ("
                        + ", ".join(_link_text(k) for k in matched) + ")",
                        "Correct the export",
                    )
                devices = matched[0]["_devices"]
                peer = devices[1] if devices[0] == local else devices[0]
                to_peer = [
                    k for k in resolve_links
                    if k["_devices"] in ((local, peer), (peer, local))
                ]
                if len(to_peer) > 1:  # REQ-46-17
                    _reject(
                        loc.session(i),
                        f"resolves to peer node '{peer}', which {local} reaches "
                        f"over more than one link ("
                        + ", ".join(_link_text(k) for k in to_peer)
                        + "); the generated configuration would use the first",
                        f"Keep one link to {peer} or correct the export",
                    )
                # REQ-46-15: the neighbour is the far-end node's name (F-11).
                node = by_name[local]
                node.setdefault("bgp", {}).setdefault("neighbors", []).append(
                    {"peer": peer, "remote_as": sess["remote_asn"]}
                )
                pairs.append((local, peer_ip))
            elif case == 2:  # REQ-46-18
                fars = []
                for k in matched:
                    devices, ifaces = k["_devices"], k["_ifaces"]
                    if devices[0] == devices[1]:
                        fars.append("-")
                    else:
                        far = ifaces[1] if devices[0] == local else ifaces[0]
                        fars.append(str(far.ip))
                _reject(
                    loc.session(i),
                    f"{peer_ip} lies inside the subnet of link "
                    + ", ".join(_link_text(k) for k in matched)
                    + f" but is not its far-end address ({', '.join(fars)}); "
                    f"is the peer address mistyped?",
                    "Correct the export",
                )
            elif case == 3:  # REQ-46-19: excluded and named
                self.exclusions.append((
                    "bgp-session", local, f"{local} -> {peer_ip}",
                    f"non-adjacent peer: {peer_ip} is an address of link "
                    f"{_link_text(matched[0])}, which {local} is not on; a "
                    f"generated lab configures a neighbour only over the "
                    f"node's own links",
                ))
            else:  # case 4, REQ-46-20
                ifaces = matched[0]["_ifaces"]
                _reject(
                    loc.session(i),
                    f"{peer_ip} lies inside the subnet of link "
                    f"{_link_text(matched[0])}, which {local} is not on, but is "
                    f"neither of its addresses ({ifaces[0].ip}, {ifaces[1].ip})",
                    "Correct the export",
                )
        # Keep neighbor lists deterministic.
        for node in nodes:
            if "bgp" in node and "neighbors" in node["bgp"]:
                node["bgp"]["neighbors"] = sorted(
                    node["bgp"]["neighbors"], key=lambda nb: str(nb.get("peer") or "")
                )
        return sorted(pairs), sorted(locals_seen)

    @staticmethod
    def _check_bgp_devices(nodes: list, bgp_devices: list, index: dict, loc) -> None:
        """A device named as local_device by a session that reached the build
        path, resolved or excluded, needs both 'asn' and 'router_id' (§4.6
        REQ-46-24, AP-6), from the export or a rendered config."""
        by_name = {n["name"]: n for n in nodes}
        for name in sorted(bgp_devices):
            for field in ("asn", "router_id"):
                if field not in by_name[name]:
                    _reject(
                        loc.device(index[name]),
                        f"has a BGP session but no '{field}' (from the export or "
                        f"a rendered config); the generated configuration renders "
                        f"BGP only when both are present",
                        f"Add '{field}'",
                    )

    # ---- produce ----------------------------------------------------------- #

    def produce(self, source_dir: Path) -> tuple[dict, list]:
        export, loc = self._load(source_dir)
        rendered = self._parse_rendered_configs(source_dir)
        return self._build(export, rendered, loc, source_dir / self.RENDERED_SUBDIR)

    def _build(self, export: dict, rendered: dict, loc, rendered_dir: Path):
        """The build path (§4.6 §13; pass order §8 / D-17)."""
        self.exclusions = []
        site = export.get("site") or {}
        name = str(site.get("name") or "").strip()
        if not name:
            _reject(
                loc.section("site"),
                "'site.name' is required as the topology name",
                "Correct the export",
            )

        nodes, node_names, index = self._build_nodes(export, rendered, loc, rendered_dir)
        links, declared_ifaces, resolve_links = self._build_links(export, node_names, loc)
        bgp_pairs, bgp_devices = self._attach_bgp(
            export, nodes, node_names, loc, resolve_links
        )
        self._check_bgp_devices(nodes, bgp_devices, index, loc)

        topo = {"name": name, "nodes": nodes, "links": links}

        declarations = {
            "bgp_session": bgp_pairs,
            "interface": sorted(set(declared_ifaces)),
            "static_route": _collect_static_routes(export, node_names, loc),
        }
        invariants = generate_starter_invariants(declarations)
        return topo, invariants


# Backend registry. Adding a backend = one entry; no consumer change (IF-1).
BACKENDS = {NetBoxBackend.name: NetBoxBackend}


# --------------------------------------------------------------------------- #
# Static-route collection (allowlist source helper)                           #
# --------------------------------------------------------------------------- #

def _collect_static_routes(export: dict, node_names: set, loc) -> list:
    routes = export.get("static_routes") or []
    if not isinstance(routes, list):
        _reject(
            loc.section("static_routes"),
            "'static_routes' must be a list",
            "Correct the export",
        )
    out = []
    seen: dict = {}  # (device, prefix) -> position
    for i, r in enumerate(routes):
        if not isinstance(r, dict):
            _reject(
                loc.item("static_routes", i),
                "each entry in 'static_routes' must be an object",
                "Correct the export",
            )
        dev = _text(r.get("device"))
        prefix = _text(r.get("prefix"))
        if dev not in node_names:
            _reject(
                loc.route(i),
                f"references undefined device '{dev}' "
                f"(allowed: declared nodes {', '.join(sorted(node_names))})",
                "Correct the export",
            )
        # §4.6 checks, in the order REQ-46-2, -11, -8 (§8 pass 7).
        if not prefix:
            _reject(
                loc.route(i),
                "'prefix' is missing or empty",
                "A static route needs its prefix. Correct the export",
            )
        try:
            canonical = ipaddress.IPv4Network(prefix, strict=True).with_prefixlen == prefix
        except ValueError:
            canonical = False
        if not canonical:
            _reject(
                loc.route(i),
                f"prefix '{prefix}' is not an IPv4 network with no host bits set "
                f"(for example '192.0.2.0/24')",
                "Correct the export",
            )
        if (dev, prefix) in seen:
            _reject(
                loc.section("static_routes"),
                f"device '{dev}' declares prefix '{prefix}' more than once "
                f"(entries [{seen[(dev, prefix)]}] and [{i}])",
                "Remove the duplicate",
            )
        seen[(dev, prefix)] = i
        out.append((dev, prefix))
    return sorted(out)


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


def _produce(source_dir, backend: str = "netbox") -> tuple[dict, list, ImporterBackend]:
    """What :func:`produce_pair` does, also returning the backend instance, so
    run_import can name the objects it excluded (§4.6 B-25, §13)."""
    src = Path(source_dir)
    if not src.is_dir():
        die(
            f"Invalid import: source '{source_dir}' is not a directory. "
            f"Point to a committed brownfield source directory and re-run.",
            code=2,
        )
    impl = _select_backend(backend)
    topo, invariants = impl.produce(src)
    return topo, invariants, impl


def produce_pair(source_dir, backend: str = "netbox") -> tuple[dict, list]:
    """Produce the authoritative ``(topology, starter_invariants)`` pair."""
    topo, invariants, _impl = _produce(source_dir, backend=backend)
    return topo, invariants


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
    ``<out_dir>/tests/starter_invariants.yaml`` (an operator-readable copy of the
    embedded invariants, plus the set-aside ``route_present`` checks under
    ``needs_device_configuration``, present only when non-empty: §4.6 REQ-46-26).
    Success prints §4.6's four-line block and one line per excluded object, and
    returns (exit 0); any invalid/ambiguous/unsupported input hard-fails at
    exit 2, before anything is written.
    """
    topo, invariants, impl = _produce(source_dir, backend=backend)
    exclusions = sorted(
        getattr(impl, "exclusions", None) or [], key=lambda e: (e[0], e[1], e[2])
    )

    # The IR-10 split (§4.6 REQ-46-26, B-26): route_present starter checks are
    # set aside in the starter file and not embedded in topology.yaml.
    route_type = INVARIANT_ALLOWLIST["static_route"]
    embedded = [t for t in invariants if t.get("type") != route_type]
    set_aside = [t for t in invariants if t.get("type") == route_type]

    # Embed the remaining starter invariants as the gate-consumed ``tests`` block.
    if embedded:
        topo["tests"] = embedded

    _validate_emitted_pair(topo)

    starter: dict = {"tests": embedded}
    if set_aside:
        starter[NEEDS_DEVICE_CONFIGURATION_KEY] = {
            "reason": NEEDS_DEVICE_CONFIGURATION_REASON,
            "tests": set_aside,
        }

    out = Path(out_dir)
    (out / "tests").mkdir(parents=True, exist_ok=True)
    topo_path = out / "topology.yaml"
    inv_path = out / "tests" / "starter_invariants.yaml"

    topo_path.write_text(_dump_yaml(topo), encoding="utf-8")
    inv_path.write_text(_dump_yaml(starter), encoding="utf-8")

    # Success block (§4.6 REQ-46-27, §6.1); provenance-free (D03).
    key = (backend or "").strip().lower()
    print(f"✅ IMPORT OK (authoritative input; backend: {key}): wrote {topo_path}")
    print(
        f"   starter invariants ({len(embedded)}): embedded in topology.yaml, "
        f"copied to {inv_path}"
    )
    print(f"   set aside, need device configuration ({len(set_aside)}): {inv_path}")
    print(f"   excluded by filter ({len(exclusions)})")
    for kind, _device, obj, reason in exclusions:
        print(f"   excluded: {kind} {obj}: {reason}")
