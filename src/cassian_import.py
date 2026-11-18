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


# --------------------------------------------------------------------------- #
# The netbox-dump reader's key lists and filter values (§4.6 stage 5)         #
# --------------------------------------------------------------------------- #

# For each endpoint the reader reads, and each nested object it reads into,
# the keys it reads and the keys it knows and does not read (§4.6 REQ-46-47,
# IR-40). A key in neither list is rejected; a key it does not read is never
# descended into. Derived from the committed NetBox 4.6.8 schema
# (tests/importer/fixtures/netbox-seeded/schema.json, whose sha256 follows) by
# contrib/netbox-seed/keylists.py and written here as literals, never
# generated at run time (REQ-46-48, D-14); PF-10 re-derives and compares.
# A cable termination's object and an IP address's assigned object take the
# "interface" lists when their type is DUMP_INTERFACE_TYPE (46-S4-R1); a
# termination of any other type is not key-checked beyond its "device" and
# "circuit" (46-S4-R2).
DUMP_SCHEMA_SHA256 = "2c4898aee0e41b4235c7ba350e636f57d7129ae8689df2fe0da6f724bdf89e0b"
DUMP_INTERFACE_TYPE = "dcim.interface"
DUMP_KEY_LISTS = {
    "asn": (
        ("asn",),
        ("description", "display", "id", "url"),
    ),
    "circuit": (
        ("cid",),
        ("description", "display", "id", "provider", "url"),
    ),
    "dcim/cables": (
        ("a_terminations", "b_terminations", "id", "status"),
        (
            "bundle", "color", "comments", "created", "custom_fields",
            "description", "display", "display_url", "label", "last_updated",
            "length", "length_unit", "owner", "profile", "tags", "tenant",
            "type", "url",
        ),
    ),
    "dcim/devices": (
        ("id", "local_context_data", "name", "platform", "site", "status"),
        (
            "airflow", "asset_tag", "cluster", "comments", "config_context",
            "config_template", "console_port_count",
            "console_server_port_count", "created", "custom_fields",
            "description", "device_bay_count", "device_type", "display",
            "display_url", "face", "front_port_count", "interface_count",
            "inventory_item_count", "last_updated", "latitude", "location",
            "longitude", "module_bay_count", "oob_ip", "owner",
            "parent_device", "position", "power_outlet_count",
            "power_port_count", "primary_ip", "primary_ip4", "primary_ip6",
            "rack", "rear_port_count", "role", "serial", "tags", "tenant",
            "url", "vc_position", "vc_priority", "virtual_chassis",
        ),
    ),
    "device": (
        ("id", "name"),
        ("description", "display", "url"),
    ),
    "interface": (
        ("device", "id", "name"),
        ("_occupied", "cable", "description", "display", "url"),
    ),
    "ip-address": (
        ("address",),
        (
            "description", "display", "dns_name", "family", "id", "nat_inside",
            "nat_outside", "url",
        ),
    ),
    "ipam/ip-addresses": (
        (
            "address", "assigned_object", "assigned_object_type", "id",
            "status", "vrf",
        ),
        (
            "assigned_object_id", "comments", "created", "custom_fields",
            "description", "display", "display_url", "dns_name", "family",
            "last_updated", "nat_inside", "nat_outside", "owner", "role",
            "tags", "tenant", "url",
        ),
    ),
    "platform": (
        ("slug",),
        (
            "_depth", "description", "device_count", "display", "id", "name",
            "url", "virtualmachine_count",
        ),
    ),
    "plugins/bgp/session": (
        ("device", "id", "local_as", "remote_address", "remote_as", "status"),
        (
            "comments", "created", "custom_fields", "description", "display",
            "export_policies", "extra_attributes", "import_policies",
            "last_updated", "local_address", "max_prefixes", "name",
            "peer_group", "prefix_list_in", "prefix_list_out",
            "remote_as_macro", "site", "tags", "tenant", "url",
            "virtualmachine",
        ),
    ),
    "site": (
        ("slug",),
        ("description", "display", "id", "name", "url"),
    ),
    "status": (
        ("value",),
        ("label",),
    ),
    "termination": (
        ("object", "object_type"),
        ("object_id",),
    ),
    "vrf": (
        ("name",),
        ("description", "display", "id", "rd", "url"),
    ),
}

# The filter's fields and in-service values (§4.6 REQ-46-64 to -69, B-69), as
# the schema whose sha256 is DUMP_SCHEMA_SHA256 names them: status on the
# four objects, read through its value, and vrf on IP addresses. PF-10 shows
# each field present on its object and each value in its field's enum.
DUMP_FILTER_FIELDS = {
    "dcim/cables": ("status",),
    "dcim/devices": ("status",),
    "ipam/ip-addresses": ("status", "vrf"),
    "plugins/bgp/session": ("status",),
}
DUMP_IN_SERVICE = {
    "dcim/cables": "connected",
    "dcim/devices": "active",
    "ipam/ip-addresses": "active",
    "plugins/bgp/session": "active",
}



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
            if (source_dir / DUMP_MANIFEST_FILENAME).is_file():  # B-49 (S-10)
                _reject(
                    (str(source_dir), ""),
                    "the 'netbox' backend expects netbox_export.json and the "
                    "'netbox-dump' backend expects manifest.json; the selected "
                    f"backend '{self.name}' found no netbox_export.json here, "
                    "and manifest.json is present",
                    "Select the backend that matches the layout",
                )
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


# --------------------------------------------------------------------------- #
# The netbox-dump reader (§4.6 stage 5: REQ-46-35 to -54, -64 to -72)          #
# --------------------------------------------------------------------------- #
# A second backend (B-35): it reads a bundle a capture of NetBox 4.6.8 with
# netbox-bgp 0.19.0 wrote (manifest.json and four endpoint files), and builds
# the contract in memory for the build path above. Its passes are B-68's:
# (i) load checks on every object, (ii) the filter, (iii) checks on kept
# objects, (iv) the contract, sorted by names, into the build path. It reads
# only the files its manifest names, never a URL, a timestamp or an ID beyond
# matching a reference to a device (D-2 to D-5).

DUMP_MANIFEST_FILENAME = "manifest.json"
DUMP_MANIFEST_KEYS = ("endpoints", "format", "netbox_version", "plugins", "schema", "site")
DUMP_PROVEN_TEXT = "the proven set is NetBox 4.6.8 with netbox-bgp 0.19.0"
DUMP_PROVEN_VERSION = "4.6.8"
DUMP_PROVEN_PLUGINS = {"netbox_bgp": "0.19.0"}
# The endpoints, in the fixed order the reader opens them (D-5).
DUMP_ENDPOINTS = ("dcim/devices", "dcim/cables", "ipam/ip-addresses", "plugins/bgp/session")
# REQ-46-42's platform table: a kept device's platform.slug -> node type.
DUMP_PLATFORM_TYPES = {"frr": "frr"}
DUMP_SCHEMA_KEYS = ("file", "sha256", "source")
DUMP_SCHEMA_SOURCES = ("plugin serializer", "published")
DUMP_CASSIAN_KEYS = ("router_id", "static_routes")
DUMP_RECAPTURE = "Re-capture at the proven versions, or report the field"
DUMP_FIX_IN_NETBOX = "Correct the object in NetBox, then capture the bundle again"

# The nested objects the reader reads into, per row of DUMP_KEY_LISTS (B-47):
# key -> the row its object is checked against. "[termination]" is a list of
# terminations; "@interface" is an interface object only where its type field
# names DUMP_INTERFACE_TYPE (46-S4-R1); a termination of another type has only
# its "device" and "circuit" checked (46-S4-R2).
_DUMP_NESTED = {
    "dcim/devices": (("platform", "platform"), ("site", "site"), ("status", "status")),
    "dcim/cables": (
        ("a_terminations", "[termination]"),
        ("b_terminations", "[termination]"),
        ("status", "status"),
    ),
    "ipam/ip-addresses": (
        ("assigned_object", "@interface"),
        ("status", "status"),
        ("vrf", "vrf"),
    ),
    "plugins/bgp/session": (
        ("device", "device"),
        ("local_as", "asn"),
        ("remote_address", "ip-address"),
        ("remote_as", "asn"),
        ("status", "status"),
    ),
    "interface": (("device", "device"),),
    "termination": (("object", "@interface"),),
}


def _dump_id(obj):
    """An object's integer ID, or None (a bool is not an ID)."""
    v = obj.get("id") if isinstance(obj, dict) else None
    return v if type(v) is int else None


def _dump_name(nested, default="-") -> str:
    """The ``name`` a nested object carries, or ``default`` (B-71: names come
    from the nested objects, never from an ID)."""
    if isinstance(nested, dict):
        name = _text(nested.get("name"))
        if name:
            return name
    return default


def _dump_status(obj) -> str:
    """An object's status value as the export writes it (B-64 to B-67)."""
    status = obj.get("status")
    return _text(status.get("value")) if isinstance(status, dict) else ""


def _dump_side(terms) -> str:
    """One side of a cable as §6.1 names it: ``<device>:<interface>`` for an
    interface; any other termination is its type, then its device and name,
    or a circuit's cid and termination side, where the nested object has them."""
    if not isinstance(terms, list) or not terms or not isinstance(terms[0], dict):
        return "-"
    t = terms[0]
    otype = _text(t.get("object_type")) or "-"
    obj = t.get("object") if isinstance(t.get("object"), dict) else {}
    if otype == DUMP_INTERFACE_TYPE:
        return f"{_dump_name(obj.get('device'))}:{_dump_name(obj)}"
    parts = [otype]
    circuit = obj.get("circuit")
    if isinstance(circuit, dict):
        parts += [p for p in (_text(circuit.get("cid")), _text(obj.get("term_side"))) if p]
    else:
        parts += [p for p in (_dump_name(obj.get("device"), ""), _dump_name(obj, "")) if p]
    return " ".join(parts)


def _dump_peer(sess) -> str:
    """A session's remote address: the address part of the nested
    ``remote_address.address``, never resolved (B-72)."""
    ra = sess.get("remote_address")
    if not isinstance(ra, dict):
        return ""
    return _text(ra.get("address")).split("/")[0]


def _dump_is_ipv6(text: str) -> bool:
    try:
        return ipaddress.ip_interface(text).version == 6
    except ValueError:
        return False


def _dump_key_problem(obj: dict, row: str, path: str = ""):
    """The first key problem in ``obj`` against its row's two lists, and in
    each nested object the reader reads into (B-47): an unknown key (this
    object's keys in sorted order first, then its nested objects in key
    order), or a nested value that is not an object. None if there is none."""
    reads, knows = DUMP_KEY_LISTS[row]
    for key in sorted(obj):
        if key not in reads and key not in knows:
            return (
                f"unknown key '{path}{key}' (not among the keys the reader "
                f"reads or knows for NetBox 4.6.8 with netbox-bgp 0.19.0)"
            )
    for key, sub in _DUMP_NESTED.get(row, ()):
        value = obj.get(key)
        if value is None:
            continue
        where = f"{path}{key}"
        if sub == "[termination]":
            if not isinstance(value, list) or not all(isinstance(t, dict) for t in value):
                return f"'{where}' must be a list of termination objects"
            for k, term in enumerate(value):
                problem = _dump_key_problem(term, "termination", f"{where}[{k}].")
                if problem:
                    return problem
            continue
        if not isinstance(value, dict):
            return f"'{where}' must be an object or null (got {json.dumps(value)})"
        if sub == "@interface":
            type_key = "object_type" if row == "termination" else "assigned_object_type"
            if obj.get(type_key) == DUMP_INTERFACE_TYPE:
                problem = _dump_key_problem(value, "interface", where + ".")
                if not problem and not isinstance(value.get("device"), dict):
                    problem = f"'{where}.device' must be an object"
            elif row == "termination":
                problem = None  # 46-S4-R2: the object is not key-checked ...
                for k2, sub2 in (("circuit", "circuit"), ("device", "device")):
                    v2 = value.get(k2)  # ... beyond its device and circuit
                    if v2 is None:
                        continue
                    if not isinstance(v2, dict):
                        problem = f"'{where}.{k2}' must be an object or null"
                    else:
                        problem = _dump_key_problem(v2, sub2, f"{where}.{k2}.")
                    if problem:
                        break
            else:
                problem = None  # an address not on an interface is not read (B-44)
        else:
            problem = _dump_key_problem(value, sub, where + ".")
        if problem:
            return problem
    return None


class _BundleLocator:
    """The reader's locator table (§4.6 §13): for each contract entry, the
    endpoint file and ``<endpoint> object id <id> (<name>)`` of the bundle
    object it was built from (a link: its cable; a static route: its device)."""

    def __init__(self, files: dict, origin: dict):
        self.files = files    # "manifest" or an endpoint -> its file's path
        self.origin = origin  # contract list -> [(file, object text)] by position

    def whole(self) -> tuple:
        return (self.files["manifest"], "")

    def section(self, key: str) -> tuple:
        endpoint = {
            "devices": "dcim/devices", "static_routes": "dcim/devices",
            "cables": "dcim/cables", "bgp_sessions": "plugins/bgp/session",
        }.get(key)
        if endpoint is None:
            return (self.files["manifest"], "manifest")
        return (self.files[endpoint], endpoint)

    def item(self, key: str, i: int) -> tuple:
        return self.origin[key][i]

    def device(self, i: int) -> tuple:
        return self.origin["devices"][i]

    def cable(self, i: int) -> tuple:
        return self.origin["cables"][i]

    def cable_end(self, i: int, side: str) -> tuple:
        file, obj = self.origin["cables"][i]
        return (file, f"{obj} end '{side}'")

    def session(self, i: int, peer: bool = True) -> tuple:
        return self.origin["bgp_sessions"][i]

    def route(self, i: int) -> tuple:
        return self.origin["static_routes"][i]


class NetBoxDumpBackend(NetBoxBackend):
    """The ``netbox-dump`` backend (§4.6 REQ-46-35): an offline reader of a
    NetBox bundle, which builds the contract in memory and hands it, with its
    locator table, to the contract backend's build path (§13)."""

    name = "netbox-dump"

    # ---- (i) load checks, on every object (B-49, B-36 to B-38, B-47, B-40) - #

    def _where(self, endpoint: str, obj: dict) -> tuple:
        """``<endpoint> object id <id> (<name>)`` in that endpoint's file, where
        ``<name>`` is §6.1's object text built from names (46-S5-R1): a
        device's name; a cable as ``<a><-><b>``; an IP address as
        ``<device>:<interface> <address>``; a session as ``<L> -> <X>``; ``-``
        for a missing part. A session's NetBox ``name`` is not read."""
        oid = obj.get("id") if isinstance(obj, dict) else None
        return (self.files[endpoint], f"{endpoint} object id {oid} ({self._label(endpoint, obj)})")

    def _label(self, endpoint: str, obj: dict) -> str:
        if endpoint == "dcim/devices":
            return _dump_name(obj)
        if endpoint == "dcim/cables":
            return f"{_dump_side(obj.get('a_terminations'))}<->{_dump_side(obj.get('b_terminations'))}"
        if endpoint == "ipam/ip-addresses":
            ao = obj.get("assigned_object") if isinstance(obj.get("assigned_object"), dict) else {}
            return f"{_dump_name(ao.get('device'))}:{_dump_name(ao)} {_text(obj.get('address')) or '-'}"
        return f"{_dump_name(obj.get('device'))} -> {_dump_peer(obj) or '-'}"

    def _load_manifest(self, source_dir: Path) -> dict:
        path = source_dir / DUMP_MANIFEST_FILENAME
        self.files = {"manifest": str(path)}
        if not path.is_file():
            if (source_dir / self.EXPORT_FILENAME).is_file():  # B-49 (S-10)
                _reject(
                    (str(source_dir), ""),
                    "the 'netbox' backend expects netbox_export.json and the "
                    "'netbox-dump' backend expects manifest.json; the selected "
                    f"backend '{self.name}' found no manifest.json here, and "
                    "netbox_export.json is present",
                    "Select the backend that matches the layout",
                )
            _reject(  # B-36
                (str(path), ""),
                "the bundle has no manifest (required keys: "
                f"{', '.join(DUMP_MANIFEST_KEYS)})",
                "Add the manifest the capture writes",
            )
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            _reject((str(path), ""), f"not valid JSON ({exc})", "Capture the bundle again")
        if not isinstance(manifest, dict):
            _reject((str(path), ""), "the manifest must be a JSON object", "Capture the bundle again")
        where = (str(path), "manifest")
        proven = "Capture the export at the proven versions"
        unknown = sorted(k for k in manifest if k not in DUMP_MANIFEST_KEYS)
        missing = [k for k in DUMP_MANIFEST_KEYS if k not in manifest]
        if unknown:  # B-37
            _reject(where, f"unknown key '{unknown[0]}' (allowed: "
                    f"{', '.join(DUMP_MANIFEST_KEYS)}); {DUMP_PROVEN_TEXT}", proven)
        if missing:
            _reject(where, f"key '{missing[0]}' is missing; {DUMP_PROVEN_TEXT}", proven)
        if type(manifest["format"]) is not int or manifest["format"] != 1:
            _reject(where, f"format {json.dumps(manifest['format'])} is not 1; "
                    f"{DUMP_PROVEN_TEXT}", proven)
        version = manifest["netbox_version"]
        if version != DUMP_PROVEN_VERSION:
            shown = f"'{version}'" if isinstance(version, str) else json.dumps(version)
            _reject(where, f"netbox_version {shown} is not in the proven set; "
                    f"{DUMP_PROVEN_TEXT}", proven)
        if manifest["plugins"] != DUMP_PROVEN_PLUGINS:
            _reject(where, f"plugins {json.dumps(manifest['plugins'], sort_keys=True)} "
                    f"is not the proven set; {DUMP_PROVEN_TEXT}", proven)
        site = manifest["site"]
        if not isinstance(site, str) or not site.strip():
            _reject(where, "'site' must be a non-empty site slug", "Correct the manifest")
        endpoints = manifest["endpoints"]
        if (
            not isinstance(endpoints, dict)
            or sorted(endpoints) != sorted(DUMP_ENDPOINTS)
            or not all(
                isinstance(f, str) and f not in ("", ".", "..")
                and "/" not in f and "\\" not in f
                for f in endpoints.values()
            )
        ):
            _reject(
                where,
                "'endpoints' must map each of " + ", ".join(DUMP_ENDPOINTS)
                + " to a file name in the bundle",
                "Correct the manifest",
            )
        schema = manifest["schema"]
        if (
            not isinstance(schema, dict)
            or sorted(schema) != list(DUMP_SCHEMA_KEYS)
            or schema.get("source") not in DUMP_SCHEMA_SOURCES
        ):
            _reject(
                where,
                "'schema' must carry file, sha256 and source (source "
                + " or ".join(f"'{s}'" for s in DUMP_SCHEMA_SOURCES) + ")",
                "Correct the manifest",
            )
        return manifest

    def _load_bundle(self, source_dir: Path) -> tuple[dict, dict]:
        """B-49, B-36 to B-38, B-47, B-40, in that order (B-68 step (i))."""
        manifest = self._load_manifest(source_dir)
        data = {}
        for endpoint in DUMP_ENDPOINTS:  # D-5: the code's fixed order
            path = source_dir / manifest["endpoints"][endpoint]
            self.files[endpoint] = str(path)
            where = (str(path), "")
            if not path.is_file():
                _reject(where, f"the manifest names this file for {endpoint}, "
                        f"and it is missing", "Capture the bundle again")
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                _reject(where, f"not valid JSON ({exc})", "Capture the bundle again")
            if not isinstance(items, list) or not all(isinstance(o, dict) for o in items):
                _reject(where, f"must be a JSON list of {endpoint} objects",
                        "Capture the bundle again")
            data[endpoint] = items
        for endpoint in DUMP_ENDPOINTS:  # B-47
            for obj in data[endpoint]:
                problem = _dump_key_problem(obj, endpoint)
                if problem:
                    _reject(self._where(endpoint, obj), problem, DUMP_RECAPTURE)
        for endpoint in DUMP_ENDPOINTS:  # B-40: IDs, status
            seen: dict = {}
            for obj in data[endpoint]:
                oid = _dump_id(obj)
                if oid is None:
                    _reject(self._where(endpoint, obj), f"'id' must be an integer "
                            f"(got {_value_text(obj, 'id')})", DUMP_RECAPTURE)
                if oid in seen:
                    _reject(self._where(endpoint, obj),
                            f"'id' {oid} is also carried by {seen[oid]}; an "
                            f"export carries each id once", "Capture the bundle again")
                seen[oid] = f"{endpoint} object ({self._label(endpoint, obj)})"
                status = obj.get("status")
                if not isinstance(status, dict) or not isinstance(status.get("value"), str):
                    _reject(self._where(endpoint, obj), "'status' must be an object "
                            "with a 'value'", DUMP_RECAPTURE)
        carried: dict = {}  # interface ID -> (device name, name, the object's text)
        for endpoint, objs in (("dcim/cables", data["dcim/cables"]),
                               ("ipam/ip-addresses", data["ipam/ip-addresses"])):
            for obj in objs:
                if endpoint == "dcim/cables":
                    ifaces = [
                        t["object"] for side in ("a_terminations", "b_terminations")
                        for t in (obj.get(side) or [])
                        if t.get("object_type") == DUMP_INTERFACE_TYPE
                    ]
                elif obj.get("assigned_object_type") == DUMP_INTERFACE_TYPE and \
                        isinstance(obj.get("assigned_object"), dict):
                    ifaces = [obj["assigned_object"]]
                else:
                    ifaces = []
                for iface in ifaces:
                    iid = _dump_id(iface)
                    pair = (_dump_name(iface.get("device")), _dump_name(iface))
                    if iid in carried and carried[iid][:2] != pair:
                        first = carried[iid]
                        _reject(
                            self._where(endpoint, obj),
                            f"interface id {iid} is carried as {pair[0]}:{pair[1]} "
                            f"here and as {first[0]}:{first[1]} by {first[2]}",
                            "Capture the bundle again",
                        )
                    carried.setdefault(iid, pair + (self._where(endpoint, obj)[1],))
        for obj in data["dcim/devices"]:  # B-40, R-3
            if "local_context_data" not in obj:
                _reject(self._where("dcim/devices", obj), "'local_context_data' is "
                        "missing; the capture must request it", "Capture the bundle again")
            lcd = obj["local_context_data"]
            if lcd is not None and not isinstance(lcd, dict):
                _reject(self._where("dcim/devices", obj), "'local_context_data' must be "
                        f"null or an object (got {json.dumps(lcd)})", DUMP_FIX_IN_NETBOX)
        return manifest, data

    # ---- (ii) the filter (B-64 to B-67, B-43 to B-45, B-71) ------------------ #

    def _filter(self, data: dict) -> dict:
        """Exclude and name what is out of scope, each object with the first
        reason in D-19's precedence for its kind, in the order devices, cables,
        IP addresses, sessions (B-68 step (ii)). Returns the kept objects."""
        out = self.filtered = []
        devices = {_dump_id(d): d for d in data["dcim/devices"]}
        gone: dict = {}  # excluded device ID -> (name, reason)
        kept_devices = []
        for d in data["dcim/devices"]:
            name = _dump_name(d)
            status = _dump_status(d)
            if status != DUMP_IN_SERVICE["dcim/devices"]:  # B-64
                reason = f"status {status or '-'} is not active"
                out.append(("device", name, name, reason))
                gone[_dump_id(d)] = (name, reason)
            else:
                kept_devices.append(d)

        def placed(nested):
            """B-71 and B-64 for an object pointing at ``nested``: the
            reason, or None if its device is kept."""
            did = _dump_id(nested)
            name = _dump_name(nested)
            if did not in devices:
                return f"device {name} is not in this site's bundle"
            if did in gone:
                return f"device {_text(devices[did].get('name'))} is excluded"
            return None

        kept_cables = []
        carried = set()  # (device, interface) on a kept cable
        for c in data["dcim/cables"]:
            terms = [
                t for side in ("a_terminations", "b_terminations")
                for t in (c.get(side) or [])
            ]
            objs = [t.get("object") if isinstance(t.get("object"), dict) else {} for t in terms]
            reason = None
            for rule in ("outside", "excluded"):
                for obj in objs:
                    if not isinstance(obj.get("device"), dict):
                        continue
                    r = placed(obj["device"])
                    if r and r.endswith("bundle") == (rule == "outside"):
                        reason = r
                        break
                if reason:
                    break
            status = _dump_status(c)
            if not reason and status != DUMP_IN_SERVICE["dcim/cables"]:  # B-65
                reason = f"status {status or '-'} is not connected"
            if not reason:  # B-43
                for t in terms:
                    if t.get("object_type") != DUMP_INTERFACE_TYPE:
                        reason = (f"termination {_text(t.get('object_type')) or '-'} "
                                  f"is not an interface; links connect interfaces")
                        break
            side_a = _dump_side(c.get("a_terminations"))
            side_b = _dump_side(c.get("b_terminations"))
            if reason:
                device = ""
                for side in ("a_terminations", "b_terminations"):
                    first = (c.get(side) or [None])[0]
                    obj = first.get("object") if isinstance(first, dict) else None
                    if isinstance(obj, dict) and isinstance(obj.get("device"), dict):
                        device = _dump_name(obj["device"])
                        break
                out.append(("cable", device, f"{side_a} <-> {side_b}", reason))
                continue
            kept_cables.append(c)
            for obj in objs:
                carried.add((_text(devices[_dump_id(obj["device"])].get("name")), _dump_name(obj)))

        kept_ips = []
        set_aside: dict = {}  # (device, interface) -> [(address, reason)] by B-66/-67
        for ip in data["ipam/ip-addresses"]:
            ao = ip.get("assigned_object")
            if ip.get("assigned_object_type") != DUMP_INTERFACE_TYPE or not isinstance(ao, dict):
                continue  # not read for links (B-44)
            address = _text(ip.get("address"))
            device = _dump_name(ao.get("device"))
            iface = _dump_name(ao)
            reason = placed(ao["device"])
            if not reason and _dump_id(ao["device"]) in devices:
                device = _text(devices[_dump_id(ao["device"])].get("name"))
            status = _dump_status(ip)
            by_filter = None
            if not reason and status != DUMP_IN_SERVICE["ipam/ip-addresses"]:  # B-66
                reason = by_filter = f"status {status or '-'} is not active"
            if not reason and ip.get("vrf") is not None:  # B-67
                reason = by_filter = (f"in VRF {_dump_name(ip['vrf'])}; the importer "
                                      f"models the global table only")
            if not reason and _dump_is_ipv6(address):  # B-44
                reason = "IPv6 address; the importer reads IPv4 link addresses only"
            if not reason and (device, iface) not in carried:
                reason = "interface is on no imported link, so no link carries the address"
            if reason:
                out.append(("ip-address", device, f"{device}:{iface} {address}", reason))
                if by_filter:
                    set_aside.setdefault((device, iface), []).append((address, by_filter))
                continue
            kept_ips.append(ip)

        kept_sessions = []
        for s in data["plugins/bgp/session"]:
            local = _dump_name(s.get("device"))
            peer = _dump_peer(s) or "-"
            reason = placed(s["device"]) if isinstance(s.get("device"), dict) else None
            status = _dump_status(s)
            if not reason and status != DUMP_IN_SERVICE["plugins/bgp/session"]:  # B-45
                reason = f"status {status or '-'} is not active"
            if not reason and _dump_is_ipv6(peer):
                reason = "IPv6 peer; the importer reads IPv4 sessions only"
            if reason:
                out.append(("bgp-session", local, f"{local} -> {peer}", reason))
                continue
            kept_sessions.append(s)

        return {
            "devices": devices, "gone": gone, "dcim/devices": kept_devices,
            "dcim/cables": kept_cables, "ipam/ip-addresses": kept_ips,
            "plugins/bgp/session": kept_sessions, "set_aside": set_aside,
        }

    # ---- (iii) checks on kept objects; (iv) the contract -------------------- #

    def _contract(self, manifest: dict, kept: dict) -> tuple[dict, _BundleLocator]:
        """B-41, B-42, B-51, B-46, B-43, B-44, B-70, B-45 and B-50 on the kept
        objects (B-68 step (iii)), then the contract, sorted by names (B-52)."""
        devices = kept["devices"]
        site = manifest["site"].strip()
        names: dict = {}
        for d in kept["dcim/devices"]:  # B-41
            name = _text(d.get("name"))
            if name and name in names:
                _reject(self._where("dcim/devices", d), f"device name '{name}' is also "
                        f"object id {_dump_id(names[name])}'s; device names must be "
                        f"unique", DUMP_FIX_IN_NETBOX)
            names[name] = d
        ifaces: dict = {}  # (device, interface) -> interface ID
        for endpoint in ("dcim/cables", "ipam/ip-addresses"):
            for obj in kept[endpoint]:
                if endpoint == "dcim/cables":
                    objs = [t["object"] for side in ("a_terminations", "b_terminations")
                            for t in (obj.get(side) or [])]
                else:
                    objs = [obj["assigned_object"]]
                for iface in objs:
                    key = (devices[_dump_id(iface["device"])].get("name"), _dump_name(iface))
                    iid = _dump_id(iface)
                    if key in ifaces and ifaces[key] != iid:
                        _reject(self._where(endpoint, obj), f"device {key[0]} has two "
                                f"interfaces named {key[1]} (interface ids "
                                f"{ifaces[key]} and {iid})", DUMP_FIX_IN_NETBOX)
                    ifaces[key] = iid
        for d in sorted(kept["dcim/devices"], key=lambda o: _text(o.get("name"))):
            where = self._where("dcim/devices", d)
            platform = d.get("platform")
            slug = _text(platform.get("slug")).lower() if isinstance(platform, dict) else ""
            if slug not in DUMP_PLATFORM_TYPES:  # B-42, the shipped message
                _reject(where, f"platform '{slug}' unsupported (allowed: "
                        f"{', '.join(SUPPORTED_PLATFORMS)})", "Correct the export")
        for d in sorted(kept["dcim/devices"], key=lambda o: _text(o.get("name"))):
            dsite = d.get("site")
            slug = _text(dsite.get("slug")) if isinstance(dsite, dict) else ""
            if slug != site:  # B-51
                _reject(self._where("dcim/devices", d), f"site '{slug or '-'}' differs "
                        f"from the manifest's site '{site}'",
                        "Capture the site that holds the device, or correct its site in NetBox")
        cassian: dict = {}
        for d in sorted(kept["dcim/devices"], key=lambda o: _text(o.get("name"))):
            cassian[_dump_id(d)] = self._cassian(d)  # B-46
        for c in kept["dcim/cables"]:  # B-43, two-termination test
            for side in ("a", "b"):
                n = len(c.get(side + "_terminations") or [])
                if n != 1:
                    _reject(self._where("dcim/cables", c), f"side {side} has {n} "
                            f"terminations; a link needs exactly one interface on "
                            f"each side", DUMP_FIX_IN_NETBOX)
        addresses: dict = {}  # (device, interface) -> (address, the object)
        for ip in kept["ipam/ip-addresses"]:  # B-44, two-address test
            ao = ip["assigned_object"]
            key = (devices[_dump_id(ao["device"])].get("name"), _dump_name(ao))
            if key in addresses:
                _reject(self._where("ipam/ip-addresses", ip), f"interface "
                        f"{key[0]}:{key[1]} carries two addresses the filter keeps "
                        f"({addresses[key][0]} and {_text(ip.get('address'))}); a "
                        f"link end takes one", "Keep one address on the interface "
                        "in service in NetBox")
            addresses[key] = (_text(ip.get("address")), ip)
        ends: dict = {}
        for c in kept["dcim/cables"]:
            pair = []
            for side in ("a_terminations", "b_terminations"):
                obj = c[side][0]["object"]
                pair.append((devices[_dump_id(obj["device"])].get("name"), _dump_name(obj)))
            ends[_dump_id(c)] = pair
            has = [p in addresses for p in pair]
            if has[0] != has[1]:  # B-70
                bare = pair[1] if has[0] else pair[0]
                aside = kept["set_aside"].get(bare)
                if aside:
                    address, reason = sorted(aside)[0]
                    _reject(
                        self._where("dcim/cables", c),
                        f"the filter excluded the address {address} on "
                        f"{bare[0]}:{bare[1]} ({reason}), so the link keeps one "
                        f"address; a link needs both addresses or neither",
                        "Bring both addresses into service in the global table, or neither",
                    )
        local_as: dict = {}  # device -> (asn, the session)
        for s in sorted(kept["plugins/bgp/session"],
                        key=lambda o: (_dump_name(o.get("device")), _dump_peer(o))):
            where = self._where("plugins/bgp/session", s)
            if not isinstance(s.get("device"), dict):  # B-45
                _reject(where, "'device' is missing; a session needs its device",
                        DUMP_FIX_IN_NETBOX)
            if not _dump_peer(s):
                _reject(where, "'remote_address' is missing; a session needs its "
                        "peer's address", DUMP_FIX_IN_NETBOX)
            name = devices[_dump_id(s["device"])].get("name")
            las = s.get("local_as")
            if not isinstance(las, dict):
                continue
            asn = las.get("asn")
            if type(asn) is not int:
                _reject(where, f"'local_as.asn' must be an integer (got "
                        f"{_value_text(las, 'asn')})", DUMP_FIX_IN_NETBOX)
            if name in local_as and local_as[name][0] != asn:
                other = local_as[name][1]
                _reject(where, f"local_as {asn} disagrees with local_as "
                        f"{local_as[name][0]} of {self._where('plugins/bgp/session', other)[1]};"
                        f" device {name}'s asn is the local_as its sessions agree on",
                        DUMP_FIX_IN_NETBOX)
            local_as.setdefault(name, (asn, s))
        if kept["devices"] and not kept["dcim/devices"]:  # B-50, filtered
            first = sorted(kept["gone"].values())[0]
            _reject(
                (self.files["dcim/devices"], "dcim/devices"),
                f"no device is in service after the filter ({len(kept['gone'])} "
                f"excluded; the first by name, '{first[0]}': {first[1]})",
                "Set the devices' NetBox status to active, or capture the site that holds them",
            )

        # (iv) The contract, every list sorted by names (B-52).
        origin: dict = {"devices": [], "cables": [], "bgp_sessions": [], "static_routes": []}
        contract: dict = {"site": {"name": site}, "devices": [], "cables": [],
                          "bgp_sessions": [], "static_routes": []}
        routes = []
        for d in sorted(kept["dcim/devices"], key=lambda o: _text(o.get("name"))):
            name = _text(d.get("name"))
            entry = {"name": name, "platform": DUMP_PLATFORM_TYPES[
                _text(d["platform"].get("slug")).lower()]}
            if name in local_as:
                entry["asn"] = local_as[name][0]
            rid, prefixes = cassian[_dump_id(d)]
            if rid is not None:
                entry["router_id"] = rid
            contract["devices"].append(entry)
            origin["devices"].append(self._where("dcim/devices", d))
            for k, prefix in prefixes:
                file, obj = self._where("dcim/devices", d)
                routes.append(((name, prefix), {"device": name, "prefix": prefix},
                               (file, f"{obj} local_context_data.cassian.static_routes[{k}]")))
        for _key, entry, where in sorted(routes, key=lambda r: r[0]):
            contract["static_routes"].append(entry)
            origin["static_routes"].append(where)
        cables = []
        for c in kept["dcim/cables"]:
            (ad, ai), (bd, bi) = ends[_dump_id(c)]
            entry = {"a": {"device": ad, "interface": ai}, "b": {"device": bd, "interface": bi}}
            for key, end in (("a_ip", (ad, ai)), ("b_ip", (bd, bi))):
                if end in addresses:
                    entry[key] = addresses[end][0]
            cables.append(((f"{ad}:{ai}", f"{bd}:{bi}"), entry, self._where("dcim/cables", c)))
        for _key, entry, where in sorted(cables, key=lambda r: r[0]):
            contract["cables"].append(entry)
            origin["cables"].append(where)
        sessions = []
        for s in kept["plugins/bgp/session"]:
            local = _text(devices[_dump_id(s["device"])].get("name"))
            entry = {"local_device": local, "peer_ip": _dump_peer(s)}
            ras = s.get("remote_as")
            if isinstance(ras, dict) and "asn" in ras:
                entry["remote_asn"] = ras["asn"]
            sessions.append(((local, entry["peer_ip"]), entry,
                             self._where("plugins/bgp/session", s)))
        for _key, entry, where in sorted(sessions, key=lambda r: r[0]):
            contract["bgp_sessions"].append(entry)
            origin["bgp_sessions"].append(where)
        return contract, _BundleLocator(self.files, origin)

    def _cassian(self, d: dict) -> tuple:
        """B-46 on a kept device: ``local_context_data.cassian`` only, with
        ``router_id`` and ``static_routes`` (entries ``{prefix}``) inside it;
        null local_context_data reads as ``cassian`` absent (R-3). Returns
        ``(router_id or None, [(position, prefix)])``."""
        where = self._where("dcim/devices", d)
        lcd = d.get("local_context_data")
        if lcd is None or "cassian" not in lcd:
            return None, []
        cas = lcd["cassian"]
        file, obj = where
        at = (file, f"{obj} local_context_data.cassian")
        allowed = ("(allowed: router_id, static_routes; a static_routes entry "
                   "allows prefix only). Cassian Gate checks only that a declared "
                   "route is present, not its next hop")
        if not isinstance(cas, dict):
            _reject(at, f"must be an object (got {json.dumps(cas)})", DUMP_FIX_IN_NETBOX)
        unknown = sorted(k for k in cas if k not in DUMP_CASSIAN_KEYS)
        if unknown:
            _reject((file, obj), f"local_context_data.cassian: unknown key "
                    f"'{unknown[0]}' {allowed}", "Remove the key")
        rid = cas.get("router_id")
        if "router_id" in cas:
            try:
                ipaddress.IPv4Address(rid if isinstance(rid, str) else "")
            except ValueError:
                _reject(at, f"'router_id' must be an IPv4 address (got "
                        f"{json.dumps(rid)})", DUMP_FIX_IN_NETBOX)
        routes = cas.get("static_routes", [])
        if not isinstance(routes, list):
            _reject(at, "'static_routes' must be a list of {prefix} entries",
                    DUMP_FIX_IN_NETBOX)
        out = []
        seen: dict = {}
        for k, entry in enumerate(routes):
            if not isinstance(entry, dict):
                _reject(at, f"static_routes[{k}] must be an object with 'prefix'",
                        DUMP_FIX_IN_NETBOX)
            extra = sorted(x for x in entry if x != "prefix")
            if extra:
                _reject((file, obj), f"local_context_data.cassian.static_routes[{k}]: "
                        f"unknown key '{extra[0]}' {allowed}", "Remove the key")
            if "prefix" not in entry:
                _reject(at, f"static_routes[{k}]: 'prefix' is missing; a static "
                        f"route needs its prefix", DUMP_FIX_IN_NETBOX)
            prefix = _text(entry["prefix"])
            if prefix in seen:
                _reject(at, f"prefix '{prefix}' is declared more than once "
                        f"(static_routes[{seen[prefix]}] and [{k}])", "Remove the duplicate")
            seen[prefix] = k
            out.append((k, prefix))
        return (rid if isinstance(rid, str) else None), out

    # ---- produce ----------------------------------------------------------- #

    def produce(self, source_dir: Path) -> tuple[dict, list]:
        manifest, data = self._load_bundle(source_dir)
        kept = self._filter(data)
        contract, loc = self._contract(manifest, kept)
        rendered = self._parse_rendered_configs(source_dir)
        topo, invariants = self._build(
            contract, rendered, loc, source_dir / self.RENDERED_SUBDIR
        )
        # The build path names what direction A excluded; the filter's
        # exclusions join them in the same list (§13; B-25).
        self.exclusions = self.filtered + self.exclusions
        return topo, invariants


# Backend registry. Adding a backend = one entry; no consumer change (IF-1).
BACKENDS = {
    NetBoxBackend.name: NetBoxBackend,
    NetBoxDumpBackend.name: NetBoxDumpBackend,
}


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
