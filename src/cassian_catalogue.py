"""Capability catalogue for `cassian checks` (Stage-1 gap item (d)(2), WI-1).

Builds the `checks.v1` catalogue (provisional shape) from the installed code each
time `cassian checks` runs, and renders it as canonical JSON bytes or as the
fixed-layout human summary. Handover v9-rev3 sections 6.1, 6.6, 7 and 8 define
every key, rule and message used here.

What is read from code (derived): the node-type axis and each provider's
`runtime_requirement`, capability declarations and exec rule; the invariant
types; the builtin invariant packs and the pack rule; the live CLI parser; the
release version, which `cmd_checks` injects.

What is written here by hand (declared, proof-bound; see `PROVENANCE`): the
parameter lists, the effect-label table, the status-class table with the
vm-gated mirror, the limitation note and the two notices. Named proofs hold each
declared part to the code.

Imports: the model and the provider types, plus `cassian_common.die` for the
construction-failure exit. No AI module, no runtime adapter, not the engine.
The parser and the release version arrive by injection. This module reads no
file, writes no file, starts no process and opens no socket.
"""

from __future__ import annotations

import argparse
import copy
import json

import cassian_common
import cassian_model
import cassian_nos_types

# ---------------------------------------------------------------------------
# Markers (derived: module constants) and notices (declared)
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "checks.v1"
PROVISIONAL = True

NOTICES = (
    # N1
    "Status values report what this release's code implements for each check "
    "on each node type. This catalogue makes no NOS-support declaration and is "
    "not a qualification claim.",
    # N2
    "The shape of this catalogue is provisional: no stability promise is made "
    "for it, and later releases may change it.",
)

# ---------------------------------------------------------------------------
# Provenance block (handover section 7.6), emitted exactly as written
# ---------------------------------------------------------------------------

PROVENANCE = {
    "declared_proof_bound": [
        "checks.limitations",
        "checks.parameters",
        "commands.effects",
        "commands.exception",
        "notices",
        "status_classes",
    ],
    "derived_from_code": [
        "checks.id",
        "checks.kind",
        "checks.status",
        "commands.command",
        "gate_release",
        "node_types",
        "profiles",
        "provisional",
        "schema_version",
    ],
}

# ---------------------------------------------------------------------------
# Check universe and status classes (declared, proof-bound)
# ---------------------------------------------------------------------------

# Mirror of the engine's test-kind literal. The checks are these kinds minus
# "invariant", plus the model's invariant types.
KIND_MIRROR = ("ping", "tcp", "bgp_neighbor", "route_prefix", "invariant", "exec")

# Mirror of the model's validate-time gate tuple for vm-runtime nodes. On a node
# type whose runtime_requirement is "vm", a check whose kind is listed here is
# decided by the provider's capability declaration.
VM_GATED = ("tcp", "bgp_neighbor", "invariant", "route_prefix")

# Which code site decides a check's status. Every check not listed is "seam":
# decided by capability_for(provider, check id). Seam is never listed by hand.
STATUS_CLASSES = {
    "core": ("interface_state", "ping", "tcp"),
    "exec": ("exec",),
}

# Declared limitation notes, per check, in declared order.
LIMITATIONS = {
    "interface_state": (
        "On a container-runtime node, the engine first checks that the node's "
        "iproute2 can emit JSON (`ip -j link show lo`); if it cannot, the test "
        "records a fixed error instead of an observation.",
    ),
}

# ---------------------------------------------------------------------------
# Parameter lists (declared, proof-bound)
# ---------------------------------------------------------------------------
# Per check: the unknown-key policy, the parameters and the cross-key
# constraints. A parameter is
#     (name, types, aliases, values, required, enforced)
# and a constraint is
#     (operator, params, when, enforced)
# where `when` is None or (param, equals, type), the unused one None.
# Every list is sorted when the catalogue is built.

_EXPECT = ("expect", ("enum",), (), ("fail", "pass"), False, "validate")
_TAGS = ("tags", ("string_list",), (), None, False, "validate")
_NODE = ("node", ("node",), (), None, True, "validate")
_NODE_SRC = ("node", ("node",), ("src",), None, True, "validate")
_PREFIX = ("prefix", ("cidr",), (), None, True, "validate")
_PEER = ("peer", ("node",), (), None, True, "validate")
_MAC = ("mac", ("mac",), (), None, True, "validate")
_VNI = ("vni", ("integer",), (), None, True, "validate")
_RETRY_RUN = ("retry_interval_s", ("number",), (), None, False, "run")
_TIMEOUT_RUN = ("timeout_s", ("integer",), (), None, False, "run")

CHECK_PARAMETERS = {
    "ping": {
        "unknown_keys": "accepted",
        "params": (
            ("count", ("integer",), (), None, False, "validate"),
            ("dst", ("ip", "node"), (), None, False, "validate"),
            _EXPECT,
            ("per_attempt_timeout_s", ("integer",), (), None, False, "run"),
            _RETRY_RUN,
            ("src", ("node",), ("from", "on"), None, True, "validate"),
            ("src_if", ("string",), (), None, False, "run"),
            ("src_ip", ("ip",), (), None, False, "run"),
            _TAGS,
            _TIMEOUT_RUN,
            ("to", ("ip",), (), None, False, "validate"),
            ("to_ip", ("ip",), (), None, False, "validate"),
        ),
        "constraints": (
            ("exactly_one_of", ("dst", "to", "to_ip"), None, "validate"),
            ("forbidden_if", ("retry_interval_s", "timeout_s"), ("expect", "fail", None), "validate"),
            ("at_most_one_of", ("src_if", "src_ip"), None, "run"),
        ),
    },
    "tcp": {
        "unknown_keys": "accepted",
        "params": (
            ("dst", ("node",), ("to",), None, True, "run"),
            _EXPECT,
            ("listener", ("boolean",), (), None, False, "validate"),
            ("port", ("integer",), (), None, True, "run"),
            _RETRY_RUN,
            ("src", ("node",), ("from", "on"), None, True, "run"),
            _TAGS,
            _TIMEOUT_RUN,
        ),
        "constraints": (),
    },
    "bgp_neighbor": {
        "unknown_keys": "accepted",
        "params": (
            ("dst", ("ipv4",), ("neighbor", "to"), None, True, "run"),
            _EXPECT,
            _RETRY_RUN,
            ("src", ("node",), ("from", "on"), None, True, "run"),
            _TAGS,
            _TIMEOUT_RUN,
        ),
        "constraints": (),
    },
    "route_prefix": {
        "unknown_keys": "accepted",
        "params": (
            _EXPECT,
            _PREFIX,
            ("src", ("node",), ("on",), None, True, "validate"),
            _TAGS,
        ),
        "constraints": (),
    },
    "exec": {
        "unknown_keys": "rejected",
        "params": (
            ("assertion", ("exec_assertion",), (), None, True, "validate"),
            ("command", ("string",), (), None, True, "validate"),
            _EXPECT,
            ("src", ("node",), ("from", "node", "on"), None, True, "validate"),
            _TAGS,
        ),
        "constraints": (),
    },
    "bgp_as_path": {
        "unknown_keys": "accepted",
        "params": (
            ("as_path", ("as_path_regex",), (), None, True, "validate"),
            _EXPECT,
            _NODE,
            _PREFIX,
            _TAGS,
        ),
        "constraints": (),
    },
    "bgp_community": {
        "unknown_keys": "accepted",
        "params": (
            _EXPECT,
            ("expected", ("community", "community_list"), (), None, True, "validate"),
            ("match", ("enum",), (), ("all", "any"), False, "validate"),
            _NODE,
            _PREFIX,
            _TAGS,
        ),
        "constraints": (
            ("required_iff", ("match",), ("expected", None, "community_list"), "validate"),
        ),
    },
    "bgp_localpref_equals": {
        "unknown_keys": "accepted",
        "params": (
            _EXPECT,
            ("expected", ("integer",), (), None, True, "validate"),
            _NODE,
            _PREFIX,
            _TAGS,
        ),
        "constraints": (),
    },
    "bgp_med_equals": {
        "unknown_keys": "accepted",
        "params": (
            _EXPECT,
            ("expected", ("integer",), (), None, True, "validate"),
            _NODE_SRC,
            _PREFIX,
            _TAGS,
        ),
        "constraints": (),
    },
    "bgp_session_up": {
        "unknown_keys": "accepted",
        "params": (
            ("dst", ("ipv4",), ("neighbor",), None, True, "run"),
            _EXPECT,
            _NODE_SRC,
            _RETRY_RUN,
            _TAGS,
            _TIMEOUT_RUN,
        ),
        "constraints": (),
    },
    "evpn_bgp_session_up": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE_SRC, _PEER, _TAGS),
        "constraints": (),
    },
    "evpn_mac_route_absent": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _MAC, _NODE_SRC, _TAGS, _VNI),
        "constraints": (),
    },
    "evpn_mac_route_present": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _MAC, _NODE_SRC, _TAGS, _VNI),
        "constraints": (),
    },
    "evpn_vni_route_present": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE_SRC, _TAGS, _VNI),
        "constraints": (),
    },
    "interface_state": {
        "unknown_keys": "rejected",
        "params": (
            _EXPECT,
            ("interface", ("string",), (), None, True, "validate"),
            _NODE,
            ("retry_interval_s", ("number",), (), None, False, "validate"),
            ("state", ("enum",), (), ("down", "up"), False, "validate"),
            ("timeout_s", ("integer",), (), None, False, "validate"),
        ),
        "constraints": (),
    },
    "ospf_neighbor_up": {
        "unknown_keys": "accepted",
        "params": (
            _EXPECT,
            ("neighbor", ("ipv4",), (), None, True, "validate"),
            _NODE_SRC,
            _RETRY_RUN,
            ("state", ("enum",), (),
             ("2-Way", "Attempt", "Down", "ExStart", "Exchange", "Full", "Init", "Loading"),
             False, "validate"),
            _TAGS,
            _TIMEOUT_RUN,
        ),
        "constraints": (),
    },
    "route_absent": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE_SRC, _PREFIX, _TAGS),
        "constraints": (),
    },
    "route_advertised_to": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE, _PEER, _PREFIX, _TAGS),
        "constraints": (),
    },
    "route_not_advertised_to": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE, _PEER, _PREFIX, _TAGS),
        "constraints": (),
    },
    "route_present": {
        "unknown_keys": "accepted",
        "params": (_EXPECT, _NODE_SRC, _PREFIX, _TAGS),
        "constraints": (),
    },
}

# ---------------------------------------------------------------------------
# Effect labels (declared, proof-bound): handover sections 5.3 and 7.5
# ---------------------------------------------------------------------------

# The five labels, in emission order.
LABEL_ORDER = ("read-only", "lab-mutating", "destructive", "authoritative", "advisory")
# Labels that combine with no other label.
EXCLUSIVE_LABELS = ("read-only", "advisory")
# The only commands that may carry the exception marker.
EXCEPTION_COMMANDS = ("ai", "import")

# Per runnable command path: a tuple of (label, reason) pairs, or, for the
# exception marker, the exception's reason as a string.
COMMAND_LABELS = {
    "adapt ansible": (
        ("advisory", "writes adapter output files (default artifacts/adapters/)"),
    ),
    "adapt terraform": (
        ("advisory", "writes adapter output files (default artifacts/adapters/)"),
    ),
    "ai": (
        "writes no file; with --online, sends the question and an evidence "
        "package to an AI endpoint, which no effect label covers"
    ),
    "checks": (
        ("read-only", "prints this catalogue; writes nothing"),
    ),
    "cleanup": (
        ("destructive", "with --yes, destroys Cassian-owned labs found under labs/"),
    ),
    "collect": (
        ("advisory", "writes collected lab evidence under labs/clab-<lab>/artifacts/"),
    ),
    "destroy": (
        ("destructive", "destroys a lab runtime; with --purge-artifacts, deletes its artifacts"),
    ),
    "doctor": (
        ("read-only", "reports environment readiness; writes nothing"),
    ),
    "down": (
        ("destructive", "destroys a deployed lab's runtime"),
    ),
    "exec": (
        ("lab-mutating", "runs a command inside a lab node"),
    ),
    "gen": (
        ("lab-mutating", "rewrites in place the config files a deployed lab of the same name bind-mounts"),
    ),
    "import": "writes an authoritative declaration pair to a path the caller names",
    "preflight": (
        ("advisory", "writes a preflight report (default artifacts/preflight/preflight.json)"),
    ),
    "replay": (
        ("lab-mutating", "deploys a lab from prior artifacts"),
        ("destructive", "replaces an existing lab of the same derived replay name (reconfigure)"),
        ("authoritative", "with --gate, runs test's gate path (cmd_test, _report_authority gate)"),
    ),
    "run": (
        ("lab-mutating", "builds, tests and tears down a lab"),
        ("destructive", "with --reconfigure, destroys the existing lab first"),
    ),
    "status": (
        ("read-only", "reads lab state with show commands; writes nothing"),
    ),
    "test": (
        ("lab-mutating", "deploys and tears down a clean lab"),
        ("destructive", "replaces an existing lab of the same name (reconfigure)"),
        ("authoritative", "produces the deploy/no-deploy verdict"),
    ),
    "up": (
        ("lab-mutating", "deploys a lab"),
        ("destructive", "with --reconfigure, destroys the existing lab first"),
    ),
    "validate": (
        ("advisory", "writes a coverage file under labs/"),
    ),
    "validate-contrib": (
        ("read-only", "structural check of contrib content; writes nothing"),
    ),
    "vty": (
        ("lab-mutating", "runs a vty command inside a lab node"),
    ),
}

_STATE_IMPLEMENTED = "implemented"
_STATE_NOT_IMPLEMENTED = "not implemented"


# ---------------------------------------------------------------------------
# Construction failure (handover section 9; LD-S1D2-1)
# ---------------------------------------------------------------------------

def _fail(message: str) -> None:
    """Stop the build: message on stderr, nothing on stdout, exit 1."""
    cassian_common.die(f"ERROR: checks: {message}", code=1)


def _blank(text: object) -> bool:
    return not isinstance(text, str) or not text.strip()


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _check_universe() -> list[tuple[str, str]]:
    """(check id, kind) for every check, sorted by id; each id once."""
    pairs = [(k, k) for k in KIND_MIRROR if k != "invariant"]
    pairs += [(t, "invariant") for t in cassian_model._INVARIANT_TYPES]
    seen: set[str] = set()
    for cid, _kind in sorted(pairs):
        if cid in seen:
            _fail(
                f"check '{cid}' is named more than once among the test kinds and "
                f"invariant types; each check ID must be unique, so rename one"
            )
        seen.add(cid)
    return sorted(pairs)


def _class_of(universe_ids: set[str]) -> dict[str, str]:
    """Map each check to its status class; E8 on overlap or a non-check member."""
    names = sorted(STATUS_CLASSES)
    for cls in names:
        for cid in sorted(STATUS_CLASSES[cls]):
            if cid not in universe_ids:
                _fail(f"status class '{cls}' names '{cid}', which is not a check")
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            for cid in sorted(set(STATUS_CLASSES[a]) & set(STATUS_CLASSES[b])):
                _fail(f"check '{cid}' is in status classes {a} and {b}")
    out = {cid: "seam" for cid in universe_ids}
    for cls in names:
        for cid in STATUS_CLASSES[cls]:
            out[cid] = cls
    return out


def _implemented(detail: str | None = None) -> dict:
    return {"state": _STATE_IMPLEMENTED, "reason": None, "detail": detail}


def _not_implemented(reason: str) -> dict:
    return {"state": _STATE_NOT_IMPLEMENTED, "reason": reason, "detail": None}


def _seam_cell(cid: str, ntype: str, provider) -> dict:
    """B03: the provider's capability declaration decides."""
    d = cassian_nos_types.capability_for(provider, cid)
    if d.state == cassian_nos_types.CAP_IMPL:
        return _implemented()
    if _blank(d.message):
        _fail(
            f"node type '{ntype}' declares '{cid}' as {d.state} with no message, so the "
            f"catalogue has no reason to give for 'not implemented'; the change that "
            f"introduces this declaration must decide how the catalogue reports it (give "
            f"the declaration a message, or change the catalogue's rule for {d.state} in "
            f"src/cassian_catalogue.py and regenerate the golden)"
        )
    return _not_implemented(d.message)


def _exec_cell(ntype: str, provider) -> dict:
    """B04: implemented iff the provider's exec rule is wired."""
    if not cassian_nos_types.is_deferred(provider.exec_command_rule):
        return _implemented(provider.exec_allowed_forms)
    return _not_implemented(cassian_model._exec_command_allowed("x", ntype)[1])


def _status_cell(cid: str, kind: str, cls: str, ntype: str, provider) -> dict:
    """B03 to B06 for one check on one node type."""
    if cls == "exec":
        return _exec_cell(ntype, provider)
    if provider.runtime_requirement == "vm" and kind in VM_GATED:
        return _seam_cell(cid, ntype, provider)
    if cls == "core":
        return _implemented()
    return _seam_cell(cid, ntype, provider)


def _param_entry(p: tuple) -> dict:
    name, types, aliases, values, required, enforced = p
    return {
        "name": name,
        "aliases": sorted(aliases),
        "types": sorted(types),
        "values": sorted(values) if values is not None else None,
        "required": required,
        "enforced": enforced,
    }


def _constraint_entry(c: tuple) -> dict:
    operator, params, when, enforced = c
    if when is not None:
        param, equals, vtype = when
        when = {"param": param, "equals": equals, "type": vtype}
    return {
        "operator": operator,
        "params": sorted(params),
        "when": when,
        "enforced": enforced,
    }


def _parameters(cid: str) -> dict:
    spec = CHECK_PARAMETERS.get(cid)
    if spec is None:
        _fail(
            f"check '{cid}' has no parameter entry; add one to the parameter table in "
            f"src/cassian_catalogue.py and regenerate the golden "
            f"(scripts/regenerate_checks_catalogue.py)"
        )
    params = sorted((_param_entry(p) for p in spec["params"]), key=lambda e: e["name"])
    constraints = sorted(
        (_constraint_entry(c) for c in spec["constraints"]),
        key=lambda e: (e["operator"], e["params"]),
    )
    return {
        "unknown_keys": spec["unknown_keys"],
        "params": params,
        "constraints": constraints,
    }


def _stale_entries(universe_ids: set[str]) -> None:
    """A declared entry for an ID that is not a check fails the build."""
    for table, keys in (("limitation", LIMITATIONS), ("parameter", CHECK_PARAMETERS)):
        for cid in sorted(keys):
            if cid not in universe_ids:
                _fail(
                    f"the {table} table names '{cid}', which is not a check; remove the "
                    f"entry and regenerate the golden"
                )


def _node_types() -> list[dict]:
    """B07: the provider registry's types, in nos_known_types() order."""
    return [
        {"type": t, "runtime_requirement": cassian_model.NOS_PROVIDERS[t].runtime_requirement}
        for t in cassian_model.nos_known_types()
    ]


def _checks(node_types: list[dict]) -> list[dict]:
    universe = _check_universe()
    ids = {cid for cid, _kind in universe}
    classes = _class_of(ids)
    _stale_entries(ids)
    out = []
    for cid, kind in universe:
        parameters = _parameters(cid)
        status = {}
        for nt in node_types:
            ntype = nt["type"]
            provider = cassian_model.NOS_PROVIDERS[ntype]
            status[ntype] = _status_cell(cid, kind, classes[cid], ntype, provider)
        out.append({
            "id": cid,
            "kind": kind,
            "parameters": parameters,
            "status": status,
            "limitations": list(LIMITATIONS.get(cid, ())),
        })
    return out


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

def _profiles() -> list[dict]:
    """B08: each builtin pack whose member types are all in the model's pack type set."""
    pack_types = cassian_model.supported_pack_invariant_types
    out = []
    for pid in sorted(cassian_model.builtin_invariant_packs):
        pack = cassian_model.builtin_invariant_packs[pid]
        invariants = pack.get("invariants") if isinstance(pack, dict) else None
        if not isinstance(invariants, list):
            continue
        if not all(isinstance(inv, dict) and inv.get("type") in pack_types for inv in invariants):
            continue
        out.append({"id": pid, "versioned": False, "content": copy.deepcopy(pack)})
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _runnable_leaves(parser: argparse.ArgumentParser) -> list[str]:
    """B10: every parser reached through subparsers whose defaults carry func."""
    leaves: list[str] = []

    def walk(p: argparse.ArgumentParser, prefix: tuple[str, ...]) -> None:
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    path = prefix + (name,)
                    if child.get_default("func") is not None:
                        leaves.append(" ".join(path))
                    walk(child, path)

    walk(parser, ())
    return sorted(set(leaves))


def _command_entry(path: str, entry) -> dict:
    """Check one label-table entry (E3 to E7) and return its catalogue form."""
    if isinstance(entry, str):
        if path not in EXCEPTION_COMMANDS:
            _fail(f"command '{path}' carries the exception marker; only 'import' and 'ai' may")
        if _blank(entry):
            _fail(f"command '{path}' has no reason for 'exception'")
        return {"command": path, "effects": None, "exception": entry}
    pairs = list(entry)
    if not pairs:
        _fail(
            f"command '{path}' has an empty effect-label set; only 'import' and 'ai' "
            f"carry the exception marker"
        )
    for label, _reason in pairs:
        if label not in LABEL_ORDER:
            _fail(
                f"command '{path}' carries '{label}', which is not one of: "
                f"{', '.join(LABEL_ORDER)}"
            )
    labels = sorted({label for label, _reason in pairs}, key=LABEL_ORDER.index)
    for a in [x for x in labels if x in EXCLUSIVE_LABELS]:
        others = [x for x in labels if x != a]
        if others:
            _fail(
                f"command '{path}' combines '{a}' with '{others[0]}'; read-only and "
                f"advisory never combine with each other or with lab-mutating, "
                f"destructive or authoritative"
            )
    ordered = sorted(pairs, key=lambda pr: LABEL_ORDER.index(pr[0]))
    for label, reason in ordered:
        if _blank(reason):
            _fail(f"command '{path}' has no reason for '{label}'")
    return {
        "command": path,
        "effects": [{"label": label, "reason": reason} for label, reason in ordered],
        "exception": None,
    }


def _commands(parser: argparse.ArgumentParser) -> list[dict]:
    """B10: the label table must name exactly the parser's runnable leaves."""
    leaves = set(_runnable_leaves(parser))
    out = []
    for path in sorted(leaves | set(COMMAND_LABELS)):
        if path not in COMMAND_LABELS:
            _fail(
                f"command '{path}' has no effect-label entry; add one to the label table "
                f"in src/cassian_catalogue.py and regenerate the golden "
                f"(scripts/regenerate_checks_catalogue.py)"
            )
        if path not in leaves:
            _fail(
                f"the label table names '{path}', which the CLI parser does not register; "
                f"remove the entry and regenerate the golden"
            )
        out.append(_command_entry(path, COMMAND_LABELS[path]))
    return out


# ---------------------------------------------------------------------------
# Build and render
# ---------------------------------------------------------------------------

def build_catalogue(parser: argparse.ArgumentParser, *, release_version: str) -> dict:
    """Build the whole catalogue in memory, or stop with a construction failure."""
    node_types = _node_types()
    checks = _checks(node_types)
    profiles = _profiles()
    commands = _commands(parser)
    return {
        "schema_version": SCHEMA_VERSION,
        "gate_release": release_version,
        "provisional": PROVISIONAL,
        "notices": list(NOTICES),
        "provenance": copy.deepcopy(PROVENANCE),
        "node_types": node_types,
        "checks": checks,
        "profiles": profiles,
        "commands": commands,
    }


def render_json(catalogue: dict) -> bytes:
    """Canonical bytes under write_json_canonical's frozen policy."""
    s = json.dumps(catalogue, indent=2, sort_keys=True, ensure_ascii=False)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.rstrip("\n") + "\n"
    return s.encode("utf-8")


def render_text(catalogue: dict) -> bytes:
    """The fixed-layout human summary (handover section 6.1)."""
    type_names = [nt["type"] for nt in catalogue["node_types"]]

    def types_or_none(names: list[str]) -> str:
        return ", ".join(names) if names else "none"

    node_parts = []
    for nt in catalogue["node_types"]:
        rr = nt["runtime_requirement"]
        node_parts.append(nt["type"] if rr is None else f"{nt['type']} (runtime {rr})")

    checks = catalogue["checks"]
    w1 = max((len(c["id"]) for c in checks), default=0) + 2
    w2 = max((len(c["kind"]) for c in checks), default=0) + 2
    commands = catalogue["commands"]
    w3 = max((len(c["command"]) for c in commands), default=0) + 2

    lines = [
        f"Cassian Gate capability catalogue ({catalogue['schema_version']}, provisional shape), "
        f"release {catalogue['gate_release']}",
        catalogue["notices"][0],
        "",
        "Node types: " + ", ".join(node_parts),
        "",
        f"Checks ({len(checks)}):",
    ]
    for c in checks:
        done = [t for t in type_names if c["status"][t]["state"] == _STATE_IMPLEMENTED]
        not_done = [t for t in type_names if c["status"][t]["state"] != _STATE_IMPLEMENTED]
        lines.append(
            f"  {c['id'].ljust(w1)}{c['kind'].ljust(w2)}"
            f"implemented: {types_or_none(done)} | not implemented: {types_or_none(not_done)}"
        )
    lines.append("")
    profiles = catalogue["profiles"]
    lines.append(f"Profiles ({len(profiles)}):")
    for p in profiles:
        lines.append(f"  {p['id']} (unversioned, {len(p['content']['invariants'])} invariants)")
    lines.append("")
    lines.append(f"Commands ({len(commands)}):")
    for c in commands:
        if c["exception"] is not None:
            tail = f"exception: {c['exception']}"
        else:
            tail = ", ".join(e["label"] for e in c["effects"])
        lines.append(f"  {c['command'].ljust(w3)}{tail}")
    lines.append("")
    lines.append("Parameters, reasons and label reasons: cassian checks --json")
    return ("\n".join(lines) + "\n").encode("utf-8")
