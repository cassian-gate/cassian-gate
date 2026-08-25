"""SONiC NOS provider (Phase 2 §4.5-c, REQ-45C-1; design §3.3).

Carries SONiC's NOS content behind the provider contract: identity, capability
declarations, and the lifecycle legs the ratified design assigns to SONiC by
name -- `gen_node_config`, `provision`, `nos_ready`, `convergence_wait`
(`nos-expansion-structure-design-RATIFIED.md:228, :240`). Core owns invariants,
predicate evaluation, verdicts, rendering, and artifacts (design §5); this
module never decides pass/fail and never writes an artifact.

Import floor: stdlib + the types leaf only. `cassian_common` is NOT imported --
no concrete shared value is needed here. Never engine, model, or
runtime_container. The loud-failure idiom below mirrors
`cassian_nos_types.deferred_leg` (`:102-109`): a stderr write plus
`SystemExit(2)`, so no core import is required to fail §13-grade.

SERIALIZATION IS CORE-OWNED. `gen_node_config` returns a filename -> content
mapping and writes nothing. `cassian_model` serializes the returned
`config_db.json` through `write_json_canonical` (PBE-P2-7; REQ-45C-20/-42).
The ratified design is explicit: "Providers return observations, never write
`results.json`; all authoritative results continue through core's
`write_json_canonical`. The provider contract structurally forbids artifact
authoring" (design `:254`).

HALT-1 NOTE -- FRR's deferral markers are PROVIDER-SCOPED, not contract-scoped.
`cassian_nos_frr.py:1608-1611` binds `gen_node_config` / `provision` /
`nos_ready` / `convergence_wait` to `deferred_leg(..., "4.5-d/-f")`. Those
placeholders bind FRR ONLY. SONiC implementing the same legs here is the
ratified design's own assignment (`nos-expansion-structure-design-RATIFIED.md:240`),
not an encroachment. A reader seeing FRR's "§4.5-d/-f" markers beside a SONiC
implementation of the same leg is not looking at a contradiction.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
import sys
import time
from typing import TYPE_CHECKING, Any, Mapping

from cassian_nos_types import (
    CapabilityDisposition,
    NosProvider,
    deferred_leg,
    impl,
)

if TYPE_CHECKING:  # annotation-only (no runtime import of the runtime leaf)
    from cassian_runtime_container import Runtime


SONIC_NODE_TYPE = "sonic-vm"

# Contrib-owned local tag (REQ-45C-11/-31: no registry pull; built by
# contrib/sonic-image-build/build.sh). Registry-derived by the model's
# `hard_defaults` chain via `nos_default_image` (`cassian_model.py:1821-1823`).
SONIC_DEFAULT_IMAGE = "local/sonic-vm:202405"


# -------------------------
# Platform port map (REQ-45C-5; founder ruling 2026-08-17)
# -------------------------
# Topologies declare container interface names (`eth1`, `eth2`, ...). SONiC's
# ConfigDB keys its ports by platform port name (`Ethernet0`, `Ethernet4`, ...).
# vrnetlab attaches container interfaces to guest data ports POSITIONALLY:
# `eth{N}` lands on the N-th data port in the platform's own index order.
#
# MEASURED, not assumed (sonic-vm:202405, 2026-08-17): with only `s1:eth1`
# wired, `Ethernet0` was the sole port reporting `Oper: up`; the guest's PORT
# table carries a 0-based `index` field aligned with numeric port-name order
# (Ethernet0 -> 0, Ethernet4 -> 1, ... Ethernet124 -> 31).
#
# THE TABLE IS A CROSS-CHECK, NOT THE MAPPING SOURCE (R-C3-13). The mapping is
# DERIVED from the guest's own PORT table by `derive_port_order` below --
# measured evidence beats an inferred table (Doctrine §1.7). This table is
# retained as a drift witness only.
#
# COVERAGE LIMIT (PBE-P2-8), stated rather than implied:
#   * `_cross_check_port_map` is LOUD when a LISTED HwSKU's derived order
#     differs from this table -- that means the image changed under a map this
#     module still records. It is SILENT on an unlisted HwSKU: derivation is
#     authoritative, so an unrecognised platform is supported, not refused.
#   * Neither derivation nor the cross-check verifies vrnetlab's positional
#     attachment contract -- that `eth{N}` reaches the N-th port is settled by
#     the REQ-45C-5 provisioning proof (declare a non-stock address, read it
#     back from the expected port), not here.
#   * F-45C-C3-21: derivation assumes `index` is UNIQUE per port. Measured
#     unique and contiguous 0..31 on Force10-S6000 (sonic-vm:202405, verified
#     through the exec channel 2026-08-18). Platforms with breakout ports may
#     repeat `index` across sub-ports; that is ambiguous for positional mapping
#     and fails loud below rather than picking arbitrarily. NOT verifiable on
#     the supported image -- no breakout-capable platform is in the set.
#   * Port speed is deliberately not asserted: sonic-vm:202405 reports
#     UINT32_MAX on the virtual link (F-45C-C3-6).
_SONIC_PORT_MAPS: dict[str, tuple[str, ...]] = {
    # Force10-S6000: 32 x 40G, four lanes per port, hence a stride of four.
    "Force10-S6000": tuple(f"Ethernet{i * 4}" for i in range(32)),
}

_ETH_IFACE_RE = re.compile(r"^eth(\d+)$")


def _fail(summary: str, node: str, reason: str, detail: str, required: str) -> None:
    """§13-grade loud failure, exit 2. Mirrors `deferred_leg`'s idiom so the
    provider needs no core import to fail deterministically."""
    sys.stderr.write(
        f"ERROR: {summary}\n"
        f"node: {node}\n"
        f"reason: {reason}\n"
        f"detail: {detail}\n"
        f"required: {required}\n"
    )
    raise SystemExit(2)


def derive_port_order(port_table: dict, node: str) -> tuple[str, ...]:
    """Derive the platform's positional port order from the guest's PORT table.

    R-C3-13: the mapping is MEASURED from the device, never inferred from a
    static table (Doctrine §1.7 -- behavioural evidence over inferred
    evidence). Ports are ordered by the platform's own `index`; `eth{N}` maps
    to position N-1. Ordering is index-base-independent, so a 1-based platform
    orders identically to a 0-based one.

    Fails loud (never guesses) when the table is empty, when `index` is absent
    or non-integer, or when `index` REPEATS -- see F-45C-C3-21 above.
    """
    if not isinstance(port_table, dict) or not port_table:
        _fail(
            "SONiC guest reported no ports",
            node,
            "the guest PORT table is empty or unreadable",
            "the positional eth<N> mapping is derived from the guest's own "
            "PORT table; without it Cassian cannot name a single interface",
            "confirm the guest booted and that ConfigDB carries a PORT table",
        )

    indexed: list[tuple[int, str]] = []
    for pname, row in port_table.items():
        raw = row.get("index") if isinstance(row, dict) else None
        try:
            idx = int(raw)
        except (TypeError, ValueError):
            _fail(
                "SONiC port carries no usable index",
                node,
                f"port {pname!r} has index {raw!r}, which is not an integer",
                "positional mapping orders ports by the platform's own index; "
                "an unusable index makes the order undefined",
                "report this with the guest's PORT table; the image may not be "
                "a supported SONiC build",
            )
        indexed.append((idx, pname))

    seen: dict[int, str] = {}
    for idx, pname in indexed:
        if idx in seen:
            _fail(
                "SONiC port index is ambiguous",
                node,
                f"index {idx} is reported by both {seen[idx]!r} and {pname!r}",
                "a repeated index makes positional eth<N> mapping ambiguous; "
                "Cassian will not pick one arbitrarily (F-45C-C3-21). Breakout "
                "platforms are outside the measured coverage of this leg",
                "declare interfaces by explicit port name, or use a platform "
                "whose PORT table carries one index per port",
            )
        seen[idx] = pname

    return tuple(pname for _, pname in sorted(indexed))


def _cross_check_port_map(hwsku: str, derived: tuple[str, ...], node: str) -> None:
    """Cross-check the derived order against the recorded map, where recorded.

    LOUD on a listed HwSKU whose derived order differs -- the image changed
    under a map this module still records, and silently adapting would hide it
    (Doctrine §1.11). SILENT on an unlisted HwSKU: derivation is authoritative
    (R-C3-13), so an unrecognised platform is supported rather than refused.
    """
    recorded = _SONIC_PORT_MAPS.get(hwsku)
    if recorded is None:
        return
    if tuple(derived) != tuple(recorded):
        _fail(
            "SONiC derived port order does not match the recorded map",
            node,
            f"HwSKU {hwsku!r} is recorded, but the guest's derived order differs",
            f"recorded[0:3]={tuple(recorded)[0:3]} derived[0:3]={tuple(derived)[0:3]}; "
            f"recorded {len(recorded)} ports, guest reports {len(derived)}",
            "the image changed under the recorded map; update _SONIC_PORT_MAPS "
            "in src/cassian_nos_sonic.py, or pin the image it was measured against",
        )


def sonic_port_for_iface(iface: str, ports: tuple[str, ...], node: str) -> str:
    """Map a topology container interface (`eth{N}`) to its SONiC port name.

    `ports` is the DERIVED order from `derive_port_order` (R-C3-13), not a
    table lookup. Pure: every input is an argument, so REQ-45C-20's determinism
    property is checkable without a runtime.
    """
    m = _ETH_IFACE_RE.match(str(iface).strip())
    if not m:
        _fail(
            "SONiC interface declaration not recognized",
            node,
            f"interface {iface!r} is not of the form 'eth<N>'",
            "sonic-vm data interfaces are declared as eth1, eth2, ... and are "
            "mapped positionally onto the platform's data ports",
            "declare link endpoints on this node as '<node>:eth<N>' with N >= 1",
        )
    n = int(m.group(1))
    if n < 1 or n > len(ports):
        _fail(
            "SONiC interface out of range",
            node,
            f"interface {iface!r} has no corresponding data port",
            f"this platform exposes {len(ports)} data ports "
            f"(eth1 .. eth{len(ports)})",
            f"declare an interface within eth1 .. eth{len(ports)}",
        )
    return ports[n - 1]


# -------------------------
# Capabilities (design §3.4 -- deny-by-default)
# -------------------------
# §4.5-c declares only what it implements. Every undeclared token resolves to a
# generated UNSUP via `capability_for` -- nothing is implicitly supported.
# Invariant-kind and operational tokens land at §4.5-d/-e.
_SONIC_CAPABILITIES: dict[str, CapabilityDisposition] = {
    "gen_node_config": impl(),
    "provision": impl(),
}


# -------------------------
# Config generation (REQ-45C-1, -5, -20, -44a)
# -------------------------

_PLATFORM_OWNED = ("PORT", "hwsku", "platform", "mac")


def _links_for_node(node_name: str, topo: dict) -> list[tuple[str, str]]:
    """Return [(iface, ip_cidr)] for this node, in declaration order.

    Deliberately re-derived from `topo["links"]` rather than importing the
    model's `build_node_links` -- provider -> model is forbidden (design §3.2).
    """
    out: list[tuple[str, str]] = []
    for link in topo.get("links") or []:
        if not isinstance(link, dict):
            continue
        eps = link.get("endpoints") or []
        ips = link.get("ipv4") or []
        if len(eps) != 2 or len(ips) != 2:
            continue
        for ep, ip in zip(eps, ips):
            if not isinstance(ep, str) or ":" not in ep:
                continue
            name, iface = ep.split(":", 1)
            if name == node_name:
                out.append((iface, str(ip)))
    return out


def _bgp_link_ips_for_node(node_name: str, topo: dict) -> dict[str, tuple[str, str]]:
    """Return {peer_node_name: (local_ip, peer_ip)} for this node's links.

    Deliberately re-derived from `topo["links"]` rather than importing the
    model's `build_node_links` -- provider -> model is forbidden (design §3.2)
    and `cassian_common` is outside §14.4's approved paths. Founder ruling
    2026-08-24. Semantics match that helper: the address with its prefix length
    stripped, and the FIRST declaration winning, which is the FRR leg's
    break-on-first-match over `node_links`. Cross-NOS parity is proven, not
    co-located (BL-P2-4.5c-54).
    """
    out: dict[str, tuple[str, str]] = {}
    for link in topo.get("links") or []:
        if not isinstance(link, dict):
            continue
        eps = link.get("endpoints") or []
        ips = link.get("ipv4") or []
        if len(eps) != 2 or len(ips) != 2:
            continue
        ends: list[tuple[str, str]] = []
        for ep, ip in zip(eps, ips):
            if not isinstance(ep, str) or ":" not in ep:
                break
            ends.append((ep.split(":", 1)[0], str(ip).split("/")[0]))
        if len(ends) != 2:
            continue
        (n1, ip1), (n2, ip2) = ends
        if n1 == node_name:
            out.setdefault(n2, (ip1, ip2))
        if n2 == node_name:
            out.setdefault(n1, (ip2, ip1))
    return out


def gen_node_config(
    node: dict, topo: dict, facts: "Mapping[str, Any] | None" = None
) -> "dict[str, Any] | None":
    """Generate the SONiC `config_db.json` OVERLAY for one node (LD-45C-2).

    Returns {"config_db.json": <overlay>} -- a filename -> content mapping.
    WRITES NOTHING: core serializes through `write_json_canonical`
    (REQ-45C-20/-42; design §:254).

    Routing-neutral baseline (REQ-45C-1): hostname, interfaces, loopback --
    rendered for every node, and the ONLY tables a node that declares no BGP
    receives. REQ-45C-2 core adds DEVICE_METADATA.localhost.bgp_asn and
    BGP_NEIGHBOR when the node declares `asn` / `bgp.neighbors`. REQ-45C-2's
    `networks` clause and REQ-45C-3 do NOT land here -- neither has a measured
    rendering target on sonic-vm:202405.

    Overlay discipline (REQ-45C-44a): carries ONLY Cassian-declared tables and
    NEVER authors `PORT`, `hwsku`, `platform` or `mac` -- those originate in the
    image's init_cfg.json and vary per platform.
    """
    name = str(node.get("name") or "").strip()
    if not name:
        _fail(
            "SONiC node declaration invalid",
            "<unnamed>",
            "node has no name",
            "every topology node requires a name",
            "add a 'name' to this node declaration",
        )

    ports = facts.get("port_order") if isinstance(facts, dict) else None
    if not ports:
        _fail(
            "SONiC generation requires observed device facts",
            name,
            "no derived port order was supplied to gen_node_config",
            "R-C3-13: interface naming is derived from the guest's own PORT "
            "table, so generation runs after boot with observed facts passed "
            "in. Generation never probes; it is a pure function of arguments",
            "call gen_node_config from provision, which probes the guest and "
            "supplies facts={'hwsku': ..., 'port_order': (...)}",
        )
    ports = tuple(ports)

    overlay: dict[str, Any] = {
        "DEVICE_METADATA": {"localhost": {"hostname": name}},
    }

    interfaces: dict[str, dict] = {}
    for iface, ip_cidr in _links_for_node(name, topo):
        port = sonic_port_for_iface(iface, ports, name)
        interfaces.setdefault(port, {})
        interfaces[f"{port}|{ip_cidr}"] = {}
    if interfaces:
        overlay["INTERFACE"] = interfaces

    rid = node.get("router_id")
    rid = str(rid).strip() if rid is not None else ""
    if rid:
        overlay["LOOPBACK_INTERFACE"] = {
            "Loopback0": {},
            f"Loopback0|{rid}/32": {},
        }

    # REQ-45C-2 core: declared `asn` and `bgp.neighbors` render here. The
    # targets are MEASURED on sonic-vm:202405 build fecd4ec81 -- `BGP_GLOBALS`
    # does not exist on this image; the ASN lives in
    # DEVICE_METADATA.localhost.bgp_asn and neighbours in BGP_NEIGHBOR keyed by
    # peer IP with string values. `networks` and `route_maps` are NOT rendered
    # here: neither has a measured target on this image, and both are carved to
    # a founder-reserved question (route-maps: BL-P2-4.5c-55).
    asn_raw = node.get("asn")
    if asn_raw is not None:
        try:
            asn_text = str(int(asn_raw))
        except (TypeError, ValueError):
            asn_text = ""
        if not asn_text:
            _fail(
                "SONiC BGP generation requires an integer ASN",
                name,
                f"declared 'asn' is not an integer: {asn_raw!r}",
                "DEVICE_METADATA.localhost.bgp_asn is a string field on this "
                "image, but its value must be a decimal AS number",
                "set an integer 'asn' on this node, or remove the key",
            )
        overlay["DEVICE_METADATA"]["localhost"]["bgp_asn"] = asn_text

    bgp = node.get("bgp") if isinstance(node.get("bgp"), dict) else {}
    declared = bgp.get("neighbors") if isinstance(bgp.get("neighbors"), list) else []
    link_ips = _bgp_link_ips_for_node(name, topo)
    peers: dict[str, dict] = {}
    for nbr in declared:
        if not isinstance(nbr, dict):
            continue
        peer_name = str(nbr.get("peer") or "").strip()
        if not peer_name or peer_name not in link_ips:
            continue
        try:
            remote_as = str(int(nbr.get("remote_as")))
        except (TypeError, ValueError):
            continue
        local_ip, peer_ip = link_ips[peer_name]
        # Only declaration-derived fields are authored. The image's own
        # holdtime/keepalive/nhopself/rrclient defaults are left to the image
        # -- the declaration surface carries no such keys (REQ-45C-23).
        peers[peer_ip] = {
            "asn": remote_as,
            "local_addr": local_ip,
            "name": peer_name,
        }
    if peers:
        overlay["BGP_NEIGHBOR"] = peers

    _assert_overlay_platform_clean(overlay, name)
    return {"config_db.json": overlay}


def _assert_overlay_platform_clean(overlay: dict, node: str) -> None:
    """REQ-45C-44(a): the overlay authors no platform-owned data.

    Enforced, not documentary -- a generation bug that reintroduces PORT/hwsku/
    platform/mac fails here rather than mutating the device.
    """
    if "PORT" in overlay:
        _fail(
            "SONiC overlay contract violation",
            node,
            "generated overlay contains a PORT table",
            "PORT carries hardware lane maps owned by the image "
            "(LD-45C-2); Cassian never authors it",
            "remove PORT from the generated overlay",
        )
    dm = overlay.get("DEVICE_METADATA", {})
    local = dm.get("localhost", {}) if isinstance(dm, dict) else {}
    for key in ("hwsku", "platform", "mac"):
        if isinstance(local, dict) and key in local:
            _fail(
                "SONiC overlay contract violation",
                node,
                f"generated overlay authors platform-owned key {key!r}",
                "hwsku/platform/mac originate in the image's init_cfg.json and "
                "vary per platform (LD-45C-2); Cassian never authors them",
                f"remove {key!r} from DEVICE_METADATA.localhost",
            )


# Guest-side staging path for the overlay. /tmp is tmpfs on the image, so the
# payload does not persist across a reboot -- consistent with LD-45C-2's
# no-persistence property (`/etc/sonic/config_db.json` is never rewritten).
_OVERLAY_GUEST_PATH = "/tmp/cassian-overlay.json"


def _guest_stdout(rt: "Runtime", lab: str, node: str, argv: list,
                  what: str) -> str:
    """Run a read command on the guest and return its STDOUT only.

    F-45C-C3-20: the guest's SSH banner (`/etc/issue.net`) lands on STDERR, and
    `VmRuntime.exec` passes rc/stdout/stderr through unrewritten (REQ-45a-1a),
    so stdout is clean. Concatenating stderr would reintroduce the banner and
    break every parse -- measured 2026-08-18, do not "fix" this by merging.
    """
    cp = rt.exec(lab, node, argv, check=False, capture_output=True)
    if getattr(cp, "returncode", 1) != 0:
        _fail(
            "SONiC guest probe failed",
            node,
            f"could not read {what} from the guest",
            f"command exited {getattr(cp, 'returncode', '?')}; the guest may "
            "not have finished booting, or is not a supported SONiC build",
            "confirm the node is running and retry; if it persists, report "
            "this with the node's boot log",
        )
    return cp.stdout or ""


# Single-sourced (PBE-P2-6): `nos_ready` asserts the very read `probe_facts`
# depends on, so the two must never drift into parallel literals.
_HWSKU_ARGV = ("sonic-cfggen", "-d", "-v", "DEVICE_METADATA.localhost.hwsku")

# REQ-45C-44(b) mode precondition. A SEPARATE single-sourced argv from
# _HWSKU_ARGV, deliberately: PBE-P2-6 single-sources `nos_ready`'s assertion
# with the read `probe_facts` depends on, and widening that literal to also
# carry the mode read would put two unrelated contracts on one string. The
# read is the measured form -- `-v "DEVICE_METADATA['localhost']"` returns a
# Python repr of the whole localhost mapping, verified on sonic-vm:202405
# 2026-08-24 (SONiC.202405.1033627-fecd4ec81):
#   {'bgp_asn': '65100', 'buffer_model': 'traditional', ..., 'type': 'LeafRouter'}
_DEVICE_METADATA_ARGV = ("sonic-cfggen", "-d", "-v", "DEVICE_METADATA['localhost']")

# The two keys that switch SONiC's BGP configuration source away from the
# tables Cassian writes. Named, not pattern-matched (Rule 14 -- enumerate the
# class). LD-45C-2 chose an OVERLAY to protect platform tables; an overlay is
# meaningless if the device is reading its routing configuration from
# somewhere else.
_FORBIDDEN_MODE_KEYS = ("docker_routing_config_mode", "frr_mgmt_framework_config")


def assert_routing_mode_clean(rt: "Runtime", lab: str, node: str) -> None:
    """REQ-45C-44(b): refuse to provision a guest in a non-default routing mode.

    Cassian's overlay writes BGP state into `config_db`. If the guest declares
    `docker_routing_config_mode` or `frr_mgmt_framework_config`, its routing
    configuration is sourced elsewhere and the overlay would be applied but not
    honoured -- silently. Deny-by-default: fail loud rather than provision into
    a mode whose semantics §4.5-c has not established.

    STATED COVERAGE LIMIT (PBE-P2-8): this asserts the keys are ABSENT. It does
    not establish what SONiC does when they are present -- that is unmeasured,
    and is why the disposition is refusal rather than adaptation.

    §4.5-c writes neither key anywhere (§15.2 negative row); this leg guards
    against a guest that arrived carrying one, not against Cassian setting it.
    """
    raw = _guest_stdout(
        rt, lab, node, list(_DEVICE_METADATA_ARGV),
        "the device metadata",
    )
    try:
        meta = ast.literal_eval(raw.strip() or "{}")
    except (ValueError, SyntaxError):
        _fail(
            "SONiC guest device metadata is not parseable",
            node,
            "the guest returned a DEVICE_METADATA payload that is not a "
            "Python literal",
            "the routing-mode precondition cannot be evaluated, and Cassian "
            "will not provision into an unverified mode",
            "report this with the guest's "
            "`" + " ".join(_DEVICE_METADATA_ARGV) + "` output",
        )
        return
    if not isinstance(meta, dict):
        _fail(
            "SONiC guest device metadata has an unexpected shape",
            node,
            "expected a mapping, got " + type(meta).__name__,
            "the routing-mode precondition cannot be evaluated",
            "report this with the guest's device metadata output",
        )
        return

    present = [k for k in _FORBIDDEN_MODE_KEYS if k in meta]
    if present:
        _fail(
            "SONiC guest is in an unsupported routing configuration mode",
            node,
            "DEVICE_METADATA.localhost carries " + ", ".join(present),
            "Cassian supplies BGP state as a config_db overlay; in this mode "
            "the guest sources its routing configuration elsewhere, so the "
            "overlay would be applied but not honoured",
            "use a guest image whose DEVICE_METADATA.localhost sets neither "
            + " nor ".join(_FORBIDDEN_MODE_KEYS),
        )


def nos_ready(rt: "Runtime", lab: str, node: str) -> None:
    """NOS-readiness leg (design :240 "control-plane responsive").

    SINGLE-SHOT, deliberately -- founder ruling 2026-08-20. Transport and
    substrate readiness are the runtime layer's and are already established
    before this leg runs: core gates vm-runtime provider nodes on
    `verify_sonic_vm_ready`, whose leg 2 polls to VM_GUEST_READY_TIMEOUT_S.
    Re-polling here would wait for something already waited for, and this
    provider is a leaf whose import floor admits neither `time` nor
    `cassian_runtime_vm` (sonic_leaf_import_proof P-SIMP-2).

    RATCHET, not a gap-closing assertion (R-C3-16, requirement (d)): measured
    across four cold boots of local/sonic-vm:202405 (2026-08-20), CONFIG_DB
    answered this read at the FIRST reachable sample every time, while SSH
    first answered at 23.0-27.6s. The leg exists to FAIL LOUDLY if that
    ordering ever ceases to hold -- silence must never read as success
    (Doctrine 1.11).

    COVERAGE LIMIT (PBE-P2-8): this asserts CONFIG_DB serves the provider's
    own read. It does NOT assert that swss, syncd, bgp or any other SONiC
    container is serving -- measured, those arrive up to ~90s later. Legs
    needing those conditions poll for them themselves (REQ-45C-8/-29 precheck;
    convergence_wait). It also does NOT bound waiting: a guest that never
    becomes reachable is caught by the runtime-layer gate, not here.
    """
    cp = rt.exec(lab, node, list(_HWSKU_ARGV), check=False, capture_output=True)
    if getattr(cp, "returncode", 1) == 0 and (cp.stdout or "").strip():
        return
    _fail(
        "SONiC control plane not ready",
        node,
        "the guest did not serve DEVICE_METADATA.localhost.hwsku from CONFIG_DB",
        f"`{' '.join(_HWSKU_ARGV)}` exited "
        f"{getattr(cp, 'returncode', '?')} with empty or no stdout; the guest "
        "is reachable but its configuration database is not serving",
        "report this with the node's boot log; the transport gate passed, so "
        "this is a NOS-readiness fault rather than a connectivity one",
    )


# REQ-45C-2 / BR-2 reconcile. Single-sourced argv (PBE-P2-6): the proof imports
# THIS tuple rather than restating the command.
_BGP_RECONCILE_ARGV = ("sudo", "systemctl", "restart", "bgp")


def _reconcile_bgp(rt: "Runtime", lab: str, node: str) -> None:
    """Make the applied overlay effective in the routing daemon.

    WHY THIS EXISTS. `config load` writes ConfigDB and `bgpcfgd` reacts within
    milliseconds -- measured 2026-08-25 -- but it REFUSES most of what Cassian
    writes, and the three surfaces fail in three different ways:

      BGP_NEIGHBOR, key already known
        ERR "Can't update the peer. Only 'admin_status' attribute is supported"
      DEVICE_METADATA.localhost.bgp_asn
        accepted with NO error and NO effect -- FRR kept the stock ASN
      router_id / set-src template
        WARNING "Update command is not supported for set src templates"

    The silent middle case is the dangerous one and it cannot be fixed by
    writing differently: `DEVICE_METADATA.localhost` ALWAYS pre-exists, so its
    write is ALWAYS an update. A restart rebuilds FRR from ConfigDB through the
    ADD path, which is the path that works -- measured: ASN, router-id and the
    declared peer all crossed into FRR after one.

    BR-2 requires the outcome: *"provisioning applies declared addresses ... and
    generated config converges a correctly-declared eBGP pair to Established."*
    Without this step that rule is unsatisfied and nothing reports it
    (BL-P2-4.5c-58).

    NO READINESS WAIT HERE, deliberately. `nos_ready`'s coverage limit assigns
    bgp readiness to the legs that need it -- *"Legs needing those conditions
    poll for them themselves (REQ-45C-8/-29 precheck; convergence_wait)"* -- and
    `convergence_wait` above polls on a bounded loop treating a not-yet-serving
    read as NOT-YET rather than a verdict. Re-polling here would wait for
    something already waited for, which is `nos_ready`'s own stated reason for
    being single-shot. Founder ruling 2026-08-25.

    COVERAGE LIMITS (PBE-P2-8), stated rather than implied:
      1. DURING-BOOT RESTART IS UNMEASURED. `nos_ready` records that bgp arrives
         up to ~90s after CONFIG_DB, and `provision` runs as soon as CONFIG_DB
         serves -- so this may restart a container that is still STARTING. The
         2026-08-25 measurement was taken on a settled guest, minutes after
         `up`. A bgp that does not come back is caught by `convergence_wait`'s
         bounded timeout with per-neighbour evidence, loudly; it is not caught
         here.
      2. A NON-ZERO rc IS NOT SWALLOWED, but a zero rc proves only that
         systemctl accepted the request -- not that bgpcfgd rebuilt anything.
         What proves that is the convergence read.
      3. `bgpcfgd` logs `Runner::commit was unsuccessful` on every reconcile
         against a stock guest, because the image ships a BGP_NEIGHBOR entry for
         its own management address. Measured non-blocking: a write issued after
         that failure was processed normally (BL-P2-4.5c-61).
    """
    cp = rt.exec(lab, node, list(_BGP_RECONCILE_ARGV), check=False,
                 capture_output=True)
    if getattr(cp, "returncode", 1) != 0:
        _fail(
            "SONiC routing daemon could not be reconciled",
            node,
            f"`{' '.join(_BGP_RECONCILE_ARGV)}` exited "
            f"{getattr(cp, 'returncode', '?')}",
            "the overlay was merged into ConfigDB but the routing daemon was "
            "not rebuilt from it; `bgpcfgd` refuses updates to an existing peer "
            "and silently ignores a changed local ASN, so the declared BGP "
            "configuration would be absent from FRR while the run looked clean",
            "report this with the guest's `systemctl status bgp` output",
        )


# REQ-45C-8/-29 convergence read. Single-sourced argv (PBE-P2-6): the proof
# imports THIS tuple rather than restating the command.
_BGP_SUMMARY_ARGV = ("vtysh", "-c", "show bgp summary json")

# FRR's inline leg polls at a 1s interval (`cassian_tests.py:620`). REQ-45C-29
# binds SONiC to the SAME bounds, interval and timeout semantics.
_CONVERGENCE_POLL_INTERVAL_S = 1


def _peers_from_summary(raw: str) -> "dict[str, str]":
    """Extract {peer_ip: state} from `show bgp summary json` output.

    Returns {} for anything unparseable -- during convergence the bgp container
    may not be serving yet, and an empty read is NOT-YET, never a verdict.

    SHAPE COVERAGE LIMIT (PBE-P2-8): the `peers` mapping is read at the top
    level OR one level down, because FRR nests it under an address-family key
    (`ipv4Unicast`) in some builds. The shape recorded for this image is
    `peers` keyed by peer IP with a `state` field (continuation rider rev 11 §2,
    measured session 8). That measurement is INHERITED, not re-taken here.
    """
    try:
        data = json.loads((raw or "").strip())
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    candidates = []
    if isinstance(data.get("peers"), dict):
        candidates.append(data["peers"])
    for value in data.values():
        if isinstance(value, dict) and isinstance(value.get("peers"), dict):
            candidates.append(value["peers"])
    out: "dict[str, str]" = {}
    for peers in candidates:
        for peer_ip, meta in peers.items():
            if isinstance(meta, dict):
                out.setdefault(str(peer_ip), str(meta.get("state", "")))
    return out


def convergence_wait(rt: "Runtime", lab: str, node: str, timeout: int,
                     expected_peers: "tuple[str, ...]") -> None:
    """Bounded wait until every DECLARED peer reads Established.

    Scoped to `expected_peers` -- the declared set core supplies through the
    widened contract (founder ruling 2026-08-25). Stock images ship BGP
    neighbours Cassian never declared and never removes (BL-P2-4.5c-9); an
    all-peers wait could never pass, which is why REQ-45C-8's positive leg
    needs the declared set. REQ-45C-24's "UNDECLARED-neighbor asymmetry"
    presupposes exactly this scoping.

    POSITIVE TEST, deliberately: a peer counts only when its state reads
    `Established`. Non-established states are NEVER enumerated -- the same
    guest was measured reading `Active` in the text table and `Connect` in
    JSON minutes apart, because the FSM oscillates while nothing answers
    (continuation rider rev 11 §2).

    REQ-45C-29: bounds, interval and timeout semantics match the FRR leg; a
    timeout is a deterministic §13-grade FAIL naming EVERY non-established
    declared peer with the state it last read -- never a hang, never silence
    (Doctrine §1.11).

    COVERAGE LIMIT (PBE-P2-8): this asserts the DECLARED peers reach
    Established. It asserts nothing about the stock peers, which remain in the
    device's own tables; how declared state relates to stock state is routed
    to §4.5-d (BL-P2-4.5c-9).
    """
    declared = tuple(str(p).strip() for p in (expected_peers or ()) if str(p).strip())
    if not declared:
        _fail(
            "SONiC convergence wait received no declared peers",
            node,
            "the expected-peer set supplied by core is empty",
            "a bounded wait with no target would return success without "
            "observing anything, which Doctrine 1.11 forbids",
            "declare `bgp.neighbors` on this node, or remove it from the "
            "control-plane precheck",
        )

    deadline = time.time() + max(int(timeout), 0)
    observed: "dict[str, str]" = {}
    while True:
        # STDOUT ONLY (F-45C-C3-20): the guest's SSH banner lands on stderr and
        # merging it breaks every parse. `check=False` deliberately -- a
        # non-zero rc while the bgp container is still starting is NOT-YET, not
        # a fault, and must not short-circuit the bounded wait.
        cp = rt.exec(lab, node, list(_BGP_SUMMARY_ARGV), check=False,
                     capture_output=True)
        observed = _peers_from_summary(cp.stdout or "")
        if all(observed.get(p, "") == "Established" for p in declared):
            return
        if time.time() >= deadline:
            break
        time.sleep(_CONVERGENCE_POLL_INTERVAL_S)

    detail = "; ".join(
        "%s:%s" % (p, observed.get(p) or "not-present")
        for p in declared
        if observed.get(p, "") != "Established"
    )
    _fail(
        "SONiC BGP did not converge",
        node,
        f"declared peers not Established within {int(timeout)}s",
        f"per-neighbour state at timeout: {detail}",
        "check the peer's declaration and reachability, or raise the "
        "convergence timeout for this lab",
    )


def probe_facts(rt: "Runtime", lab: str, node: str) -> "dict[str, Any]":
    """Observe the device facts generation needs (R-C3-13).

    Returns the opaque facts mapping passed to `gen_node_config`. Core never
    interprets it -- it is provider vocabulary by design (contract note at
    `cassian_nos_types.py`).
    """
    hwsku = _guest_stdout(
        rt, lab, node,
        list(_HWSKU_ARGV),
        "the platform HwSKU",
    ).strip()

    raw = _guest_stdout(
        rt, lab, node, ["sonic-cfggen", "-d", "--var-json", "PORT"],
        "the PORT table",
    )
    try:
        port_table = json.loads(raw)
    except ValueError:
        _fail(
            "SONiC guest PORT table is not parseable",
            node,
            "the guest returned a PORT payload that is not JSON",
            "generation derives interface naming from this table; Cassian "
            "will not proceed on an unreadable one",
            "report this with the guest's `sonic-cfggen -d --var-json PORT` "
            "output",
        )

    order = derive_port_order(port_table, node)
    _cross_check_port_map(hwsku, order, node)
    return {"hwsku": hwsku, "port_order": order}


def provision(rt: "Runtime", lab: str, node: str, node_d: dict,
              topo: dict) -> "dict[str, Any] | None":
    """Probe, generate, supply, and return what was applied (R-C3-12/-14).

    SUPPLY PATH (R-C3-12, founder ruling): the overlay reaches the guest
    through the supported `exec` verb -- write, then `config load -y`, which
    dispatches to `sonic-cfggen --write-to-db` and MERGES at field level.
    Measured 2026-08-18 on sonic-vm:202405: PORT 32 -> 32, hwsku/platform/mac
    intact, `/etc/sonic/config_db.json` md5 unchanged. The containerlab boot
    mount is NOT used: vrnetlab resolves it to `config replace` + `config save`,
    which is wholesale replacement and is what LD-45C-2 forbids.

    This does NOT use `copy_to_node`, whose REQ-45a-8/B10 UNSUP declaration for
    vm-runtime guests stands unchanged and is §4.5-f's to lift.

    SERIALIZATION: the string built here is the TRANSPORT payload, not the
    authoritative artifact. Core writes the artifact from this function's
    return value via `write_json_canonical` (PBE-P2-7, REQ-45C-42). The policy
    below is byte-identical to that serializer's, and the supply proof asserts
    the equality rather than assuming it.
    """
    # REQ-45C-44(b): precondition before anything is generated or supplied.
    # Ordered first deliberately -- probing and generating for a guest we
    # will refuse to provision wastes two guest reads and reports the
    # failure later than it is knowable.
    assert_routing_mode_clean(rt, lab, node)

    facts = probe_facts(rt, lab, node)
    out = gen_node_config(node_d, topo, facts)
    if not out:
        return None

    overlay = out.get("config_db.json")
    if overlay is None:
        _fail(
            "SONiC generation returned no overlay",
            node,
            "gen_node_config returned a mapping without 'config_db.json'",
            "the supply path has nothing to apply; this is a generation defect",
            "report this with the topology that produced it",
        )

    payload = json.dumps(overlay, indent=2, sort_keys=True, ensure_ascii=False)
    payload = payload.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"

    write_cmd = "printf '%s' " + shlex.quote(payload) + " > " + shlex.quote(_OVERLAY_GUEST_PATH)
    cp = rt.exec(lab, node, ["sh", "-c", write_cmd], check=False, capture_output=True)
    if getattr(cp, "returncode", 1) != 0:
        _fail(
            "SONiC overlay could not be staged on the guest",
            node,
            f"writing {_OVERLAY_GUEST_PATH} exited {getattr(cp, 'returncode', '?')}",
            "the overlay is supplied through the exec verb; without the staged "
            "file `config load` has nothing to merge",
            "confirm the guest filesystem is writable at /tmp and retry",
        )

    cp = rt.exec(lab, node,
                 ["sudo", "config", "load", _OVERLAY_GUEST_PATH, "-y"],
                 check=False, capture_output=True)
    if getattr(cp, "returncode", 1) != 0:
        _fail(
            "SONiC overlay apply failed",
            node,
            f"`config load` exited {getattr(cp, 'returncode', '?')}",
            "the generated overlay was staged but not merged into ConfigDB; "
            "the node's declared addressing is therefore absent",
            "report this with the staged overlay and the command output",
        )

    # REQ-45C-2 / BR-2: ConfigDB is written, but `bgpcfgd` refuses most of it on
    # the update path. Rebuild FRR from ConfigDB so the declared configuration is
    # actually in force (BL-P2-4.5c-58, founder ruling 2026-08-25).
    _reconcile_bgp(rt, lab, node)

    return out


SONIC_PROVIDER = NosProvider(
    node_type=SONIC_NODE_TYPE,
    default_image=SONIC_DEFAULT_IMAGE,
    runtime_requirement="vm",
    capabilities=_SONIC_CAPABILITIES,
    # -- lifecycle legs the ratified design assigns to SONiC (design :240) --
    gen_node_config=gen_node_config,
    provision=provision,
    # nos_ready lands here (§4.5-c, founder ruling 2026-08-20); design :228
    # and :240 assign it to SONiC, and RG-45C-P7 / NG-9 require it wired before
    # closure. convergence_wait remains a transient placeholder, replaced
    # before closure by the convergence leg. Provider-scoped, per the HALT-1
    # note above.
    nos_ready=nos_ready,
    convergence_wait=convergence_wait,
    # -- validation seam: SONiC collection lands at §4.5-d/-e --
    collect=deferred_leg("collect", "§4.5-d/-e"),
    # -- change workflow: §4.5-f (BL-P2-4.5b-2 shape) --
    candidate=None,
    # -- operational legs: §4.5-d --
    status_bgp_summary=None,  # design §3.3: None => explicit UNSUP
    status_routes=None,
    collect_targets=(),
    # -- legs the ratified design does NOT assign to SONiC (NG-9) --
    doctor_checks=deferred_leg("doctor_checks", "unassigned"),
    exec_command_rule=deferred_leg("exec_command_rule", "§4.5-d (LD-45b-6)"),
    state_profiles={},
    state_argv_allow=deferred_leg("state_argv_allow", "§4.5-d"),
)
