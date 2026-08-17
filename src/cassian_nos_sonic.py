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

import re
import sys
from typing import TYPE_CHECKING, Any

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
# COVERAGE LIMIT (PBE-P2-8), stated rather than implied:
#   * This table is keyed on HwSKU and covers ONLY the HwSKUs listed. A guest
#     reporting an unlisted HwSKU is a loud failure, never a best-effort guess.
#   * `_assert_port_map_matches_guest` verifies the guest's port SET and INDEX
#     ORDER against this table. It does NOT verify vrnetlab's positional
#     attachment contract -- that `eth{N}` reaches the N-th port is settled by
#     the REQ-45C-5 provisioning proof (declare a non-stock address, read it
#     back from the expected port), not by this assertion.
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


def _port_map_for(hwsku: str, node: str) -> tuple[str, ...]:
    ports = _SONIC_PORT_MAPS.get(hwsku)
    if ports is None:
        known = ", ".join(sorted(_SONIC_PORT_MAPS)) or "<none>"
        _fail(
            "SONiC platform port map unknown",
            node,
            f"no port map is declared for HwSKU {hwsku!r}",
            "interface names are platform-specific; Cassian will not guess a "
            "port map, because a wrong guess addresses the wrong ports silently",
            f"add a port map for {hwsku!r} to _SONIC_PORT_MAPS in "
            f"src/cassian_nos_sonic.py (known: {known})",
        )
    return ports  # type: ignore[return-value]


def sonic_port_for_iface(iface: str, hwsku: str, node: str) -> str:
    """Map a topology container interface (`eth{N}`) to its SONiC port name."""
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
    ports = _port_map_for(hwsku, node)
    if n < 1 or n > len(ports):
        _fail(
            "SONiC interface out of range",
            node,
            f"interface {iface!r} has no corresponding data port",
            f"HwSKU {hwsku!r} exposes {len(ports)} data ports "
            f"(eth1 .. eth{len(ports)})",
            f"declare an interface within eth1 .. eth{len(ports)}",
        )
    return ports[n - 1]


def _assert_port_map_matches_guest(port_table: dict, hwsku: str, node: str) -> None:
    """Verify the guest's live PORT table against the assumed map (REQ-45C-5).

    Checks the port SET and the platform's own `index` ORDER. A mismatch means
    the image or HwSKU changed under a map this module still assumes -- a loud
    failure, never a silent adaptation (Doctrine §1.11).
    """
    expected = _port_map_for(hwsku, node)
    observed_names = set(port_table)
    if observed_names != set(expected):
        missing = sorted(set(expected) - observed_names)
        extra = sorted(observed_names - set(expected))
        _fail(
            "SONiC port map does not match the guest",
            node,
            f"guest PORT table does not match the declared map for HwSKU {hwsku!r}",
            f"expected {len(expected)} ports; guest reports {len(observed_names)}"
            f" (missing: {missing[:4] or 'none'}; unexpected: {extra[:4] or 'none'})",
            "update _SONIC_PORT_MAPS in src/cassian_nos_sonic.py for this image, "
            "or pin the image the map was measured against",
        )

    def _idx(name: str) -> int:
        raw = port_table.get(name, {})
        val = raw.get("index") if isinstance(raw, dict) else None
        try:
            return int(val)
        except (TypeError, ValueError):
            return -1

    observed_order = tuple(sorted(expected, key=_idx))
    if observed_order != expected:
        _fail(
            "SONiC port ordering does not match the guest",
            node,
            f"guest PORT index order differs from the declared map for {hwsku!r}",
            f"declared[0:3]={expected[0:3]} guest[0:3]={observed_order[0:3]}",
            "the positional eth<N> mapping is unsafe on this image; update "
            "_SONIC_PORT_MAPS in src/cassian_nos_sonic.py",
        )


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


def gen_node_config(node: dict, topo: dict) -> "dict[str, Any] | None":
    """Generate the SONiC `config_db.json` OVERLAY for one node (LD-45C-2).

    Returns {"config_db.json": <overlay>} -- a filename -> content mapping.
    WRITES NOTHING: core serializes through `write_json_canonical`
    (REQ-45C-20/-42; design §:254).

    Routing-neutral baseline only at this leg (REQ-45C-1): hostname,
    interfaces, loopback. BGP rendering lands at REQ-45C-2/-3.

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

    hwsku = str(node.get("hwsku") or "Force10-S6000").strip()

    overlay: dict[str, Any] = {
        "DEVICE_METADATA": {"localhost": {"hostname": name}},
    }

    interfaces: dict[str, dict] = {}
    for iface, ip_cidr in _links_for_node(name, topo):
        port = sonic_port_for_iface(iface, hwsku, name)
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


def provision(rt: "Runtime", lab: str, node: str, node_d: dict, topo: dict) -> None:
    """Supply the generated overlay to the guest (REQ-45C-1 supply path).

    Wired at the WI-1 base leg for the port-map precondition only; the overlay
    apply path lands with the interface/addressing content leg. The design
    places both inside `provision` (design `:228`).
    """
    _fail(
        "SONiC provision leg not yet wired",
        node,
        "the overlay apply path lands with the §4.5-c addressing content leg",
        "reaching this placeholder is a defect; the base leg wires generation "
        "and the port-map precondition only",
        "report this with the command that produced it",
    )


SONIC_PROVIDER = NosProvider(
    node_type=SONIC_NODE_TYPE,
    default_image=SONIC_DEFAULT_IMAGE,
    runtime_requirement="vm",
    capabilities=_SONIC_CAPABILITIES,
    # -- lifecycle legs the ratified design assigns to SONiC (design :240) --
    gen_node_config=gen_node_config,
    provision=provision,
    # nos_ready / convergence_wait land with the precheck + convergence leg;
    # transient placeholders, replaced before closure (RG-45C-P7 is a closure
    # gate). Provider-scoped, per the HALT-1 note above.
    nos_ready=deferred_leg("nos_ready", "§4.5-c precheck leg"),
    convergence_wait=deferred_leg("convergence_wait", "§4.5-c convergence leg"),
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
