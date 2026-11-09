#!/usr/bin/env python3
"""tests/sonic_configgen_determinism_proof.py — §4.5-c WI-1.

Req-IDs: REQ-45C-20 (byte-deterministic generation via write_json_canonical)
         REQ-45C-44(a) (overlay authors no platform-owned data)
         REQ-45C-5  (eth<N> -> platform port mapping; HALT-2 address discipline)
         REQ-45C-1  (routing-neutral baseline: hostname, interfaces, loopback)
         REQ-45C-2  (PARTIAL -- core only: declared `asn` and `bgp.neighbors`;
                     see coverage limit 2)
         REQ-45C-23 (no new topology keys: the declaration surface read here is
                     identical to the FRR leg's)

The §6.7.2 assignment for this file is [2, 3, 20, 21, 25]; the declared set
above is [1, 2, 5, 20, 23, 44a]. The divergence is recorded at BL-P2-4.5c-51
and is NOT closed here -- REQ-45C-3 and REQ-45C-21/-25 have no assertions in
this file.

Host-independent. No lab, no containerlab, no Docker.

Coverage limits (PBE-P2-8), stated rather than implied:
  1. This proof exercises OFFLINE generation only. It cannot verify that
     vrnetlab attaches container `eth<N>` to the N-th platform port -- that
     positional contract is settled by the REQ-45C-5 provisioning proof
     (declare a non-stock address, provision, read it back from the expected
     port), which is VM-bound. What is proven here: given the mapping,
     generation is deterministic, correctly ordered, platform-clean, and
     rejects what it should reject.
  2. REQ-45C-2 is covered here only for `asn` and `bgp.neighbors`. Its
     `router_id` and `networks` clauses and REQ-45C-3 are NOT asserted:
     `networks` and route-maps have no measured rendering target on
     sonic-vm:202405, and the `router_id` clause's disposition is
     founder-reserved. REQ-45C-2 does not discharge on this file alone.
  3. Rendering is proven; ACCEPTANCE by the guest is not. That a SONiC device
     ingests BGP_NEIGHBOR as written and reaches Established is REQ-45C-22,
     which is VM-bound and travels with WI-3.
"""
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import cassian_nos_sonic as S  # noqa: E402
from cassian_artifacts import write_json_canonical  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


# RFC 5737 TEST-NET-1 -- outside the stock canned ranges 10.0.0.0/26 and
# 10.1.0.0/24 measured on sonic-vm:202405 (HALT-2, REQ-45C-5).
TOPO = {
    "name": "sonic-gen-proof",
    "nodes": [{"name": "s1", "type": "sonic-vm", "router_id": "192.0.2.11"}],
    "links": [
        {"endpoints": ["s1:eth1", "r1:eth1"], "ipv4": ["192.0.2.0/31", "192.0.2.1/31"]},
        {"endpoints": ["s1:eth2", "r2:eth1"], "ipv4": ["192.0.2.4/31", "192.0.2.5/31"]},
    ],
}
NODE = TOPO["nodes"][0]

# Observed-facts fixture: the guest PORT table measured on sonic-vm:202405
# (2026-08-18, through the exec channel). Generation is a PURE function of its
# arguments -- no runtime is needed here, which is the property R-C3-14 chose
# this orchestration shape to preserve.
_GUEST_PORT_TABLE = {f"Ethernet{i * 4}": {"index": str(i)} for i in range(32)}
_PORT_ORDER = S.derive_port_order(_GUEST_PORT_TABLE, "s1")
FACTS = {"hwsku": "Force10-S6000", "port_order": _PORT_ORDER}

check("R-C3-13 derived order reproduces the recorded Force10-S6000 map",
      _PORT_ORDER == S._SONIC_PORT_MAPS["Force10-S6000"],
      "32/32 agreement, measured on the guest")

out = S.gen_node_config(NODE, TOPO, FACTS)
check("REQ-45C-1 generation returns a filename->content mapping",
      isinstance(out, dict) and list(out) == ["config_db.json"],
      "keys: %s" % (list(out) if isinstance(out, dict) else type(out).__name__))
overlay = out["config_db.json"]

# --- REQ-45C-1: routing-neutral baseline ------------------------------------
check("REQ-45C-1 hostname rendered",
      overlay.get("DEVICE_METADATA", {}).get("localhost", {}).get("hostname") == "s1")
check("REQ-45C-1 loopback carries router_id/32",
      "Loopback0|192.0.2.11/32" in overlay.get("LOOPBACK_INTERFACE", {}))
check("REQ-45C-1 routing-neutral: no BGP table at the base leg",
      "BGP_NEIGHBOR" not in overlay and
      "bgp_asn" not in overlay.get("DEVICE_METADATA", {}).get("localhost", {}))

# --- REQ-45C-5: eth<N> -> platform port -------------------------------------
iface = overlay.get("INTERFACE", {})
check("REQ-45C-5 eth1 -> Ethernet0 with its declared address",
      "Ethernet0|192.0.2.0/31" in iface, "measured on sonic-vm:202405, 2026-08-17")
check("REQ-45C-5 eth2 -> Ethernet4 with its declared address",
      "Ethernet4|192.0.2.4/31" in iface)
check("REQ-45C-5 NON-VACUITY: a wrong-port key is absent",
      "Ethernet4|192.0.2.0/31" not in iface and "Ethernet0|192.0.2.4/31" not in iface,
      "proves the mapping discriminates rather than emitting every port")
check("REQ-45C-5 HALT-2: no generated address inside the stock canned ranges",
      not any(k.split("|")[-1].startswith(("10.0.0.", "10.1.0.")) for k in iface))

# --- REQ-45C-44(a): platform-owned data never authored ----------------------
check("REQ-45C-44a no PORT table in the overlay", "PORT" not in overlay)
_local = overlay.get("DEVICE_METADATA", {}).get("localhost", {})
for _k in ("hwsku", "platform", "mac"):
    check("REQ-45C-44a overlay does not author %r" % _k, _k not in _local)
_seeded_rejected = False
try:
    S._assert_overlay_platform_clean({"PORT": {"Ethernet0": {}}}, "s1")
except SystemExit as _e:
    _seeded_rejected = (_e.code == 2)
check("REQ-45C-44a NON-VACUITY: seeded PORT table is rejected, exit 2",
      _seeded_rejected, "proves the guard fires; it is not decorative")

_seeded_hwsku = False
try:
    S._assert_overlay_platform_clean(
        {"DEVICE_METADATA": {"localhost": {"hwsku": "X"}}}, "s1")
except SystemExit as _e:
    _seeded_hwsku = (_e.code == 2)
check("REQ-45C-44a NON-VACUITY: seeded hwsku is rejected, exit 2", _seeded_hwsku)

# --- REQ-45C-20: byte-determinism through write_json_canonical --------------
_tmp = os.path.join(_HERE, ".sonic_gen_determinism_tmp")
os.makedirs(_tmp, exist_ok=True)
try:
    from pathlib import Path
    _p1 = Path(_tmp) / "a.json"
    _p2 = Path(_tmp) / "b.json"
    write_json_canonical(_p1, S.gen_node_config(NODE, TOPO, FACTS)["config_db.json"])
    write_json_canonical(_p2, S.gen_node_config(NODE, TOPO, FACTS)["config_db.json"])
    _b1 = io.open(_p1, "rb").read()
    _b2 = io.open(_p2, "rb").read()
    check("REQ-45C-20 two consecutive generations are byte-identical",
          _b1 == _b2, "%d bytes" % len(_b1))
    check("REQ-45C-20 serialized form is canonical (sorted, indent=2, one final NL)",
          _b1.endswith(b"\n") and not _b1.endswith(b"\n\n")
          and json.loads(_b1.decode("utf-8")) == overlay)
    _keys = list(json.loads(_b1.decode("utf-8")))
    check("REQ-45C-20 NON-VACUITY: top-level keys are sorted by the serializer",
          _keys == sorted(_keys), "keys: %s" % _keys)
finally:
    for _f in ("a.json", "b.json"):
        try:
            os.remove(os.path.join(_tmp, _f))
        except OSError:
            pass
    try:
        os.rmdir(_tmp)
    except OSError:
        pass

# --- Rejection legs ---------------------------------------------------------
_bad_iface = False
try:
    S.sonic_port_for_iface("swp1", _PORT_ORDER, "s1")
except SystemExit as _e:
    _bad_iface = (_e.code == 2)
check("REQ-45C-5 unrecognized interface form rejected, exit 2", _bad_iface)

_oob = False
try:
    S.sonic_port_for_iface("eth99", _PORT_ORDER, "s1")
except SystemExit as _e:
    _oob = (_e.code == 2)
check("REQ-45C-5 out-of-range interface rejected, exit 2", _oob)

_unlisted_ok = True
try:
    S._cross_check_port_map("Some-Unlisted-HwSKU", _PORT_ORDER, "s1")
except SystemExit:
    _unlisted_ok = False
check("R-C3-13 an unlisted HwSKU is SUPPORTED, not refused",
      _unlisted_ok, "derivation is authoritative; the table is a drift witness")

_missing_generation = False
try:
    S.gen_node_config(NODE, TOPO, None)
except SystemExit as _e:
    _missing_generation = (_e.code == 2)
check("R-C3-13 NON-VACUITY: generation without observed facts fails loud, exit 2",
      _missing_generation, "generation never probes and never guesses")

_dup = {"Ethernet0": {"index": "0"}, "Ethernet4": {"index": "0"}}
_dup_caught = False
try:
    S.derive_port_order(_dup, "s1")
except SystemExit as _e:
    _dup_caught = (_e.code == 2)
check("F-45C-C3-21 duplicate port index is ambiguous and fails loud, exit 2",
      _dup_caught, "breakout platforms are outside measured coverage")

_noidx = {"Ethernet0": {"lanes": "25,26,27,28"}}
_noidx_caught = False
try:
    S.derive_port_order(_noidx, "s1")
except SystemExit as _e:
    _noidx_caught = (_e.code == 2)
check("F-45C-C3-21 a port with no usable index fails loud, exit 2", _noidx_caught)

_empty_caught = False
try:
    S.derive_port_order({}, "s1")
except SystemExit as _e:
    _empty_caught = (_e.code == 2)
check("R-C3-13 an empty guest PORT table fails loud, exit 2", _empty_caught)

# --- Port-map assertion against a guest PORT table --------------------------
_ok = True
try:
    S._cross_check_port_map("Force10-S6000", _PORT_ORDER, "s1")
except SystemExit:
    _ok = False
check("REQ-45C-5 derived order matching the recorded map passes the cross-check",
      _ok)

_reordered_table = dict(_GUEST_PORT_TABLE)
_reordered_table["Ethernet0"] = {"index": "31"}
_reordered_table["Ethernet124"] = {"index": "0"}
_caught = False
try:
    S._cross_check_port_map(
        "Force10-S6000", S.derive_port_order(_reordered_table, "s1"), "s1")
except SystemExit as _e:
    _caught = (_e.code == 2)
check("REQ-45C-5 NON-VACUITY: a re-ordered guest PORT table is caught, exit 2",
      _caught, "proves the cross-check compares order, not just membership")

_short_table = {f"Ethernet{i * 4}": {"index": str(i)} for i in range(16)}
_caught_set = False
try:
    S._cross_check_port_map(
        "Force10-S6000", S.derive_port_order(_short_table, "s1"), "s1")
except SystemExit as _e:
    _caught_set = (_e.code == 2)
check("REQ-45C-5 NON-VACUITY: a different guest port set is caught, exit 2",
      _caught_set)

# --- REQ-45C-2 core: declared asn + bgp.neighbors render --------------------
# A SECOND fixture. TOPO/NODE above declare no BGP and must stay routing-neutral
# -- that is the discriminator for the REQ-45C-1 case above, so it is not edited.
# Addresses stay in TEST-NET-1, outside the stock canned ranges (HALT-2).
BGP_TOPO = {
    "name": "sonic-bgp-gen-proof",
    "nodes": [{
        "name": "s1",
        "type": "sonic-vm",
        "router_id": "192.0.2.11",
        "asn": 65001,
        "bgp": {"neighbors": [
            {"peer": "r2", "remote_as": 65003},
            {"peer": "r1", "remote_as": 65002},
            {"peer": "ghost", "remote_as": 65999},
        ]},
        "networks": ["192.0.2.128/25"],
    }],
    "links": [
        {"endpoints": ["s1:eth1", "r1:eth1"], "ipv4": ["192.0.2.0/31", "192.0.2.1/31"]},
        {"endpoints": ["s1:eth2", "r2:eth1"], "ipv4": ["192.0.2.4/31", "192.0.2.5/31"]},
    ],
}
BGP_NODE = BGP_TOPO["nodes"][0]
bov = S.gen_node_config(BGP_NODE, BGP_TOPO, FACTS)["config_db.json"]
_bl = bov.get("DEVICE_METADATA", {}).get("localhost", {})
_bn = bov.get("BGP_NEIGHBOR", {})

check("REQ-45C-2 declared asn renders to DEVICE_METADATA.localhost.bgp_asn",
      _bl.get("bgp_asn") == "65001",
      "measured target on sonic-vm:202405 build fecd4ec81; BGP_GLOBALS absent")
check("REQ-45C-2 bgp_asn is a STRING, matching the measured table shape",
      isinstance(_bl.get("bgp_asn"), str))
check("REQ-45C-2 BGP_NEIGHBOR is keyed by PEER IP, mask stripped",
      sorted(_bn) == ["192.0.2.1", "192.0.2.5"], "keys: %s" % sorted(_bn))
check("REQ-45C-2 r1 neighbour carries remote_as, local_addr and peer name",
      _bn.get("192.0.2.1") == {"asn": "65002", "local_addr": "192.0.2.0", "name": "r1"})
check("REQ-45C-2 r2 neighbour resolves through its OWN link, not the first",
      _bn.get("192.0.2.5") == {"asn": "65003", "local_addr": "192.0.2.4", "name": "r2"},
      "declaration order r2-then-r1 is deliberately not link order")
check("REQ-45C-2 every BGP_NEIGHBOR value is a string",
      all(isinstance(v, str) for e in _bn.values() for v in e.values()))
check("REQ-45C-2 NON-VACUITY: a neighbour with no matching link is not rendered",
      not any(e.get("name") == "ghost" for e in _bn.values()),
      "mirrors the FRR leg, which skips a neighbour with no link_match")
check("REQ-45C-2 NON-VACUITY: the routing-neutral fixture stays BGP-free",
      "BGP_NEIGHBOR" not in overlay
      and "bgp_asn" not in overlay.get("DEVICE_METADATA", {}).get("localhost", {}),
      "proves rendering is declaration-driven, not unconditional")
check("REQ-45C-2 UNCOVERED: declared `networks` is not rendered anywhere",
      not any("192.0.2.128" in json.dumps(v) for v in bov.values()),
      "no measured target on this image; carved to a founder-reserved question")
check("REQ-45C-44a BGP rendering authors no platform-owned key",
      "PORT" not in bov and not any(k in _bl for k in ("hwsku", "platform", "mac")))
check("REQ-45C-1 baseline survives BGP rendering (hostname, loopback, ifaces)",
      _bl.get("hostname") == "s1"
      and "Loopback0|192.0.2.11/32" in bov.get("LOOPBACK_INTERFACE", {})
      and "Ethernet0|192.0.2.0/31" in bov.get("INTERFACE", {}))
check("REQ-45C-20 BGP generation is byte-deterministic across two calls",
      json.dumps(S.gen_node_config(BGP_NODE, BGP_TOPO, FACTS)["config_db.json"],
                 sort_keys=True)
      == json.dumps(bov, sort_keys=True))

_bad_asn = False
try:
    S.gen_node_config(
        {"name": "s1", "type": "sonic-vm", "asn": "six-five-thousand"},
        {"links": []}, FACTS)
except SystemExit as _e:
    _bad_asn = (_e.code == 2)
check("REQ-45C-2 NON-VACUITY: a non-integer asn fails loud, exit 2",
      _bad_asn, "never rendered as a silent empty string")

# REQ-45C-23: the SONiC leg reads only keys the FRR declaration surface has.
# Behavioural, not declarative: seed keys FRR does not define and assert the
# generated overlay is byte-unchanged. A leg that read a SONiC-only key would
# diverge here. Limit: this discriminates against the seeded names, not against
# every possible one.
_probe_topo = json.loads(json.dumps(BGP_TOPO))
_probe_node = _probe_topo["nodes"][0]
_probe_node["sonic_only_key"] = "x"
_probe_node["bgp"]["sonic_bgp_key"] = "x"
_probe_node["bgp"]["neighbors"][0]["sonic_nbr_key"] = "x"
check("REQ-45C-23 NON-VACUITY: undeclared keys leave the overlay byte-unchanged",
      json.dumps(S.gen_node_config(_probe_node, _probe_topo, FACTS)["config_db.json"],
                 sort_keys=True) == json.dumps(bov, sort_keys=True),
      "cassian_model.py binds asn :1613, router_id :1562, bgp.neighbors :1614, "
      "networks :1730 -- the SONiC leg reads that set and no more")

# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok2, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok2 else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-1 SONiC config generation)"
      % ("PASS" if not _failed else "FAIL", len(_checks)))
sys.exit(1 if _failed else 0)
