#!/usr/bin/env python3
"""tests/sonic_configgen_determinism_proof.py — §4.5-c WI-1.

Req-IDs: REQ-45C-20 (byte-deterministic generation via write_json_canonical)
         REQ-45C-44(a) (overlay authors no platform-owned data)
         REQ-45C-5  (eth<N> -> platform port mapping; HALT-2 address discipline)
         REQ-45C-1  (routing-neutral baseline: hostname, interfaces, loopback)

Host-independent. No lab, no containerlab, no Docker.

Coverage limit (PBE-P2-8), stated rather than implied:
  This proof exercises OFFLINE generation only. It cannot verify that vrnetlab
  attaches container `eth<N>` to the N-th platform port -- that positional
  contract is settled by the REQ-45C-5 provisioning proof (declare a non-stock
  address, provision, read it back from the expected port), which is VM-bound.
  What is proven here: given the mapping, generation is deterministic, correctly
  ordered, platform-clean, and rejects what it should reject.
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

out = S.gen_node_config(NODE, TOPO)
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
    write_json_canonical(_p1, S.gen_node_config(NODE, TOPO)["config_db.json"])
    write_json_canonical(_p2, S.gen_node_config(NODE, TOPO)["config_db.json"])
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
    S.sonic_port_for_iface("swp1", "Force10-S6000", "s1")
except SystemExit as _e:
    _bad_iface = (_e.code == 2)
check("REQ-45C-5 unrecognized interface form rejected, exit 2", _bad_iface)

_oob = False
try:
    S.sonic_port_for_iface("eth99", "Force10-S6000", "s1")
except SystemExit as _e:
    _oob = (_e.code == 2)
check("REQ-45C-5 out-of-range interface rejected, exit 2", _oob)

_unknown_hwsku = False
try:
    S.sonic_port_for_iface("eth1", "Some-Unlisted-HwSKU", "s1")
except SystemExit as _e:
    _unknown_hwsku = (_e.code == 2)
check("REQ-45C-5 unknown HwSKU fails loud rather than guessing, exit 2",
      _unknown_hwsku, "deny-by-default")

# --- Port-map assertion against a guest PORT table --------------------------
_good_table = {n: {"index": str(i)} for i, n in
               enumerate(S._SONIC_PORT_MAPS["Force10-S6000"])}
_ok = True
try:
    S._assert_port_map_matches_guest(_good_table, "Force10-S6000", "s1")
except SystemExit:
    _ok = False
check("REQ-45C-5 matching guest PORT table passes the assertion", _ok)

_reordered = dict(_good_table)
_reordered["Ethernet0"] = {"index": "31"}
_reordered["Ethernet124"] = {"index": "0"}
_caught = False
try:
    S._assert_port_map_matches_guest(_reordered, "Force10-S6000", "s1")
except SystemExit as _e:
    _caught = (_e.code == 2)
check("REQ-45C-5 NON-VACUITY: a re-ordered guest PORT table is caught, exit 2",
      _caught, "proves the assertion checks order, not just membership")

_short = {n: {"index": str(i)} for i, n in
          enumerate(S._SONIC_PORT_MAPS["Force10-S6000"][:16])}
_caught_set = False
try:
    S._assert_port_map_matches_guest(_short, "Force10-S6000", "s1")
except SystemExit as _e:
    _caught_set = (_e.code == 2)
check("REQ-45C-5 NON-VACUITY: a different guest port set is caught, exit 2",
      _caught_set)

# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok2, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok2 else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-1 SONiC config generation)"
      % ("PASS" if not _failed else "FAIL", len(_checks)))
sys.exit(1 if _failed else 0)
