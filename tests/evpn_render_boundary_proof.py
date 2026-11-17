#!/usr/bin/env python3
"""evpn_render_boundary_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 5 (REQ-45E-33).

DOCTRINE SURFACE THIS SCRIPT OWNS (proof-script ruling 1a): Design Contract v2.1 §13, "Failed-invariant
rendering in results.summary.txt" (§13(b)(c)), the PRESENT half: each EVPN payload's `observed:` block.

EXISTING OWNERS OF THE REST (proof-script ruling 1b; no leg is proved twice):
  - tests/bl6_observed_state_absence_render_proof.py: the ABSENT half (a failed record with no structured
    observed_state renders the explicit absence block); it is generic, and already uses an EVPN meta.
  - tests/bl_h3_8_scenarios_summary_existing_type_render_proof.py PO-3: the scenario step lines.

HOW. Lab-free. cassian_tests._format_test_summary renders a synthetic results document holding one failed
record per EVPN kind, each with a dict observed_state in its schema v1.5 §4 shape. The renderer is
type-generic (it branches on whether observed_state is a dict, and on the list keys it knows), so the
script reads what it renders for each kind's own fields.

LEGS (one leg per EVPN kind; a new kind adds a leg)
  RB-SESS   evpn_bgp_session_up: the block renders type, peer, state, last_reset_reason and source_node,
            one `<key>: <value>` line each, keys sorted.
  RB-PRES   evpn_mac_route_present: type, mac, vni, source_node, and the list key evpn_routes rendered
            multi-line: one `- key=value, ...` line per entry (keys sorted, route_type an int), at 8 spaces.
  RB-ABS    evpn_mac_route_absent: the same, with `evpn_routes: []` for an empty list.
  RB-VNI    evpn_vni_route_present: type, vni, source_node and evpn_routes; no mac line.
  RB-VALID  evpn_mac_route_valid: §4.7's lines plus `valid: false` (REQ-45E-25).
  RB-CAP    A list of seven entries renders five entry lines and `(+2 more)`; a list of exactly five renders
            five and no over-cap line.
  RB-DET    Two renders of the same document are byte-identical; the failed line precedes each block.
  RB-NV     Non-vacuity: two mutants of src/cassian_tests.py, each with one line changed, loaded in memory.
            (1) evpn_routes dropped from the renderer's list keys: the list renders inline as one line, and
            RB-PRES goes red. (2) The cap raised from 5 to 50: RB-CAP goes red.

COVERAGE LIMITS (PBE-P2-8). The payloads are synthetic, in the schema's shape; that the engine writes that
shape is tests/evpn_authority_parity_proof.py's. This script reads no lab.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import contextlib
import io
import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

HOST1 = "00:11:22:33:44:55"
HOST2 = "00:11:22:33:44:66"
VNI = 10100

_FAILED = []
_COUNT = [0]
_QUIET = [False]


def check(name, ok, detail=""):
    if not _QUIET[0]:
        _COUNT[0] += 1
        print(("PASS   " if ok else "FAIL   ") + name + ("" if ok or not detail else "  -- " + str(detail)))
    if not ok:
        _FAILED.append(name)
    return bool(ok)


def _route(mac):
    return {"rd": "", "prefix": "", "mac": mac, "vni": VNI, "route_type": 2}


def _rec(name, inv_type, os_, meta=None):
    return {"name": name, "kind": "invariant", "from": "leaf2", "to": "", "expected": "pass", "observed": "fail",
            "verdict": "fail", "error": "%s mismatch (expected pass, observed fail)" % inv_type,
            "meta": dict(meta or {}, type=inv_type), "observed_state": os_}


def results():
    many = ["00:11:22:33:44:%02x" % i for i in range(0x50, 0x57)]  # seven entries
    five = ["00:11:22:33:44:%02x" % i for i in range(0x60, 0x65)]
    tests = [
        _rec("rb-sess", "evpn_bgp_session_up", {"type": "evpn_bgp_session_up", "peer": "spine1", "state": "Active",
                                                 "last_reset_reason": "", "source_node": "leaf2"}, {"peer": "spine1"}),
        _rec("rb-pres", "evpn_mac_route_present", {"type": "evpn_mac_route_present", "mac": HOST1, "vni": VNI,
                                                    "evpn_routes": [_route(HOST2)], "source_node": "leaf2"}),
        _rec("rb-abs", "evpn_mac_route_absent", {"type": "evpn_mac_route_absent", "mac": HOST1, "vni": VNI,
                                                  "evpn_routes": [], "source_node": "leaf2"}),
        _rec("rb-vni", "evpn_vni_route_present", {"type": "evpn_vni_route_present", "vni": VNI,
                                                   "evpn_routes": [_route(HOST1)], "source_node": "leaf2"}),
        _rec("rb-valid", "evpn_mac_route_valid", {"type": "evpn_mac_route_valid", "mac": HOST1, "vni": VNI,
                                                   "evpn_routes": [_route(HOST1)], "valid": False,
                                                   "source_node": "leaf2"}),
        _rec("rb-cap7", "evpn_vni_route_present", {"type": "evpn_vni_route_present", "vni": VNI,
                                                    "evpn_routes": [_route(m) for m in many], "source_node": "leaf2"}),
        _rec("rb-cap5", "evpn_vni_route_present", {"type": "evpn_vni_route_present", "vni": VNI,
                                                    "evpn_routes": [_route(m) for m in five], "source_node": "leaf2"}),
    ]
    return {"lab": "evpn-render-boundary-proof", "result": "fail",
            "summary": {"total": len(tests), "passed": 0, "failed": len(tests)}, "tests": tests}


def block(out, name):
    """The lines after test `name`'s failed line, up to the next failed line or the end."""
    lines = out.split("\n")
    start = next((i for i, l in enumerate(lines) if l.startswith(" - %s (invariant)" % name)), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith(" - ")), len(lines))
    return lines[start + 1:end]


def entry(mac):
    return "        - mac=%s, prefix=, rd=, route_type=2, vni=%d" % (mac, VNI)


def legs(ct, label="RB"):
    out = ct._format_test_summary(results())
    ok = True
    b = block(out, "rb-sess") or []
    ok &= check("%s-SESS evpn_bgp_session_up: one line per field, keys sorted" % label,
                b[:6] == ["    observed:", "      last_reset_reason: ", "      peer: spine1", "      source_node: leaf2",
                          "      state: Active", "      type: evpn_bgp_session_up"], b)
    b = block(out, "rb-pres") or []
    ok &= check("%s-PRES evpn_mac_route_present: scalars and the evpn_routes list, multi-line" % label,
                b[:7] == ["    observed:", "      evpn_routes:", entry(HOST2), "      mac: %s" % HOST1,
                          "      source_node: leaf2", "      type: evpn_mac_route_present", "      vni: %d" % VNI], b)
    b = block(out, "rb-abs") or []
    ok &= check("%s-ABS evpn_mac_route_absent: an empty evpn_routes renders `[]` inline" % label,
                "      evpn_routes: []" in b and "      type: evpn_mac_route_absent" in b, b)
    b = block(out, "rb-vni") or []
    ok &= check("%s-VNI evpn_vni_route_present: evpn_routes, source_node, type, vni; no mac line" % label,
                b[:6] == ["    observed:", "      evpn_routes:", entry(HOST1), "      source_node: leaf2",
                          "      type: evpn_vni_route_present", "      vni: %d" % VNI], b)
    b = block(out, "rb-valid") or []
    ok &= check("%s-VALID evpn_mac_route_valid: §4.7's lines plus `valid: false`" % label,
                b[:8] == ["    observed:", "      evpn_routes:", entry(HOST1), "      mac: %s" % HOST1,
                          "      source_node: leaf2", "      type: evpn_mac_route_valid", "      valid: false",
                          "      vni: %d" % VNI], b)
    b = block(out, "rb-cap7") or []
    entries = [l for l in b if l.startswith("        - ")]
    ok &= check("%s-CAP seven entries: five entry lines and `(+2 more)`" % label,
                len(entries) == 5 and "        (+2 more)" in b, b)
    b = block(out, "rb-cap5") or []
    entries = [l for l in b if l.startswith("        - ")]
    ok &= check("%s-CAP exactly five entries: five lines and no over-cap line" % label,
                len(entries) == 5 and not any("more)" in l for l in b), b)
    ok &= check("%s-DET two renders are byte-identical" % label, out == ct._format_test_summary(results()))
    ok &= check("%s-DET every failed record's line precedes its block" % label,
                all(block(out, n) is not None for n in ("rb-sess", "rb-pres", "rb-abs", "rb-vni", "rb-valid")))
    ok &= check("%s-DET no record renders the absence indicator (each has a dict observed_state)" % label,
                "structured failure detail unavailable" not in out)
    return ok


def mutant(old, new):
    path = os.path.join(_SRC, "cassian_tests.py")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if text.count(old) != 1:
        return None
    mod = types.ModuleType("cassian_tests_evpn_rb_mutant")
    mod.__file__ = path
    sys.modules[mod.__name__] = mod
    try:
        exec(compile(text.replace(old, new), "<cassian_tests mutant>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(mod.__name__, None)
    return mod


def main():
    import cassian_tests as ct
    legs(ct)
    for label, leg, old, new in (
            ("evpn_routes dropped from the renderer's list keys", "RB-PRES", '    "evpn_routes",\n', ""),
            ("the list cap raised from 5 to 50", "RB-CAP",
             "_OBSERVED_STATE_LIST_CAP: int = 5\n", "_OBSERVED_STATE_LIST_CAP: int = 50\n")):
        m = mutant(old, new)
        if not check("RB-NV the mutant's anchor is found once (%s)" % label, m is not None):
            continue
        _QUIET[0] = True
        n0 = len(_FAILED)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                legs(m, label="(mutant)")
            red = [f for f in _FAILED[n0:] if f.startswith("(mutant)-" + leg.split("-")[1])]
        finally:
            _QUIET[0] = False
            del _FAILED[n0:]
        if red:
            print("MUTATION-FAIL: %s -> %s red" % (label, leg))
        check("RB-NV %s: %s goes red" % (label, leg), bool(red))

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_render_boundary_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_render_boundary_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
