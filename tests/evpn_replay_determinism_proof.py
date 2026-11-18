#!/usr/bin/env python3
"""evpn_replay_determinism_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 6 (REQ-45E-34).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Doctrine §1.4 Deterministic Execution; Design
Contract v2.1 §2 Determinism -- for the EVPN record branches, and BL-H2.5-03 (REQ-45E-23; BL-P2-4.5c-245).

EXISTING OWNERS OF THE REST (proof-script ruling 1b; no leg is proved twice): the bgp_as_path and
bgp_community replay proofs, leg C: `_observed_state_finalize_in_results` is type-generic and replay-stable
for every kind's observed_state. This script does not repeat it.

HOW. The record legs run the engine's ACTUAL run_invariant_test body, AST-extracted and bound with
`_evaluate_invariant_attempt` stubbed to an answered read. The comparison legs read the engine's and the
two-run module's own source: replay's `_canon_test` (src/cassian_engine.py, inside the replay
verification) is AST-extracted and run; two-run's compared fields are read from `_two_run_compare`'s
`fields = (...)` assignment in src/cassian_two_run.py.

LEGS (one leg per EVPN kind for RD-REPLAY; a new kind adds a leg)
  RD-REPLAY  Each EVPN kind's record, built twice from the same read, serialises to the same bytes
             (canonical JSON), on a failed and on a passed verdict.
  RD-SORT    The route branch's evidence: entries the read returns in any order come out in one order,
             sorted by (mac, vni, route_type, node); every route_type is an int (REQ-45E-21); no
             (mac, vni, node) appears twice when the JSON leg and the text leg both see a route.
  RD-MACS    BL-H2.5-03, as schema v1.5 §4.7 states it (REQ-45E-23):
               - evidence.routes keeps every MAC the read returned, a container MAC included;
               - observed_state.evpn_routes carries the declared host MACs only;
               - replay's `_canon_test` keeps exactly name, kind, expected, observed and verdict, so it
                 reads neither evidence nor observed_state;
               - two-run compares exactly expected, observed, verdict and duration_ms;
               - two records that differ only by a container MAC compare equal under both.
  RD-NV      Non-vacuity, each a mutant with one line changed: (1) the engine's declared-MAC filter
             removed: RD-MACS goes red (a container MAC reaches observed_state); (2) replay's
             `_canon_test` keeps `evidence`: RD-MACS goes red; (3) two-run compares `evidence`: RD-MACS
             goes red.

COVERAGE LIMITS (PBE-P2-8). The reads are synthetic; no lab is read, and no replay or two-run is executed
end to end. The legs read the compared field sets from the code that compares them.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import contextlib
import io
import json
import os
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

NODE = "leaf2"
HOST1 = "00:11:22:33:44:55"
HOST2 = "00:11:22:33:44:66"
CONTAINER_A = "aa:c1:ab:82:f1:d8"   # measured container MACs, FRR 10.7.1 capture (tests/fixtures/evpn-mac-route-valid/)
CONTAINER_B = "aa:b6:46:97:77:f0"
VNI = 10100
TOPO = {"name": "rd", "nodes": [{"name": "leaf2", "type": "frr"}, {"name": "host1", "type": "host", "mac": HOST1},
                                {"name": "host2", "type": "host", "mac": HOST2}]}
KINDS = ("evpn_bgp_session_up", "evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present",
         "evpn_mac_route_valid")

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


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class _FakeTime:
    @staticmethod
    def time():
        return 0.0

    @staticmethod
    def sleep(_s):
        return None


class _Completed:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


class _Rt:
    def __init__(self, text):
        self.text = text

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        return _Completed(self.text)


def bind(engine_src):
    import cassian_engine
    fn = next(n for n in ast.walk(ast.parse(engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test")
    body = "\n".join(ast.unparse(s) for s in fn.body)
    ns = dict(cassian_engine.__dict__)
    ns.update(time=_FakeTime, lab="rd", topo=TOPO, rt=_Rt("Route Distinguisher: 10.255.0.11:2\n"))
    exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(body, "    "), ns)
    return ns


def run(ns, kind, entries, satisfied, expect="pass", text=None):
    def stub(*, inv_type, t, src):
        ev = {"cmd": "stub", "rc": 0, "parse_error": "", "probe_ok": True}
        if kind == "evpn_bgp_session_up":
            ev["neighbors"] = [{"neighbor": "172.16.0.2", "peerName": "spine1",
                                "state": "Established" if satisfied else "Active", "node": src}]
            return True, satisfied, {"peer": "spine1", "present": satisfied, "neighbors": ev["neighbors"]}, ev
        present = any(e["mac"] == HOST1 for e in entries)
        state = {"mac": HOST1, "vni_i": VNI, "present": present, "evidence_entries": [dict(e) for e in entries]}
        if kind == "evpn_mac_route_valid":
            state["valid"] = satisfied
        return True, satisfied, state, ev
    ns["_evaluate_invariant_attempt"] = stub
    ns["rt"] = _Rt(text if text is not None else "Route Distinguisher: 10.255.0.11:2\n")
    t = {"type": kind, "node": NODE, "expect": expect}
    if kind == "evpn_bgp_session_up":
        t["peer"] = "spine1"
    else:
        t["mac"], t["vni"] = HOST1, VNI
    rec = {}
    ns["_rit"]("rd_" + kind, NODE, t, lambda **kw: rec.update(kw))
    return rec


def _e(mac):
    return {"mac": mac, "vni": VNI, "route_type": 2, "node": NODE}


def canon(rec):
    return json.dumps({k: v for k, v in rec.items() if k != "duration_ms"}, sort_keys=True)


def rd_replay(ns):
    entries = [_e(HOST1), _e(CONTAINER_A)]
    for kind in KINDS:
        for satisfied in (False, True):
            a = canon(run(ns, kind, entries, satisfied))
            b = canon(run(ns, kind, entries, satisfied))
            check("RD-REPLAY %s (%s): the record from the same read serialises to the same bytes" % (
                kind, "pass" if satisfied else "fail"), a == b)


def rd_sort(ns):
    order1 = [_e(CONTAINER_A), _e(HOST2), _e(HOST1)]
    order2 = [_e(HOST1), _e(CONTAINER_A), _e(HOST2)]
    r1 = run(ns, "evpn_vni_route_present", order1, True)
    r2 = run(ns, "evpn_vni_route_present", order2, True)
    routes = (r1.get("evidence") or {}).get("routes") or []
    check("RD-SORT the evidence order does not depend on the read's order",
          routes and routes == (r2.get("evidence") or {}).get("routes"))
    check("RD-SORT the evidence is sorted by (mac, vni, route_type, node)",
          routes == sorted(routes, key=lambda x: (x["mac"], x["vni"], str(x["route_type"]), x["node"])),
          [r["mac"] for r in routes])
    check("RD-SORT every route_type is an int (REQ-45E-21)",
          routes and all(type(r["route_type"]) is int for r in routes), [r["route_type"] for r in routes])
    # the JSON leg and the text leg both see host2's route: it is recorded once
    text = ("Route Distinguisher: 10.255.0.11:2\n *>i [2]:[0]:[48]:[%s] RD 10.255.0.11:2\n"
            " *>i [2]:[0]:[48]:[%s] RD 10.255.0.11:2\n" % (HOST1, HOST2))
    rec = run(ns, "evpn_mac_route_present", [_e(HOST2)], False, text=text)
    routes = (rec.get("evidence") or {}).get("routes") or []
    keys = [(r["mac"], r["vni"], r["node"]) for r in routes]
    check("RD-SORT no (mac, vni, node) twice when both legs see a route", len(keys) == len(set(keys)) == 2, keys)


def canon_test_fn(engine_src):
    node = next((n for n in ast.walk(ast.parse(engine_src))
                 if isinstance(n, ast.FunctionDef) and n.name == "_canon_test"), None)
    getter = next((n for n in ast.walk(ast.parse(engine_src))
                   if isinstance(n, ast.FunctionDef) and n.name == "_get"), None)
    if node is None or getter is None:
        return None
    ns = {}
    exec(ast.unparse(getter) + "\n" + ast.unparse(node), ns)
    return ns["_canon_test"]


def two_run_fields(two_run_src):
    fn = next((n for n in ast.walk(ast.parse(two_run_src))
               if isinstance(n, ast.FunctionDef) and n.name == "_two_run_compare"), None)
    if fn is None:
        return None
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == "fields":
            return tuple(ast.literal_eval(n.value))
    return None


def rd_macs(ns, engine_src, two_run_src, label="RD-MACS"):
    ok = True
    rec_a = run(ns, "evpn_mac_route_present", [_e(HOST2), _e(CONTAINER_A)], False)
    rec_b = run(ns, "evpn_mac_route_present", [_e(HOST2), _e(CONTAINER_B)], False)
    ev_macs = {r["mac"] for r in (rec_a.get("evidence") or {}).get("routes") or []}
    os_macs = {r["mac"] for r in (rec_a.get("observed_state") or {}).get("evpn_routes") or []}
    ok &= check("%s evidence.routes keeps every MAC the read returned, the container MAC included" % label,
                ev_macs == {HOST2, CONTAINER_A}, sorted(ev_macs))
    ok &= check("%s observed_state.evpn_routes carries the declared host MACs only" % label,
                os_macs == {HOST2}, sorted(os_macs))
    ct = canon_test_fn(engine_src)
    ok &= check("%s replay's _canon_test is found and runs" % label, ct is not None)
    if ct is not None:
        keys = set(ct(rec_a))
        ok &= check("%s replay's _canon_test keeps exactly name, kind, expected, observed, verdict" % label,
                    keys == {"name", "kind", "expected", "observed", "verdict"}, sorted(keys))
        ok &= check("%s replay: two records that differ only by a container MAC compare equal" % label,
                    rec_a != rec_b and ct(rec_a) == ct(rec_b))
    fields = two_run_fields(two_run_src)
    ok &= check("%s two-run compares exactly expected, observed, verdict, duration_ms" % label,
                fields == ("expected", "observed", "verdict", "duration_ms"), fields)
    if fields is not None:
        ok &= check("%s two-run: the same two records compare equal on its fields" % label,
                    all(rec_a.get(f) == rec_b.get(f) for f in fields))
    return ok


def main():
    import cassian_common
    cassian_common._QUIET_DIE = True
    engine_src = _read(os.path.join(_SRC, "cassian_engine.py"))
    two_run_src = _read(os.path.join(_SRC, "cassian_two_run.py"))
    ns = bind(engine_src)
    rd_replay(ns)
    rd_sort(ns)
    rd_macs(ns, engine_src, two_run_src)

    filt = "                    if _e_mac and _e_mac not in _declared_host_macs:\n                        continue\n"
    canon_old = '                    "verdict": _get(t, "verdict", default=""),\n                }\n\n            def _canon_scenario'
    canon_new = ('                    "verdict": _get(t, "verdict", default=""),\n'
                 '                    "evidence": _get(t, "evidence", default=None),\n                }\n\n'
                 '            def _canon_scenario')
    fields_old = '        fields = ("expected", "observed", "verdict", "duration_ms")\n'
    fields_new = '        fields = ("expected", "observed", "verdict", "duration_ms", "evidence")\n'
    for label, which, old, new in (
            ("the engine's declared-MAC filter removed", "engine", filt, ""),
            ("replay's _canon_test keeps evidence", "engine", canon_old, canon_new),
            ("two-run compares evidence", "two_run", fields_old, fields_new)):
        src = engine_src if which == "engine" else two_run_src
        if not check("RD-NV the mutant's anchor is found once (%s)" % label, src.count(old) == 1):
            continue
        m_engine = engine_src.replace(old, new) if which == "engine" else engine_src
        m_two = two_run_src.replace(old, new) if which == "two_run" else two_run_src
        _QUIET[0] = True
        n0 = len(_FAILED)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                held = rd_macs(bind(m_engine), m_engine, m_two, label="(mutant)")
        finally:
            _QUIET[0] = False
            del _FAILED[n0:]
        if not held:
            print("MUTATION-FAIL: %s -> RD-MACS red" % label)
        check("RD-NV %s: RD-MACS goes red" % label, not held)

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_replay_determinism_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_replay_determinism_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
