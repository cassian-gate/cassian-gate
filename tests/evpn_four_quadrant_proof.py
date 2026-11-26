#!/usr/bin/env python3
"""evpn_four_quadrant_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 4 (REQ-45E-32).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Doctrine §1.8 Negative Test; Design Contract v2.1 §7
"Negative tests" -- expect: fail through each EVPN record branch.

EXISTING OWNERS OF THE REST (proof-script ruling 1b; no leg is proved twice):
  - tests/expf_four_quadrant_catalog_proof.py: the shared verdict line (`verdict = "pass" if observed ==
    expected else "fail"`) for every invariant type.
  - tests/unusable_read_sweep_proof.py and tests/probe_unusable_verdict_proof.py: reads that give no answer,
    under both expects. This script drives answered reads only.
  - tests/evpn_collection_migration_proof.py: REQ-45C-14's text leg for evpn_mac_route_present and _absent
    (W-TEXT). This script uses the text leg only for evpn_mac_route_valid.
  - tests/evpn_eval_match_proof.py: what each kind reads as satisfied (the predicates).

LEGS (one leg per EVPN kind; a new kind adds a leg). Each runs the engine's ACTUAL run_invariant_test body,
AST-extracted and bound with `_evaluate_invariant_attempt` stubbed to an answered read, so the harness sets
what the read saw; the text leg, where it runs, goes through the real collection seam (`_nos_collect`) to
FRR's real text parser, answered by a fake runtime. Quadrants, numbered as P-EXPF numbers them:
  Q1 expect pass, observed pass -> verdict pass, no observed_state
  Q2 expect pass, observed fail -> verdict fail, observed_state a dict of the kind's type
  Q3 expect fail, observed fail -> verdict pass, no observed_state
  Q4 expect fail, observed pass -> verdict fail, observed_state a dict of the kind's type
  FQ-SESS    evpn_bgp_session_up, the four quadrants.
  FQ-PRES    evpn_mac_route_present, the four quadrants.
  FQ-ABS     evpn_mac_route_absent, the four quadrants.
  FQ-VNI     evpn_vni_route_present, the four quadrants.
  FQ-VALID   evpn_mac_route_valid, the four quadrants, observed from a JSON leg that shows the route.
  FQ-GRACE   For each route kind, a route absent from the table (JSON and text) is a graceful fail owned by
             Cassian: a record, no SystemExit.
  FQ-ESC3    The case the ESC-3 ruling names (handover §6.7.2 L372, §15.2 row 25): the JSON shows no
             matching route and the text table shows it valid. Under expect: fail the test FAILS (Q4), and
             under expect: pass it passes (Q1); the record carries `valid` true.
  FQ-NV      Non-vacuity. (1) The kind dropped from the text-leg trigger (`if not present and inv_type in
             (...)` in run_invariant_test): FQ-ESC3 goes red, because the valid kind then never reads the
             text table and its expect: fail test passes on a route that is present and valid. (2) The
             observed_state guard `if verdict == "fail":` replaced by `if True:`: the Q1/Q3 legs go red.
             Each mutant is the engine's own source with one line changed, bound the same way.

COVERAGE LIMITS (PBE-P2-8). The reads are synthetic and answered; no lab is read. This script proves what
the record branch does with a read, not what FRR returns.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import contextlib
import io
import os
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

NODE = "leaf2"
HOST1 = "00:11:22:33:44:55"
VNI = 10100
TOPO = {"name": "fq", "nodes": [
    {"name": "spine1", "type": "frr"}, {"name": "leaf2", "type": "frr"},
    {"name": "host1", "type": "host", "mac": HOST1}]}
TEXT_VALID = ("Route Distinguisher: 10.255.0.11:2\n"
              " *>i [2]:[0]:[48]:[%s] RD 10.255.0.11:2\n"
              "                    10.255.0.11                   100      0 i\n" % HOST1)
TEXT_EMPTY = "Route Distinguisher: 10.255.0.11:2\n"

_FAILED = []
_COUNT = [0]
_QUIET = [False]

QUADRANTS = (
    ("Q1", "pass", "pass", "pass", False),
    ("Q2", "pass", "fail", "fail", True),
    ("Q3", "fail", "fail", "pass", False),
    ("Q4", "fail", "pass", "fail", True),
)


def check(name, ok, detail=""):
    if not _QUIET[0]:
        _COUNT[0] += 1
        print(("PASS   " if ok else "FAIL   ") + name + ("" if ok or not detail else "  -- " + str(detail)))
    if not ok:
        _FAILED.append(name)
    return bool(ok)


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
        self.calls = []

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append(list(cmd))
        return _Completed(self.text)


def bind(engine_src):
    import cassian_engine
    fn = next(n for n in ast.walk(ast.parse(engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test")
    body = "\n".join(ast.unparse(s) for s in fn.body)
    ns = dict(cassian_engine.__dict__)
    ns.update(time=_FakeTime, lab="fq", topo=TOPO)
    exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(body, "    "), ns)
    return ns


def _stub(kind, present, valid):
    def stub(*, inv_type, t, src):
        ev = {"cmd": "stub", "rc": 0, "parse_error": "", "probe_ok": True}
        if kind == "evpn_bgp_session_up":
            ev["neighbors"] = [{"neighbor": "172.16.0.2", "peerName": "spine1",
                                "state": "Established" if present else "Active", "node": src}]
            return True, present, {"peer": "spine1", "present": present, "neighbors": ev["neighbors"]}, ev
        entries = [{"mac": HOST1, "vni": VNI, "route_type": 2, "node": src}] if present else []
        state = {"mac": HOST1, "vni_i": VNI, "present": present, "evidence_entries": entries}
        if kind == "evpn_mac_route_valid":
            state["valid"] = valid
        return True, (valid if kind == "evpn_mac_route_valid" else present), state, ev
    return stub


def run(ns, kind, expect, present, valid=False, text=TEXT_EMPTY):
    ns["_evaluate_invariant_attempt"] = _stub(kind, present, valid)
    ns["rt"] = rt = _Rt(text)
    t = {"type": kind, "node": NODE, "expect": expect}
    if kind == "evpn_bgp_session_up":
        t["peer"] = "spine1"
    else:
        t["mac"], t["vni"] = HOST1, VNI
    rec = {}
    try:
        verdict = ns["_rit"]("fq_" + kind, NODE, t, lambda **kw: rec.update(kw))
    except BaseException as exc:  # SystemExit included: an escape is red, never a pass
        verdict = "raised: %r" % (exc,)
    return verdict, rec, rt


def _observed_inputs(kind, observed):
    """The read that makes `kind` observe `observed`: (present, valid)."""
    if kind == "evpn_mac_route_absent":
        return (observed == "fail"), False
    if kind == "evpn_mac_route_valid":
        return True, (observed == "pass")
    return (observed == "pass"), False


def quadrants(ns, kind, label):
    ok = True
    for q, expect, observed, verdict_want, has_os in QUADRANTS:
        present, valid = _observed_inputs(kind, observed)
        verdict, rec, _rt = run(ns, kind, expect, present, valid)
        os_ = rec.get("observed_state")
        good = (verdict == verdict_want and rec.get("verdict") == verdict_want and rec.get("observed") == observed
                and rec.get("expected") == expect)
        if has_os:
            good = good and isinstance(os_, dict) and os_.get("type") == kind
        else:
            good = good and os_ is None
        ok &= check("%s %s %s: expect %s, observed %s -> verdict %s, observed_state %s" % (
            label, kind, q, expect, observed, verdict_want, "a dict" if has_os else "none"), good,
            "verdict=%s rec=%s" % (verdict, {k: rec.get(k) for k in ("observed", "verdict", "observed_state")}))
    return ok


def grace(ns, label="FQ-GRACE"):
    ok = True
    for kind in ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_mac_route_valid", "evpn_vni_route_present"):
        verdict, rec, _rt = run(ns, kind, "pass", False, False, TEXT_EMPTY)
        want = "pass" if kind == "evpn_mac_route_absent" else "fail"
        ok &= check("%s %s: a route absent from the table is a record, no SystemExit (verdict %s)" % (label, kind, want),
                    verdict == want and rec.get("kind") == "invariant", verdict)
    return ok


def esc3(ns, label="FQ-ESC3"):
    ok = True
    verdict, rec, rt = run(ns, "evpn_mac_route_valid", "fail", False, False, TEXT_VALID)
    asked = [c for c in rt.calls if c == ["vtysh", "-c", "show bgp l2vpn evpn route"]]
    ok &= check("%s the JSON shows no matching route, so the text leg is asked once" % label, len(asked) == 1, rt.calls)
    os_ = rec.get("observed_state") or {}
    ok &= check("%s expect: fail on a route the text table shows valid -> the test FAILS (Q4)" % label,
                verdict == "fail" and rec.get("observed") == "pass" and os_.get("valid") is True,
                "verdict=%s observed=%s observed_state=%s" % (verdict, rec.get("observed"), os_))
    verdict, rec, _rt = run(ns, "evpn_mac_route_valid", "pass", False, False, TEXT_VALID)
    ok &= check("%s expect: pass on the same read -> pass (Q1)" % label, verdict == "pass", verdict)
    return ok


def all_kinds(ns, label="FQ"):
    ok = True
    for kind, tag in (("evpn_bgp_session_up", "SESS"), ("evpn_mac_route_present", "PRES"),
                      ("evpn_mac_route_absent", "ABS"), ("evpn_vni_route_present", "VNI"),
                      ("evpn_mac_route_valid", "VALID")):
        ok &= quadrants(ns, kind, "%s-%s" % (label, tag))
    return ok


def mutant(engine_src, old, new):
    if engine_src.count(old) != 1:
        return None
    return bind(engine_src.replace(old, new))


def quiet(fn, *a):
    _QUIET[0] = True
    n0 = len(_FAILED)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*a)
    finally:
        _QUIET[0] = False
        del _FAILED[n0:]


def main():
    import cassian_common
    cassian_common._QUIET_DIE = True
    with open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8") as fh:
        engine_src = fh.read()
    ns = bind(engine_src)
    all_kinds(ns)
    grace(ns)
    esc3(ns)

    trig_old = ('if not present and inv_type in (\'evpn_mac_route_present\', \'evpn_mac_route_absent\', '
                '\'evpn_mac_route_valid\'):')
    # the trigger, as the engine writes it
    trig_src = ('            if not present and inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent", '
                '"evpn_mac_route_valid"):\n')
    m = mutant(engine_src, trig_src, trig_src.replace(', "evpn_mac_route_valid"', ""))
    if check("FQ-NV the text-leg trigger is found once in run_invariant_test", m is not None, trig_old):
        held = quiet(esc3, m)
        if not held:
            print("MUTATION-FAIL: evpn_mac_route_valid dropped from the text-leg trigger -> FQ-ESC3 red")
        check("FQ-NV the kind dropped from the text-leg trigger: FQ-ESC3 goes red", not held)
    guard = '            if verdict == "fail":\n                # WI-1 Patch 4 (D06)'
    m = mutant(engine_src, guard, '            if True:\n                # WI-1 Patch 4 (D06)')
    if check("FQ-NV the route branch's observed_state guard is found once", m is not None):
        held = quiet(quadrants, m, "evpn_mac_route_present", "(mutant)")
        if not held:
            print("MUTATION-FAIL: observed_state emitted on every verdict -> Q1/Q3 red")
        check("FQ-NV observed_state emitted on every verdict: the Q1/Q3 legs go red", not held)

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_four_quadrant_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_four_quadrant_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
