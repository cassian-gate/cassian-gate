#!/usr/bin/env python3
"""bgp_as_path_four_quadrant_proof.py -- §4.11 WI-2 VERDICT-1 four-quadrant proof (P4-P5).

run_invariant_test is a nested closure in cmd_test, so -- exactly as the §4.10
bgp_community sibling does -- this proof extracts its ACTUAL body via AST and binds
it as a callable in the engine namespace (a faithful behavioral test of the shipped
bgp_as_path record branch, not a reimplementation). The sibling closure
`_evaluate_invariant_attempt` is stubbed so the harness controls the eval output
(observed_as_path / route_present / rc), driving the verdict seam:

    verdict = "pass" if observed == expected else "fail"

across the four quadrants, expect-fail first-class:

  Q1  observed=pass  expect=pass  -> verdict pass
  Q2  observed=pass  expect=fail  -> verdict fail   (P5: expect-fail, path matched)
  Q3  observed=fail  expect=pass  -> verdict fail
  Q4  observed=fail  expect=fail  -> verdict pass   (P4: expect-fail, path unmatched)

Also confirms the LD-4/B16 boundary through the shipped code: route-absent is a
graceful Cassian-owned fail (no SystemExit) -- here via the route-absent guard
(F-WI2-1); a genuine provider failure (rc != 0) raises SystemExit(2) (misuse).
Present-half dict emitted on fail, None on pass.

Non-vacuity: the seam idiom is pinned against raw source, and flipping `expect`
flips the verdict on identical observed state.

Exit 0 on all-pass; exit 1 on first failure.
"""
import os
import sys
import ast
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E  # noqa: E402
try:
    import cassian_common as C  # noqa: E402
    if hasattr(C, "_QUIET_DIE"):
        C._QUIET_DIE = True
except Exception:
    pass

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))

# ---- extract the actual run_invariant_test body and bind it as a callable ----
_engine_src = open(os.path.join(_SRC, "cassian_engine.py"), "r", encoding="utf-8").read()
_tree = ast.parse(_engine_src)
_node = next((n for n in ast.walk(_tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test"), None)
check("run_invariant_test located in engine", _node is not None)
_body = "\n".join(ast.unparse(s) for s in _node.body)
check("verdict seam idiom present (shared canonical)",
      'verdict = "pass" if observed == expected else "fail"' in _engine_src)

_ns = dict(E.__dict__)

class _FakeTime:
    @staticmethod
    def time():
        return 0.0
    @staticmethod
    def sleep(_s):
        return None
_ns["time"] = _FakeTime

exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(_body, "    "), _ns)
rit = _ns["_rit"]


def _make_eval_stub(observed_as_path, route_present=True, rc=0, empty_first_doc=False, parse_error=""):
    def _stub(*, inv_type, t, src):
        last_state = {
            "norm_prefix": str(t.get("_norm_prefix") or ""),
            "route_present": route_present,
            "observed_as_path": observed_as_path,
        }
        last_evidence = {
            "cmd": "vtysh -c 'show ip bgp json'",
            "rc": rc,
            "parse_error": parse_error,
            "empty_first_doc": empty_first_doc,
        }
        return (rc == 0, route_present, last_state, last_evidence)
    return _stub


def run_q(as_path_pat, observed_as_path, expect, *,
          route_present=True, rc=0, empty_first_doc=False):
    _ns["_evaluate_invariant_attempt"] = _make_eval_stub(
        observed_as_path, route_present, rc, empty_first_doc)
    cap = {}
    def record_fn(**kw):
        cap.update(kw)
    t = {"type": "bgp_as_path", "node": "r2", "prefix": "1.1.1.1/32",
         "as_path": as_path_pat, "expect": expect}
    v = rit("t1", "r2", t, record_fn)
    return v, cap


# ---- the four quadrants ----
v, r = run_q("_65001_", "65001", "pass")
check("Q1 observed=pass expect=pass -> pass", v == "pass" and r["verdict"] == "pass")
v, r = run_q("_65001_", "65001", "fail")
check("Q2/P5 observed=pass expect=fail -> fail (expect-fail, path matched)", v == "fail" and r["verdict"] == "fail")
v, r = run_q("_65001_", "65999", "pass", route_present=True)
check("Q3 observed=fail expect=pass -> fail", v == "fail" and r["verdict"] == "fail")
v, r = run_q("_65001_", "65999", "fail", route_present=True)
check("Q4/P4 observed=fail expect=fail -> pass (expect-fail, path unmatched)", v == "pass" and r["verdict"] == "pass")

# ---- anchored patterns through the same seam ----
v, r = run_q("^65001$", "65001", "pass")
check("anchored exact observed=pass expect=pass -> pass", v == "pass" and r["verdict"] == "pass")
v, r = run_q("^65002", "65001 65002", "fail")
check("anchored not-at-start observed=fail expect=fail -> pass", v == "pass" and r["verdict"] == "pass")
v, r = run_q("_65002_65003_", "65001 65002 65003", "pass")
check("sequential observed=pass expect=pass -> pass", v == "pass" and r["verdict"] == "pass")

# ---- LD-4/B16 + F-WI2-1: route-absent is a graceful Cassian-owned fail (NO SystemExit) ----
absent_graceful = True
try:
    v, r = run_q("_65001_", "", "pass", route_present=False)
    check("route-absent graceful (no SystemExit), verdict fail", v == "fail" and r["verdict"] == "fail")
except SystemExit:
    absent_graceful = False
    check("route-absent graceful (no SystemExit)", False)
v, r = run_q("_65001_", "", "fail", route_present=False)
check("route-absent + expect-fail -> pass (graceful)", v == "pass" and r["verdict"] == "pass")

# ---- genuine provider failure (rc != 0) -> SystemExit(2) misuse ----
misuse = False
try:
    run_q("_65001_", "", "pass", rc=2)
except SystemExit as e:
    misuse = (e.code == 2)
check("provider failure rc!=0 -> SystemExit(2) (misuse, not verdict)", misuse)

# ---- present-half dict on fail; None on pass ----
v, r = run_q("_65001_", "65999", "pass", route_present=True)  # observed fail, route present
os_ = r.get("observed_state")
check("present-half dict emitted on fail", isinstance(os_, dict) and os_.get("type") == "bgp_as_path")
check("present-half route_present True + actual populated (data-present-match-failed)",
      os_.get("route_present") is True and os_.get("actual_as_path") == "65999")
check("present-half expected_as_path reflects declared pattern", os_.get("expected_as_path") == "_65001_")
v, r = run_q("_65001_", "65001", "pass")  # observed pass
check("observed_state None on pass", r.get("observed_state") is None)

# ---- record surface parity spot-check (AUTH-1 adjacent) ----
v, r = run_q("_65001_", "65999", "pass")
check("record kind=invariant", r.get("kind") == "invariant")
check("record meta.type bgp_as_path", r.get("meta", {}).get("type") == "bgp_as_path")
check("record expected mirrors expect field", r.get("expected") == "pass")

# ---- Non-vacuity: flip expect flips verdict on identical observed ----
check("NV flip expect flips verdict on identical observed (matched)",
      run_q("_65001_", "65001", "pass")[0] == "pass"
      and run_q("_65001_", "65001", "fail")[0] == "fail")
check("NV flip expect flips verdict on identical observed (unmatched)",
      run_q("_65001_", "65999", "pass")[0] == "fail"
      and run_q("_65001_", "65999", "fail")[0] == "pass")

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
