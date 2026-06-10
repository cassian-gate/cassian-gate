#!/usr/bin/env python3
"""udi_render_boundary_proof.py -- WI-4 render-boundary proof (RENDER-1/2/3, EXEC-3).

SP #1 render-boundary pattern: drives _format_test_summary with synthetic results
(no deploy/runtime) and asserts the rendered summary text.

  RENDER-1  a failed exec record renders a §13(b)(c) block (not silently dropped)
  RENDER-2  identity sourced from meta.exec (command + assertion); expectation; and
            observed_state via _format_observed_state_block
  EXEC-3    the present-path renderer fires on the dict observed_state
  RENDER-3  the kind == "invariant" render path is byte-unchanged; non-invariant/
            non-exec kinds (ping) get no observed block (R27 preserved)
  F-1       §13(c) absence-clause symmetry: a failed exec on the observed:pass x
            expect:fail quadrant (non-dict observed_state) renders an EXPLICIT
            structured-detail-unavailable indicator, not an implicitly-absent (c)
  silence != pass: a failed exec is present in failed_tests

Non-vacuity: a passing exec is NOT rendered as a failure; the F-1 absence check
fails on a pre-Fix-B tree (no explicit unavailable indicator).
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_tests as T

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))


def _rec(**kw):
    return kw

def _exec_fail():
    return _rec(name="exec_fail_t", kind="exec", **{"from": "r1", "to": ""},
               expected="pass", verdict="fail",
               error="exec assertion not satisfied (observed fail, expected pass)",
               meta={"exec": {"command": 'vtysh -c "show ip route"', "assertion": {"contains": "0.0.0.0/0"}}},
               observed_state={"command": 'vtysh -c "show ip route"', "returncode": 0, "stdout_excerpt": "no default route"})

def _exec_expectfail_observedpass():
    # F-1 Q2: observed:pass x expect:fail -> verdict:fail with NO observed_state.
    # The command ran and the assertion held (observed:pass), but the operator
    # declared expect:fail, so the verdict is fail and there is no failure-state
    # payload. observed_state is deliberately absent on this record.
    return _rec(name="exec_q2_t", kind="exec", **{"from": "r1", "to": ""},
                expected="fail", verdict="fail",
                error="exec assertion not satisfied (observed pass, expected fail)",
                meta={"exec": {"command": 'vtysh -c "show bgp summary json"', "assertion": {"contains": "Established"}}})

def _exec_pass():
    return _rec(name="exec_pass_t", kind="exec", **{"from": "r1", "to": ""},
                expected="pass", verdict="pass",
                meta={"exec": {"command": 'nft list ruleset', "assertion": {"contains": "drop"}}})

def _inv_fail():
    return _rec(name="inv_fail_t", kind="invariant", **{"from": "r2", "to": ""},
                expected="pass", verdict="fail", error="bgp_session_up mismatch",
                meta={"type": "bgp_session_up", "peer": "10.0.0.2"},
                observed_state={"state": "Idle", "peer": "10.0.0.2"})

def _ping_fail():
    return _rec(name="ping_fail_t", kind="ping", **{"from": "h1", "to": "h2"},
                expected="pass", verdict="fail", error="100% loss",
                observed_state={"loss": "100%"})

def summary(tests):
    res = {"lab": "demo", "summary": {"total": len(tests), "passed": 0, "failed": sum(1 for t in tests if t["verdict"] == "fail")},
           "tests": tests, "scenarios": [], "events": []}
    return T._format_test_summary(res)

# ---- RENDER-1 / RENDER-2 / EXEC-3: failed exec renders (a)/(b)/(c) ----
s = summary([_exec_fail()])
check("RENDER-1 failed exec present in failed_tests (silence != pass)", "exec_fail_t (exec)" in s)
check("RENDER-2 (a) identity command from meta.exec", 'command: vtysh -c "show ip route"' in s)
check("RENDER-2 (a) identity assertion from meta.exec (canonical JSON)", '"contains": "0.0.0.0/0"' in s)
check("RENDER-2 (b) expectation rendered", "expected: pass" in s)
check("EXEC-3 (c) observed_state block fires (present path)", "    observed:" in s and "stdout_excerpt:" in s)
check("exec header block present", "    exec:" in s)

# ---- F-1 (Fix-B): §13(c) absence-clause symmetry on the observed:pass x expect:fail quadrant ----
s_q2 = summary([_exec_expectfail_observedpass()])
check("F-1 Q2 failed exec present in failed_tests (silence != pass)", "exec_q2_t (exec)" in s_q2)
check("F-1 Q2 exec header + identity rendered", "    exec:" in s_q2 and '"contains": "Established"' in s_q2)
check("F-1 Q2 (b) expectation rendered (expected: fail)", "expected: fail" in s_q2)
check("F-1 Q2 (c) EXPLICIT unavailable indicator, not implicitly-absent",
      "structured failure detail unavailable" in s_q2)
check("F-1 Q2 (c) absence emits explicit observed: section (symmetric with invariant path)",
      "    observed:" in s_q2)

# ---- RENDER-3: invariant render path byte-unchanged (exec branch does not interfere) ----
s_inv = summary([_inv_fail()])
check("RENDER-3 invariant fail still renders observed block", "    observed:" in s_inv and "state:" in s_inv)
check("RENDER-3 invariant render has no exec header", "    exec:" not in s_inv)
check("RENDER-3 invariant absence wording unchanged (present-path inv has dict, so not triggered here)",
      "for this invariant type" not in s_inv)  # this inv_fail has a dict observed_state

# ---- R27 preserved: non-invariant/non-exec kind gets no observed block ----
s_ping = summary([_ping_fail()])
check("R27 ping fail present in failed_tests", "ping_fail_t (ping)" in s_ping)
check("R27 ping fail gets NO observed block", "    observed:" not in s_ping and "    exec:" not in s_ping)

# ---- mixed: exec + invariant render independently in one summary ----
s_mix = summary([_exec_fail(), _inv_fail()])
check("mixed: exec block present", "    exec:" in s_mix)
check("mixed: invariant observed block present", "state: Idle" in s_mix)

# ---- Non-vacuity: a passing exec is not rendered as a failure ----
s_pass = summary([_exec_pass()])
check("NV passing exec not in failed_tests", "exec_pass_t" not in s_pass)
check("NV no exec block for an all-pass summary", "    exec:" not in s_pass)

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
