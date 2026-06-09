#!/usr/bin/env python3
"""udi_replay_determinism_proof.py -- WI-3 / Amendment A8 preservation + replay proof.

Proves the A8 observed_state guard widening (EXEC-3 / RENDER-2) and replay-stability:

  PRESERVATION byte-table (_observed_state_finalize_in_results):
    - invariant fail   -> observed_state PRESERVED (byte-unchanged; no spurious flags)
    - exec fail        -> observed_state PRESERVED (A8 delivery of EXEC-3)
    - exec pass        -> observed_state STRIPPED (matches invariant semantics)
    - ping/tcp/bgp_neighbor/route_prefix (any verdict) -> STRIPPED (unchanged)
  REPLAY determinism:
    - finalize is deterministic (same input -> identical serialized bytes)
    - the exec evaluator record is replay-stable modulo wall-clock duration_ms

Non-vacuity: the preserve-vs-strip contrast shows finalize actively discriminates.
"""
import os, sys, ast, json, copy, subprocess, textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))

fin = E._observed_state_finalize_in_results

def rec(kind, verdict, state=None):
    return {"name": f"{kind}_{verdict}", "kind": kind, "verdict": verdict,
            "observed_state": (state if state is not None else {"k": "v", "n": 1})}

# ---- A: preservation byte-table ----
results = {"tests": [
    rec("invariant", "fail"), rec("exec", "fail"), rec("exec", "pass"),
    rec("ping", "fail"), rec("tcp", "fail"),
    rec("bgp_neighbor", "fail"), rec("route_prefix", "fail"),
]}
inv_in = copy.deepcopy(results["tests"][0])
fin(results)
by = {r["name"]: r for r in results["tests"]}
check("invariant fail PRESERVES observed_state", "observed_state" in by["invariant_fail"])
check("invariant fail byte-unchanged (== input, no truncation flags)",
      by["invariant_fail"].get("observed_state") == inv_in["observed_state"]
      and "observed_state_truncated" not in by["invariant_fail"])
check("exec fail PRESERVES observed_state (A8/EXEC-3)", "observed_state" in by["exec_fail"])
check("exec PASS strips observed_state", "observed_state" not in by["exec_pass"])
for k in ("ping_fail", "tcp_fail", "bgp_neighbor_fail", "route_prefix_fail"):
    check(f"{k} strips observed_state (unchanged)", "observed_state" not in by[k])

# ---- B: deterministic truncation parity (invariant vs exec, oversized state) ----
big = {"blob": "Z" * 200000}
ri = {"tests": [rec("invariant", "fail", copy.deepcopy(big))]}
re_ = {"tests": [rec("exec", "fail", copy.deepcopy(big))]}
fin(ri); fin(re_)
check("oversized invariant fail truncates", ri["tests"][0].get("observed_state_truncated") is True)
check("oversized exec fail truncates identically",
      re_["tests"][0].get("observed_state_truncated") is True
      and ri["tests"][0].get("observed_state") == re_["tests"][0].get("observed_state"))

# ---- C: finalize replay determinism ----
r1 = {"tests": [rec("exec", "fail"), rec("invariant", "fail"), rec("ping", "fail")]}
r2 = copy.deepcopy(r1)
fin(r1); fin(r2)
check("finalize replay: identical serialized bytes",
      json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True))

# ---- D: exec evaluator record replay-stable modulo duration_ms ----
_engine_src = open(os.path.join(_SRC, "cassian_engine.py"), "r", encoding="utf-8").read()
_node = next((n for n in ast.walk(ast.parse(_engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_exec_test"), None)
_body = "\n".join(ast.unparse(s) for s in _node.body)
_ns = dict(E.__dict__)
exec("def _hbody(rt, lab, src, t, test_name, record_fn):\n" + textwrap.indent(_body, "    "), _ns)
hbody = _ns["_hbody"]

class MockRT:
    def __init__(self, out): self.out = out
    def exec(self, lab, node, cmd, *, check=False, capture_output=True, interactive=False, timeout_s=None):
        return subprocess.CompletedProcess(cmd, 0, stdout=self.out, stderr="")

def run_once():
    cap = {}
    t = {"kind": "exec", "src": "r1", "command": 'vtysh -c "show x"',
         "assertion": {"field": {"path": ["a"], "op": "==", "value": "no"}}, "expect": "pass"}
    hbody(MockRT(json.dumps({"a": "yes"})), "lab1", "r1", t, "t1", lambda **kw: cap.update(kw))
    cap.pop("duration_ms", None)  # wall-clock; normalized for replay comparison
    return json.dumps(cap, sort_keys=True)
check("exec record replay-stable (modulo duration_ms)", run_once() == run_once())

# ---- Non-vacuity: finalize actively discriminates (a pass record loses state a fail record keeps) ----
check("NV non-vacuous: exec fail keeps, exec pass drops (same state input)",
      "observed_state" in by["exec_fail"] and "observed_state" not in by["exec_pass"])

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
