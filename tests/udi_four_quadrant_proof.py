#!/usr/bin/env python3
"""udi_four_quadrant_proof.py -- WI-3 four-quadrant verdict proof (EXEC-2/VERDICT-1/2).

run_exec_test is a nested closure in cmd_test, so this proof extracts its ACTUAL body
via AST and executes it against mock runtimes -- a faithful behavioral test of the
shipped code (not a reimplementation). It proves:

  - the four quadrants: verdict = "pass" iff observed == expected (expect-fail first-class)
  - additions-only record: meta.exec={command,assertion}; bounded evidence
    {stdout,stderr,returncode,truncated} (deterministic 4096 truncation);
    observed_state dict on fail, None on pass
  - runtime backends: rt.exec returning str OR CompletedProcess; bytes stdout decoded
  - timeout / exec exception -> Cassian-owned observed: fail (never a crash)

Non-vacuity: the source verdict idiom is pinned, and a deliberately-mismatched
expectation is shown to flip the verdict.
"""
import os, sys, ast, json, subprocess, textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))

# ---- extract the actual run_exec_test body and bind it as a callable ----
_engine_src = open(os.path.join(_SRC, "cassian_engine.py"), "r", encoding="utf-8").read()
_tree = ast.parse(_engine_src)
_node = next((n for n in ast.walk(_tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_exec_test"), None)
check("run_exec_test located in engine", _node is not None)
_body = "\n".join(ast.unparse(s) for s in _node.body)
# Pin the idiom against the RAW source (ast.unparse normalizes quotes, so grep raw, not _body).
check("verdict idiom present (four-quadrant)", 'verdict = "pass" if observed == expected else "fail"' in _engine_src)
_fn_src = "def _hbody(rt, lab, src, t, test_name, record_fn):\n" + textwrap.indent(_body, "    ")
_ns = dict(E.__dict__)
exec(_fn_src, _ns)
hbody = _ns["_hbody"]


class MockRT:
    def __init__(self, out, mode="cp", rc=0):
        self.out, self.mode, self.rc = out, mode, rc
    def exec(self, lab, node, cmd, *, check=False, capture_output=True, interactive=False, timeout_s=None):
        if self.mode == "timeout":
            raise subprocess.TimeoutExpired(cmd, timeout_s)
        if self.mode == "str":
            return self.out
        return subprocess.CompletedProcess(cmd, self.rc, stdout=self.out, stderr="")


def run(out, expect, mode="cp"):
    cap = {}
    def record_fn(**kw):
        cap.update(kw)
    t = {"kind": "exec", "src": "r1", "command": 'vtysh -c "show x"',
         "assertion": {"contains": "GOOD"}, "expect": expect}
    v = hbody(MockRT(out, mode), "lab1", "r1", t, "t1", record_fn)
    return v, cap

# ---- four quadrants (observed=pass when stdout contains GOOD) ----
v, r = run("xGOODx", "pass"); check("Q1 observed=pass expect=pass -> pass", v == "pass" and r["verdict"] == "pass")
v, r = run("xGOODx", "fail"); check("Q2 observed=pass expect=fail -> fail", v == "fail" and r["verdict"] == "fail")
v, r = run("xBADx", "pass");  check("Q3 observed=fail expect=pass -> fail", v == "fail" and r["verdict"] == "fail")
v, r = run("xBADx", "fail");  check("Q4 observed=fail expect=fail -> pass (expect-fail)", v == "pass" and r["verdict"] == "pass")

# ---- additions-only record surface ----
v, r = run("xBADx", "pass")
check("record kind=exec", r.get("kind") == "exec")
check("record meta.exec={command,assertion}", r.get("meta", {}).get("exec") == {"command": 'vtysh -c "show x"', "assertion": {"contains": "GOOD"}})
check("record evidence keys", set(["stdout", "stderr", "returncode", "truncated"]) <= set(r.get("evidence", {})))
check("observed_state dict on fail", isinstance(r.get("observed_state"), dict))
v, r = run("xGOODx", "pass")
check("observed_state None on pass", r.get("observed_state") is None)

# ---- backends ----
v, _ = run("xGOODx", "pass", mode="str"); check("backend: rt.exec returns str", v == "pass")
v, _ = run(b"xGOODx", "pass", mode="cp"); check("backend: bytes stdout decoded", v == "pass")

# ---- deterministic evidence truncation ----
v, r = run("G" * 5000, "pass")  # 'GOOD' absent -> observed fail
check("evidence truncated deterministically at 4096", r["evidence"]["truncated"] is True and len(r["evidence"]["stdout"]) == 4096)

# ---- timeout / exec exception -> Cassian-owned fail ----
v, r = run("", "pass", mode="timeout")
check("timeout -> observed/verdict fail (Cassian-owned)", v == "fail" and r["verdict"] == "fail")
check("timeout reason recorded in observed_state", "eval_error" in (r.get("observed_state") or {}))

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
