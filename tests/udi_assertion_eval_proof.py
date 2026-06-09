#!/usr/bin/env python3
"""udi_assertion_eval_proof.py -- WI-3 / Amendment A7 assertion-evaluation proof.

Proves the ruled evaluation algorithm (A7 sec2/sec3/sec4) and the A7 schema
refinements (field list-form path, count/matches regex-compile rejection):

  RUNTIME (cassian_engine._eval_exec_assertion):
    - per-operator semantics: contains/not_contains/equals/matches/count/field
    - field list-form traversal; missing-segment / non-dict-descent / bad-JSON -> fail
    - type-coercion: typed == (str/num/bool, mismatch -> non-match); >=,<= numeric-only
    - every failure-to-evaluate is a Cassian-owned ("fail", <reason>), never a raise
  VALIDATE-TIME (cassian_model._validate_exec_assertion):
    - field.path must be a non-empty list of literal segments (string path rejected)
    - count.pattern / matches must compile (uncompilable rejected at validate time)

Refines SCHEMA-3 / VALIDATE-2 / EXEC-2 (no new Req-ID). Non-vacuity asserted at end.
"""
import os, sys, json

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E
import cassian_model as M
try:
    import cassian_common as C
    if hasattr(C, "_QUIET_DIE"):
        C._QUIET_DIE = True
except Exception:
    pass

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))

ev = E._eval_exec_assertion
JSON = json.dumps({"peers": {"10.0.0.1": {"state": "Established", "uptime": 42, "up": True}}})

# ---- A: per-operator semantics (observed derivation) ----
matrix = [
    ("contains hit",  {"contains": "Estab"}, "xEstabx", "pass"),
    ("contains miss", {"contains": "ZZZ"}, "xEstabx", "fail"),
    ("not_contains hit",  {"not_contains": "ZZZ"}, "abc", "pass"),
    ("not_contains miss", {"not_contains": "abc"}, "abc", "fail"),
    ("equals strip match", {"equals": "ok"}, "  ok\n", "pass"),
    ("equals mismatch", {"equals": "ok"}, "no", "fail"),
    ("matches hit", {"matches": r"Est\w+"}, "Established", "pass"),
    ("matches miss", {"matches": r"^ZZZ$"}, "abc", "fail"),
    ("count == hit", {"count": {"pattern": "x", "op": "==", "value": 3}}, "xxx", "pass"),
    ("count == miss", {"count": {"pattern": "x", "op": "==", "value": 2}}, "xxx", "fail"),
    ("count >= hit", {"count": {"pattern": "x", "op": ">=", "value": 2}}, "xxx", "pass"),
    ("count <= miss", {"count": {"pattern": "x", "op": "<=", "value": 2}}, "xxx", "fail"),
    ("field == str hit", {"field": {"path": ["peers", "10.0.0.1", "state"], "op": "==", "value": "Established"}}, JSON, "pass"),
    ("field == str miss", {"field": {"path": ["peers", "10.0.0.1", "state"], "op": "==", "value": "Idle"}}, JSON, "fail"),
    ("field == num hit", {"field": {"path": ["peers", "10.0.0.1", "uptime"], "op": "==", "value": 42}}, JSON, "pass"),
    ("field >= num hit", {"field": {"path": ["peers", "10.0.0.1", "uptime"], "op": ">=", "value": 40}}, JSON, "pass"),
    ("field <= num miss", {"field": {"path": ["peers", "10.0.0.1", "uptime"], "op": "<=", "value": 10}}, JSON, "fail"),
]
for name, a, out, want in matrix:
    check(f"A {name} -> {want}", ev(a, out)[0] == want)

# ---- B: field list-traversal failure-to-evaluate (Cassian-owned fail) ----
check("B field missing segment -> fail", ev({"field": {"path": ["peers", "9.9.9.9", "state"], "op": "==", "value": "x"}}, JSON)[0] == "fail")
check("B field non-dict descent -> fail", ev({"field": {"path": ["peers", "10.0.0.1", "state", "deep"], "op": "==", "value": "x"}}, JSON)[0] == "fail")
check("B field unparseable JSON -> fail", ev({"field": {"path": ["a"], "op": "==", "value": "x"}}, "not json")[0] == "fail")
check("B failure-to-evaluate carries a reason", ev({"field": {"path": ["a"], "op": "==", "value": "x"}}, "not json")[1] != "")
check("B field traversal never raises (returns tuple)", isinstance(ev({"field": {"path": ["x"]*50, "op": "==", "value": 1}}, JSON), tuple))

# ---- C: type-coercion (A7 sec4) ----
check("C == typed: num vs str-num -> non-match", ev({"field": {"path": ["peers", "10.0.0.1", "uptime"], "op": "==", "value": "42"}}, JSON)[0] == "fail")
check("C == typed: bool vs bool hit", ev({"field": {"path": ["peers", "10.0.0.1", "up"], "op": "==", "value": True}}, JSON)[0] == "pass")
check("C == typed: bool vs 1 -> non-match", ev({"field": {"path": ["b"], "op": "==", "value": True}}, json.dumps({"b": 1}))[0] == "fail")
check("C ordering on non-numeric value -> fail", ev({"field": {"path": ["peers", "10.0.0.1", "state"], "op": ">=", "value": 5}}, JSON)[0] == "fail")
check("C ordering numeric ok", ev({"field": {"path": ["peers", "10.0.0.1", "uptime"], "op": ">=", "value": 42}}, JSON)[0] == "pass")

# ---- D: validate-time schema rejections (M1/M2) ----
def rejected(assertion):
    try:
        M._validate_exec_assertion(assertion, "ctx")
        return False
    except SystemExit:
        return True
check("D string field.path REJECTED (A7 list-form)", rejected({"field": {"path": "a.b", "op": "==", "value": "x"}}))
check("D list field.path ACCEPTED", not rejected({"field": {"path": ["a", "b"], "op": "==", "value": "x"}}))
check("D empty-list field.path REJECTED", rejected({"field": {"path": [], "op": "==", "value": "x"}}))
check("D non-string segment REJECTED", rejected({"field": {"path": ["a", 7], "op": "==", "value": "x"}}))
check("D uncompilable count.pattern REJECTED", rejected({"count": {"pattern": "(", "op": "==", "value": 1}}))
check("D valid count ACCEPTED", not rejected({"count": {"pattern": "Up", "op": ">=", "value": 1}}))
check("D uncompilable matches REJECTED (regression)", rejected({"matches": "("}))

# ---- Non-vacuity: flipping the predicate flips the observation ----
_a = {"contains": "GOOD"}
check("NV non-vacuous: same op, hit vs miss differ", ev(_a, "GOOD")[0] == "pass" and ev(_a, "nope")[0] == "fail")

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
