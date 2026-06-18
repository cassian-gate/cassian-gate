#!/usr/bin/env python3
"""bgp_community_replay_determinism_proof.py -- §4.10 WI-2 DET-1 replay proof (P14).

Proves replay-determinism of the bgp_community record path:

  A  RECORD-BRANCH REPLAY: the shipped run_invariant_test body (AST-extracted,
     eval stubbed) produces byte-identical observed_state + verdict across replay
     of identical captured state (modulo wall-clock duration_ms).
  B  SORTED + ORDER-INDEPENDENT: actual_communities in the present-half dict is
     emitted sorted and is invariant to observed-token input order.
  C  FINALIZE PRESERVATION: _observed_state_finalize_in_results preserves the
     bgp_community (kind=invariant) fail observed_state byte-unchanged, and is
     itself replay-deterministic (so the present-half survives to rendering).
  D  EVAL-HELPER DETERMINISM: the canonical observed set is replay-identical and
     order-independent.

Mirrors udi_replay_determinism_proof. Non-vacuity: distinct observed state yields
distinct serialized output (the replay equality is not a trivial constant).

Exit 0 on all-pass; exit 1 on first failure.
"""
import os
import sys
import ast
import json
import copy
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

# ---- extract the shipped run_invariant_test body; bind with eval stub + fake time ----
_engine_src = open(os.path.join(_SRC, "cassian_engine.py"), "r", encoding="utf-8").read()
_node = next((n for n in ast.walk(ast.parse(_engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test"), None)
check("run_invariant_test located in engine", _node is not None)
_body = "\n".join(ast.unparse(s) for s in _node.body)

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


def _stub(observed_communities, route_present=True, rc=0):
    # NOTE: returns observed_communities AS GIVEN (unsorted) so Section B proves
    # the RECORD BRANCH sorts, not the stub.
    def s(*, inv_type, t, src):
        last_state = {"norm_prefix": str(t.get("_norm_prefix") or ""),
                      "route_present": route_present,
                      "observed_communities": list(observed_communities)}
        last_evidence = {"cmd": "vtysh -c 'show ip bgp json'", "rc": rc,
                         "parse_error": "", "empty_first_doc": False}
        return (rc == 0, route_present, last_state, last_evidence)
    return s


def run_rec(observed_communities, *, expected_spec="65000:100", match=None,
            expect="pass", route_present=True):
    _ns["_evaluate_invariant_attempt"] = _stub(observed_communities, route_present)
    cap = {}
    t = {"type": "bgp_community", "node": "r2", "prefix": "1.1.1.1/32",
         "expected": expected_spec, "match": match, "expect": expect}
    rit("t1", "r2", t, lambda **kw: cap.update(kw))
    return cap


def serialize(observed_communities, **kw):
    cap = run_rec(observed_communities, **kw)
    cap.pop("duration_ms", None)  # wall-clock; normalized for replay comparison
    return json.dumps(cap, sort_keys=True, default=str)


# ---- A: record-branch replay byte-identity ----
check("replay byte-identical (fail / present-half dict)",
      serialize([], expected_spec="65000:100", route_present=True)
      == serialize([], expected_spec="65000:100", route_present=True))
check("replay byte-identical (pass / observed_state None)",
      serialize(["65000:100"], expected_spec="65000:100")
      == serialize(["65000:100"], expected_spec="65000:100"))
check("replay byte-identical (list-all fail)",
      serialize(["65000:100"], expected_spec=["65000:100", "no-export"], match="all")
      == serialize(["65000:100"], expected_spec=["65000:100", "no-export"], match="all"))

# ---- B: actual_communities sorted + order-independent (record branch sorts) ----
cap_a = run_rec(["no-export", "65000:100", "internet"], expected_spec="65111:9")  # observed fail
os_a = cap_a["observed_state"]
check("actual_communities emitted sorted", os_a["actual_communities"] == sorted(os_a["actual_communities"]))
cap_b = run_rec(["internet", "65000:100", "no-export"], expected_spec="65111:9")  # same set, diff order
check("actual_communities order-independent",
      os_a["actual_communities"] == cap_b["observed_state"]["actual_communities"])
check("actual_communities value correct", os_a["actual_communities"] == ["65000:100", "internet", "no-export"])

# ---- C: finalize preserves bgp_community present-half byte-unchanged + replay-deterministic ----
fin = E._observed_state_finalize_in_results
present_half = {"type": "bgp_community", "prefix": "1.1.1.1/32",
                "expected_communities": ["65000:100"], "actual_communities": [],
                "match": "", "route_present": True, "source_node": "r2"}
res = {"tests": [{"name": "bc_fail", "kind": "invariant", "verdict": "fail",
                  "observed_state": copy.deepcopy(present_half)}]}
fin(res)
check("finalize PRESERVES bgp_community invariant-fail observed_state",
      "observed_state" in res["tests"][0])
check("finalize byte-unchanged (== input, no truncation flag)",
      res["tests"][0].get("observed_state") == present_half
      and "observed_state_truncated" not in res["tests"][0])
r1 = {"tests": [{"name": "bc", "kind": "invariant", "verdict": "fail", "observed_state": copy.deepcopy(present_half)}]}
r2 = copy.deepcopy(r1)
fin(r1); fin(r2)
check("finalize replay identical serialized bytes",
      json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True))

# ---- D: eval-helper canonical observed set determinism + order-independence ----
def observed_set(route_obj):
    return sorted({E._canonical_community_token(t) for t in E._route_communities(route_obj)})
R1 = {"community": {"list": ["internet", "65000:100", "noExport"]}}
R2 = {"community": {"list": ["noExport", "65000:100", "internet"]}}
check("observed_set replay-identical", observed_set(R1) == observed_set(R1))
check("observed_set order-independent (sorted canonical set)", observed_set(R1) == observed_set(R2))
check("observed_set value sorted-canonical", observed_set(R1) == ["65000:100", "internet", "no-export"])

# ---- Non-vacuity: distinct observed state -> distinct serialized output ----
check("NV distinct observed -> distinct present-half (not a trivial constant)",
      run_rec([], expected_spec="65000:100", route_present=True)["observed_state"]["actual_communities"]
      != run_rec(["65000:100", "no-export"], expected_spec="65111:9", route_present=True)["observed_state"]["actual_communities"])

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
