#!/usr/bin/env python3
"""bgp_as_path_replay_determinism_proof.py -- §4.11 WI-2 DET-1 replay proof (P13).

Proves replay-determinism of the bgp_as_path record path:

  A  RECORD-BRANCH REPLAY: the shipped run_invariant_test body (AST-extracted,
     eval stubbed) produces byte-identical observed_state + verdict across replay
     of identical captured state (modulo wall-clock duration_ms).
  B  PATH-ORDER VERBATIM (NEVER sorted) + replay-identical: actual_as_path in the
     present-half dict preserves AS path order exactly and is order-SIGNIFICANT
     (distinct order -> distinct value), unlike the sorted bgp_community analog.
  C  FINALIZE PRESERVATION: _observed_state_finalize_in_results preserves the
     bgp_as_path (kind=invariant) fail observed_state byte-unchanged, and is itself
     replay-deterministic (so the present-half survives to rendering).
  D  EVAL-HELPER DETERMINISM: _route_as_path is replay-identical and order-verbatim.

Mirrors bgp_community_replay_determinism_proof. Non-vacuity: distinct observed state
yields distinct serialized output (the replay equality is not a trivial constant).

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
import cassian_nos_frr as F  # noqa: E402  # §4.5-c WI-5: route extractors are provider-homed (§4.5-b B')
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


def _stub(observed_as_path, route_present=True, rc=0):
    def s(*, inv_type, t, src):
        return (rc == 0, route_present,
                {"norm_prefix": str(t.get("_norm_prefix") or ""), "route_present": route_present,
                 "observed_as_path": observed_as_path},
                {"cmd": "vtysh -c 'show ip bgp json'", "rc": rc, "parse_error": "", "empty_first_doc": False})
    return s


def run_rec(observed_as_path, *, as_path_pat="_65001_", expect="pass", route_present=True):
    _ns["_evaluate_invariant_attempt"] = _stub(observed_as_path, route_present)
    cap = {}
    t = {"type": "bgp_as_path", "node": "r2", "prefix": "1.1.1.1/32",
         "as_path": as_path_pat, "expect": expect}
    rit("t1", "r2", t, lambda **kw: cap.update(kw))
    return cap


def serialize(observed_as_path, **kw):
    cap = run_rec(observed_as_path, **kw)
    cap.pop("duration_ms", None)  # wall-clock; normalized for replay comparison
    return json.dumps(cap, sort_keys=True, default=str)


# ---- A: record-branch replay byte-identity ----
check("replay byte-identical (fail / present-half dict)",
      serialize("65999", as_path_pat="_65001_", route_present=True)
      == serialize("65999", as_path_pat="_65001_", route_present=True))
check("replay byte-identical (pass / observed_state None)",
      serialize("65001", as_path_pat="_65001_")
      == serialize("65001", as_path_pat="_65001_"))
check("replay byte-identical (anchored fail)",
      serialize("65001 65002", as_path_pat="^65002")
      == serialize("65001 65002", as_path_pat="^65002"))

# ---- B: actual_as_path path-order verbatim (NEVER sorted) + order-significant ----
cap_a = run_rec("65003 65001 65002", as_path_pat="_65999_")  # observed fail (path present, no match)
os_a = cap_a["observed_state"]
check("actual_as_path verbatim path-order (NOT sorted)", os_a["actual_as_path"] == "65003 65001 65002")
cap_b = run_rec("65003 65001 65002", as_path_pat="_65999_")
check("actual_as_path replay-identical", os_a["actual_as_path"] == cap_b["observed_state"]["actual_as_path"])
cap_c = run_rec("65001 65002 65003", as_path_pat="_65999_")  # same AS set, different order
check("actual_as_path order-SIGNIFICANT (distinct order -> distinct value)",
      os_a["actual_as_path"] != cap_c["observed_state"]["actual_as_path"])

# ---- C: finalize preserves bgp_as_path present-half byte-unchanged + replay-deterministic ----
fin = E._observed_state_finalize_in_results
present_half = {"type": "bgp_as_path", "prefix": "1.1.1.1/32",
                "expected_as_path": "_65001_", "actual_as_path": "65999",
                "route_present": True, "source_node": "r2"}
res = {"tests": [{"name": "ap_fail", "kind": "invariant", "verdict": "fail",
                  "observed_state": copy.deepcopy(present_half)}]}
fin(res)
check("finalize PRESERVES bgp_as_path invariant-fail observed_state",
      "observed_state" in res["tests"][0])
check("finalize byte-unchanged (== input, no truncation flag)",
      res["tests"][0].get("observed_state") == present_half
      and not res["tests"][0].get("observed_state_truncated"))
r1 = {"tests": [{"name": "ap", "kind": "invariant", "verdict": "fail", "observed_state": copy.deepcopy(present_half)}]}
r2 = copy.deepcopy(r1)
fin(r1); fin(r2)
check("finalize replay identical serialized bytes",
      json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True))

# ---- D: eval-helper _route_as_path determinism + order-verbatim ----
def observed_p(route_obj):
    return F._route_as_path(route_obj)
R1 = {"paths": [{"aspath": {"string": "65001 65002 65003"}}]}
R2 = {"paths": [{"aspath": {"string": "65003 65002 65001"}}]}
check("_route_as_path replay-identical", observed_p(R1) == observed_p(R1))
check("_route_as_path path-order verbatim", observed_p(R1) == "65001 65002 65003")
check("_route_as_path order-significant (distinct order -> distinct)", observed_p(R1) != observed_p(R2))

# ---- Non-vacuity: distinct observed state -> distinct present-half ----
check("NV distinct observed -> distinct present-half (not a trivial constant)",
      run_rec("65999", as_path_pat="_65001_", route_present=True)["observed_state"]["actual_as_path"]
      != run_rec("65888", as_path_pat="_65001_", route_present=True)["observed_state"]["actual_as_path"])

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
