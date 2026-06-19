#!/usr/bin/env python3
"""bgp_as_path_authority_parity_proof.py -- §4.11 WI-2 AUTH-1 record-parity proof (P14).

Proves the bgp_as_path invariant record shape is identical, at the authority
contract level, to an existing invariant record (the bgp_localpref_equals analog --
the direct structural twin; same per-prefix BGP-attribute family). Both branches
are driven through the SAME AST-extracted run_invariant_test body (eval stubbed),
and their captured records are compared live (no hand-coded reference shape):

  - top-level record_fn kwargs key-set IDENTICAL (name/kind/src/dst/expected/
    observed/verdict/duration_ms/error/evidence/meta/observed_state)
  - kind == "invariant"; dst == ""; expected mirrors the expect field
  - observed_state: dict on fail, None on pass (same convention)
  - present-half convention: {type, prefix, source_node} present, plus exactly one
    expected_* and one actual_* field (the attribute-specific pair)
  - evidence convention {cmd, rc, prefix}; meta convention {type, prefix}
  - the bgp_as_path record branch invokes the shared record_fn (no bespoke recorder)

Non-vacuity: a deliberately divergent record (extra key) breaks parity.

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

# ---- extract the shipped run_invariant_test body ----
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


def _stub_ap(observed_as_path, route_present=True, rc=0):
    def s(*, inv_type, t, src):
        return (rc == 0, route_present,
                {"norm_prefix": str(t.get("_norm_prefix") or ""), "route_present": route_present,
                 "observed_as_path": observed_as_path},
                {"cmd": "vtysh -c 'show ip bgp json'", "rc": rc, "parse_error": "", "empty_first_doc": False})
    return s


def _stub_lp(observed_localpref, rc=0):
    def s(*, inv_type, t, src):
        return (rc == 0, True, {"observed_localpref": observed_localpref}, {"rc": rc, "parse_error": ""})
    return s


def run_ap(observed_as_path, as_path_pat, expect, *, route_present=True):
    _ns["_evaluate_invariant_attempt"] = _stub_ap(observed_as_path, route_present)
    cap = {}
    t = {"type": "bgp_as_path", "node": "r2", "prefix": "1.1.1.1/32",
         "as_path": as_path_pat, "expect": expect}
    rit("t1", "r2", t, lambda **kw: cap.update(kw))
    return cap


def run_lp(observed_localpref, expected_val, expect):
    _ns["_evaluate_invariant_attempt"] = _stub_lp(observed_localpref)
    cap = {}
    t = {"type": "bgp_localpref_equals", "node": "r2", "prefix": "1.1.1.1/32",
         "expected": expected_val, "expect": expect}
    rit("t1", "r2", t, lambda **kw: cap.update(kw))
    return cap


# captured records: fail (present-half) + pass (no observed_state) for both types
ap_fail = run_ap("65999", "_65001_", "pass", route_present=True)   # path mismatch -> fail
ap_pass = run_ap("65001", "_65001_", "pass")                       # matched -> pass
lp_fail = run_lp(50, 100, "pass")                                  # 50 != 100 -> fail
lp_pass = run_lp(100, 100, "pass")                                 # 100 == 100 -> pass

CONTRACT = {"name", "kind", "src", "dst", "expected", "observed", "verdict",
            "duration_ms", "error", "evidence", "meta", "observed_state"}

# ---- top-level kwargs key-set parity ----
check("bgp_as_path fail record kwargs == authority contract", set(ap_fail) == CONTRACT)
check("localpref fail record kwargs == authority contract", set(lp_fail) == CONTRACT)
check("bgp_as_path kwargs key-set == localpref kwargs key-set (PARITY)", set(ap_fail) == set(lp_fail))
check("bgp_as_path pass record kwargs == contract", set(ap_pass) == CONTRACT)

# ---- authority field conventions ----
check("kind == invariant (both)", ap_fail["kind"] == "invariant" and lp_fail["kind"] == "invariant")
check("dst == '' (node-local invariants, both)", ap_fail["dst"] == "" and lp_fail["dst"] == "")
check("expected mirrors expect field (both)", ap_fail["expected"] == "pass" and lp_fail["expected"] == "pass")
check("verdict/observed in {pass,fail} (both)",
      ap_fail["verdict"] in ("pass", "fail") and lp_fail["verdict"] in ("pass", "fail"))

# ---- observed_state convention: dict on fail, None on pass ----
check("observed_state dict on fail (both)",
      isinstance(ap_fail["observed_state"], dict) and isinstance(lp_fail["observed_state"], dict))
check("observed_state None on pass (both)",
      ap_pass["observed_state"] is None and lp_pass["observed_state"] is None)

# ---- present-half convention parity ----
def _exp_act(os_):
    return ([k for k in os_ if k.startswith("expected_")],
            [k for k in os_ if k.startswith("actual_")])
ap_os, lp_os = ap_fail["observed_state"], lp_fail["observed_state"]
check("present-half shared convention keys {type,prefix,source_node} (both)",
      {"type", "prefix", "source_node"} <= set(ap_os) and {"type", "prefix", "source_node"} <= set(lp_os))
ap_e, ap_a = _exp_act(ap_os)
lp_e, lp_a = _exp_act(lp_os)
check("present-half has exactly one expected_* + one actual_* (parity)",
      len(ap_e) == 1 and len(ap_a) == 1 and len(lp_e) == 1 and len(lp_a) == 1)
check("present-half type field names the invariant type",
      ap_os["type"] == "bgp_as_path" and lp_os["type"] == "bgp_localpref_equals")

# ---- evidence / meta conventions ----
check("evidence convention {cmd,rc,prefix} (both)",
      {"cmd", "rc", "prefix"} <= set(ap_fail["evidence"]) and {"cmd", "rc", "prefix"} <= set(lp_fail["evidence"]))
check("meta convention {type,prefix} (both)",
      {"type", "prefix"} <= set(ap_fail["meta"]) and {"type", "prefix"} <= set(lp_fail["meta"]))

# ---- source-pin: shared recorder, no bespoke record function in the branch ----
_rit_start = _engine_src.find("def run_invariant_test")
_ap_start = _engine_src.find('if inv_type == "bgp_as_path":', _rit_start)
_ap_branch = _engine_src[_ap_start:_engine_src.find("return verdict", _ap_start) + len("return verdict")]
check("bgp_as_path record branch invokes shared record_fn", "record_fn(" in _ap_branch)
check("bgp_as_path record branch defines no bespoke recorder", "\n            def " not in _ap_branch)

# ---- Non-vacuity: a divergent record breaks parity ----
_divergent = dict(ap_fail)
_divergent["bespoke_key"] = 1
check("NV non-vacuous: extra key breaks contract parity", set(_divergent) != CONTRACT)

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
