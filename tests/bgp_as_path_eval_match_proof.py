#!/usr/bin/env python3
"""bgp_as_path_eval_match_proof.py -- §4.11 WI-2 EXEC-1 eval-match proof (P1-P3).

Lab-free. Mirrors bgp_community_eval_match_proof: the eval branch is a nested
closure (not importable), so the testable surface is the two module-level helpers
composed exactly as the branch composes them (engine predicate + record):

    observed_path = _route_as_path(route_obj)
    observed      = _bgp_as_path_observed(as_path_pattern, observed_path)

driven against the real-FRR captured shape (contrib/.../udi-bgp-variant/passing/
evidence/results.json:106 -> paths[].aspath.string asplain) and synthetic
variants. The AS_PATH is path-ordered and NEVER sorted (B08); the operator regex
honors LD-C `_`-translation (`_` -> (?:^| |$)) and explicit `^`/`$` anchors.

  P1  scalar/anchored pattern present -> pass
  P2  multi-AS path-ordered sequence match (order-significant) -> pass
  P3  route present, pattern unmatched -> pass->fail (present-half:
      route_present true, observed_path present-or-empty, match failed)

Exit 0 on all-pass; exit 1 on first failure. Non-vacuity asserted at end.
"""
import os
import sys

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


# --- exact branch composition, via the module-level helpers ---
def observed_path(route_obj):
    return E._route_as_path(route_obj)

def decide(route_obj, pattern):
    return E._bgp_as_path_observed(pattern, E._route_as_path(route_obj))


# --- captured live forms (paths[].aspath.string, asplain, path-order) ---
ROUTE_REAL = {  # results.json:106 real-capture shape (single AS)
    "prefix": "1.1.1.1/32",
    "paths": [{"aspath": {"string": "65001",
                          "segments": [{"type": "as-sequence", "list": [65001]}],
                          "length": 1}}],
}
ROUTE_MULTI = {  # multi-AS path
    "prefix": "10.0.0.0/24",
    "paths": [{"aspath": {"string": "65001 65002 65003", "length": 3}}],
}
ROUTE_TOP = {  # defensive top-level aspath mirror preferred over per-path
    "prefix": "10.0.0.0/24",
    "aspath": {"string": "65010 65020"},
    "paths": [{"aspath": {"string": "999"}}],
}
ROUTE_PRESENT_NO_PATH = {  # route present, no aspath attached (P3 present-half)
    "prefix": "10.0.0.0/24",
    "paths": [{"valid": True}],
}

# ---- extraction: asplain string, path-ordered, NEVER sorted ----
check("extract real-capture single AS -> '65001'", observed_path(ROUTE_REAL) == "65001")
check("extract multi-AS path-ordered (verbatim)", observed_path(ROUTE_MULTI) == "65001 65002 65003")
check("extract top-level aspath mirror preferred", observed_path(ROUTE_TOP) == "65010 65020")
check("extract NEVER sorted (order-significant)",
      observed_path({"paths": [{"aspath": {"string": "65003 65001 65002"}}]}) == "65003 65001 65002")
check("route present, no aspath -> empty observed path", observed_path(ROUTE_PRESENT_NO_PATH) == "")

# ---- P1: scalar / anchored pattern present -> pass ----
check("P1 _AS_ delimited present -> pass", decide(ROUTE_REAL, "_65001_") == "pass")
check("P1 ^AS$ exact single-AS -> pass", decide(ROUTE_REAL, "^65001$") == "pass")
check("P1 ^AS start-anchor on multi -> pass", decide(ROUTE_MULTI, "^65001") == "pass")
check("P1 AS$ end-anchor on multi -> pass", decide(ROUTE_MULTI, "65003$") == "pass")
check("P1 _AS_ middle element -> pass", decide(ROUTE_MULTI, "_65002_") == "pass")
check("P1 absent AS specifier -> fail", decide(ROUTE_REAL, "_65999_") == "fail")
check("P1 partial-AS rejected (_6500_ !~ 65001)", decide(ROUTE_REAL, "_6500_") == "fail")

# ---- P2: multi-AS path-ordered sequence (order-significant) ----
check("P2 sequential _A_B_ matches path order -> pass", decide(ROUTE_MULTI, "_65001_65002_") == "pass")
check("P2 reversed sequence does NOT match (order-significant) -> fail",
      decide(ROUTE_MULTI, "_65003_65001_") == "fail")
check("P2 ^A.*B$ spanning anchors -> pass", decide(ROUTE_MULTI, "^65001.*65003$") == "pass")
check("P2 ^B (not at start) -> fail", decide(ROUTE_MULTI, "^65002") == "fail")

# ---- P3: route present, pattern unmatched -> fail (present-half) ----
check("P3 route-present-no-path vs pattern -> fail", decide(ROUTE_PRESENT_NO_PATH, "_65001_") == "fail")
check("P3 route-present path mismatch -> fail", decide(ROUTE_MULTI, "_65999_") == "fail")
check("P3 present-half data: route_obj is a dict (route present)", isinstance(ROUTE_MULTI, dict))
check("P3 present-half data: observed_path populated (data-present)", observed_path(ROUTE_MULTI) != "")

# ---- determinism: identical route_obj -> identical observed path across replay ----
check("DET observed path replay-identical + order-verbatim",
      observed_path(ROUTE_MULTI) == observed_path(ROUTE_MULTI) == "65001 65002 65003")

# ---- LD-C `_`-translation pinned at helper boundary ----
check("LDC _ -> start/space/end (matches at boundaries)",
      decide({"paths": [{"aspath": {"string": "65001 65002"}}]}, "_65002_") == "pass")
check("LDC operator ^/$ preserved verbatim",
      decide(ROUTE_REAL, "^65002$") == "fail" and decide(ROUTE_REAL, "^65001$") == "pass")
check("malformed regex -> fail (defensive; resolve-time already rejects)",
      E._bgp_as_path_observed("(", "65001") == "fail")

# ---- Non-vacuity: same route, present vs absent pattern flip the outcome ----
check("NV non-vacuous: present->pass, absent->fail on same route",
      decide(ROUTE_REAL, "_65001_") == "pass" and decide(ROUTE_REAL, "_65999_") == "fail")

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
