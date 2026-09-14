#!/usr/bin/env python3
"""bgp_community_eval_match_proof.py -- §4.10 WI-2 EXEC-1 eval-match proof (P1-P3).

Lab-free. Mirrors the udi_assertion_eval pattern: drives the module-level eval
helpers in cassian_engine with the community forms captured live from FRR
(`show ip bgp <prefix> json`) in the Chat-3 deploy de-risk (LD 5), and asserts
the observed-community extraction + match outcome the eval branch computes.

The eval branch (cassian_engine `_evaluate_invariant_attempt`, bgp_community) is
a nested closure (not importable), so -- exactly as the udi eval proof tests the
pure `_eval_exec_assertion` -- the testable surface is the three module-level
helpers, composed exactly as the branch composes them (engine ~L6049):

    observed_communities = sorted({_canonical_community_token(t)
                                   for t in _route_communities(route_obj)})
    observed             = _bgp_community_observed(expected, match,
                                                   observed_communities)

  P1  scalar present pass->pass (incl. well-known + casing tolerance)
  P2  list any / list all present pass->pass
  P3  community absent / route present -> pass->fail (present-half: route_present
      true, observed_communities empty -- the data-present-match-failed condition)

Tolerant normalizer (LD 5 / live-supersedes-stale): `.list` camelCase
(noExport/noAdvertise/localAs) and `.string` hyphenated (no-export/...) and the
operator-declared forms (local-AS) and numeric 0:0 all canonicalize to one token;
`internet` is observed as the literal "internet" (live), and 0:0 also maps to it.

Exit 0 on all-pass; exit 1 on first failure. Non-vacuity asserted at end.
"""
import os
import sys

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


# --- exact eval-branch composition (engine ~L6049), via the module-level helpers ---
def observed_set(route_obj):
    return sorted({E._canonical_community_token(t) for t in F._route_communities(route_obj)})

def decide(route_obj, expected, match):
    return E._bgp_community_observed(expected, match, observed_set(route_obj))


# --- captured live forms (Chat-3 deploy de-risk; community in paths[], camelCase
#     .list preferred, hyphenated .string fallback, internet as literal "internet") ---
LIVE_LIST = ["internet", "65000:100", "noExport", "noAdvertise", "localAs"]
LIVE_STR = "internet 65000:100 no-export no-advertise local-AS"

ROUTE_PATHS = {  # per-path community (the live FRR location)
    "prefix": "1.1.1.1/32",
    "paths": [{"community": {"list": list(LIVE_LIST), "string": LIVE_STR}}],
}
ROUTE_TOP = {  # top-level community (the .list-preferred path of _route_communities)
    "prefix": "1.1.1.1/32",
    "community": {"list": list(LIVE_LIST), "string": LIVE_STR},
}
ROUTE_STR_ONLY = {  # .string fallback (no .list)
    "prefix": "1.1.1.1/32",
    "community": {"string": "no-export 65000:100"},
}
ROUTE_ZEROZERO = {  # FRR numeric internet form 0:0 -> canonical "internet"
    "prefix": "1.1.1.1/32",
    "community": {"list": ["0:0", "65000:100"]},
}
ROUTE_PRESENT_NO_COMM = {  # route present, no community attached (P3 present-half)
    "prefix": "1.1.1.1/32",
    "paths": [{"valid": True}],
}

CANON_LIVE = ["65000:100", "internet", "local-as", "no-advertise", "no-export"]

# ---- extraction: live forms canonicalize identically across .list / .string / paths ----
check("extract paths[].list (camelCase) -> canonical set", observed_set(ROUTE_PATHS) == CANON_LIVE)
check("extract top-level .list -> canonical set", observed_set(ROUTE_TOP) == CANON_LIVE)
check("extract .string fallback", observed_set(ROUTE_STR_ONLY) == ["65000:100", "no-export"])
check("extract 0:0 -> canonical internet", observed_set(ROUTE_ZEROZERO) == ["65000:100", "internet"])
check("route present, no community -> empty observed set", observed_set(ROUTE_PRESENT_NO_COMM) == [])

# ---- P1: scalar present pass->pass (AS:VAL, well-known, casing tolerance) ----
check("P1 scalar AS:VAL present -> pass", decide(ROUTE_PATHS, "65000:100", None) == "pass")
check("P1 scalar well-known no-advertise present -> pass", decide(ROUTE_PATHS, "no-advertise", None) == "pass")
check("P1 scalar declared local-AS casing -> pass", decide(ROUTE_PATHS, "local-AS", None) == "pass")
check("P1 scalar internet present -> pass", decide(ROUTE_PATHS, "internet", None) == "pass")
check("P1 scalar absent specifier -> fail", decide(ROUTE_PATHS, "65111:9", None) == "fail")

# ---- P2: list any / list all present pass->pass ----
check("P2 list any (one present) -> pass", decide(ROUTE_PATHS, ["65000:100", "65111:9"], "any") == "pass")
check("P2 list any (none present) -> fail", decide(ROUTE_PATHS, ["65111:9", "65222:8"], "any") == "fail")
check("P2 list all (all present, mixed forms) -> pass",
      decide(ROUTE_PATHS, ["internet", "no-export", "65000:100", "local-AS"], "all") == "pass")
check("P2 list all (one missing) -> fail",
      decide(ROUTE_PATHS, ["internet", "65111:9"], "all") == "fail")

# ---- P3: community absent / route present -> fail (present-half data-present-match-failed) ----
check("P3 scalar vs route-present-no-community -> fail", decide(ROUTE_PRESENT_NO_COMM, "65000:100", None) == "fail")
check("P3 list-all vs route-present-no-community -> fail",
      decide(ROUTE_PRESENT_NO_COMM, ["internet", "no-export"], "all") == "fail")
check("P3 present-half data: route_present True (route_obj is a dict)",
      isinstance(ROUTE_PRESENT_NO_COMM, dict))
check("P3 present-half data: observed_communities empty", observed_set(ROUTE_PRESENT_NO_COMM) == [])

# ---- determinism: identical route_obj -> identical sorted observed set across replay ----
check("DET observed set sorted + replay-identical", observed_set(ROUTE_PATHS) == observed_set(ROUTE_PATHS) == CANON_LIVE)

# ---- tolerant normalizer: forms equivalence ----
check("NORM camelCase == hyphenated (noExport == no-export)",
      E._canonical_community_token("noExport") == E._canonical_community_token("no-export"))
check("NORM internet literal == 0:0", E._canonical_community_token("internet") == E._canonical_community_token("0:0"))
check("NORM AS:VAL lowercased passthrough", E._canonical_community_token("65000:100") == "65000:100")

# ---- Non-vacuity: same route, present vs absent specifier flip the outcome ----
check("NV non-vacuous: present->pass, absent->fail on same route",
      decide(ROUTE_PATHS, "65000:100", None) == "pass" and decide(ROUTE_PATHS, "65111:9", None) == "fail")

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
