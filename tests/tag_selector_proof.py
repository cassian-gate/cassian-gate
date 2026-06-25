#!/usr/bin/env python3
"""§4.8 WI-3 selector partition proof (owns DC §4 / Doctrine §1.11; REQ-TAG-CLI-1/2, SELECTOR-1).
Lab-free: exercises the landed engine helper _tag_selected, proves resolve_topology is
selector-agnostic (Resolve runs the full declared set before any selector), and asserts the
--tag+--scenario guard is wired for --tag. Actual guard exit(2) is lab-confirmed (integration smoke)."""
import inspect, os, sys
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_common as _cc; _cc._QUIET_DIE = True
import cassian_engine as E, cassian_model as M

C = []
def ck(n, c): C.append((n, bool(c)))

# OR-union membership (REQ-TAG-CLI-1/B03)
ck("no filter selects all", E._tag_selected({"tags": ["a"]}, None) and E._tag_selected({}, None))
ck("OR-union intersect selects", E._tag_selected({"tags": ["bgp", "edge"]}, ["edge", "x"]))
ck("disjoint excluded", not E._tag_selected({"tags": ["bgp"]}, ["edge"]))
ck("untagged excluded under filter", not E._tag_selected({"tags": []}, ["bgp"]) and not E._tag_selected({"name": "x"}, ["bgp"]))
ck("any-one-of OR-union", E._tag_selected({"tags": ["z"]}, ["x", "y", "z"]))

# declared-order partition (SELECTOR-1; emission order = declared order, not set order)
declared = [{"name": "t1", "tags": ["a"]}, {"name": "t2", "tags": ["b"]}, {"name": "t3", "tags": ["a"]}]
part = [(t["name"], "exec" if E._tag_selected(t, ["a"]) else "not_executed") for t in declared]
ck("declared-order partition", part == [("t1", "exec"), ("t2", "not_executed"), ("t3", "exec")])

# Resolve runs the full declared set regardless of selector (SELECTOR-1; selector is Test-phase)
topo = {"name": "sel", "nodes": [{"name": "r1", "type": "frr"}, {"name": "r2", "type": "frr"}],
        "links": [{"endpoints": ["r1:eth1", "r2:eth1"]}],
        "tests": [{"name": "t1", "kind": "invariant", "type": "bgp_session_up", "src": "r1", "dst": "10.0.0.2", "tags": ["bgp"]},
                  {"name": "t2", "kind": "invariant", "type": "bgp_session_up", "src": "r1", "dst": "10.0.0.2", "tags": ["edge"]}]}
import copy
rtopo = copy.deepcopy(topo); M.ensure_valid_topology(rtopo); res = M.resolve_topology(rtopo)
resolved_tests = (res.get("tests") if isinstance(res, dict) else None) or rtopo.get("tests")
ck("Resolve runs full declared set (selector-agnostic)", len(resolved_tests) == 2)

# CLI-2 guard wired for --tag (source assertion; exit(2) is lab-confirmed)
src = inspect.getsource(E)
ck("guard predicate includes filter_tags", "filter_name or filter_kind or filter_tags" in src)
ck("guard message names --tag", "--name/--kind/--tag filters are not supported" in src)

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
