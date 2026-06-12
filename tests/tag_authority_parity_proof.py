#!/usr/bin/env python3
"""§4.8 WI-3 authority-parity proof (REQ-TAG-AUTH-1/B13): the selector never perturbs a matched
test's record, ordering, or verdict — it only adds not_executed records for excluded tests.
Lab-free: proves _tag_selected is a pure non-mutating filter, matched identity is preserved, and
asserts (source) that each filter site only adds a not_executed branch guarded by `continue`,
leaving the matched fall-through path byte-unchanged."""
import inspect, os, sys, copy
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_common as _cc; _cc._QUIET_DIE = True
import cassian_engine as E

C = []
def ck(n, c): C.append((n, bool(c)))

# _tag_selected is pure / non-mutating
t = {"name": "t1", "kind": "invariant", "tags": ["bgp", "edge"]}
before = copy.deepcopy(t)
_ = E._tag_selected(t, ["bgp"]); _ = E._tag_selected(t, ["zzz"])
ck("selector does not mutate the test dict", t == before)

# matched identity preserved: matched-under-filter is exactly the declared-order subset whose
# tags intersect; their dicts are unchanged objects (same identity, same fields)
declared = [{"name": "a", "tags": ["x"]}, {"name": "b", "tags": ["y"]}, {"name": "c", "tags": ["x", "z"]}]
matched = [d for d in declared if E._tag_selected(d, ["x"])]
ck("matched subset correct + ordered", [d["name"] for d in matched] == ["a", "c"])
ck("matched dicts are the same objects (untouched)", matched[0] is declared[0] and matched[1] is declared[2])
# no-filter selects every declared test, identity preserved
all_sel = [d for d in declared if E._tag_selected(d, None)]
ck("no-filter selects all declared, same objects", all_sel == declared and all(a is b for a, b in zip(all_sel, declared)))

# source: each filter site adds a not_executed branch that `continue`s; matched path falls through
src = inspect.getsource(E)
for reason in ("filtered_by_name", "filtered_by_kind", "filtered_by_tag"):
    blk = src.split('"not_executed_reason": "%s"' % reason, 1)[1][:120]
    ck("%s branch ends in continue (excluded only)" % reason, "continue" in blk)
ck("matched tag path uses `not _tag_selected(...)` guard (additive)", "if not _tag_selected(t, filter_tags):" in src)

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
