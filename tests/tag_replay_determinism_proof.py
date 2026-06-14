#!/usr/bin/env python3
"""§4.8 WI-3 replay-determinism proof (Doctrine §1.4; REQ-TAG-SELECTOR-2/D02): the same --tag
selector over the same topology yields an identical matched/excluded partition in stable declared
order across replays. Lab-free: exercises landed _tag_selected / _summarize_test_counts."""
import os, sys
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_common as _cc; _cc._QUIET_DIE = True
import cassian_engine as E

C = []
def ck(n, c): C.append((n, bool(c)))

declared = [{"name": "t%d" % i, "tags": (["a"] if i % 2 else ["b"])} for i in range(1, 8)]
fset = ["a", "c"]
def partition(): return [(t["name"], bool(E._tag_selected(t, fset))) for t in declared]
p1, p2, p3 = partition(), partition(), partition()
ck("partition identical across replays", p1 == p2 == p3)
ck("partition value-based, not set-order (sorted vs unsorted filter equal)",
   [E._tag_selected(t, ["a", "c"]) for t in declared] == [E._tag_selected(t, ["c", "a"]) for t in declared])
ck("declared order preserved", [n for n, _ in p1] == ["t1", "t2", "t3", "t4", "t5", "t6", "t7"])

tests = [{"verdict": "pass"}, {"verdict": "not_executed", "meta": {}}, {"verdict": "fail"},
         {"verdict": "not_executed", "meta": {}}, {"verdict": "skip"}]
s1 = E._summarize_test_counts(tests); s2 = E._summarize_test_counts(tests)
ck("summary counts deterministic", s1 == s2)
ck("summary reconciliation holds", s1["total"] == s1["passed"] + s1["failed"] + s1["not_executed"] + s1["skipped"])

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
