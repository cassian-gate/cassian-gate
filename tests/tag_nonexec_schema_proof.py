#!/usr/bin/env python3
"""§4.8 WI-3 non-execution record + reconciliation proof (Doctrine §1.11; REQ-TAG-NONEXEC-1..5).
Lab-free: exercises landed _summarize_test_counts + _fail_fast_drops, the not_executed record
shape and reason enum, and asserts the in-place record_test(verdict="not_executed") wiring at the
name/kind/tag filter sites + summary emission via source inspection."""
import inspect, os, sys
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_common as _cc; _cc._QUIET_DIE = True
import cassian_engine as E

REASONS = {"filtered_by_tag", "filtered_by_name", "filtered_by_kind", "fail_fast"}
C = []
def ck(n, c): C.append((n, bool(c)))

# reconciliation: total == executed + not_executed (+ skipped); not_executed != skipped (NONEXEC-2)
tests = [{"verdict": "pass"}, {"verdict": "fail"}, {"verdict": "pass"},
         {"verdict": "not_executed", "meta": {"not_executed_reason": "filtered_by_tag"}},
         {"verdict": "not_executed", "meta": {"not_executed_reason": "filtered_by_name"}},
         {"verdict": "skip"}]
s = E._summarize_test_counts(tests); ex = s["passed"] + s["failed"]
ck("total == executed + not_executed + skipped", s["total"] == ex + s["not_executed"] + s["skipped"])
ck("executed excludes not_executed", ex == 3 and s["not_executed"] == 2)
ck("not_executed separate from skipped", s["not_executed"] == 2 and s["skipped"] == 1)
ck("passed not inflated by not_executed", s["passed"] == 2)
ck("full run => not_executed 0", E._summarize_test_counts([{"verdict": "pass"}, {"verdict": "fail"}])["not_executed"] == 0)

# fail-fast drops (NONEXEC-3 / BL-1b7-1)
declared = [{"name": "t1", "kind": "ping"}, {"name": "t2", "kind": "ping"}, {"name": "t3", "kind": "tcp"}]
d = E._fail_fast_drops(declared, 0)
ck("fail-fast drops remaining in declared order", [x["name"] for x in d] == ["t2", "t3"])
ck("fail-fast records verdict not_executed", all(x["verdict"] == "not_executed" for x in d))
ck("fail-fast reason fail_fast", all(x["meta"]["not_executed_reason"] == "fail_fast" for x in d))
ck("fail-fast carries kind", d[0]["kind"] == "ping" and d[1]["kind"] == "tcp")
ck("last failure => no drops", E._fail_fast_drops(declared, 2) == [])

# record shape + reason enum (NONEXEC-1/5)
r = d[0]
ck("record observed/verdict not_executed", r["observed"] == "not_executed" and r["verdict"] == "not_executed")
ck("record verdict != skip/skipped", r["verdict"] not in ("skip", "skipped"))
ck("reason in enumerated set", r["meta"]["not_executed_reason"] in REASONS)

# in-place wiring (source assertions): record_test not_executed at each filter site + summary
src = inspect.getsource(E)
ck("wires filtered_by_name record", '"not_executed_reason": "filtered_by_name"' in src)
ck("wires filtered_by_kind record", '"not_executed_reason": "filtered_by_kind"' in src)
ck("wires filtered_by_tag record", '"not_executed_reason": "filtered_by_tag"' in src)
ck("summary emits not_executed", 'results["summary"]["not_executed"]' in src)
ck("summary emits filtered_by_tag", 'results["summary"]["filtered_by_tag"]' in src)

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
