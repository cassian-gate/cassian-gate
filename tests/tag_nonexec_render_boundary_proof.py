#!/usr/bin/env python3
"""§4.8 WI-4 non-execution render-boundary proof (Doctrine §1.11; REQ-TAG-RENDER-1/2, B11/B12).
Lab-free: calls _format_test_summary directly on constructed results sets (udi render pattern).
Proves BOTH halves render (executed -> verdict/summary/failed_tests; non-executed -> explicit
per-test indicator) and that the indicator is absence-sensitive -- if the non-execution branch
were removed the proof fails loudly (the §4.7 F-1 lesson: silence must not equal pass)."""
import os, sys
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_tests as T

C = []
def ck(n, c): C.append((n, bool(c)))

# Mixed run: 1 pass, 1 fail, 2 not_executed (declared order tag then fail_fast), 1 skip
mixed = {
    "lab": "demo", "result": "fail",
    "summary": {"total": 5, "passed": 1, "failed": 1, "not_executed": 2, "skipped": 1,
                "filtered_by_tag": "edge"},
    "tests": [
        {"name": "t1", "kind": "invariant", "verdict": "pass"},
        {"name": "t2", "kind": "ping", "from": "r1", "to": "r2", "verdict": "fail", "error": "loss", "meta": {}},
        {"name": "t3", "kind": "invariant", "verdict": "not_executed", "meta": {"not_executed_reason": "filtered_by_tag"}},
        {"name": "t4", "kind": "exec", "verdict": "not_executed", "meta": {"not_executed_reason": "fail_fast"}},
        {"name": "t5", "kind": "ping", "verdict": "skip"},
    ],
}
out = T._format_test_summary(mixed)

# executed half
ck("executed half: result line", "\nresult: fail" in out)
ck("executed half: summary reconciles not_executed", "tests: total=5 passed=1 failed=1 not_executed=2" in out)
ck("executed half: failed_tests rendered", "failed_tests:" in out and "t2 (ping)" in out)
# non-executed half (RENDER-1)
ck("non-exec half: section present", "not_executed_tests:" in out)
ck("non-exec half: t3 indicator + reason", " - t3 (invariant) not_executed: filtered_by_tag" in out)
ck("non-exec half: t4 indicator + reason", " - t4 (exec) not_executed: fail_fast" in out)
neb = out.split("not_executed_tests:", 1)[1] if "not_executed_tests:" in out else ""
ck("non-exec half: declared order (t3 before t4)",
   (" - t3 " in neb) and (" - t4 " in neb) and neb.index(" - t3 ") < neb.index(" - t4 "))
ck("F-1: indicators carry reason (never bare)", "filtered_by_tag" in neb and "fail_fast" in neb)

# Absence sensitivity (B12 / F-1): zero non-executed -> section + suffix omitted (byte-unchanged)
clean = {"lab": "demo", "result": "pass",
         "summary": {"total": 2, "passed": 2, "failed": 0},
         "tests": [{"name": "a", "kind": "ping", "verdict": "pass"},
                   {"name": "b", "kind": "ping", "verdict": "pass"}]}
out0 = T._format_test_summary(clean)
ck("absence: section omitted when none", "not_executed_tests:" not in out0)
ck("absence: summary suffix omitted (byte-unchanged)", "tests: total=2 passed=2 failed=0\n" in out0 and "not_executed=" not in out0)
# The check is genuinely tied to the indicator existing (would fail loudly if branch removed):
ck("F-1 sensitivity: indicator present iff records present",
   (" - t3 (invariant) not_executed: filtered_by_tag" in out) and ("not_executed_tests:" not in out0))

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
