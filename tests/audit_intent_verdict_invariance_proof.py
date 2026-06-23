#!/usr/bin/env python3
"""PO-4 (REQ-413-4-INV) — intent verdict-invariance, lab-free with/without-field
regression (PBE-1b-5). Declaring, omitting, or changing intent never changes the
verdict-authoritative fields (result, overall.verdict, overall.exit_code)."""
import sys, os, copy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

def verdict_fields(base, **kw):
    r = copy.deepcopy(base)
    e._finalize_results_schema(results=r, command="test", topo_name="t",
                               lab_name="l", phase="collect", **kw)
    return (r.get("result"), r["overall"]["verdict"], r["overall"]["exit_code"])

for label, base in [("PASS-run", {"result": "pass", "tests": [{"name": "t1", "verdict": "pass"}], "summary": {"passed": 1}}),
                    ("FAIL-run", {"result": "fail", "tests": [{"name": "t1", "verdict": "fail"}], "summary": {"failed": 1}})]:
    without = verdict_fields(base)
    with_a  = verdict_fields(base, intent="purpose A")
    with_b  = verdict_fields(base, intent="a totally different purpose B")
    ck(without == with_a, f"{label}: verdict identical with-intent vs without-intent")
    ck(with_a == with_b, f"{label}: verdict identical across distinct intent values")
    ck(without[1] == ("pass" if "pass" in label.lower() else "fail"), f"{label}: verdict still correct (not masked by intent)")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-4 intent verdict-invariance")
sys.exit(1 if fails else 0)
