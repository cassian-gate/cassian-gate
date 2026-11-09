#!/usr/bin/env python3
"""§4.4 REQ-44-6 / BR-7 (negative leg i) — an injected invariant-relevant OBSERVED
difference between runs is REPORTED in the baseline_diff subset, never silently equal.
Lab-free; reuses the shared subset source (_two_run_determinism_safe_subset)."""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pathlib import Path
from cassian_two_run import _two_run_compare, _two_run_determinism_safe_subset

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

RESOLVED = ("name: r46\nnodes: []\nlinks: []\ntests:\n"
            "  - name: t-alpha\n    kind: route_present\n"
            "  - name: t-beta\n    kind: bgp_session_up\n")
def _mkrun(d, results):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "topology.resolved.yaml"), "w").write(RESOLVED)
    json.dump(results, open(os.path.join(d, "results.json"), "w"))

BASE = {"result": "pass", "tests": [
    {"name": "t-alpha", "verdict": "pass", "expected": "present", "observed": "present", "duration_ms": 10},
    {"name": "t-beta",  "verdict": "pass", "expected": "up", "observed": "up", "duration_ms": 12}]}
# injected observed-state difference on t-alpha (present -> absent); t-beta unchanged
CHANGE = {"result": "fail", "tests": [
    {"name": "t-alpha", "verdict": "fail", "expected": "present", "observed": "absent", "duration_ms": 11},
    {"name": "t-beta",  "verdict": "pass", "expected": "up", "observed": "up", "duration_ms": 13}]}

def _sub(bdir, cdir):
    s, _ = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir), base_name="r46")
    return _two_run_determinism_safe_subset(s)

scratch = tempfile.mkdtemp(prefix="r46_")
try:
    b = os.path.join(scratch, "b"); c = os.path.join(scratch, "c"); eq = os.path.join(scratch, "eq")
    _mkrun(b, BASE); _mkrun(c, CHANGE); _mkrun(eq, BASE)
    sub = _sub(b, c)
    reported = [t for t in sub["diffs"]["tests"] if t["name"] == "t-alpha"]
    ck(len(reported) == 1, "injected observed difference on t-alpha is REPORTED")
    ck(bool(reported) and reported[0]["changes"].get("observed") == {"baseline": "present", "change": "absent"},
       "reported delta names the observed present->absent change")
    ck(not any(t["name"] == "t-beta" for t in sub["diffs"]["tests"]),
       "behaviourally-unchanged t-beta is NOT reported (no false diff)")
    # control: identical evidence -> empty behavioural diff (never a silent false-equal report)
    ck(_sub(b, eq)["diffs"]["tests"] == [], "identical evidence -> empty behavioural diff (control)")
finally:
    shutil.rmtree(scratch, ignore_errors=True)
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- REQ-44-6 injected-difference reported")
sys.exit(1 if fails else 0)
