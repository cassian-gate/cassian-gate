#!/usr/bin/env python3
"""§4.4 REQ-44-8 / BR-8 (negative leg iii) — a config-only difference with IDENTICAL
behavioural evidence yields NO behavioural-difference report in the baseline_diff subset.
Lab-free; reuses the shared subset source."""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pathlib import Path
from cassian_two_run import _two_run_compare, _two_run_determinism_safe_subset

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

RESOLVED = ("name: r48\nnodes: []\nlinks: []\ntests:\n  - name: t-alpha\n    kind: route_present\n")
def _mkrun(d, results):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "topology.resolved.yaml"), "w").write(RESOLVED)
    json.dump(results, open(os.path.join(d, "results.json"), "w"))

BASE = {"result": "pass", "tests": [
    {"name": "t-alpha", "verdict": "pass", "expected": "present", "observed": "present", "duration_ms": 10}]}
# identical behavioural evidence (same expected/observed/verdict); only duration differs
# (a config change that did NOT alter observed behaviour)
CHANGE_CFG = {"result": "pass", "tests": [
    {"name": "t-alpha", "verdict": "pass", "expected": "present", "observed": "present", "duration_ms": 900}]}
# contrast: a genuine behavioural difference IS reported (non-vacuity)
CHANGE_BEH = {"result": "fail", "tests": [
    {"name": "t-alpha", "verdict": "fail", "expected": "present", "observed": "absent", "duration_ms": 11}]}

def _sub(bdir, cdir):
    s, _ = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir), base_name="r48")
    return _two_run_determinism_safe_subset(s)

scratch = tempfile.mkdtemp(prefix="r48_")
try:
    b = os.path.join(scratch, "b"); ccfg = os.path.join(scratch, "ccfg"); cbeh = os.path.join(scratch, "cbeh")
    _mkrun(b, BASE); _mkrun(ccfg, CHANGE_CFG); _mkrun(cbeh, CHANGE_BEH)
    ck(_sub(b, ccfg)["diffs"]["tests"] == [],
       "config/timing-only difference (identical behaviour) -> NO behavioural report")
    ck(len(_sub(b, cbeh)["diffs"]["tests"]) == 1,
       "genuine behavioural difference IS reported (non-vacuity)")
finally:
    shutil.rmtree(scratch, ignore_errors=True)
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- REQ-44-8 config-vs-behaviour")
sys.exit(1 if fails else 0)
