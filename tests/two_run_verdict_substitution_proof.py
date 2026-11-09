#!/usr/bin/env python3
"""§4.4 REQ-44-7 (negative leg ii, non-negotiable) — verdict-substitution guard:
populating results.json.baseline_diff NEVER alters the record's verdict fields; it only
adds baseline_diff (additions-only) and recomputes tamper_check to cover it (BR-5).
Lab-free; exercises the real population path (_two_run_populate_baseline_diff)."""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pathlib import Path
from cassian_two_run import _two_run_compare, _two_run_populate_baseline_diff

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

RESOLVED = ("name: r47\nnodes: []\nlinks: []\ntests:\n  - name: t-alpha\n    kind: route_present\n")
def _mkrun(d, results):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "topology.resolved.yaml"), "w").write(RESOLVED)
    json.dump(results, open(os.path.join(d, "results.json"), "w"))

BASE = {"result": "pass", "tests": [
    {"name": "t-alpha", "verdict": "pass", "expected": "present", "observed": "present", "duration_ms": 10}]}
# CHANGE fails; carries a deliberately STALE tamper_check to prove it is recomputed.
CHANGE = {"result": "fail", "overall": {"verdict": "fail", "exit_code": 1},
          "tests": [{"name": "t-alpha", "verdict": "fail", "expected": "present", "observed": "absent", "duration_ms": 11}],
          "tamper_check": {"algo": "sha256", "digest": "STALEDIGEST", "domain": "canonical-filtered", "state": "verified"}}

scratch = tempfile.mkdtemp(prefix="r47_")
try:
    b = os.path.join(scratch, "b"); c = os.path.join(scratch, "c")
    _mkrun(b, BASE); _mkrun(c, CHANGE)
    cpath = Path(c) / "results.json"
    before = json.loads(cpath.read_text())
    summary, _ = _two_run_compare(baseline_dir=Path(b), change_dir=Path(c), base_name="r47")
    _two_run_populate_baseline_diff(cpath, summary)
    after = json.loads(cpath.read_text())
    ck(after["result"] == before["result"] == "fail", "record verdict (result) unchanged by population")
    ck(after["overall"] == before["overall"], "overall verdict/exit_code unchanged by population")
    ck([t["verdict"] for t in after["tests"]] == [t["verdict"] for t in before["tests"]],
       "per-test verdicts unchanged by population")
    ck("baseline_diff" in after and "baseline_diff" not in before, "baseline_diff added (additions-only)")
    ck(after["tamper_check"]["digest"] != before["tamper_check"]["digest"] and after["tamper_check"]["digest"],
       "tamper_check recomputed to cover baseline_diff (BR-5); no longer STALE")
    ck(set(after) - set(before) == {"baseline_diff"}, "ONLY baseline_diff added; no other field introduced")
finally:
    shutil.rmtree(scratch, ignore_errors=True)
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- REQ-44-7 verdict-substitution guard")
sys.exit(1 if fails else 0)
