#!/usr/bin/env python3
"""§4.4 F-1 regression (lab-free) — the change-run results.json is written through the
frozen canonical serializer (write_json_canonical: ensure_ascii=False + newline policy),
so non-ASCII field content is stored LITERALLY and the authoritative artifact is
byte-deterministic on replay. Guards against re-introducing a hand-rolled
`json.dumps(...)` (ensure_ascii=True) write that bypasses the frozen policy."""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pathlib import Path
from cassian_two_run import _two_run_compare, _two_run_populate_baseline_diff

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

RESOLVED = ("name: r-f1\nnodes: []\nlinks: []\ntests:\n  - name: t-caf\u00e9\n    kind: k\n")
def _mkrun(d, results):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "topology.resolved.yaml"), "w").write(RESOLVED)
    json.dump(results, open(os.path.join(d, "results.json"), "w"))

# non-ASCII content in lab name and test name
BASE = {"result": "pass", "lab_obj": {"name": "caf\u00e9-\u03b4"},
        "tests": [{"name": "t-caf\u00e9", "verdict": "pass", "expected": "x", "observed": "x", "duration_ms": 1}]}
CHANGE = {"result": "fail", "lab_obj": {"name": "caf\u00e9-\u03b4"},
          "tests": [{"name": "t-caf\u00e9", "verdict": "fail", "expected": "x", "observed": "y", "duration_ms": 2}]}

def _populated_text(root):
    b = os.path.join(root, "b"); c = os.path.join(root, "c")
    _mkrun(b, BASE); _mkrun(c, CHANGE)
    summary, _ = _two_run_compare(baseline_dir=Path(b), change_dir=Path(c), base_name="caf\u00e9")
    cp = Path(c) / "results.json"
    _two_run_populate_baseline_diff(cp, summary)
    return cp.read_text(encoding="utf-8")

scratch = tempfile.mkdtemp(prefix="f1_")
try:
    raw1 = _populated_text(os.path.join(scratch, "run1"))
    raw2 = _populated_text(os.path.join(scratch, "run2"))
    ck("caf\u00e9" in raw1, "non-ASCII stored LITERALLY (canonical, ensure_ascii=False)")
    ck("caf\\u00e9" not in raw1, "no \\uXXXX escaping (frozen canonical serializer not bypassed)")
    ck(raw1.endswith("\n") and not raw1.endswith("\n\n"), "single trailing newline (canonical newline policy)")
    ck(raw1 == raw2, "authoritative results.json byte-identical on replay over identical non-ASCII evidence")
    r = json.loads(raw1)
    ck(r.get("baseline_diff", {}).get("authority") == "supporting_evidence", "baseline_diff present + evidence-only")
    ck(isinstance(r.get("tamper_check"), dict) and bool(r["tamper_check"].get("digest")),
       "tamper_check present over the record")
finally:
    shutil.rmtree(scratch, ignore_errors=True)
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- F-1 canonical serialization (non-ASCII)")
sys.exit(1 if fails else 0)
