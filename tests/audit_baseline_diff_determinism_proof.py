#!/usr/bin/env python3
"""PO-5 (REQ-413-5 / §4.4 REQ-44-9) — baseline-diff determinism, lab-free.
Re-anchored (PBE-1b-4 A1): proves the BEHAVIOURAL determinism of _two_run_compare and of
the stored results.json.baseline_diff (the determinism-safe subset) — byte-identical,
declared-order, comparability-gated, and TIMING-INVARIANT — WITHOUT relying on
cassian_two_run.py being byte-unchanged (this handover modifies that module). The subset is
consumed from its single shared source (_two_run_determinism_safe_subset, BR-10), never
re-implemented here. Writes fixtures to scratch only; cleans up."""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from cassian_two_run import _two_run_compare, _two_run_determinism_safe_subset

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

RESOLVED = (
    "name: po5-fixture\n"
    "nodes: []\n"
    "links: []\n"
    "tests:\n"
    "  - name: t-alpha\n"
    "    kind: route_present\n"
    "  - name: t-beta\n"
    "    kind: bgp_session_up\n"
)
def _mkrun(d, results):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "topology.resolved.yaml"), "w").write(RESOLVED)
    json.dump(results, open(os.path.join(d, "results.json"), "w"))

B = {"result": "pass", "tests": [
    {"name": "t-alpha", "verdict": "pass", "duration_ms": 10, "expected": "present", "observed": "present"},
    {"name": "t-beta",  "verdict": "pass", "duration_ms": 20, "expected": "up", "observed": "up"}]}
C = {"result": "fail", "tests": [
    {"name": "t-alpha", "verdict": "fail", "duration_ms": 11, "expected": "present", "observed": "absent"},
    {"name": "t-beta",  "verdict": "fail", "duration_ms": 25, "expected": "up", "observed": "down"}]}

scratch = tempfile.mkdtemp(prefix="po5_")
try:
    from pathlib import Path
    bdir = os.path.join(scratch, "baseline"); cdir = os.path.join(scratch, "change")
    _mkrun(bdir, B); _mkrun(cdir, C)
    s1, h1 = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir), base_name="po5")
    s2, h2 = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir), base_name="po5")
    ck(json.dumps(s1, sort_keys=True) == json.dumps(s2, sort_keys=True), "diff byte-identical on repeat (deterministic)")
    ck(h1 == h2, "human summary byte-identical on repeat")
    names = [d["name"] for d in s1["diffs"]["tests"]]
    ck(names == ["t-alpha", "t-beta"], "per-test diffs in DECLARED order")
    ck(s1["comparability"]["ok"] is True, "comparability ok=True when topo/test-set match")
    ck(s1["authority"] == "supporting_evidence", "diff labeled supporting_evidence (never verdict-bearing)")

    # incomparable: change dir with a DIFFERENT resolved topology -> gated
    cdir2 = os.path.join(scratch, "change2"); os.makedirs(cdir2, exist_ok=True)
    open(os.path.join(cdir2, "topology.resolved.yaml"), "w").write(
        RESOLVED.replace("nodes: []", "nodes: [{name: extra}]"))
    json.dump(C, open(os.path.join(cdir2, "results.json"), "w"))
    s3, _ = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir2), base_name="po5")
    ck(s3["comparability"]["ok"] is False, "comparability GATED (ok=False) when topology identity differs")
    ck(any("topology identity" in e for e in s3["comparability"]["errors"]), "gating reason names topology identity mismatch")

    # §4.4 REQ-44-9 / BR-4 / D02: the STORED baseline_diff is the determinism-safe SUBSET.
    sub1 = _two_run_determinism_safe_subset(s1)
    ck(json.dumps(sub1, sort_keys=True) == json.dumps(_two_run_determinism_safe_subset(s1), sort_keys=True),
       "baseline_diff subset deterministic on repeat")
    ck("duration_ms" not in json.dumps(sub1), "baseline_diff subset excludes duration_ms (timing noise stripped)")
    ck(sub1["authority"] == "supporting_evidence", "baseline_diff subset labeled supporting_evidence")
    ck(any(t.get("changes", {}).get("observed") for t in sub1["diffs"]["tests"]),
       "baseline_diff subset retains behavioural (observed) deltas")
    # Timing-invariance: a change run differing ONLY in duration_ms yields a byte-identical subset.
    C_retimed = {"result": "fail", "tests": [
        {"name": "t-alpha", "verdict": "fail", "duration_ms": 999, "expected": "present", "observed": "absent"},
        {"name": "t-beta",  "verdict": "fail", "duration_ms": 888, "expected": "up", "observed": "down"}]}
    cdir3 = os.path.join(scratch, "change3"); _mkrun(cdir3, C_retimed)
    s_retimed, _ = _two_run_compare(baseline_dir=Path(bdir), change_dir=Path(cdir3), base_name="po5")
    ck(json.dumps(sub1, sort_keys=True) == json.dumps(_two_run_determinism_safe_subset(s_retimed), sort_keys=True),
       "baseline_diff subset byte-identical when only duration_ms differs (REQ-44-9 replay-determinism)")
finally:
    shutil.rmtree(scratch, ignore_errors=True)

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-5 baseline-diff determinism")
sys.exit(1 if fails else 0)
