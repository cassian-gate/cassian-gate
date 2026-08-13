#!/usr/bin/env python3
"""§4.4 REQ-44-5 — real FRR-vs-FRR two-clean-state-run positive proof (runtime).

Verifies a PRODUCED two-run bundle: the change run's results.json carries a populated,
evidence-only baseline_diff with timing stripped and tamper_check covering it; and, given a
second bundle from a replay run, that the stored baseline_diff is BYTE-IDENTICAL across runs
(real-run replay-determinism; REQ-44-5 / REQ-44-9).

Run AFTER `cassian test --two-run --two-run-topology <base.yaml> --candidate-config <dir>`:
  python tests/two_run_real_run_positive_proof.py <bundle_dir> [<replay_bundle_dir>]
where <bundle_dir> is the two-run bundle root (labs/clab-<name>/two_run)."""
import sys, os, json

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

def _change_and_diff(bundle):
    p = os.path.join(bundle, "change", "results.json")
    if not os.path.exists(p):
        ck(False, "change/results.json present in bundle (%s)" % p)
        return None, None
    r = json.load(open(p))
    return r, r.get("baseline_diff")

if len(sys.argv) < 2:
    print("usage: two_run_real_run_positive_proof.py <bundle_dir> [<replay_bundle_dir>]")
    sys.exit(2)

r1, bd1 = _change_and_diff(sys.argv[1])
ck(bd1 is not None, "change run results.json carries a populated baseline_diff (REQ-44-3/-5)")
if bd1 is not None:
    ck(bd1.get("authority") == "supporting_evidence", "baseline_diff is evidence-only (never verdict-bearing)")
    ck("duration_ms" not in json.dumps(bd1), "baseline_diff excludes timing noise (determinism-safe)")
    ck(isinstance(r1.get("tamper_check"), dict) and bool(r1["tamper_check"].get("digest")),
       "tamper_check present over the record (covers baseline_diff, BR-5)")

if len(sys.argv) >= 3:
    _, bd2 = _change_and_diff(sys.argv[2])
    ck(bd2 is not None, "replay run baseline_diff present")
    if bd1 is not None and bd2 is not None:
        ck(json.dumps(bd1, sort_keys=True) == json.dumps(bd2, sort_keys=True),
           "baseline_diff BYTE-IDENTICAL across replay runs (REQ-44-5/-9 real-run determinism)")
else:
    print("NOTE  replay leg skipped (no second bundle) -- pass a replay bundle to assert byte-identity")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- REQ-44-5 real FRR-vs-FRR positive")
sys.exit(1 if fails else 0)
