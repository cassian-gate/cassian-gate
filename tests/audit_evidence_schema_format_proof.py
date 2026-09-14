#!/usr/bin/env python3
"""PO-1 (REQ-413-1/-2/-4) — §4.13 audit-evidence schema/format, lab-free.
New fields present, typed, additive; existing keys byte-stable. Snapshot-grounded
via the implementation-surface engine (PBE-1b-8)."""
import sys, copy, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e

def _synth():
    # Fully schema-stabilized bundle (every key _finalize_results_schema sets is
    # already present) so the ONLY keys it newly adds are the §4.13 audit fields.
    return {
        "result": "pass", "tests": [{"name": "t1", "verdict": "pass", "duration_ms": 12}],
        "scenarios": [], "events": [],
        "results_schema": "results.v1", "results_schema_version": "1.0.0",
        "tool": "cassian-gate", "command": "test",
        "lab_obj": {"name": "l"}, "topology": {"name": "t"},
        "authority": {"verdict_source": "tests", "supporting_evidence": []},
        "summary": {"total": 1, "passed": 1, "failed": 0,
                    "started_at": 1.0, "finished_at": 2.0, "duration_ms": 1000},
        "timing": {"duration_ms": 1000},
        "overall": {"observed": "pass", "verdict": "pass", "exit_code": 0, "phase": "collect"},
        "hard_failure": None,
    }

fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

base = _synth()
r = copy.deepcopy(base)
e._finalize_results_schema(results=r, command="test", topo_name="t", lab_name="l",
                           phase="collect", intent="ticket-4412")

ck(r.get("release_version") == "2.1.0" and isinstance(r.get("release_version"), str), "release_version present, str, == 2.1.0")
tc = r.get("tamper_check")
ck(isinstance(tc, dict) and set(tc) == {"algo","digest","domain","state"}, "tamper_check object shape {algo,digest,domain,state}")
ck(tc.get("algo") == "sha256" and tc.get("state") == "verified", "tamper_check algo=sha256 state=verified")
ck(isinstance(tc.get("digest"), str) and len(tc["digest"]) == 64, "tamper_check digest 64-hex")
ck(r.get("intent") == "ticket-4412", "intent echoed verbatim")
ck("baseline_diff" not in r, "baseline_diff absent when not supplied (Option A)")
ck(all(r[k] == base[k] for k in base), "existing keys byte-stable (additive only)")
ck(set(r) - set(base) == {"release_version", "tamper_check", "intent"}, "ONLY the additive audit keys newly added")
r2 = copy.deepcopy(base)
e._finalize_results_schema(results=r2, command="test", topo_name="t", lab_name="l",
                           phase="collect", baseline_diff={"schema_version": "1"})
ck(r2.get("baseline_diff") == {"schema_version": "1"}, "baseline_diff echoed when supplied")
r3 = copy.deepcopy(base)
e._finalize_results_schema(results=r3, command="test", topo_name="t", lab_name="l", phase="collect")
ck("intent" not in r3, "intent omitted when not declared (no synthesized default)")
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-1 schema/format")
sys.exit(1 if fails else 0)
