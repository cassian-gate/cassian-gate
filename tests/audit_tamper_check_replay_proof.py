#!/usr/bin/env python3
"""PO-2 (REQ-413-3) — tamper-check replay byte-identity + sharp exclusion axis, lab-free, loud-fail."""
import sys, copy, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e

def _synth():
    return {
        "result": "pass", "tool": "cassian-gate",
        "tests": [{"name": "t1", "verdict": "pass", "duration_ms": 12}],
        "summary": {"passed": 1, "started_at": 1.0, "finished_at": 2.0, "duration_ms": 1000,
                    "resolved_topology_mtime": 99.9, "resolved_topology_path": "/abs/run/x"},
        "timing": {"duration_ms": 1000},
        "blast_radius": {"path": "/abs/run/blast"},
        "authority": {"verdict_source": "tests",
                      "supporting_evidence": [{"type": "x", "path": "/abs/run/se"}]},
    }
fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

base = _synth()
t1 = e._audit_compute_tamper_check(base)["digest"]
t2 = e._audit_compute_tamper_check(base)["digest"]
ck(t1 == t2, "replay byte-identical (same input -> same digest)")

# mutate EXCLUDED runtime-variant fields -> digest unchanged
for path, mut in [("timing.duration_ms", lambda d: d["timing"].__setitem__("duration_ms", 9)),
                  ("summary.started_at", lambda d: d["summary"].__setitem__("started_at", 7.7)),
                  ("summary.resolved_topology_path", lambda d: d["summary"].__setitem__("resolved_topology_path", "/other")),
                  ("blast_radius.path", lambda d: d["blast_radius"].__setitem__("path", "/zzz")),
                  ("authority.supporting_evidence.path", lambda d: d["authority"]["supporting_evidence"][0].__setitem__("path", "/qqq"))]:
    d = copy.deepcopy(base); mut(d)
    ck(e._audit_compute_tamper_check(d)["digest"] == t1, f"mutate EXCLUDED {path} -> digest unchanged")

# mutate AUTHORITATIVE fields -> digest changes
for path, mut in [("result", lambda d: d.__setitem__("result", "fail")),
                  ("tests[0].verdict", lambda d: d["tests"][0].__setitem__("verdict", "fail"))]:
    d = copy.deepcopy(base); mut(d)
    ck(e._audit_compute_tamper_check(d)["digest"] != t1, f"mutate AUTHORITATIVE {path} -> digest changes")

# replay at finalize level
r1 = copy.deepcopy(base); e._finalize_results_schema(results=r1, command="test", topo_name="t", lab_name="l", phase="collect")
r2 = copy.deepcopy(base); e._finalize_results_schema(results=r2, command="test", topo_name="t", lab_name="l", phase="collect")
ck(r1["tamper_check"]["digest"] == r2["tamper_check"]["digest"], "finalize-level replay byte-identical")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-2 hash replay + sharp axis")
sys.exit(1 if fails else 0)
