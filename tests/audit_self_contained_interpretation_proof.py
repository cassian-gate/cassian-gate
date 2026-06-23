#!/usr/bin/env python3
"""PO-9 (REQ-413-1) — bundle interpretable with no external dependency, lab-free."""
import sys, copy, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e
fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

base = {"result": "pass", "tests": [{"name": "t1", "verdict": "pass"}],
        "summary": {"passed": 1}, "timing": {"duration_ms": 5}}
r = copy.deepcopy(base)
e._finalize_results_schema(results=r, command="test", topo_name="t", lab_name="l",
                           phase="collect", intent="self-contained check")
# round-trips through JSON with no external resolver/network
blob = json.dumps(r)
r2 = json.loads(blob)
ck(r2 == r, "bundle round-trips through JSON standalone (no external lookup)")
# each audit field is a literal/inline value, not a reference/URL/resolver token
ck(isinstance(r2["release_version"], str) and "://" not in r2["release_version"], "release_version is an inline literal (no resolver/URL)")
tc = r2["tamper_check"]
ck(set(tc) == {"algo","digest","domain","state"} and "://" not in str(tc.get("digest")), "tamper_check carries algo+digest+domain inline (self-describing)")
ck(isinstance(r2["intent"], str) and "://" not in r2["intent"], "intent is an inline literal")
ck(r2["tamper_check"]["domain"] == "canonical-filtered", "tamper domain named inline (interpretable without source)")
# verdict authority interpretable inline
ck("result" in r2, "verdict/result interpretable inline")
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-9 self-contained interpretation")
sys.exit(1 if fails else 0)
