#!/usr/bin/env python3
"""PO-10 (REQ-413-3/-13BC) — render-boundary harness (PBE-1b-1): when the tamper-check
cannot be computed, it renders an EXPLICIT 'unverifiable' state, never 'verified', never
readable as pass. The engine admits no normal runtime trigger for the unverifiable state
(results are normally JSON-serializable), so the boundary is exercised directly."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e
fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

# Induce the failure branch: a non-JSON-serializable leaf forces json.dumps to raise.
class _Unser:  # not JSON-serializable
    pass
bad = {"result": "pass", "weird": _Unser()}
tc = e._audit_compute_tamper_check(bad)
ck(tc.get("state") == "unverifiable", "unverifiable state rendered explicitly on compute failure")
ck(tc.get("state") != "verified", "never 'verified' on failure")
ck(tc.get("digest") is None, "no digest emitted when unverifiable (never a spoofable token)")
ck(tc.get("algo") == "sha256" and tc.get("domain") == "canonical-filtered", "field shape stable even when unverifiable (self-describing)")
# a consumer reading state must not be able to read it as a pass/verified
ck(tc.get("state") not in ("pass", "verified", "ok", "true", True), "unverifiable not readable as pass/verified")
# positive control: a serializable bundle renders 'verified'
good = e._audit_compute_tamper_check({"result": "pass", "tests": []})
ck(good.get("state") == "verified" and good.get("digest"), "serializable bundle renders 'verified' with digest (positive control)")
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-10 unverifiable render boundary")
sys.exit(1 if fails else 0)
