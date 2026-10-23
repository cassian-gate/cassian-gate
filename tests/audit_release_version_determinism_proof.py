#!/usr/bin/env python3
"""PO-3 (REQ-413-2) — release-version stamp determinism, lab-free."""
import sys, os, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_engine as e
fails = []
def ck(c, m):
    print(("PASS  " if c else "FAIL  ") + m)
    if not c: fails.append(m)

v1 = e._audit_release_version(); v2 = e._audit_release_version()
ck(v1 == v2, "stable across calls (deterministic)")
ck(v1 == "2.1.0", "stamp == release version 2.1.0")
pp = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
m = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', open(pp, encoding="utf-8").read())
ck(m and v1 == m.group(1), "stamp == pyproject [project].version")
ck(isinstance(v1, str) and v1 != "unknown", "stamp resolved (not runtime-derived / unknown)")
print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-3 version determinism")
sys.exit(1 if fails else 0)
