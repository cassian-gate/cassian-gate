#!/usr/bin/env python3
"""§4.12 B-6 — PASS-scope render hardening proof (PO-B6-render).

Lab-free behavioral-model harness over synthetic PASS results (PBE-1b-1:
the PASS render is runtime-triggerable, so a runtime-triggerable lab-free
harness is used; no deployed topology fixture). Cites lab-free
source-validation directly (handover §15.1; not PBE-1b-4 — src/ modified).

REQ-4.12-B6-1: a PASS results.summary.txt is not readable as broader than the
declared/executed scope (Doctrine §1.11); the hardened "PASS does not mean"
block explicitly excludes items shown under "Not validated".

REQ-4.12-B6-4: PASS-render replay byte-identity for fixed inputs; the hardening
adds no runtime-variant field to the PASS surface.

Run:  PYTHONPATH=src python3 tests/b6_pass_scope_render_proof.py
"""
import sys
import tempfile
import pathlib

sys.path.insert(0, "src")
import cassian_tests as ct

NARROW_LINE = '  Validation of items shown under "Not validated" above'


def _render(results, lab="b6demo"):
    tmp = pathlib.Path(tempfile.mkdtemp()) / f"clab-{lab}"
    tmp.mkdir(parents=True, exist_ok=True)
    orig = ct.lab_dir
    try:
        ct.lab_dir = lambda l: tmp
        return ct.write_test_summary_artifact(lab, results).read_text(encoding="utf-8")
    finally:
        ct.lab_dir = orig


POS = {"result": "pass", "topology": {"name": "b6demo"},
       "tests": [{"name": "t1", "verdict": "pass"}],
       "scenarios": [{"id": "s1", "verdict": "pass"}]}
# Declared scope broader than executed: scenarios declared but not executed.
NEG = {"result": "pass", "topology": {"name": "b6demo"},
       "tests": [{"name": "t1", "verdict": "pass"}],
       "scenarios": []}

checks = []


def check(name, ok):
    checks.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name)


pos = _render(POS)
check("P-B6-1 POS verdict PASS", "RESULT: PASS" in pos)
check("P-B6-1 POS nothing outside executed scope",
      "Not validated: (none declared outside executed scope)" in pos)
check("P-B6-1 POS 'PASS does not mean' present", "PASS does not mean:" in pos)
check("P-B6-1 POS narrowing line present", NARROW_LINE in pos)

neg = _render(NEG)
neg_validated = next((l for l in neg.splitlines() if l.strip().startswith("Validated:")), "")
check("P-B6-1 NEG verdict still PASS", "RESULT: PASS" in neg)
check("P-B6-1 NEG unexecuted scope shown under Not validated",
      "Not validated: scenario behavior" in neg)
check("P-B6-1 NEG scenario scope not absorbed into Validated",
      "scenario" not in neg_validated)
check("P-B6-1 NEG narrowing line excludes Not-validated items", NARROW_LINE in neg)

r1 = _render(POS)
r2 = _render(POS)
check("P-B6-4 PASS render replay byte-identical (fixed input)", r1 == r2)
check("P-B6-4 narrowing line is a static literal (no interpolation token)",
      "{" not in NARROW_LINE and "%" not in NARROW_LINE)

print("=" * 60)
fails = [n for n, ok in checks if not ok]
if fails:
    print(f"RESULT: FAIL -- {len(fails)} check(s): " + "; ".join(fails))
    sys.exit(1)
print(f"RESULT: PASS -- {len(checks)} checks: B-6 PASS-scope narrowing + replay byte-identity.")
sys.exit(0)
