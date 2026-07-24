#!/usr/bin/env python3
"""§4.12 B-6 — §13(b)(c) seam + FAIL-branch preservation proof (PO-B6-preserve).

Source-validation, loud-fail. Asserts the §13(b)(c) failed-invariant render
seam and the FAIL-branch fail_meaning_block are byte-unchanged by the B-6
PASS-scope edit (REQ-4.12-B6-2, REQ-4.12-B6-3; DC §13 / §14 item **8**;
PBE-1b-3).

Citation corrected §4.5-b (REQ-45b-15(ii), per E-1): this proof's authority is
§14 item 8 ("No silent mutation introduced") -- the drift-guard clause -- not
§14 item 9 ("Engineer-experience guarantees of §13 preserved"). The subject
matter is the §13(b)(c) render seam, but the mechanism is byte-identity
drift-guarding, so item 8 governs. The E-1 note itself is not edited; this
correction is recorded additively in the E-1 addendum (§4.8).

Method (Rule 2 + Rule 4): per-function SHA-256 over AST source segments for the
three seam functions, plus byte-exact string-content anchors for the
FAIL-branch wording. Loud-fail on any drift.

Run:  PYTHONPATH=src python3 tests/b6_13bc_seam_preservation_proof.py
"""
import ast
import hashlib
import pathlib
import sys

SRC = pathlib.Path("src/cassian_tests.py")

# Pinned post-§4.12 baselines (identical to pre-§4.12; B-6 must not touch these).
SEAM_PINS = {
    "_format_observed_state_block":         "4b0f0ac4afbe0015675c0598753eadf740ebcd7b60e5944e701ae68f4682d417",
    "_format_observed_state_absence_block": "5734fdc0b1f6eeb20b80ac182bb21de08e9494db9b75cf72b52ffd782d39200d",
    "_format_test_summary":                 "438a0dd25f42babcd8695e9ca131c5aea5240da1e802fc190e00f41cb7db2bda",
}

# FAIL-branch fail_meaning_block string anchors (must remain byte-exact).
FAIL_ANCHORS = [
    r'"FAIL means:\n"',
    "A system/runtime failure interrupted validation",
    "One or more declared checks did not match expected outcomes",
    "This is a validation failure, not a system/runtime failure",
]

checks = []


def check(name, ok):
    checks.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name)


src = SRC.read_text(encoding="utf-8")
tree = ast.parse(src)
found = {n.name: ast.get_source_segment(src, n)
         for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name in SEAM_PINS}

for name, pin in SEAM_PINS.items():
    if name not in found:
        check(f"P-B6-2 seam fn present: {name}", False)
        continue
    h = hashlib.sha256(found[name].encode("utf-8")).hexdigest()
    check(f"P-B6-2 seam byte-unchanged: {name}", h == pin)

for i, anchor in enumerate(FAIL_ANCHORS, 1):
    check(f"P-B6-3 FAIL-branch anchor {i} present (byte-exact)", anchor in src)

# PASS branch must zero the FAIL block (confirms the PASS edit did not bleed into FAIL).
check('P-B6-3 PASS branch sets fail_meaning_block = ""', '        fail_meaning_block = ""\n' in src)

print("=" * 60)
fails = [n for n, ok in checks if not ok]
if fails:
    print(f"RESULT: FAIL -- {len(fails)} check(s): " + "; ".join(fails))
    sys.exit(1)
print(f"RESULT: PASS -- {len(checks)} checks: §13(b)(c) seam + FAIL-branch byte-unchanged.")
sys.exit(0)
