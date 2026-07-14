#!/usr/bin/env python3
"""preservation_proof.py -- §4.14 WI-4 (PO-6), lab-free, CI-safe (static-pinned).

Proves §4.14 preservation (REQ-414-PRES-1/-2/-3): every src/ module OUTSIDE the
scoped set is byte-identical to its pre-§4.14 baseline (the fork point,
`git merge-base HEAD develop/phase1b`), via reproducible per-module SHA-256, plus
a module-set-drift guard. The baseline below was generated at apply-time from the
live merge-base and is pinned static for the cassian-test-alone CI posture (no
runtime git; runs under a shallow checkout), matching the sibling preservation
proofs.

Scoped (modifiable by §4.14; excluded from byte-identity enforcement):
  src/cassian_cli.py    -- additive `cassian import` registration (WI-2)
Allowed new module (added by §4.14; absent at baseline):
  src/cassian_import.py -- the importer (WI-1)

Everything else in src/ -- including cassian_model.py (reuse-by-import only,
LD-4), the §13(b)(c) render seam + invariant-evaluation path (cassian_tests.py,
cassian_engine.py), the results.json writer (cassian_artifacts.py), and the
advisory adapt/adapters.v1 surface (cassian_engine.py) -- must be byte-identical.

Exit 0 on all-pass; loud exit 1 on any drift or module-set change. Run from the
repo root:
    python tests/importer/preservation_proof.py
"""
import hashlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.join(_ROOT, "tests"))  # locate preservation_manifest (script-dir is tests/importer/)

from preservation_manifest import MODULE_ROSTER

# === FORK_BASELINE BEGIN (generated at apply-time from the live merge-base) ===
BASELINE = {
    "src/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "src/cassian.py": "cbc931d2f977c37249599bf63229b507ce6ea4d58eb6ca5525b7269b70d4c895",
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "src/cassian_common.py": "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "src/cassian_engine.py": "f3831817f66e62840deae7153270e8c627b09ba4131c965cf80e623f0f4db85e",
    "src/cassian_model.py": "4b9f01aaa95e9c67e5bddc6e30752e60627103c1588a529db88cc0703732fa01",
    "src/cassian_runtime_container.py": "b2a493f947c121416c992b8b9788a60acead190d305d58654c3c457def116ba3",
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_tests.py": "ba0a1f36245de1ac01853fca4e8a3100ff5aad28525e91ef26ebaf24f404b0af",
    "src/cassian_two_run.py": "cfafdfa6ccd11bbbe9e7b8797de91834785c824edc5a6a93710f20dd8d8a1cf8",  # re-baselined from 694f4e0d (phase2 4.4 WI-1): results.json baseline_diff population
}
# === FORK_BASELINE END ===

SCOPED = {"src/cassian_cli.py"}
ALLOWED_NEW = {"src/cassian_import.py"}
PRES_CRITICAL = {
    "src/cassian_model.py",      # LD-4 reuse-by-import; never edited
    "src/cassian_tests.py",      # §13(b)(c) render seam + invariant evaluation
    "src/cassian_engine.py",     # results.json path + advisory adapt surface
    "src/cassian_artifacts.py",  # results.json canonical writer
}

checks = []


def record(name, ok, detail=""):
    checks.append((name, ok, detail))


def _sha_file(rel):
    h = hashlib.sha256()
    with open(os.path.join(_ROOT, rel), "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def main():
    src_dir = os.path.join(_ROOT, "src")
    if not os.path.isdir(src_dir):
        print("FAIL: run from repo root (src/ not found)")
        sys.exit(1)
    head = set("src/" + n for n in os.listdir(src_dir) if n.endswith(".py"))

    # module-set drift read from the roster (bidirectional; LD-9 leg).
    added, removed = head - MODULE_ROSTER, MODULE_ROSTER - head
    record("PO-6 module-set matches roster (denom " + str(len(MODULE_ROSTER)) + ", bidirectional)",
           (not added) and (not removed),
           "added=" + str(sorted(added)) + " removed=" + str(sorted(removed)))

    # enforced set derived FROM THE ROSTER (not baseline keys); a rostered-enforced
    # module absent from the baseline fails loud, never skipped, never auto-baselined.
    enforced_set = MODULE_ROSTER - SCOPED - ALLOWED_NEW
    unbaselined = sorted(m for m in enforced_set if m not in BASELINE)
    record("PO-6 all enforced modules baselined (F-1 re-baseline guard)",
           not unbaselined, "re-baseline required: " + str(unbaselined))

    enforced = 0
    drift = []
    for mod in sorted(enforced_set):
        if mod not in BASELINE:
            continue
        enforced += 1
        actual = _sha_file(mod)
        if actual != BASELINE[mod]:
            drift.append(mod + " expected " + BASELINE[mod][:12]
                         + " actual " + actual[:12])
    record("PO-6 non-scoped byte-identity vs baseline (" + str(enforced)
           + " enforced, cassian_cli.py scoped)", not drift and enforced >= 1,
           "; ".join(drift))

    record("PO-6 §13(b)(c) seam + advisory + results-writer + model in enforced set",
           PRES_CRITICAL.issubset(enforced_set),
           "missing=" + str(sorted(PRES_CRITICAL - enforced_set)))

    failed = [n for n, ok, _ in checks if not ok]
    for n, ok, detail in checks:
        print(("PASS" if ok else "FAIL") + "  " + n + (("  -- " + detail) if detail else ""))
    if failed:
        print("\nPRESERVATION FAIL: " + str(len(failed)) + " check(s)")
        sys.exit(1)
    print("\nRESULT: PASS -- " + str(len(checks)) + " checks (PO-6)")
    sys.exit(0)


if __name__ == "__main__":
    main()
