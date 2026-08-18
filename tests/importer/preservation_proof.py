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
    "src/cassian.py": "45c5180e30e2d4bda791db9c90d8ae31c0797e7fbe98d2df47c54127643b6c2d",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "217d8f08621db367a0d0666470793ff2335136846a4663ce95b4d0d3110330bc",  # re-baselined from 7775a062 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 93db9b61
    "src/cassian_common.py": "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_engine.py": "854aa1bb109cdd1ca79e3e2be2b8f95d8f8a6f127432d7fa213303afb97a363d",  # re-baselined from c9b536d4 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig f3831817
    "src/cassian_model.py": "4bef85cd0a6be4edd2c4a24ffadecf46833512108046e32e297153d66a22ec48",  # re-baselined from 5cd62d9d (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 4b9f01aa
    "src/cassian_nos_frr.py": "3c53970d87a18ea828f0bb9008f24c75b22fdf5dd3a45a7c45e0b72faedd7ff3",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_nos_sonic.py": "673179d6d58c8c1ec6de338020e03cd3fdd9c6f4c0c2e816478050c0b7a62c43",  # §4.5-c new module (WI-1 SONiC provider); enforced (REQ-45C-39; LD-9)
    "src/cassian_nos_types.py": "fc04876a3850df098dc500c7f70c55e54b06279b792c13fadf424bc25a08f85c",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_runtime_container.py": "7eecee129911d838d15e7e20463db66475fd190b9cbbfb0435ebc33a79303761",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_runtime_vm.py": "3832ad07ef6e9ce483bc0fe0f017df4584b15bf6c3a90c55fbb0b2b14f84f494",  # re-baselined from 865545e4 (phase2 §4.5-b WI-D2 node_runtime_map model-homing); orig 865545e4
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_tests.py": "49f484b027c146c3c4f513ef3829e6909b0d142743f3ffdbcdadf3c8751ae2d0",  # re-baselined from dd56046b (phase2 §4.5-b WI-C1 parse-family relocation shims); orig ba0a1f36
    "src/cassian_two_run.py": "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
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
