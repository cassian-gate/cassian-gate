#!/usr/bin/env python3
"""
udi_preservation_proof.py — PRES-1 regression guard (§4.7 UDI).

PRES-1: every src/ module OUTSIDE the §4.7 scoped set must be byte-identical
to its v484 fork-point baseline (develop/phase1b post-§4.5-merge; merge-base
8e87e6409c946acfc9033a46762e7abce8699ab6).

This is the reproducible per-module SHA-256 regression guard. It is distinct
from the founder-reserved composite per-module pin (BL-1b4-1), which is a
separate certification attestation whose derivation is not reproducible by
standard means — and therefore not the right instrument for a CI guard.

Scoped (modifiable by §4.7; NOT enforced against v484 here):
  cassian_model.py, cassian_engine.py, cassian_tests.py.

Exits 1 (loud) on:
  * any non-scoped module whose HEAD SHA-256 != its v484 baseline (drift), or
  * any src/ module-set change (a module added or removed vs the known set).

Run from the repo root:  python tests/udi_preservation_proof.py
"""
import hashlib
import pathlib
import sys

from preservation_manifest import MODULE_ROSTER

# v484 fork-point per-module SHA-256 baselines (merge-base 8e87e640).
# Full set recorded for the module-set check; only non-scoped modules are enforced.
V484_BASELINE = {
    "src/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "src/cassian.py": "cbc931d2f977c37249599bf63229b507ce6ea4d58eb6ca5525b7269b70d4c895",
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "src/cassian_cli.py": "9234f3fdb76b5432bac8bf22a9807f234da9dff3a72d7c334ed9e2508183898a",  # re-baselined from 920e0e7f (F3): section 4.8 --tag flag (dc89591, REQ-TAG-CLI-1)
    "src/cassian_import.py": "604c8d8ff2bc461f8b43d7e5be6f63bd00f653ce6f83b64ffff9cf90450cf71c",  # §4.14 new module, enforced (LD-8/LD-9)
    "src/cassian_common.py": "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "src/cassian_runtime_container.py": "b2a493f947c121416c992b8b9788a60acead190d305d58654c3c457def116ba3",
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_two_run.py": "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
}

# §4.7 scoped set — modifiable; excluded from the v484 byte-identity enforcement.
SCOPED = {
    "src/cassian_model.py",
    "src/cassian_engine.py",
    "src/cassian_tests.py",
}

ALLOWED_NEW = set()  # #1 udi: no allowed-new; cassian_import is enforced


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main():
    src = pathlib.Path("src")
    if not src.is_dir():
        sys.exit("FAIL: run from the repo root (src/ not found)")

    head_modules = {f"src/{p.name}" for p in src.glob("*.py")}

    # (1) module-set drift — read the roster (bidirectional); a new or removed
    #     src/ module must not slip past the guard (LD-9 leg).
    added, removed = head_modules - MODULE_ROSTER, MODULE_ROSTER - head_modules
    if added or removed:
        if added:
            print(f"FAIL: src/ modules absent from the module roster (unregistered): {sorted(added)}")
        if removed:
            print(f"FAIL: rostered src/ modules missing at HEAD: {sorted(removed)}")
        sys.exit(1)

    # (2) PRES-1 — enforced set derived FROM THE ROSTER (not baseline keys); a
    #     rostered-enforced module absent from the baseline fails loud, never
    #     skipped, never auto-baselined.
    enforced = MODULE_ROSTER - SCOPED - ALLOWED_NEW
    failures = []
    checked = 0
    for mod in sorted(enforced):
        if mod not in V484_BASELINE:
            print(f"FAIL: re-baseline required: {mod} (rostered + enforced, absent from the v484 baseline)")
            sys.exit(1)
        checked += 1
        actual, expected = sha256(mod), V484_BASELINE[mod]
        if actual != expected:
            failures.append((mod, expected, actual))

    if failures:
        print("FAIL: PRES-1 violated — non-scoped module(s) drifted from the v484 baseline:")
        for mod, exp, act in failures:
            print(f"  {mod}\n    expected {exp}\n    actual   {act}")
        sys.exit(1)

    print(f"PASS: PRES-1 — {checked} non-scoped src/ modules byte-identical to v484 "
          f"(fork-point 8e87e640); scoped set {sorted(SCOPED)} excluded.")


if __name__ == "__main__":
    main()
