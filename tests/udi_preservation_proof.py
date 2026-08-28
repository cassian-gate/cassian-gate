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
    "src/cassian.py": "2da8db410415bb4e77fc6da1e944ff0919a5b6c03e1e630d42a99e5e10cbc664",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "217d8f08621db367a0d0666470793ff2335136846a4663ce95b4d0d3110330bc",  # re-baselined from 7775a062 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 93db9b61
    "src/cassian_cli.py": "9234f3fdb76b5432bac8bf22a9807f234da9dff3a72d7c334ed9e2508183898a",  # re-baselined from 920e0e7f (F3): section 4.8 --tag flag (dc89591, REQ-TAG-CLI-1)
    "src/cassian_import.py": "604c8d8ff2bc461f8b43d7e5be6f63bd00f653ce6f83b64ffff9cf90450cf71c",  # §4.14 new module, enforced (LD-8/LD-9)
    "src/cassian_nos_frr.py": "0b48fba120ca67edd35d0379a906cb82b726da75d7ba5f88908bd6f07a5c2756",  # re-baselined from 898eb296 (§4.5-c WI-7: supplementary EVPN text collect leg, REQ-45C-14); §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_nos_sonic.py": "64757ef468a42a7da883c963a0fa5b3260bbadbc944ecc5c063381cff73ffcf6",  # re-baselined from 44aae825 (WI-3 REQ-45C-9: gated daemon observation on convergence_wait's timeout path; LD-45C-R4); §4.5-c new module (WI-1 SONiC provider); enforced (REQ-45C-39; LD-9)
    "src/cassian_nos_types.py": "470ea87fa0cb3bfae6eec450ef95ed970ab9a0415866df1875a2b43d1db5a72f",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_common.py": "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_runtime_container.py": "6c323e7980d44a88cd80324b6bda74210134c906d465bf670e9a83470b46d7f1",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_runtime_vm.py": "3832ad07ef6e9ce483bc0fe0f017df4584b15bf6c3a90c55fbb0b2b14f84f494",  # re-baselined from 865545e4 (phase2 §4.5-b WI-D2 node_runtime_map model-homing); orig 865545e4
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
