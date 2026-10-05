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
    "src/cassian.py": "2da8db410415bb4e77fc6da1e944ff0919a5b6c03e1e630d42a99e5e10cbc664",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "217d8f08621db367a0d0666470793ff2335136846a4663ce95b4d0d3110330bc",  # re-baselined from 7775a062 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 93db9b61
    "src/cassian_common.py": "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_engine.py": "58dcf113bfd6961035061895e3b06813de6fd06bd50616ae708bb1b932166cb9",  # re-baselined from 5fda5624 (phase2 §4.5-d H1-b3 script 2a (founder rulings Q20-3 i of 2026-10-02, and F-S21-1 A, R2 and Decision A a of 2026-10-03), touched module src/cassian_engine.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from c409d4dd (phase2 §4.5-d H1-b3 script 1b (founder rulings A of 2026-09-25, D-1 and D-4 of 2026-09-30, Q-A, Q-B and Q13 a of 2026-10-01, and Q20-1 A and Q20-2 A of 2026-10-02), touched module src/cassian_engine.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined (phase2 §4.5-c WI-1 packet 1 script A: resolve_topology topo_path keyword at four call sites; LD-45C-R21 R2/R5)
    "src/cassian_model.py": "844be3bce59a60663e8e546bcbcd67750ef478fc016b5c737474b167bbf21f7f",  # re-baselined from 6fcfd028 (phase2 §4.5-d H1-b1 script 2 (founder rulings A of 2026-09-25, alpha of 2026-09-25, D1 of 2026-09-26 and A-prime of 2026-09-28), touched module src/cassian_model.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from ff8253bc (phase2 §4.5-d REQ-45D-33 early re-baseline at c619814 (founder ruling 2026-09-24), touched module src/cassian_model.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined (phase2 §4.5-c WI-1 packet 1 script A: sonic_mode/sonic_config_db resolution + cassian_common import; LD-45C-R17 R1/R9, LD-45C-R21 R1/R3)
    "src/cassian_nos_frr.py": "b9b5bb53bfdf2656054db1ba0fd82e40d6205365e9e2d9aa5db0068d7ab4e8ff",  # re-baselined from 8ecb147b (phase2 §4.5-d H1-b3 script 1b (founder rulings A of 2026-09-25, D-1 and D-4 of 2026-09-30, Q-A, Q-B and Q13 a of 2026-10-01, and Q20-1 A and Q20-2 A of 2026-10-02), touched module src/cassian_nos_frr.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 0b48fba1 (phase2 §4.5-d REQ-45D-33 early re-baseline at c619814 (founder ruling 2026-09-24), touched module src/cassian_nos_frr.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 898eb296 (§4.5-c WI-7: supplementary EVPN text collect leg, REQ-45C-14); §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_nos_sonic.py": "a7c212fad4f5714cfbedfd5e114ef5b362dd8ba04a19c94ae969f5f0a78c2c0e",  # re-baselined from 7d715dce (phase2 §4.5-d H1-b3 script 2b-i (founder rulings R2 of 2026-10-03 and Decision 2, Decision 3 i and the REQ-45D-2 render ruling ii of 2026-10-05), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from a3f904eb (phase2 §4.5-d H1-b3 script 1b (founder rulings A of 2026-09-25, D-1 and D-4 of 2026-09-30, Q-A, Q-B and Q13 a of 2026-10-01, and Q20-1 A and Q20-2 A of 2026-10-02), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 7306690b (phase2 §4.5-d H1-b3 script 1a (founder rulings A of 2026-09-25, D-3 and D-4 of 2026-09-30, and Q13 a, IPv6 I and B of 2026-10-01), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from b86372da (phase2 §4.5-d H1-b2 script 2 (founder rulings A of 2026-09-25, D2 A-prime of 2026-09-29 and 1 of 2026-09-29), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 765ad929 (phase2 §4.5-d H1-b2 script 1 (founder rulings A of 2026-09-25, D1 P1 and D2 A-prime of 2026-09-29, and the session-15 two-script split of 2026-09-29), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 775c7c54 (phase2 §4.5-d H1-b1 script 2 (founder rulings A of 2026-09-25, alpha of 2026-09-25, D1 of 2026-09-26 and A-prime of 2026-09-28), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 14180f56 (phase2 §4.5-d H1-b1 script 1 (founder rulings A of 2026-09-25 and D1 of 2026-09-26), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 12ba458e (phase2 §4.5-d REQ-45D-33 early re-baseline at c619814 (founder ruling 2026-09-24), touched module src/cassian_nos_sonic.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 0cd5bc21 (LD-45C-R36: REQ-45C-44(b) abort message names the key and its value), itself from 44aae825 (WI-3 REQ-45C-9: gated daemon observation on convergence_wait's timeout path; LD-45C-R4); §4.5-c new module (WI-1 SONiC provider); enforced (REQ-45C-39; LD-9)
    "src/cassian_nos_types.py": "49246567d0b5b8b475001fb3a52cfc262206036b8f38f75fdfe46f24607f420d",  # re-baselined from 470ea87f (phase2 §4.5-d REQ-45D-33 early re-baseline at c619814 (founder ruling 2026-09-24), touched module src/cassian_nos_types.py; named check DC v2.1 §14 item 8: No silent mutation introduced); §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_runtime_container.py": "1863184e7d739b4faf2749fa3e133824851b7fe05a1b80025fc7806e24d7309f",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_runtime_vm.py": "a4c48685a81a47407587c502f0a9e730c03236abfd9a73e470f79095dd3d0aea",  # re-baselined from 3832ad07 (phase2 §4.5-d BL-P2-4.5c-32 rc=5 fix under founder rulings R1 and D-i (2026-09-24), touched module src/cassian_runtime_vm.py; named check DC v2.1 §14 item 8: No silent mutation introduced); re-baselined from 865545e4 (phase2 §4.5-b WI-D2 node_runtime_map model-homing); orig 865545e4
    "src/cassian_state.py": "771d8c069e1cdd48c002d5ff3edd25912a8941912395b56844ef6f4df041bf57",  # re-baselined from aec4d412 (phase2 §4.5-d REQ-45D-33 early re-baseline at c619814 (founder ruling 2026-09-24), touched module src/cassian_state.py; named check DC v2.1 §14 item 8: No silent mutation introduced)
    "src/cassian_tests.py": "d977b4b1318266d6eea1360295b716db6d757ff1eb98f781f29c37f1e509a920",  # re-baselined from b8dc8534 (phase2 §4.5-c Unit B: wait_for_bgp gate predicate + LD-45C-R10 header import; LD-45C-R9/R10/R11); prior dd56046b; orig ba0a1f36
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
