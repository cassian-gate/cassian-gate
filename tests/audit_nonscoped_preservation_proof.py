#!/usr/bin/env python3
"""PO-7 (REQ-413-P) — non-scoped module preservation, lab-free.
Per-module SHA-256 byte-identity vs the v9 baseline for EVERY non-scoped src/ module.
Scoped set {cassian_engine.py, cassian_model.py} is excluded (free to modify per LD-5);
every other module must be byte-identical to v9."""
import sys, os, hashlib
from preservation_manifest import MODULE_ROSTER
# REQ-45b-14: baseline keys carry the src/ prefix (manifest convention), so
# paths join from the repo root, not from src/.
ROOTDIR = os.path.join(os.path.dirname(__file__), "..")

SCOPED = {"src/cassian_engine.py", "src/cassian_model.py"}
# v9 baselines (computed from the declared v9 consolidated snapshot).
V9 = {
    "src/cassian_ai.py":                "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py":         "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py":         "217d8f08621db367a0d0666470793ff2335136846a4663ce95b4d0d3110330bc",  # re-baselined from 7775a062 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 93db9b61
    "src/cassian_cli.py":               "9234f3fdb76b5432bac8bf22a9807f234da9dff3a72d7c334ed9e2508183898a",
    "src/cassian_common.py":            "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_nos_frr.py": "0b48fba120ca67edd35d0379a906cb82b726da75d7ba5f88908bd6f07a5c2756",  # re-baselined from 898eb296 (§4.5-c WI-7: supplementary EVPN text collect leg, REQ-45C-14); §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_nos_types.py": "fc04876a3850df098dc500c7f70c55e54b06279b792c13fadf424bc25a08f85c",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_runtime_container.py": "6c323e7980d44a88cd80324b6bda74210134c906d465bf670e9a83470b46d7f1",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_runtime_vm.py": "3832ad07ef6e9ce483bc0fe0f017df4584b15bf6c3a90c55fbb0b2b14f84f494",  # re-baselined from 865545e4 (phase2 §4.5-b WI-D2 node_runtime_map model-homing); orig 865545e4
    "src/cassian_state.py":             "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_tests.py":             "b8dc85343fd4cbff537add7d103cd75cf838434064a6a3503c76fa8305e32ee6",  # re-baselined from dd56046b (phase2 §4.5-b WI-C1 parse-family relocation shims); orig ba0a1f36
    "src/cassian_two_run.py":           "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
    "src/cassian.py":                   "2da8db410415bb4e77fc6da1e944ff0919a5b6c03e1e630d42a99e5e10cbc664",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
}

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

ck(not (SCOPED & set(V9)), "scoped modules excluded from preservation set (engine/model free)")
# REQ-43-5: subset consistency -- the curated subset may not reference a non-rostered module.
# REQ-45b-14: keys are src/<n>.py (the manifest convention); the "src/"+k
# adapter shim is removed -- no bare-name key survives.
ck(set(V9) <= MODULE_ROSTER,
   "curated subset registered in module roster (no non-rostered key)")
for mod, baseline in V9.items():
    p = os.path.join(ROOTDIR, mod)
    if not os.path.isfile(p):
        ck(False, f"{mod} present"); continue
    sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
    ck(sha == baseline, f"{mod} byte-identical to v9  [{sha[:12]}...]")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-7 non-scoped preservation")
sys.exit(1 if fails else 0)
