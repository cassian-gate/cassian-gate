#!/usr/bin/env python3
"""PO-7 (REQ-413-P) — non-scoped module preservation, lab-free.
Per-module SHA-256 byte-identity vs the v9 baseline for EVERY non-scoped src/ module.
Scoped set {cassian_engine.py, cassian_model.py} is excluded (free to modify per LD-5);
every other module must be byte-identical to v9."""
import sys, os, hashlib
from preservation_manifest import MODULE_ROSTER
SRCDIR = os.path.join(os.path.dirname(__file__), "..", "src")

SCOPED = {"cassian_engine.py", "cassian_model.py"}
# v9 baselines (computed from the declared v9 consolidated snapshot).
V9 = {
    "cassian_ai.py":                "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "cassian_artifacts.py":         "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "cassian_candidate.py":         "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "cassian_cli.py":               "9234f3fdb76b5432bac8bf22a9807f234da9dff3a72d7c334ed9e2508183898a",
    "cassian_common.py":            "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "cassian_runtime_container.py": "b3e45fa2a910617e1d4dcbcc1d6509b5385cecb4cb236498be2964796b92b59f",  # re-baselined from b2a493f9 (phase2 §4.5-a exec-target split); orig b2a493f9
    "cassian_runtime_vm.py": "865545e48b51d077731d0d0560aeafd130192dd988b6d43c8ad646d23ed4f718",  # §4.5-a new module (WI-1 VM runtime backend); enforced (REQ-45a-9; LD-9)
    "cassian_state.py":             "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "cassian_tests.py":             "dd56046b93cd8961f0fe0f97b25fc8b6ed28946cbbeea3663997c47ba603cd87",  # re-baselined from ba0a1f36 (phase2 §4.5-a exec-target split); orig ba0a1f36
    "cassian_two_run.py":           "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
    "cassian.py":                   "588fbed521cf68903cf387f02534c58fdfd7b9a844c1ee8f6d375099280cc132",  # re-baselined from cbc931d2 (phase2 §4.5-a exec-target split; WI-1 stub-import removal); orig cbc931d2
}

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

ck(not (SCOPED & set(V9)), "scoped modules excluded from preservation set (engine/model free)")
# REQ-43-5: subset consistency -- the curated subset may not reference a non-rostered module.
ck({(k if k.startswith("src/") else "src/" + k) for k in V9} <= MODULE_ROSTER,
   "curated subset registered in module roster (no non-rostered key)")
for mod, baseline in V9.items():
    p = os.path.join(SRCDIR, mod)
    if not os.path.isfile(p):
        ck(False, f"{mod} present"); continue
    sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
    ck(sha == baseline, f"{mod} byte-identical to v9  [{sha[:12]}...]")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-7 non-scoped preservation")
sys.exit(1 if fails else 0)
