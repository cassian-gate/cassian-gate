#!/usr/bin/env python3
"""PO-7 (REQ-413-P) — non-scoped module preservation, lab-free.
Per-module SHA-256 byte-identity vs the v9 baseline for EVERY non-scoped src/ module.
Scoped set {cassian_engine.py, cassian_model.py} is excluded (free to modify per LD-5);
every other module must be byte-identical to v9."""
import sys, os, hashlib
SRCDIR = os.path.join(os.path.dirname(__file__), "..", "src")

SCOPED = {"cassian_engine.py", "cassian_model.py"}
# v9 baselines (computed from the declared v9 consolidated snapshot).
V9 = {
    "cassian_ai.py":                "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "cassian_artifacts.py":         "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "cassian_candidate.py":         "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "cassian_cli.py":               "bcf460f7be2d2ec4280569bdfe3f30ab9d0784d6677a98a8db64579bf32ebf75",
    "cassian_common.py":            "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "cassian_runtime_container.py": "b2a493f947c121416c992b8b9788a60acead190d305d58654c3c457def116ba3",
    "cassian_state.py":             "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "cassian_tests.py":             "ba0a1f36245de1ac01853fca4e8a3100ff5aad28525e91ef26ebaf24f404b0af",
    "cassian_two_run.py":           "694f4e0d8ca7e07e7f4843e4f269a697d74d19bcdece60adf6f339952e471452",
    "cassian.py":                   "cbc931d2f977c37249599bf63229b507ce6ea4d58eb6ca5525b7269b70d4c895",
}

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

ck(not (SCOPED & set(V9)), "scoped modules excluded from preservation set (engine/model free)")
for mod, baseline in V9.items():
    p = os.path.join(SRCDIR, mod)
    if not os.path.isfile(p):
        ck(False, f"{mod} present"); continue
    sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
    ck(sha == baseline, f"{mod} byte-identical to v9  [{sha[:12]}...]")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-7 non-scoped preservation")
sys.exit(1 if fails else 0)
