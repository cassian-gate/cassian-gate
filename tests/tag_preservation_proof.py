#!/usr/bin/env python3
"""§4.8 WI-5 preservation proof (REQ-TAG-PRES-1): the 8 modules outside this handover's scope
are byte-unchanged from the post-§4.7 baseline (captured at the phase1b-4_8 branch cut).
Reproducible per-module SHA-256; exit 0 if all match, exit 1 on any drift (fails loudly).
Independent of udi_preservation_proof.py; this is NOT the founder-reserved composite pin (BL-1b4-1)."""
import hashlib
import os
import sys

from preservation_manifest import MODULE_ROSTER

# REQ-45b-14: baseline keys carry the src/ prefix (manifest convention), so
# paths join from the repo root, not from src/.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Post-§4.7 baseline (branch-cut state). The 4 scoped modules (cassian_engine, cassian_model,
# cassian_cli, cassian_tests) are intentionally excluded -- they are modified by §4.8.
BASELINE = {
    "src/cassian.py": "2da8db410415bb4e77fc6da1e944ff0919a5b6c03e1e630d42a99e5e10cbc664",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "217d8f08621db367a0d0666470793ff2335136846a4663ce95b4d0d3110330bc",  # re-baselined from 7775a062 (undef remediation: _cand_misuse helper, vty import, cmd_test rebinds + scenarios reads, resolve_topology names); orig 93db9b61
    "src/cassian_common.py": "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_runtime_container.py": "1863184e7d739b4faf2749fa3e133824851b7fe05a1b80025fc7806e24d7309f",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_two_run.py": "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    drift = []
    # REQ-43-5: subset consistency -- the curated subset may not reference a non-rostered module.
    # REQ-45b-14: keys are src/<n>.py; the "src/"+k adapter shim is removed.
    non_rostered = sorted(k for k in BASELINE if k not in MODULE_ROSTER)
    if non_rostered:
        print("FAIL: curated subset references non-rostered module(s): %s" % ", ".join(non_rostered))
        sys.exit(1)
    for mod, expected in sorted(BASELINE.items()):
        path = os.path.join(_ROOT, mod)
        if not os.path.isfile(path):
            print("  MISSING %s" % mod)
            drift.append(mod)
            continue
        actual = sha256(path)
        if actual == expected:
            print("  MATCH  %s" % mod)
        else:
            print("  DRIFT  %s" % mod)
            print("           expected %s" % expected)
            print("           actual   %s" % actual)
            drift.append(mod)
    if drift:
        print("\nPRESERVATION DRIFT in %d module(s): %s" % (len(drift), ", ".join(drift)))
        sys.exit(1)
    print("\nPreservation intact: all %d non-scoped modules byte-unchanged from baseline." % len(BASELINE))
    sys.exit(0)


if __name__ == "__main__":
    main()
