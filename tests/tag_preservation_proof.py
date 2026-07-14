#!/usr/bin/env python3
"""§4.8 WI-5 preservation proof (REQ-TAG-PRES-1): the 8 modules outside this handover's scope
are byte-unchanged from the post-§4.7 baseline (captured at the phase1b-4_8 branch cut).
Reproducible per-module SHA-256; exit 0 if all match, exit 1 on any drift (fails loudly).
Independent of udi_preservation_proof.py; this is NOT the founder-reserved composite pin (BL-1b4-1)."""
import hashlib
import os
import sys

from preservation_manifest import MODULE_ROSTER

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

# Post-§4.7 baseline (branch-cut state). The 4 scoped modules (cassian_engine, cassian_model,
# cassian_cli, cassian_tests) are intentionally excluded -- they are modified by §4.8.
BASELINE = {
    "cassian.py": "cbc931d2f977c37249599bf63229b507ce6ea4d58eb6ca5525b7269b70d4c895",
    "cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "cassian_candidate.py": "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "cassian_common.py": "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "cassian_runtime_container.py": "b2a493f947c121416c992b8b9788a60acead190d305d58654c3c457def116ba3",
    "cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "cassian_two_run.py": "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
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
    non_rostered = sorted(k for k in BASELINE
                          if (k if k.startswith("src/") else "src/" + k) not in MODULE_ROSTER)
    if non_rostered:
        print("FAIL: curated subset references non-rostered module(s): %s" % ", ".join(non_rostered))
        sys.exit(1)
    for mod, expected in sorted(BASELINE.items()):
        path = os.path.join(_SRC, mod)
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
