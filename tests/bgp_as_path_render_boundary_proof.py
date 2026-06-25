#!/usr/bin/env python3
"""bgp_as_path_render_boundary_proof.py -- §4.11 WI-3 RENDER-1 proof (P6/P7).

DC §13(b)(c) failed-invariant render-boundary symmetry for bgp_as_path, lab-free
(PBE-1b-1 render-boundary pattern; mirrors bgp_community_render_boundary_proof).
Drives cassian_tests._format_test_summary with synthetic results; cassian_tests.py
is byte-unchanged (the render surface is type-generic: it branches on
isinstance(observed_state, dict), not inv_type).

Both §13(c) halves are proof-covered from distinct, evidence-backed conditions
(PBE-1b-1; §4.9 option-d distinct runtime data condition per half):

  P6  PRESENT-HALF  data-present-match-failed: a kind:invariant verdict:fail
      record with a DICT observed_state (route_present:true, AS_PATH present but
      not matching the declared pattern) -> _format_observed_state_block: explicit
      `observed:` block surfacing the bgp_as_path fields.
  P7  ABSENT-HALF   data-absent: a kind:invariant verdict:fail record with a
      NON-dict observed_state -> _format_observed_state_absence_block: explicit
      (a) type+target, (b) expectation, (c) "structured failure detail
      unavailable" indicator. The engine admits no runtime trigger for the
      non-dict state (every fail emits a dict -- incl. route-absent, which emits
      route_present:false), so it is proven synthetically.

R27 preserved (non-invariant kinds get no block); silence != pass (the failed
line is present); D06 runtime-variant meta excluded from the absence surface;
byte-identity across two renders. Non-vacuity: a passing record renders no block,
and the present dict renders the present block (NOT the unavailable indicator).

Exit 0 on all-pass; exit 1 on first failure.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_tests as ct  # noqa: E402

UNAVAILABLE = "detail: (structured failure detail unavailable for this invariant type)"


def _results():
    return {
        "lab": "bgp-as-path-render-boundary-proof",
        "result": "fail",
        "summary": {"total": 4, "passed": 1, "failed": 3},
        "tests": [
            # P6 PRESENT-HALF: dict observed_state, data-present-match-failed
            # (route present; AS_PATH present but not matching the declared pattern).
            {
                "name": "ap-present",
                "kind": "invariant",
                "from": "r2",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "bgp_as_path mismatch (expected pass, observed fail)",
                "meta": {"type": "bgp_as_path", "prefix": "1.1.1.1/32",
                         "route_present": True, "observed_as_path": "65999 65888"},
                "observed_state": {
                    "type": "bgp_as_path",
                    "prefix": "1.1.1.1/32",
                    "expected_as_path": "_65001_",
                    "actual_as_path": "65999 65888",
                    "route_present": True,
                    "source_node": "r2",
                },
            },
            # P7 ABSENT-HALF: non-dict observed_state (omitted), data-absent.
            # meta carries a runtime-variant key (observed_as_path) that must NOT
            # enter the rendered absence surface (D06).
            {
                "name": "ap-absent",
                "kind": "invariant",
                "from": "r2",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "bgp_as_path mismatch (expected pass, observed fail)",
                "meta": {"type": "bgp_as_path", "prefix": "1.1.1.1/32",
                         "observed_as_path": "65777"},
            },
            # passing bgp_as_path invariant: not a failure -> not in failed_tests.
            {
                "name": "ap-pass",
                "kind": "invariant",
                "from": "r2",
                "to": "",
                "expected": "pass",
                "observed": "pass",
                "verdict": "pass",
                "meta": {"type": "bgp_as_path", "prefix": "1.1.1.1/32"},
                "observed_state": None,
            },
            # non-invariant kind (ping) failed -> R27: no observed block.
            {
                "name": "ping-fail",
                "kind": "ping",
                "from": "r1",
                "to": "r2",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: 100% loss",
            },
        ],
    }


def main():
    out1 = ct._format_test_summary(_results())
    out2 = ct._format_test_summary(_results())

    checks = []
    def check(name, cond):
        checks.append((name, bool(cond)))

    # ---- determinism / non-empty ----
    check("byte-identity across two renders", out1 == out2)
    check("output non-empty", bool(out1.strip()))

    # ---- P6 PRESENT-HALF (data-present-match-failed -> present `observed:` block) ----
    check("P6 present failed line present", " - ap-present (invariant) r2->" in out1)
    check("P6 present block renders actual_as_path", "actual_as_path: 65999 65888" in out1)
    check("P6 present block renders expected_as_path", "expected_as_path: _65001_" in out1)
    check("P6 present block renders route_present true", "route_present: true" in out1)
    check("P6 present block renders source_node", "source_node: r2" in out1)
    check("P6 present block renders type", "type: bgp_as_path" in out1)
    check("P6 present record does NOT render the unavailable indicator (dict -> present path)",
          out1.split("ap-present")[1].split("ap-absent")[0].find("structured failure detail unavailable") == -1)

    # ---- P7 ABSENT-HALF (data-absent -> explicit (a)/(b)/(c) indicator) ----
    check("P7 absent failed line present", " - ap-absent (invariant) r2->" in out1)
    check("P7 (iv) explicit unavailable indicator renders", UNAVAILABLE in out1)
    check("P7 (a) invariant type present", "type: bgp_as_path" in out1)
    check("P7 (a) target present (src + declaration-derived prefix)",
          "target: r2 prefix=1.1.1.1/32" in out1)
    check("P7 (b) declared expectation present", "expected: pass" in out1)
    check("P7 exactly one unavailable indicator (R27 / present path not triggered)",
          out1.count(UNAVAILABLE) == 1)
    check("P7 (D06) runtime-variant meta excluded", "observed_as_path" not in out1)

    # ---- distinctness (PBE-1b-1 / option-d): two halves, two observed blocks ----
    check("two `observed:` blocks (present + absent)", out1.count("    observed:") == 2)

    # ---- R27 / non-vacuity ----
    check("passing invariant not in failed_tests (silence guarded by failed line)",
          "ap-pass" not in out1)
    check("ping failed line present, no block", " - ping-fail (ping) r1->r2" in out1)

    print(out1)
    print("=" * 60)
    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
