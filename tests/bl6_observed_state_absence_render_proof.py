import sys as _s; _s.exit(1)  # C1 NEGCHECK -- scratch only, never merged
#!/usr/bin/env python3
"""
BL-6 WI-1 render-boundary proof (PO-2, amended per founder ruling 2026-05-29).

Proves the genuine-absence failed-invariant rendering path of
cassian_tests._format_test_summary WITHOUT a deployed lab. v474 admits no clean,
resolve-valid topology that yields a runtime failed-invariant record with
non-dict observed_state (founder ruling 2026-05-29; closure-report finding):
every reachable runtime invariant fail path populates observed_state; the
resolve-pre-empted engine guards are unreachable post-Resolve; the SystemExit(2)
misuse sites do not produce a clean gate-verdict pathway. B02 is render-time
defensive-completeness logic closing the DC v2.1 §13 absence clause, so the proof
tracks where the logic lives: the render seam.

Asserts (ruling spec):
  (i)   absence indicator renders on a genuine kind:invariant + verdict:fail
        record whose observed_state is non-dict;
  (ii)  (a) invariant type + target present in the indicator;
  (iii) (b) declared expectation present in the indicator;
  (iv)  explicit "structured failure detail unavailable" statement present;
  (v)   output non-empty; the absence record is not a bare failed line
        (no implicitly-absent (c));
  (vi)  byte-identity across two render calls of identical input.
Mixed-record R27 preservation: a passing invariant, a non-invariant kind (ping),
and a prereq-blocked record alongside the genuine-absence failed invariant;
only the absence record renders the unavailable indicator. A present-path failed
invariant is included as a discriminator (renders the present observed: block,
not the unavailable indicator). Runtime-variant meta (observed_neighbor_count)
must be excluded from the rendered surface (D06 / REQ-BL6-8 / REQ-BL6-10).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_tests as ct

UNAVAILABLE = "detail: (structured failure detail unavailable for this invariant type)"


def _results():
    return {
        "lab": "bl6-absence-render-proof",
        "result": "fail",
        "summary": {"total": 7, "passed": 1, "failed": 6},
        "tests": [
            # genuine-absence failed invariant: observed_state omitted -> non-dict.
            {
                "name": "inv-absent",
                "kind": "invariant",
                "from": "r1",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: bgp session not established",
                "meta": {
                    "type": "bgp_session_up",
                    "peer": "10.0.0.2",
                    "observed_neighbor_count": 7,  # runtime-variant; must NOT render
                },
            },
            # present-path failed invariant: observed_state is a dict (B01).
            {
                "name": "inv-present",
                "kind": "invariant",
                "from": "r2",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: route missing",
                "meta": {"type": "route_present", "prefix": "10.0.0.0/24"},
                "observed_state": {"present": False, "prefix": "10.0.0.0/24"},
            },
            # present-path failed invariant (BGP-policy category): observed_state dict.
            {
                "name": "inv-policy",
                "kind": "invariant",
                "from": "leaf1",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: prefix not advertised to peer",
                "meta": {"type": "route_advertised_to", "prefix": "10.99.99.0/24",
                         "peer": "spine1"},
                "observed_state": {"advertised_routes": [], "peer": "spine1",
                                   "prefix": "10.99.99.0/24"},
            },
            # present-path failed invariant (EVPN category): observed_state dict.
            {
                "name": "inv-evpn",
                "kind": "invariant",
                "from": "leaf2",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: evpn mac route absent",
                "meta": {"type": "evpn_mac_route_present", "mac": "de:ad:be:ef:00:01",
                         "vni": 10100},
                "observed_state": {"evpn_routes": [], "mac": "de:ad:be:ef:00:01",
                                   "present": False, "vni": 10100},
            },
            # passing invariant: not a failure -> not in failed_tests.
            {
                "name": "inv-pass",
                "kind": "invariant",
                "from": "r1",
                "to": "",
                "expected": "pass",
                "observed": "pass",
                "verdict": "pass",
                "meta": {"type": "bgp_session_up", "peer": "10.0.0.3"},
                "observed_state": {"present": True},
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
            # prereq-blocked failed -> R27: no observed block.
            {
                "name": "prereq-x",
                "kind": "prereq",
                "from": "r1",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "container not running",
            },
        ],
    }


def main():
    out1 = ct._format_test_summary(_results())
    out2 = ct._format_test_summary(_results())

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    check("(vi) byte-identity across two renders", out1 == out2)
    check("(v) output non-empty", bool(out1.strip()))
    check("absence failed line present", " - inv-absent (invariant) r1->" in out1)
    check("(i)/(iv) explicit unavailable indicator renders", UNAVAILABLE in out1)
    check("(ii)(a) invariant type present", "type: bgp_session_up" in out1)
    check("(ii)(a) target present", "target: r1 peer=10.0.0.2" in out1)
    check("(iii)(b) declared expectation present", "expected: pass" in out1)
    check("(D06) runtime-variant meta excluded", "observed_neighbor_count" not in out1)
    check("R27: exactly one unavailable indicator", out1.count(UNAVAILABLE) == 1)
    check("present-path renders present block (route)", "prefix: 10.0.0.0/24" in out1)
    check("present-path renders present block (bgp-policy)", "peer: spine1" in out1)
    check("present-path renders present block (evpn)", "mac: de:ad:be:ef:00:01" in out1)
    check(
        "REQ-BL6-5: representative-per-category (absence + 3 present = 4 blocks)",
        out1.count("    observed:") == 4,
    )
    check("passing invariant not listed in failed_tests", "inv-pass" not in out1)
    check("ping failed line present (no block)", " - ping-fail (ping) r1->r2" in out1)
    check("prereq failed line present (no block)", " - prereq-x (prereq) r1->" in out1)

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
