#!/usr/bin/env python3
"""
§4.11 bgp_as_path -- resolve-time misuse-rejection proof (P8-P12; handover
§15.2 / §6.7.2). Mirrors bgp_community_validate_rejection_proof.py.

Proves resolve_topology hard-fails every bgp_as_path misuse at schema-validation
time with DC v2.1 §13(a)-sufficient content (what / where {ctx} / what-would-be-
valid), and that well-formed declarations resolve without false-fail. Covers
REQ-BGPASPATH-VALIDATE-1..5 (P8-P12) and REQ-BGPASPATH-SCHEMA-1 (positive).

resolve_topology is a module-level function, so this harness feeds synthetic
topologies through the real resolve seam directly (the bl6_*/udi_* pattern),
WITHOUT a deployed lab. cassian validate's quiet-die mode is mirrored
(cassian_common._QUIET_DIE = True) so the deterministic rejection message is
captured from SystemExit, exactly as cmd_validate captures it.

Proof obligations:
  P-NEG    well-formed anchored + _-idiom declarations resolve.
  P8  (V1) empty / non-string as_path specifier rejected.
  P9  (V2) non-compiling as_path regex (incl. after LD-C _-translation) rejected.
  P10 (V3) invalid / absent (non-CIDR) prefix rejected.
  P11 (V4) non-frr src node rejected.
  P12 (V5) missing / unknown src node rejected.
  P-13A    a representative rejection carries (a) what / (b) {ctx} / (c) what-valid.
  P-DET    identical misuse input -> byte-identical rejection message.
  P-NR     an existing invariant (bgp_community) still resolves (non-regression).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_common as _cc
_cc._QUIET_DIE = True  # mirror cmd_validate: die raises SystemExit(str(msg))
import cassian_model as cm

_NODES = [
    {"name": "r1", "type": "frr"},
    {"name": "h1", "type": "host"},
]


def _topo(test):
    return {"name": "bgpaspath-reject-proof", "nodes": [dict(n) for n in _NODES],
            "links": [], "tests": [test]}


def _inv(name="x", **kw):
    t = {"name": name, "kind": "invariant", "type": "bgp_as_path",
         "node": "r1", "prefix": "10.0.0.0/24", "as_path": "^65001 65002$",
         "expect": "pass"}
    t.update(kw)
    return t


def _resolve(topo):
    try:
        cm.resolve_topology(topo)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


def main():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # P-NEG: well-formed declarations resolve (no false-fail)
    o, _ = _resolve(_topo(_inv(as_path="^65001 65002$")))
    check("P-NEG anchored regex resolves", o == "ok")
    o, _ = _resolve(_topo(_inv(as_path="_65002_")))
    check("P-NEG _-idiom regex resolves", o == "ok")

    # P8 (VALIDATE-1): empty / non-string as_path specifier
    o, msg = _resolve(_topo(_inv(as_path="")))
    check("P8 empty as_path rejected",
          o == "die" and "bgp_as_path requires 'as_path'" in msg)
    o, msg = _resolve(_topo(_inv(as_path=123)))
    check("P8 non-string as_path rejected",
          o == "die" and "bgp_as_path requires 'as_path'" in msg)

    # P9 (VALIDATE-2): non-compiling regex (after LD-C _-translation)
    o, msg = _resolve(_topo(_inv(as_path="(")))
    check("P9 non-compiling regex rejected",
          o == "die" and "is not a valid AS-path regex" in msg
          and "bgp_as_path.as_path" in msg)

    # P10 (VALIDATE-3): invalid / absent (non-CIDR) prefix
    o, msg = _resolve(_topo(_inv(prefix="not-a-cidr")))
    check("P10 invalid prefix rejected",
          o == "die" and "bgp_as_path.prefix must be a valid CIDR" in msg)
    o, msg = _resolve(_topo(_inv(prefix="")))
    check("P10 absent prefix rejected",
          o == "die" and "bgp_as_path requires 'prefix'" in msg)

    # P11 (VALIDATE-4): non-frr src node
    o, msg = _resolve(_topo(_inv(node="h1")))
    check("P11 non-frr src rejected",
          o == "die" and "of type 'host'" in msg and "node of type 'frr'" in msg)

    # P12 (VALIDATE-5): missing / unknown src node
    o, msg = _resolve(_topo(_inv(node="r99")))
    check("P12 unknown src rejected",
          o == "die" and "no node by that name exists" in msg and "'r99'" in msg)

    # P-13A: §13(a) (a)/(b)/(c) on a representative rejection
    o, msg = _resolve(_topo(_inv(name="badap", as_path="(")))
    check("P-13A (a) what-wrong (not a valid regex)",
          "is not a valid AS-path regex" in msg)
    check("P-13A (b) {ctx} location (tests[i] (name))",
          "tests[" in msg and "(badap)" in msg)
    check("P-13A (c) what-valid (names field as_path + offending value)",
          "bgp_as_path.as_path" in msg and "'('" in msg)

    # P-DET: byte-identical rejection across two resolves
    _, ma = _resolve(_topo(_inv(name="d", as_path="(")))
    _, mb = _resolve(_topo(_inv(name="d", as_path="(")))
    check("P-DET rejection byte-identical across two resolves", ma == mb)

    # P-NR: existing invariant still resolves (non-regression)
    o, _ = _resolve(_topo({"name": "com", "kind": "invariant",
                           "type": "bgp_community", "node": "r1",
                           "prefix": "1.1.1.1/32", "expected": "65001:100"}))
    check("P-NR bgp_community resolves (non-regression)", o == "ok")

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
