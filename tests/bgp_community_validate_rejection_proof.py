#!/usr/bin/env python3
"""
§4.10 bgp_community -- resolve-time misuse-rejection proof (P8-P13; handover
§15.2 / §6.7.2; SP #1-pattern). Mirrors udi_validate_rejection_proof.py.

Proves resolve_topology hard-fails every bgp_community misuse at
schema-validation time with DC v2.1 §13(a)-sufficient content (what / where
{ctx} / what-would-be-valid), and that well-formed scalar/list declarations
resolve without false-fail. Covers REQ-BGPCOM-VALIDATE-1..6 (P8-P13) and
REQ-BGPCOM-SCHEMA-1 (positive).

resolve_topology is a module-level function, so this harness feeds synthetic
topologies through the real resolve seam directly (the bl6_*/udi_* pattern),
WITHOUT a deployed lab. cassian validate's quiet-die mode is mirrored
(cassian_common._QUIET_DIE = True) so the deterministic rejection message is
captured from SystemExit, exactly as cmd_validate captures it.

Proof obligations:
  P-NEG    well-formed scalar + list(any/all) + well-known declarations resolve.
  P8  (V1) malformed community specifier rejected.
  P9  (V2) invalid (non-CIDR) prefix rejected.
  P10 (V3) `match` with scalar `expected` rejected.
  P11 (V4) list `expected` with missing/invalid `match` rejected.
  P12 (V5) malformed list element rejected.
  P13 (V6) unsupported node type (undeclared + non-frr) rejected.
  P-13A    each rejection carries (a) what / (b) {ctx} / (c) what-would-be-valid.
  P-DET    identical misuse input -> byte-identical rejection message.
  P-NR     an existing invariant (bgp_med_equals) still resolves (non-regression).

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
    return {"name": "bgpcom-reject-proof", "nodes": [dict(n) for n in _NODES],
            "links": [], "tests": [test]}


def _inv(name="x", **kw):
    t = {"name": name, "kind": "invariant", "type": "bgp_community",
         "node": "r1", "prefix": "1.1.1.1/32", "expected": "65001:100",
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
    o, _ = _resolve(_topo(_inv(expected="65001:100")))
    check("P-NEG scalar AS:VAL resolves", o == "ok")
    o, _ = _resolve(_topo(_inv(expected=["65001:100", "no-export"], match="any")))
    check("P-NEG list match:any resolves", o == "ok")
    o, _ = _resolve(_topo(_inv(expected=["65001:100", "no-export"], match="all")))
    check("P-NEG list match:all resolves", o == "ok")
    o, _ = _resolve(_topo(_inv(expected="internet")))
    check("P-NEG scalar well-known resolves", o == "ok")

    # P8 (VALIDATE-1): malformed community specifier
    o, msg = _resolve(_topo(_inv(expected="x")))
    check("P8 malformed scalar specifier rejected",
          o == "die" and "is malformed" in msg and "bgp_community.expected" in msg)

    # P9 (VALIDATE-2): invalid (non-CIDR) prefix
    o, msg = _resolve(_topo(_inv(prefix="not-a-cidr")))
    check("P9 invalid prefix rejected",
          o == "die" and "bgp_community.prefix must be a valid CIDR" in msg)

    # P10 (VALIDATE-3): match with scalar expected
    o, msg = _resolve(_topo(_inv(expected="65001:100", match="any")))
    check("P10 scalar + match rejected",
          o == "die" and "not permitted when 'expected' is a single community" in msg)

    # P11 (VALIDATE-4): list expected, missing / invalid match
    o, msg = _resolve(_topo(_inv(expected=["65001:100"])))
    check("P11 list missing match rejected",
          o == "die" and "must be one of {any, all} and is required when 'expected' is a list" in msg)
    o, msg = _resolve(_topo(_inv(expected=["65001:100"], match="some")))
    check("P11 list invalid match rejected",
          o == "die" and "must be one of {any, all}" in msg)

    # P12 (VALIDATE-5): malformed list element
    o, msg = _resolve(_topo(_inv(expected=["65001:100", "x"], match="any")))
    check("P12 malformed list element rejected",
          o == "die" and "community 'x' is malformed" in msg)

    # P13 (VALIDATE-6): unsupported node type
    o, msg = _resolve(_topo(_inv(node="r99")))
    check("P13 undeclared node rejected",
          o == "die" and "no node by that name exists" in msg and "'r99'" in msg)
    o, msg = _resolve(_topo(_inv(node="h1")))
    check("P13 non-frr node rejected",
          o == "die" and "of type 'host'" in msg and "node of type 'frr'" in msg)

    # P-13A: §13(a) (a)/(b)/(c) on a representative rejection
    o, msg = _resolve(_topo(_inv(name="badcom", expected="bogus")))
    check("P-13A (a) what-wrong (malformed)", "is malformed" in msg)
    check("P-13A (b) {ctx} location (tests[i] (name))",
          "tests[" in msg and "(badcom)" in msg)
    check("P-13A (c) what-valid (AS:VAL / well-known set)",
          "expected AS:VAL" in msg and "no-export" in msg)

    # P-DET: byte-identical rejection across two resolves
    _, ma = _resolve(_topo(_inv(name="d", expected="bad")))
    _, mb = _resolve(_topo(_inv(name="d", expected="bad")))
    check("P-DET rejection byte-identical across two resolves", ma == mb)

    # P-NR: existing invariant still resolves (non-regression)
    o, _ = _resolve(_topo({"name": "med", "kind": "invariant",
                           "type": "bgp_med_equals", "node": "r1",
                           "prefix": "1.1.1.1/32", "expected": 50}))
    check("P-NR bgp_med_equals resolves (non-regression)", o == "ok")

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
