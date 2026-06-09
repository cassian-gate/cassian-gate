#!/usr/bin/env python3
"""
§4.7 User-Defined Invariants (`exec`) -- resolve-time misuse-rejection proof
(SP #1-pattern; handover §15(c) / §6.7.2; A5).

Proves that resolve_topology hard-fails every `exec` misuse at schema-validation
time (cassian validate exit 2) with DC v2.1 §13(a)-sufficient content, and that
well-formed `exec` tests resolve without false-fail. Covers REQ-UDI-VALIDATE-1/2/3/4,
SCHEMA-2/3, DOCTRINE-2 (freeform grep impossible by construction).

resolve_topology is a module-level function, so this harness feeds synthetic
topologies through the real resolve seam directly (the bl6_* / h53_* pattern),
WITHOUT a deployed lab. cassian validate's quiet-die mode is mirrored
(cassian_common._QUIET_DIE = True) so the deterministic rejection message is
captured from SystemExit, exactly as cmd_validate captures it.

Proof obligations:
  P-NEG    well-formed frr/nft-fw exec tests resolve (no false-fail).
  P-V1     out-of-allow-list / raw-shell commands rejected (VALIDATE-1).
  P-V2     non-typed / freeform assertions rejected (VALIDATE-2, DOCTRINE-2).
  P-V3     missing / undeclared / unsupported-derived-type target rejected (VALIDATE-3).
  P-S2     unknown keys (incl. `scope`, operator timing) rejected (SCHEMA-2).
  P-13A    each rejection carries (a) what was wrong, (b) {ctx} (tests[i] (name)),
           (c) what would be valid (allow-list / operator set / supported types) (VALIDATE-4).
  P-DET    identical misuse input -> byte-identical rejection message (deterministic).
  P-NR     existing invariant/ping tests still resolve (non-regression).

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
    {"name": "fw1", "type": "nft-fw"},
    {"name": "h1", "type": "host"},
]


def _topo(test):
    return {"name": "udi-reject-proof", "nodes": [dict(n) for n in _NODES],
            "links": [], "tests": [test]}


def _exec(name="x", **kw):
    t = {"name": name, "kind": "exec", "src": "r1",
         "command": 'vtysh -c "show bgp summary json"',
         "assertion": {"contains": "Established"}}
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

    # P-NEG: well-formed exec tests resolve (no false-fail)
    o, _ = _resolve(_topo(_exec(src="r1", command='vtysh -c "show ip route"',
                                assertion={"field": {"path": ["0", "prefix"], "op": "==",
                                                     "value": "0.0.0.0/0"}})))
    check("P-NEG frr show + field assertion resolves", o == "ok")
    o, _ = _resolve(_topo(_exec(src="fw1", command='nft list ruleset',
                                assertion={"contains": "drop"})))
    check("P-NEG nft-fw list + contains resolves", o == "ok")

    # P-V1: out-of-allow-list / raw-shell commands rejected
    for label, cmd, node in [
        ("frr non-show (configure)", 'vtysh -c "configure terminal"', "r1"),
        ("nft mutation (flush)", "nft flush ruleset", "fw1"),
        ("raw shell sh -lc", 'sh -lc "show bgp"', "r1"),
        ("pipe", "nft list ruleset | grep drop", "fw1"),
    ]:
        o, msg = _resolve(_topo(_exec(src=node, command=cmd)))
        check(f"P-V1 {label} rejected", o == "die" and "command rejected" in msg)

    # P-V2: non-typed / freeform assertions rejected (DOCTRINE-2)
    o, msg = _resolve(_topo(_exec(assertion="grep Established")))
    check("P-V2 freeform-string assertion rejected",
          o == "die" and "typed predicate" in msg)
    o, msg = _resolve(_topo(_exec(assertion={"grep": "x"})))
    check("P-V2 unknown-operator assertion rejected",
          o == "die" and "typed operator" in msg)

    # P-V3: target rejections
    nt = {"name": "x", "kind": "exec", "command": 'vtysh -c "show ip route"',
          "assertion": {"contains": "x"}}
    o, msg = _resolve(_topo(nt))
    check("P-V3 missing target rejected",
          o == "die" and "requires a target node" in msg)
    o, msg = _resolve(_topo(_exec(src="r99")))
    check("P-V3 undeclared target rejected",
          o == "die" and "not declared in topology" in msg and "'r99'" in msg)
    o, msg = _resolve(_topo(_exec(src="h1")))
    check("P-V3 unsupported derived type (host) rejected",
          o == "die" and "node type 'host'" in msg)

    # P-S2: unknown keys (incl. scope, operator timing) -- A5
    o, msg = _resolve(_topo(_exec(scope="frr")))
    check("P-S2 'scope' key rejected as unknown (A5)",
          o == "die" and "unknown key 'scope'" in msg)
    o, msg = _resolve(_topo(_exec(timeout_s=5)))
    check("P-S2 operator timing key rejected as unknown (A5)",
          o == "die" and "unknown key 'timeout_s'" in msg)

    # P-13A: §13(a) (a)/(b)/(c) on a representative out-of-allow-list rejection
    o, msg = _resolve(_topo(_exec(name="badcmd", src="r1",
                                  command='vtysh -c "configure terminal"')))
    check("P-13A (a) what-wrong (not read-only)", "is not read-only" in msg)
    check("P-13A (b) {ctx} location (tests[i] (name))",
          "tests[" in msg and "(badcmd)" in msg)
    check("P-13A (c) what-valid (allow-list)",
          "Allowed: frr ->" in msg and "nft list" in msg)

    # P-DET: byte-identical rejection across two resolves
    _, ma = _resolve(_topo(_exec(name="d", src="fw1", command="nft flush ruleset")))
    _, mb = _resolve(_topo(_exec(name="d", src="fw1", command="nft flush ruleset")))
    check("P-DET rejection byte-identical across two resolves", ma == mb)

    # P-NR: existing kinds still resolve (non-regression)
    o, _ = _resolve(_topo({"name": "inv", "kind": "invariant", "type": "bgp_session_up",
                           "node": "r1", "neighbor": "fw1"}))
    check("P-NR invariant resolves (non-regression)", o == "ok")
    o, _ = _resolve(_topo({"name": "png", "kind": "ping", "src": "r1", "dst": "10.0.0.1"}))
    check("P-NR ping resolves (non-regression)", o == "ok")

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
