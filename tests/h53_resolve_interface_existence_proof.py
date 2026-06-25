#!/usr/bin/env python3
"""
§4.4 BL-H5-3 resolve-time interface-existence proof (owns doctrine surface S2;
handover §10a / §6.7.2).

Proves that resolve_topology hard-fails an invariant interface reference absent
from the referenced node's resolved interface set (link interfaces + 'lo' +
fw/host interfaces, LD-2), parallel to the node-existence rejection, with DC
v2.1 §13(a)-sufficient content -- and that existing interfaces never false-fail.

resolve_topology is a module-level function, so this harness feeds synthetic
topologies through the real resolve seam directly (the bl6_* / bl_h3_8_* pattern),
WITHOUT a deployed lab. cassian validate's quiet-die mode is mirrored
(cassian_common._QUIET_DIE = True) so the deterministic rejection message is
captured from SystemExit, exactly as cmd_validate captures it.

Proof obligations (handover §15.2):
  P-H53-POS  a nonexistent interface reference hard-fails resolve (SystemExit;
             cassian validate exit 2) with a §13(a) rejection.
  P-H53-NEG  existing interfaces, 'lo', and fw/host interfaces resolve with no
             false positive.
  P-13A      the rejection contains (a) the unknown-interface clause + value,
             (b) the {ctx} location (tests[i] (name)), and (c) the declared
             interface set rendered in sorted order.
  P-DET      two resolves of identical input produce a byte-identical rejection
             message (deterministic; element (c) sorted) -- REQ-ENGVAL-PRES-4 / D03.
  H53-4      the existing node-existence / presence / format rejections are
             unchanged (non-regression).

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


def _topo(test, *, nodes=None, links=None):
    return {
        "name": "h53-proof",
        "nodes": nodes if nodes is not None else [
            {"name": "r1", "type": "frr"},
            {"name": "r2", "type": "frr"},
        ],
        "links": links if links is not None else [
            {"endpoints": ["r1:eth1", "r2:eth1"]},
            {"endpoints": ["r1:eth2", "r2:eth2"]},
        ],
        "tests": [test],
    }


def _iface_test(name, node, interface):
    return {"name": name, "kind": "invariant", "type": "interface_state",
            "node": node, "interface": interface, "state": "up", "expect": "pass"}


def _resolve(topo):
    # ("ok", "") if resolve succeeds; ("die", msg) if it hard-fails.
    try:
        cm.resolve_topology(topo)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


def main():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # P-H53-NEG: existing link interfaces + 'lo' resolve (no false positive)
    for iface in ("eth1", "eth2", "lo"):
        outcome, _ = _resolve(_topo(_iface_test("pos", "r1", iface)))
        check(f"P-H53-NEG existing iface {iface!r} resolves (no false positive)",
              outcome == "ok")

    # P-H53-NEG: fw/host interfaces (node 'interfaces' dict) resolve
    fw_nodes = [
        {"name": "r1", "type": "frr"},
        {"name": "fw1", "type": "nft-fw",
         "interfaces": {"eth0": "10.1.1.1/24", "eth1": "10.1.2.1/24"}},
    ]
    fw_links = [{"endpoints": ["fw1:eth0", "r1:eth1"]}]
    outcome, _ = _resolve(_topo(_iface_test("fwpos", "fw1", "eth1"),
                                 nodes=fw_nodes, links=fw_links))
    check("P-H53-NEG fw interfaces-dict iface 'eth1' resolves", outcome == "ok")

    # P-H53-POS + P-13A: nonexistent interface hard-fails with §13(a) content
    outcome, msg = _resolve(_topo(_iface_test("bad_iface", "r1", "eth9")))
    check("P-H53-POS nonexistent iface hard-fails (SystemExit)", outcome == "die")
    check("P-13A (a) unknown-interface clause + value",
          "references unknown 'interface'" in msg and "'eth9'" in msg)
    check("P-13A (b) {ctx} location present (tests[i] (name))",
          "tests[" in msg and "(bad_iface)" in msg)
    check("P-13A (c) declared set present and sorted",
          "(declared interfaces: eth1, eth2, lo)" in msg)

    # P-DET: byte-identical rejection across two resolves of identical input
    _, msg_a = _resolve(_topo(_iface_test("bad_iface", "r1", "eth9")))
    _, msg_b = _resolve(_topo(_iface_test("bad_iface", "r1", "eth9")))
    check("P-DET rejection byte-identical across two resolves", msg_a == msg_b)

    # H53-4 non-regression: existing node-existence / presence / format rejections
    outcome, msg = _resolve(_topo(_iface_test("bad_node", "r99", "eth1")))
    check("H53-4 unknown node still rejected (node-existence intact)",
          outcome == "die" and "references unknown 'node'" in msg and "'r99'" in msg)
    outcome, msg = _resolve(_topo({"name": "bad_missing", "kind": "invariant",
                                   "type": "interface_state", "node": "r1",
                                   "state": "up", "expect": "pass"}))
    check("H53-4 missing 'interface' still rejected (presence intact)",
          outcome == "die" and "requires 'interface'" in msg)
    outcome, msg = _resolve(_topo({"name": "bad_state", "kind": "invariant",
                                   "type": "interface_state", "node": "r1",
                                   "interface": "eth1", "state": "maybe",
                                   "expect": "pass"}))
    check("H53-4 invalid 'state' still rejected (format intact)",
          outcome == "die" and "invalid 'state'" in msg)

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
