#!/usr/bin/env python3
"""
R-O1 exec-into gate -- vm-runtime rejection proof (lab-free, CI-safe).

Authority: sonic-vm-open-questions-ruling-record (`d9850b4`), as extended by the
H-1..H-5 carry-forward note (the exec-into principle, Rev-3). Authors no
governance; numbers no precedent.

Proves that every node reference the framework EXECS INTO -- `src` (or `from`) on
ping / tcp / bgp_neighbor / all invariant types, and `dst` (or `to`) on tcp -- is
hard-failed at validation time (exit 2) with DC v2.1 §13-grade content when it
resolves to a node whose runtime is `vm`, and that the deliberate carve-outs are
NOT gated.

Harness pattern mirrors the established validate-rejection proofs (udi_*, tag_*,
bgp_community_*, bgp_as_path_*): synthetic in-code topologies fed through the real
seams (`ensure_valid_topology` -> `resolve_topology`) in cmd_validate's call order,
WITHOUT a deployed lab. cassian validate's quiet-die mode is mirrored
(cassian_common._QUIET_DIE = True) so the deterministic rejection message is
captured from SystemExit exactly as cmd_validate captures it.

Ruled cases (carry-forward note §5):
  (a) interface_state declared via `node:` on a vm node -> RUNTIME-gate message.
      Also proves the placement clause's invariant-coverage dependency: the gate
      sees `node:`-declared invariants ONLY because the invariant block's own
      node->src backfill runs earlier in the same loop iteration. A gate moved
      ahead of that backfill silently loses invariant coverage; this case reds.
  (b) bgp_community with `src` on a vm node -> FRR-gate message.
      Pins the accepted ordering (§4 note 1) as a CI-guarded fact: the existing
      frr type gate fires first and its message stands. The runtime gate is a
      backstop, not the first line. If a future change makes the runtime gate
      pre-empt, this case reds and the note's ordering claim gets revisited.
  (c) ping `src` on a vm node   -> RUNTIME-gate message.
  (d) tcp `src` on a vm node    -> RUNTIME-gate message.
  (e) tcp `dst` on a vm node    -> RUNTIME-gate message (the listener; C-4 leg).

Additional obligations:
  P-13     each runtime-gate rejection carries DC §13 (a) what / (b) where /
           (c) what-would-be-valid, names the kind and the node, and states the
           capability is UNSUPPORTED (not broken).
  P-CARVE  ping `dst` / `to` / `to_ip` against a vm node are NOT gated.
  P-IP     IP-literal references are never gated.
  P-MAP    map-resolved references only: an undeclared name is not gated here
           (no new declaration hard-fail -- carry-forward note §3).
  P-ALIAS  `from` and `to` alias forms are read.
  P-NR     container-runtime topologies still validate (no false-fail).
  P-DET    identical input -> byte-identical rejection message.

Exit 0 on all-pass; exit 1 on any failed assertion.
"""
import copy
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_common as _cc
_cc._QUIET_DIE = True  # mirror cmd_validate: die raises SystemExit(str(msg))
import cassian_model as cm

_VM_IMAGE = "ghcr.io/cassian-gate/sonic-vm:202405"

_NODES = [
    {"name": "r1", "type": "frr"},
    {"name": "r2", "type": "frr"},
    {"name": "s1", "type": "sonic-vm", "runtime": "vm", "image": _VM_IMAGE},
]


def _topo(test):
    return {
        "name": "vm-runtime-reject-proof",
        "nodes": [dict(n) for n in _NODES],
        # s1 is linked so that case (a)'s interface_state names a DECLARED interface.
        # The invariant block's own interface check fires before the runtime gate; an
        # undeclared interface would red case (a) for the wrong reason.
        "links": [
            {"endpoints": ["r1:eth1", "r2:eth1"]},
            {"endpoints": ["r1:eth2", "s1:eth1"]},
        ],
        "tests": [test],
    }


def _validate(test):
    """Mirror cmd_validate: ensure_valid_topology then resolve_topology."""
    td = copy.deepcopy(_topo(test))
    try:
        cm.ensure_valid_topology(td)
        cm.resolve_topology(td)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def _is_runtime_gate(msg):
    """The runtime gate's identifying content (not the frr type gate's)."""
    return "resolved runtime is 'vm'" in msg and "NOT SUPPORTED in this release" in msg


def main():
    # ---------------------------------------------------------------- ruled case (a)
    # interface_state declared via `node:` -- no frr gate intervenes; reaches the
    # runtime gate only via the invariant block's node->src backfill.
    a_o, a_m = _validate({
        "name": "ifs-vm", "kind": "invariant", "type": "interface_state",
        "node": "s1", "interface": "eth1",
    })
    check("(a) interface_state via node: on vm node rejected", a_o == "die")
    check("(a) rejection is the RUNTIME gate (proves node->src backfill dependency)",
          _is_runtime_gate(a_m))
    check("(a) message names the kind", "invariant test references" in a_m)
    check("(a) message names the node", "'s1'" in a_m)

    # ---------------------------------------------------------------- ruled case (b)
    # bgp_community: the existing frr type gate fires FIRST and its message stands.
    b_o, b_m = _validate({
        "name": "bc-vm", "kind": "invariant", "type": "bgp_community",
        "src": "s1", "prefix": "10.0.0.0/24", "expected": "65000:100",
    })
    check("(b) bgp_community src on vm node rejected", b_o == "die")
    check("(b) rejection is the FRR type gate, not the runtime gate (accepted ordering)",
          "src to be a node of type 'frr'" in b_m and not _is_runtime_gate(b_m))

    # ---------------------------------------------------------------- ruled case (c)
    c_o, c_m = _validate({
        "name": "ping-vm-src", "kind": "ping", "src": "s1", "dst": "r1",
    })
    check("(c) ping src on vm node rejected", c_o == "die")
    check("(c) rejection is the RUNTIME gate", _is_runtime_gate(c_m))
    check("(c) message names the kind", "ping test references" in c_m)

    # ---------------------------------------------------------------- ruled case (d)
    d_o, d_m = _validate({
        "name": "tcp-vm-src", "kind": "tcp", "src": "s1", "dst": "r1", "port": 443,
    })
    check("(d) tcp src on vm node rejected", d_o == "die")
    check("(d) rejection is the RUNTIME gate", _is_runtime_gate(d_m))
    check("(d) message names src", "references src node 's1'" in d_m)

    # ---------------------------------------------------------------- ruled case (e)
    e_o, e_m = _validate({
        "name": "tcp-vm-dst", "kind": "tcp", "src": "r1", "dst": "s1", "port": 443,
    })
    check("(e) tcp dst (listener) on vm node rejected", e_o == "die")
    check("(e) rejection is the RUNTIME gate", _is_runtime_gate(e_m))
    check("(e) message names dst", "references dst node 's1'" in e_m)

    # ---------------------------------------------------------------- P-13
    # DC v2.1 §13 (a)/(b)/(c) are non-negotiable for hard-fail rejection of
    # authoritative input. Asserted on the ping case; the message is one template.
    check("P-13 (a) what: names the offending reference and its runtime",
          "references src node 's1', whose resolved runtime is 'vm'" in c_m)
    check("P-13 (a) what: states UNSUPPORTED, not broken",
          "NOT SUPPORTED in this release" in c_m and "broken" not in c_m)
    check("P-13 (b) where: names the input locus",
          "tests[1] (ping-vm-src)" in c_m)
    check("P-13 (c) valid: names the corrective action",
          "Valid: give src a node whose resolved runtime is 'container'" in c_m)
    check("P-13 (c) valid: cites the contract clause defining validity",
          "DC v2.1 §10" in c_m)
    check("P-13 explains WHY the verdict would be wrong (engineer-first)",
          "vrnetlab launcher" in c_m and "wrong entity" in c_m)

    # ---------------------------------------------------------------- P-CARVE
    # ping dst/to/to_ip are addressing only -- dataplane ICMP to a vm node is
    # legitimate evidence and must NOT be gated.
    pc1_o, _ = _validate({"name": "ping-dst-vm", "kind": "ping", "src": "r1", "dst": "s1"})
    check("P-CARVE ping dst on vm node NOT gated", pc1_o == "ok")
    pc2_o, _ = _validate({"name": "ping-to-ip", "kind": "ping", "src": "r1", "to_ip": "10.0.0.2"})
    check("P-CARVE ping to_ip NOT gated", pc2_o == "ok")
    pc3_o, _ = _validate({"name": "ping-to", "kind": "ping", "src": "r1", "to": "10.0.0.2"})
    check("P-CARVE ping to NOT gated", pc3_o == "ok")

    # ---------------------------------------------------------------- P-IP
    ip_o, _ = _validate({"name": "tcp-ip-dst", "kind": "tcp", "src": "r1",
                         "dst": "10.0.0.2", "port": 443})
    check("P-IP IP-literal tcp dst not gated (only node names resolve to a runtime)",
          ip_o == "ok")

    # ---------------------------------------------------------------- P-MAP
    # Undeclared names keep existing behaviour: this gate introduces no new
    # declaration hard-fail (carry-forward note §3). Whatever happens to an
    # undeclared tcp src, it must not be THIS gate.
    map_o, map_m = _validate({"name": "tcp-undeclared", "kind": "tcp",
                              "src": "nosuchnode", "dst": "r1", "port": 443})
    check("P-MAP undeclared src not rejected by the runtime gate",
          not (map_o == "die" and _is_runtime_gate(map_m)))

    # ---------------------------------------------------------------- P-ALIAS
    al1_o, al1_m = _validate({"name": "ping-from-vm", "kind": "ping",
                              "from": "s1", "dst": "r1"})
    check("P-ALIAS ping 'from' alias is read", al1_o == "die" and _is_runtime_gate(al1_m))
    al2_o, al2_m = _validate({"name": "tcp-to-vm", "kind": "tcp", "src": "r1",
                              "to": "s1", "port": 443})
    check("P-ALIAS tcp 'to' alias is read", al2_o == "die" and _is_runtime_gate(al2_m))

    # ---------------------------------------------------------------- P-NR
    nr1_o, _ = _validate({"name": "ping-ok", "kind": "ping", "src": "r1", "dst": "r2"})
    check("P-NR container ping still validates", nr1_o == "ok")
    nr2_o, _ = _validate({"name": "tcp-ok", "kind": "tcp", "src": "r1", "dst": "r2",
                          "port": 443})
    check("P-NR container tcp still validates", nr2_o == "ok")
    nr3_o, _ = _validate({"name": "ifs-ok", "kind": "invariant", "type": "interface_state",
                          "node": "r1", "interface": "eth1"})
    check("P-NR container interface_state still validates", nr3_o == "ok")

    # ---------------------------------------------------------------- P-DET
    d1_o, d1_m = _validate({"name": "ping-vm-src", "kind": "ping", "src": "s1", "dst": "r1"})
    d2_o, d2_m = _validate({"name": "ping-vm-src", "kind": "ping", "src": "s1", "dst": "r1"})
    check("P-DET deterministic rejection message", d1_m == d2_m and d1_m == c_m)

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(("  PASS " if ok else "  FAIL ") + n)
    if failed:
        print("\nFAILED %d/%d: %s" % (len(failed), len(checks), "; ".join(failed)))
        sys.exit(1)
    print("\nAll %d checks passed." % len(checks))
    sys.exit(0)


if __name__ == "__main__":
    main()
