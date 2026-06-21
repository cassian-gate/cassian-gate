#!/usr/bin/env python3
"""
bgp_community_preservation_proof.py -- REQ-BGPCOM-PRES-1 (Phase 1b s4.10 WI-5).

Two halves, both lab-free (cassian-test-alone CI posture):

  P17 -- out-of-scope byte-identity. Every src/ module OUTSIDE
         {cassian_model.py, cassian_engine.py} is byte-identical to its
         d37a75f baseline (develop/phase1b post-s4.9-merge fork point) via
         reproducible per-module SHA-256, plus a module-set-drift guard.
         This is the BL-1b4-1 reproducible regression instrument, NOT the
         founder-reserved composite per-module pin. Baseline anchored to
         `git show d37a75f:src/*`.

  P19 -- predecessor positive replay. A representative positive topology
         fixture for each pre-s4.10 invariant family resolves cleanly through
         the real resolve_topology seam, proving the 14th-type catalog
         addition + the GEN-2 set-block validation did not newly reject any
         predecessor fixture. (The deployed verdict/output replay of the
         project's own topology is covered separately by the cassian.yml
         "Project gate" step; this harness covers the lab-free resolve
         boundary where s4.10's model change actually lives.)

Scoped (modifiable by s4.10; excluded from P17 byte-identity enforcement):
  cassian_model.py, cassian_engine.py.

Mirrors udi_preservation_proof.py / tag_preservation_proof.py (P17 half) and
the bl6_/udi_ lab-free resolve pattern (P19 half). No f-strings (version-port).

Exit 0 on all-pass; exit 1 (loud) on any drift, module-set change, or
predecessor resolve failure. Run from the repo root:
    python tests/bgp_community_preservation_proof.py
"""
import hashlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# d37a75f per-module SHA-256 baseline (authoritative: git show d37a75f:src/*).
D37A75F_BASELINE = {
    "src/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "src/cassian.py": "cbc931d2f977c37249599bf63229b507ce6ea4d58eb6ca5525b7269b70d4c895",
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "93db9b61e9fd22c74156fc0492119fc4e170a7a192684354c8a31c70876ff52d",
    "src/cassian_cli.py": "bcf460f7be2d2ec4280569bdfe3f30ab9d0784d6677a98a8db64579bf32ebf75",
    "src/cassian_common.py": "a0469a2a1b3cdcc5a1fffc7cd02198447cf1e0cb1ee8657469c3fb2c57139a10",
    "src/cassian_engine.py": "76edf21eadee1445a67b33248184a819c874a8f69940c15231f1e1453603b5a9",
    "src/cassian_model.py": "3e2b702ff3a62c55d4d24a7fd1b632cb400121e55107f3a6c9fccc78f08c89f6",
    "src/cassian_runtime_container.py": "b2a493f947c121416c992b8b9788a60acead190d305d58654c3c457def116ba3",
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_tests.py": "ba0a1f36245de1ac01853fca4e8a3100ff5aad28525e91ef26ebaf24f404b0af",
    "src/cassian_two_run.py": "694f4e0d8ca7e07e7f4843e4f269a697d74d19bcdece60adf6f339952e471452",
}

# s4.10 scoped set -- modifiable; excluded from byte-identity enforcement.
SCOPED = {"src/cassian_model.py", "src/cassian_engine.py"}

# P19 -- one representative positive fixture per pre-s4.10 invariant family.
PREDECESSOR_FIXTURES = [
    "bgp_med_equals.yaml",          # s4.5 bgp_med_equals (route-map set-block)
    "bgp_localpref_equals.yaml",    # s4.5 bgp_localpref_equals (route-map set-block)
    "route_advertised_to.yaml",     # s4.4 route_advertised_to
    "evpn_bgp_session_up.yaml",     # s4.1 bgp_session_up (evpn variant)
    "evpn_mac_route_present.yaml",  # evpn mac-route
    "evpn_vni_route_present.yaml",  # evpn vni-route
    "ospf_neighbor_up.yaml",        # ospf_neighbor_up
    "interface_state_up.yaml",      # interface_state
]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _p17(checks):
    src = os.path.join(_ROOT, "src")
    if not os.path.isdir(src):
        print("FAIL: run from the repo root (src/ not found)")
        checks.append(("P17 src/ present", False))
        return
    head = set("src/" + n for n in os.listdir(src) if n.endswith(".py"))
    known = set(D37A75F_BASELINE)
    added, removed = head - known, known - head
    set_ok = True
    if added:
        print("FAIL: src/ modules absent from the d37a75f baseline: " + str(sorted(added)))
        set_ok = False
    if removed:
        print("FAIL: d37a75f baseline modules missing at HEAD: " + str(sorted(removed)))
        set_ok = False
    checks.append(("P17 module-set matches d37a75f baseline", set_ok))

    enforced = 0
    drift_ok = True
    for mod in sorted(head):
        if mod in SCOPED:
            continue
        enforced += 1
        actual, expected = _sha256(os.path.join(_ROOT, mod)), D37A75F_BASELINE[mod]
        if actual != expected:
            print("FAIL: P17 drift " + mod)
            print("        expected " + expected)
            print("        actual   " + actual)
            drift_ok = False
    checks.append(("P17 non-scoped byte-identity vs d37a75f (" + str(enforced)
                   + " enforced, {model,engine} scoped)", drift_ok and enforced >= 11))


def _p19(checks):
    import yaml
    import cassian_common as _cc
    _cc._QUIET_DIE = True  # mirror cmd_validate: die -> SystemExit(str(msg))
    import cassian_model as cm

    topo_dir = os.path.join(_ROOT, "topologies")
    resolved_count = 0
    for fx in PREDECESSOR_FIXTURES:
        path = os.path.join(topo_dir, fx)
        if not os.path.isfile(path):
            checks.append(("P19 " + fx + " present", False))
            continue
        ok = True
        try:
            with open(path, "r", encoding="utf-8") as f:
                topo = yaml.safe_load(f)
            cm.resolve_topology(topo)
        except SystemExit as e:
            ok = False
            print("FAIL: P19 " + fx + " newly REJECTED at resolve: " + str(e))
        except Exception as e:
            ok = False
            print("FAIL: P19 " + fx + " resolve raised " + type(e).__name__ + ": " + str(e))
        if ok:
            resolved_count += 1
        checks.append(("P19 " + fx + " resolves clean", ok))
    # non-vacuity guard: the curated predecessor set must actually have run
    checks.append(("P19 non-vacuity (>=6 predecessor fixtures resolved clean)",
                   resolved_count >= 6))


def main():
    checks = []
    _p17(checks)
    _p19(checks)
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + "  " + name)
    failed = [n for n, ok in checks if not ok]
    if failed:
        print("\nPRESERVATION FAIL: " + str(len(failed)) + " check(s): " + "; ".join(failed))
        sys.exit(1)
    print("\nRESULT: PASS -- " + str(len(checks))
          + " checks: P17 out-of-scope byte-identity vs d37a75f + P19 predecessor resolve intact.")
    sys.exit(0)


if __name__ == "__main__":
    main()
