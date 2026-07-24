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

from preservation_manifest import MODULE_ROSTER

# d37a75f per-module SHA-256 baseline (authoritative: git show d37a75f:src/*).
D37A75F_BASELINE = {
    "src/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "src/cassian.py": "45c5180e30e2d4bda791db9c90d8ae31c0797e7fbe98d2df47c54127643b6c2d",  # re-baselined from 588fbed5 (phase2 §4.5-b WI-F dead-code sweep (ensure_ip_tools import) + guardrail comment correction); orig cbc931d2
    "src/cassian_ai.py": "6900c52ea52f2a4a588b99478f10e967603b7a1a5f87b3b257878d4fde569361",
    "src/cassian_artifacts.py": "ae8a54302e4fa8fe2f89e3af0e1e16dcda0ff2ae7bc4a805b671f69029fbb04c",
    "src/cassian_candidate.py": "7775a062f27461fc76b1ae6c1e252550e30ecf3498412885e0a82e9fe02799ed",  # re-baselined from 93db9b61 (phase2 §4.5-b WI-D1 registry-derived candidate subdirs); orig 93db9b61
    "src/cassian_cli.py": "9234f3fdb76b5432bac8bf22a9807f234da9dff3a72d7c334ed9e2508183898a",
    "src/cassian_import.py": "604c8d8ff2bc461f8b43d7e5be6f63bd00f653ce6f83b64ffff9cf90450cf71c",  # §4.14 new module, enforced (LD-8/LD-9)
    "src/cassian_nos_frr.py": "3c53970d87a18ea828f0bb9008f24c75b22fdf5dd3a45a7c45e0b72faedd7ff3",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_nos_types.py": "b4e4cec8e0532b3280db4c8f0480f1884336a273ee7690d8992eee087b362eb6",  # §4.5-b new module (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9)
    "src/cassian_common.py": "0f5a326f3407811ba9afa8c449a15a9526e101a0ba258998b29bd633e48223bb",  # re-baselined from a0469a2a (phase2 §4.5-b WI-C1/C2 NOS-neutral re-homes + A-S6 provenance comment); orig a0469a2a
    "src/cassian_runtime_container.py": "7eecee129911d838d15e7e20463db66475fd190b9cbbfb0435ebc33a79303761",  # re-baselined from b3e45fa2 (phase2 §4.5-b WI-C1 _normalize_prefix shim + WI-F ensure_ip_tools removal); orig b2a493f9
    "src/cassian_runtime_vm.py": "3832ad07ef6e9ce483bc0fe0f017df4584b15bf6c3a90c55fbb0b2b14f84f494",  # re-baselined from 865545e4 (phase2 §4.5-b WI-D2 node_runtime_map model-homing); orig 865545e4
    "src/cassian_state.py": "aec4d412ee53555156cb5275c5d7a1329f54aaef298d4409feebcad2c198a9d6",
    "src/cassian_tests.py": "49f484b027c146c3c4f513ef3829e6909b0d142743f3ffdbcdadf3c8751ae2d0",  # re-baselined from dd56046b (phase2 §4.5-b WI-C1 parse-family relocation shims); orig ba0a1f36
    "src/cassian_two_run.py": "a6432665dbfee699713fe60c2e42d427c3c3fd9f82be7ec0ab65caa8b34c3ed9",  # re-baselined from cfafdfa6 (phase2 4.4 F-1 canonical serializer); orig 694f4e0d
}

# s4.10 scoped set -- modifiable; excluded from byte-identity enforcement.
SCOPED = {"src/cassian_model.py", "src/cassian_engine.py"}
ALLOWED_NEW = set()  # #3 bgp_community: no allowed-new; cassian_import is enforced

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
    # module-set drift read from the roster (bidirectional; LD-9 leg).
    added, removed = head - MODULE_ROSTER, MODULE_ROSTER - head
    set_ok = True
    if added:
        print("FAIL: src/ modules absent from the module roster (unregistered): " + str(sorted(added)))
        set_ok = False
    if removed:
        print("FAIL: rostered src/ modules missing at HEAD: " + str(sorted(removed)))
        set_ok = False
    checks.append(("P17 module-set matches roster (denom " + str(len(MODULE_ROSTER)) + ")", set_ok))

    # enforced set derived FROM THE ROSTER (not baseline keys); a rostered-enforced
    # module absent from the baseline fails loud, never skipped, never auto-baselined.
    enforced_set = MODULE_ROSTER - SCOPED - ALLOWED_NEW
    unbaselined = sorted(m for m in enforced_set if m not in D37A75F_BASELINE)
    if unbaselined:
        print("FAIL: re-baseline required (rostered + enforced, absent from baseline): " + str(unbaselined))
    checks.append(("P17 all enforced modules baselined (F-1 re-baseline guard)", not unbaselined))

    enforced = 0
    drift_ok = True
    for mod in sorted(enforced_set):
        if mod not in D37A75F_BASELINE:
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
