#!/usr/bin/env python3
"""evpn_catalog_coherence_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 2 (REQ-45E-30).

DOCTRINE SURFACE THIS SCRIPT OWNS (proof-script ruling 1a): Doctrine §1.14 Invariant-Driven Support -- the
operative catalogue's pack-subset membership of the EVPN kinds, and the support boundary of REQ-45E-45 and
REQ-45E-26: EVPN is FRR's, and no other node type declares it.

EXISTING OWNERS OF THE REST (proof-script ruling 1b; no leg is proved twice):
  - tests/expf_four_quadrant_catalog_proof.py P-EXPF-CAT: Site A membership and the catalogue drift guard.
  - the bgp_as_path and bgp_community coherence proofs, P15-AB: Site A equals Site B, catalogue-wide.
  - evpn_bgp_session_up in Site C: guarded by the golden's `datacenter-bgp-safety` profile
    (tests/fixtures/checks_catalogue.json), through tests/checks_catalogue_coherence_proof.py P15 and the drift
    proof. This script does not assert it.
  - tests/sonic_observation_kinds_proof.py K-CAP: the existing partial owner of SONiC's capability map, for the
    kinds SONiC implements. This script reads the same map for the EVPN kinds only.
  - tests/checks_catalogue_drift_proof.py: the golden equals the generated catalogue, so the cells read here
    are the cells the golden carries.

LEGS (one leg per EVPN kind; a new kind adds a leg)
  CC-C       Site C (`supported_pack_invariant_types`, src/cassian_model.py) holds evpn_mac_route_present,
             evpn_mac_route_absent and evpn_vni_route_present, each, and does NOT hold evpn_mac_route_valid
             (the ESC-3 ruling; REQ-45E-26). Site C stays a subset of Site A.
  CC-SONIC   SONiC's capability map (`_SONIC_CAPABILITIES`, src/cassian_nos_sonic.py) holds no `evpn_*` key
             (REQ-45E-45).
  CC-CELLS   For each of the five EVPN kinds, the catalogue's cell for every node type other than frr reads
             `not implemented`, with a reason (REQ-45E-26). The node types are the provider registry's, read
             live; frr is the only one excluded, by name.
  CC-NV      Non-vacuity: (1) a model mutant whose Site C gains evpn_mac_route_valid: CC-C goes red; (2) a model
             mutant whose Site C loses evpn_vni_route_present: CC-C goes red; (3) SONiC's map given an
             `evpn_mac_route_valid` entry, in memory: CC-SONIC and CC-CELLS go red. Each is undone before
             the result.

COVERAGE LIMITS (PBE-P2-8). Site C is read from the model's source, as the bgp coherence proofs read it.
This script reads no lab and runs no command.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import contextlib
import io
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

EVPN_KINDS = ("evpn_bgp_session_up", "evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present",
              "evpn_mac_route_valid")
IN_SITE_C = ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present")
NOT_IN_SITE_C = ("evpn_mac_route_valid",)

_FAILED = []
_COUNT = [0]
_QUIET = [False]


def check(name, ok, detail=""):
    if not _QUIET[0]:
        _COUNT[0] += 1
        print(("PASS   " if ok else "FAIL   ") + name + ("" if ok or not detail else "  -- " + str(detail)))
    if not ok:
        _FAILED.append(name)
    return bool(ok)


def site_a(model_src):
    if not re.search(r"^\s*if inv_type not in _INVARIANT_TYPES:", model_src, re.MULTILINE):
        return ()
    m = re.search(r"^_INVARIANT_TYPES\b[^=\n]*=\s*\((.*?)\)", model_src, re.DOTALL | re.MULTILINE)
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1))) if m else ()


def site_c(model_src):
    m = re.search(r"supported_pack_invariant_types\s*=\s*\{(.*?)\}", model_src, re.DOTALL)
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1))) if m else ()


def cc_c(model_src, label="CC-C"):
    a, c = site_a(model_src), site_c(model_src)
    ok = check("%s Site A and Site C are read from the model" % label, bool(a) and bool(c), (len(a), len(c)))
    for kind in IN_SITE_C:
        ok &= check("%s %s is in Site C" % (label, kind), kind in c)
    for kind in NOT_IN_SITE_C:
        ok &= check("%s %s is NOT in Site C (ESC-3 ruling)" % (label, kind), kind not in c)
    ok &= check("%s Site C is a subset of Site A" % label, set(c) <= set(a), sorted(set(c) - set(a)))
    return ok


def cc_sonic(sonic, label="CC-SONIC"):
    keys = sorted(k for k in sonic._SONIC_CAPABILITIES if k.startswith("evpn"))
    return check("%s SONiC's capability map holds no evpn_* key (REQ-45E-45)" % label, not keys, keys)


def cc_cells(label="CC-CELLS"):
    import cassian_catalogue
    cells = {c["id"]: c["status"] for c in cassian_catalogue._checks(cassian_catalogue._node_types())}
    others = [nt["type"] for nt in cassian_catalogue._node_types() if nt["type"] != "frr"]
    ok = check("%s the registry has node types other than frr to read" % label, bool(others), others)
    for kind in EVPN_KINDS:
        st = cells.get(kind)
        good = st is not None and all(
            st.get(nt, {}).get("state") == "not implemented" and st.get(nt, {}).get("reason") for nt in others)
        ok &= check("%s %s: every node type other than frr reads `not implemented`, with a reason (%s)" % (
            label, kind, ", ".join(others)), good, None if st is None else {nt: st.get(nt) for nt in others})
    return ok


def model_mutant_src(model_src, old, new):
    return model_src.replace(old, new) if model_src.count(old) == 1 else None


def quiet(fn, *a):
    _QUIET[0] = True
    n0 = len(_FAILED)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*a)
    finally:
        _QUIET[0] = False
        del _FAILED[n0:]


def main():
    import cassian_common
    cassian_common._QUIET_DIE = True
    import cassian_nos_sonic as sonic
    with open(os.path.join(_SRC, "cassian_model.py"), encoding="utf-8") as fh:
        model_src = fh.read()

    cc_c(model_src)
    cc_sonic(sonic)
    cc_cells()

    anchor = 'supported_pack_invariant_types = {\n    "evpn_bgp_session_up",\n'
    for label, old, new in (
            ("Site C gains evpn_mac_route_valid", anchor, anchor + '    "evpn_mac_route_valid",\n'),
            ("Site C loses evpn_vni_route_present",
             '    "evpn_mac_route_absent",\n    "evpn_vni_route_present",\n    "bgp_localpref_equals",\n',
             '    "evpn_mac_route_absent",\n    "bgp_localpref_equals",\n')):
        m = model_mutant_src(model_src, old, new)
        if not check("CC-NV the mutant's anchor is found once (%s)" % label, m is not None):
            continue
        held = quiet(cc_c, m, "(mutant)")
        if not held:
            print("MUTATION-FAIL: %s -> CC-C red" % label)
        check("CC-NV %s: CC-C goes red" % label, not held)

    from cassian_nos_types import impl
    sonic._SONIC_CAPABILITIES["evpn_mac_route_valid"] = impl()
    try:
        sonic_held = quiet(cc_sonic, sonic, "(mutant)")
        cells_held = quiet(cc_cells, "(mutant)")
    finally:
        del sonic._SONIC_CAPABILITIES["evpn_mac_route_valid"]
    if not sonic_held and not cells_held:
        print("MUTATION-FAIL: SONiC declares evpn_mac_route_valid -> CC-SONIC and CC-CELLS red")
    check("CC-NV SONiC's map given evpn_mac_route_valid: CC-SONIC and CC-CELLS go red",
          not sonic_held and not cells_held, (sonic_held, cells_held))
    check("CC-NV SONiC's map is restored", "evpn_mac_route_valid" not in sonic._SONIC_CAPABILITIES
          and quiet(cc_cells, "(restored)"))

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_catalog_coherence_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_catalog_coherence_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
