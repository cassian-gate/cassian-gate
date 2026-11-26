#!/usr/bin/env python3
"""evpn_validate_rejection_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 7 (REQ-45E-35).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Doctrine §1.6 Hard-Fail Authoritative Input;
Doctrine §2.7; Design Contract v2.1 §13, "Authoritative input rejection content" (§13(a)) -- misuse of the
EVPN test declarations, the new kind's parameters included.

EXISTING OWNERS OF THE REST (proof-script ruling 1b; no leg is proved twice):
  - tests/checks_param_conformance_proof.py: the session kind's `peer` (P34), and every kind's declared
    parameters against validate in both directions.
  - tests/evpn_rr_next_hop_self_proof.py L-CENSUS: the rejected `fabric.evpn` files, by set membership.
  - tests/vm_runtime_validate_rejection_proof.py: `src` on a vm node.
  - tests/evpn_gen_proof.py: misuse of `fabric.evpn` itself, the L998 refusal among it.

HOW. Lab-free, through the real resolve seam: each test declaration is placed in the resolved-able hosted
fixture's topology (tests/fixtures/evpn-mac-route-valid/topology.yaml, its tests replaced) and handed to
cassian_model.resolve_topology, with cassian_common._QUIET_DIE set as `cassian validate --json` sets it,
so a rejection is the SystemExit carrying the message validate prints.

LEGS (one leg per EVPN route kind; a new kind adds a leg). For evpn_mac_route_present, evpn_mac_route_absent
and evpn_mac_route_valid (the new kind's parameters, REQ-45E-25):
  VR-OK      a well-formed declaration resolves, the MAC lowercased and the VNI an int.
  VR-MAC     `mac` missing, empty, or not six colon-separated octets: rejected, naming the kind and `mac`.
  VR-VNI     `vni` missing, not an integer, or 0: rejected, naming the kind and `vni`.
For evpn_vni_route_present: VR-OK, and VR-VNI as above.
  VR-13A     A representative rejection (evpn_mac_route_valid, vni 0) carries (a) what is wrong (`vni`),
             (b) where (its `tests[<index>]` locator and the test's name) and (c) what would be valid (`>= 1`).
  VR-DET     The same misuse, resolved twice, gives the same message bytes.
  VR-NV      Non-vacuity: two model mutants, one line changed each, loaded in memory: (1) the MAC-kind VNI
             range check removed: VR-VNI goes red for evpn_mac_route_valid; (2) the MAC format check
             removed: VR-MAC goes red.

COVERAGE LIMITS (PBE-P2-8). Only the declaration checks of the EVPN test kinds are exercised; the topology
around them is the hosted fixture's, which resolves. This script reads no lab.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import contextlib
import copy
import io
import os
import re
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

FIXTURE = os.path.join(_HERE, "fixtures", "evpn-mac-route-valid", "topology.yaml")
MAC_KINDS = ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_mac_route_valid")
VNI_KIND = "evpn_vni_route_present"

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


def base():
    import yaml
    with open(FIXTURE, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve(model, doc_base, test):
    from pathlib import Path
    doc = copy.deepcopy(doc_base)
    doc["tests"] = [test]
    try:
        out = model.resolve_topology(doc, topo_path=Path(FIXTURE))
        return "ok", out["tests"][0]
    except SystemExit as exc:
        return "die", str(exc)


def decl(kind, name="vr", **kw):
    t = {"name": name, "kind": "invariant", "type": kind, "node": "leaf2", "expect": "pass", "vni": 10100}
    if kind != VNI_KIND:
        t["mac"] = "00:11:22:33:44:55"
    t.update(kw)
    return {k: v for k, v in t.items() if v is not _DROP}


_DROP = object()


def legs(model, doc_base, label="VR"):
    ok = True
    for kind in MAC_KINDS + (VNI_KIND,):
        extra = {"mac": "00:11:22:33:44:AA"} if kind != VNI_KIND else {}
        o, t = resolve(model, doc_base, decl(kind, vni="10100", **extra))
        good = o == "ok" and t.get("vni") == 10100
        if kind != VNI_KIND:
            good = good and t.get("mac") == "00:11:22:33:44:aa"
        ok &= check("%s-OK %s: a well-formed declaration resolves (MAC lowercased, VNI an int)" % (label, kind), good, t)
        if kind != VNI_KIND:
            for what, mac in (("missing", _DROP), ("empty", ""), ("five octets", "00:11:22:33:44"),
                              ("not hex", "00:11:22:33:44:zz")):
                o, msg = resolve(model, doc_base, decl(kind, mac=mac))
                ok &= check("%s-MAC %s: mac %s is rejected, naming the kind and mac" % (label, kind, what),
                            o == "die" and kind in msg and "mac" in msg, msg)
        for what, vni in (("missing", _DROP), ("not an integer", "ten"), ("0", 0)):
            o, msg = resolve(model, doc_base, decl(kind, vni=vni))
            ok &= check("%s-VNI %s: vni %s is rejected, naming the kind and vni" % (label, kind, what),
                        o == "die" and kind in msg and "vni" in msg, msg)
    return ok


def model_mutant(old, new):
    path = os.path.join(_SRC, "cassian_model.py")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if text.count(old) != 1:
        return None
    mod = types.ModuleType("cassian_model_evpn_vr_mutant")
    mod.__file__ = path
    sys.modules[mod.__name__] = mod
    try:
        exec(compile(text.replace(old, new), "<cassian_model mutant>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(mod.__name__, None)
    return mod


def main():
    import cassian_common
    import cassian_model
    cassian_common._QUIET_DIE = True
    doc_base = base()
    o, _t = resolve(cassian_model, doc_base, decl("evpn_mac_route_valid"))
    check("VR the hosted fixture's topology resolves with one EVPN test in place", o == "ok", _t)
    legs(cassian_model, doc_base)

    o, msg = resolve(cassian_model, doc_base, decl("evpn_mac_route_valid", name="badvni", vni=0))
    check("VR-13A (a) what is wrong: the kind's vni", o == "die" and "evpn_mac_route_valid.vni" in msg, msg)
    check("VR-13A (b) where: the tests[<index>] locator and the test's name",
          re.search(r"tests\[[0-9]+\] \(badvni\)", msg) is not None, msg)
    check("VR-13A (c) what would be valid: >= 1", ">= 1" in msg, msg)
    _o, m2 = resolve(cassian_model, doc_base, decl("evpn_mac_route_valid", name="badvni", vni=0))
    check("VR-DET the same misuse gives the same message bytes twice", msg == m2)

    vni_check = ('                if vni_i < 1:\n                    die(f"{ctx}: {inv_type}.vni must be >= 1")\n'
                 '                t["vni"] = vni_i\n\n            elif inv_type == "evpn_vni_route_present":\n')
    vni_new = '                t["vni"] = vni_i\n\n            elif inv_type == "evpn_vni_route_present":\n'
    mac_check = ('                if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac_s):\n'
                 '                    die(f"{ctx}: {inv_type}.mac must be a valid MAC address")\n')
    for label, leg, old, new in (("the MAC kinds' VNI range check removed", "VR-VNI", vni_check, vni_new),
                                 ("the MAC format check removed", "VR-MAC", mac_check, "")):
        m = model_mutant(old, new)
        if not check("VR-NV the mutant's anchor is found once (%s)" % label, m is not None):
            continue
        _QUIET[0] = True
        n0 = len(_FAILED)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                legs(m, doc_base, label="(mutant)")
            red = [f for f in _FAILED[n0:] if f.startswith("(mutant)-" + leg.split("-")[1] + " evpn_mac_route_valid")]
        finally:
            _QUIET[0] = False
            del _FAILED[n0:]
        if red:
            print("MUTATION-FAIL: %s -> %s red for evpn_mac_route_valid" % (label, leg))
        check("VR-NV %s: %s goes red for evpn_mac_route_valid" % (label, leg), bool(red))

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_validate_rejection_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_validate_rejection_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
