#!/usr/bin/env python3
"""evpn_eval_match_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 3 (REQ-45E-31).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Design Contract v2.1 §8 Routing invariant contract;
Doctrine §1.7 Evidence-First Validation -- the EVPN predicates: what each EVPN kind reads as satisfied.

EXISTING OWNERS OF THE REST (proof-script ruling 1b): none. EVPN has no module-level predicate helper; the bgp
twins test module-level helpers, EVPN's predicates are inline. The verdict line (observed vs expect) is
tests/expf_four_quadrant_catalog_proof.py's and the record branch's quadrants are
tests/evpn_four_quadrant_proof.py's; this script repeats neither.

LEGS (one leg per EVPN kind; a new kind adds a leg)
  EM-MAP      The engine's own observed mapping in run_invariant_test's route branch (AST-extracted, the
              `if inv_type == "evpn_mac_route_present"` chain that assigns `observed`), run on every
              (present, valid) pair: present -> pass for evpn_mac_route_present and evpn_vni_route_present;
              not present -> pass for evpn_mac_route_absent; valid -> pass for evpn_mac_route_valid, so a
              route present with no valid path reads fail (REQ-45E-25). The session branch's mapping
              (`observed = "pass" if present else "fail"`) is read the same way.
  EM-SESS     evpn_bgp_session_up: FRR's collector (`_collect_evpn_bgp_summary`) on synthetic
              `show bgp l2vpn evpn summary json` shapes: present iff the peer, by name or by a link IP the
              core derived, is Established. Established to another peer, or the peer in another state, is
              not present.
  EM-ROUTE    evpn_mac_route_present / _absent / evpn_vni_route_present: FRR's JSON collector
              (`_collect_evpn_routes`) on synthetic `show bgp l2vpn evpn route json` shapes: a type-2 route for
              the (mac, vni) is present; a route for another MAC or VNI is not; the VNI kind reads the VNI.
  EM-VJSON    evpn_mac_route_valid, JSON leg: `valid` iff a path of a matching type-2 route has `valid` true.
              A matching route whose paths are all not valid is present and not valid; a valid path on
              another MAC is not valid; no matching route is not valid.
  EM-VTEXT    evpn_mac_route_valid, text leg (`_collect_evpn_routes_text` asked for validity), on the fixture
              captured on FRR 10.7.1, tests/fixtures/evpn-mac-route-valid/frr-10.7.1-show-bgp-l2vpn-evpn-route.txt
              (sha256 9cf7c8cf...b636, capture run 2 state 1; ruling 45E-S5-R1): host1's MAC route, whose two
              paths FRR lists valid then not valid, is valid, with and without its IP suffix; host2's MAC is
              valid; an undeclared MAC is not; a request without validity returns no `valid_macs`
              (REQ-45E-47).
  EM-DERIVED  Ruling 45E-S5-R2. The two cases FRR 10.7.1 does not print are tested on variants DERIVED from the
              captured lines, never captured, and named as derived here and in the closure report:
                Each derivation is applied to both of host1's captured two-path routes, its MAC route and its
                MAC+IP route, so host1's validity is decided by the derived lines alone.
                D-SWAP     the two path blocks swapped: the first path not valid, the second valid (handover
                           §15.2 row 25). Valid.
                D-NOPFX    the captured order with the second path line's prefix removed. Valid (its first
                           path is), and the no-prefix line is read without error.
                D-SWAP-NOPFX  D-SWAP with the second (valid) path line's prefix removed: the only valid paths
                           carry no prefix and belong to the last prefix above them (rule B08). Valid.
                D-RD       D-SWAP-NOPFX with a `Route Distinguisher:` line inserted before each prefix-less
                           valid line: that line then follows no prefix in its own block, so it belongs to none
                           (rule B08). Not valid.
                D-NOSTAR   the captured text with every `*` removed from the status columns. Not valid.
  EM-NV       Non-vacuity. Each mutant below is a copy of the shipped module with one line changed, loaded
              in memory; the leg it targets goes red under it:
                text leg requires a prefix on the valid line            -> D-SWAP-NOPFX red
                text leg ignores `Route Distinguisher:` boundaries      -> D-RD red
                text leg reads the first path line of a prefix only     -> D-SWAP red
                JSON leg ignores the path's `valid` flag                -> EM-VJSON present-not-valid red
                engine maps the valid kind on `present`                 -> EM-MAP present-not-valid red
                session collector ignores the state                     -> EM-SESS not-Established red

COVERAGE LIMITS (PBE-P2-8). The JSON shapes are synthetic, built in FRR's documented form; the text legs read
the captured fixture and its derived variants. A layout change on another FRR image is not seen here: the
image pin holds it (handover D19). This script reads no lab.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import contextlib
import io
import json
import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

FIXTURE = os.path.join(_HERE, "fixtures", "evpn-mac-route-valid", "frr-10.7.1-show-bgp-l2vpn-evpn-route.txt")
HOST1 = "00:11:22:33:44:55"
HOST2 = "00:11:22:33:44:66"
UNDECLARED = "00:11:22:33:44:77"
VNI = 10100

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


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def load_mutant(module, old, new):
    """A copy of src/<module>.py with `old` (which must occur exactly once) replaced by `new`, loaded in memory."""
    text = _read(os.path.join(_SRC, module + ".py"))
    if text.count(old) != 1:
        raise SystemExit("mutant anchor in %s found %d times, expected 1: %r" % (module, text.count(old), old))
    name = "%s_evpn_eval_mutant" % module
    mod = types.ModuleType(name)
    mod.__file__ = os.path.join(_SRC, module + ".py")
    sys.modules[name] = mod
    try:
        exec(compile(text.replace(old, new), "<%s>" % name, "exec"), mod.__dict__)
    finally:
        sys.modules.pop(name, None)
    return mod


# ------------------------------------------------------------------ a fake runtime --
class _Completed:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class _Rt:
    def __init__(self, out):
        self.out = out
        self.calls = []

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append(list(cmd))
        return _Completed(self.out)


def collect(frr, kind, out, **params):
    from cassian_nos_types import ObservationRequest
    handler = {"evpn_bgp_session_up": frr._collect_evpn_bgp_summary,
               "evpn_mac_route_text": frr._collect_evpn_routes_text}.get(kind, frr._collect_evpn_routes)
    return handler(_Rt(out), "lab", "leaf2", ObservationRequest(kind=kind, params=params))


# ------------------------------------------------------------------ EM-MAP --
def _mapping_text(engine_src):
    """The route branch's observed mapping and the session branch's, from run_invariant_test's own source."""
    fn = next(n for n in ast.walk(ast.parse(engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test")
    route = sess = None
    for node in ast.walk(fn):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            t = ast.unparse(node.test)
            if t == "inv_type == 'evpn_mac_route_present'" and route is None:
                if any(isinstance(s, ast.Assign) and ast.unparse(s.targets[0]) == "observed" for s in node.body):
                    route = ast.unparse(node)
            if t == "inv_type == 'evpn_bgp_session_up'" and sess is None:
                for s in node.body:
                    if isinstance(s, ast.Assign) and ast.unparse(s.targets[0]) == "observed":
                        sess = ast.unparse(s)
    return route, sess


def em_map(engine_src, label="EM-MAP"):
    route, sess = _mapping_text(engine_src)
    if not check("%s the route branch's observed mapping and the session branch's are found" % label,
                 route is not None and sess is not None):
        return False

    def obs(inv_type, present, valid):
        ns = {"inv_type": inv_type, "present": present, "valid": valid}
        exec(route, ns)
        return ns["observed"]

    ok = True
    for present in (False, True):
        ok &= check("%s evpn_mac_route_present, present=%s -> %s" % (label, present, "pass" if present else "fail"),
                    obs("evpn_mac_route_present", present, False) == ("pass" if present else "fail"))
        ok &= check("%s evpn_mac_route_absent, present=%s -> %s" % (label, present, "fail" if present else "pass"),
                    obs("evpn_mac_route_absent", present, False) == ("fail" if present else "pass"))
        ok &= check("%s evpn_vni_route_present, present=%s -> %s" % (label, present, "pass" if present else "fail"),
                    obs("evpn_vni_route_present", present, False) == ("pass" if present else "fail"))
    for present, valid, want in ((True, True, "pass"), (True, False, "fail"), (False, False, "fail")):
        ok &= check("%s evpn_mac_route_valid, present=%s valid=%s -> %s" % (label, present, valid, want),
                    obs("evpn_mac_route_valid", present, valid) == want)
    for present in (False, True):
        ns = {"present": present}
        exec(sess, ns)
        ok &= check("%s evpn_bgp_session_up, present=%s -> %s" % (label, present, "pass" if present else "fail"),
                    ns["observed"] == ("pass" if present else "fail"))
    return ok


# ------------------------------------------------------------------ EM-SESS --
def _summary(peers):
    return json.dumps({"peers": {ip: {"peerName": n, "state": s} for ip, n, s in peers}})


def em_sess(frr, label="EM-SESS"):
    ok = True
    cases = (
        ("Established, by name", [("172.16.0.2", "spine1", "Established")], True),
        ("Established, by a core-derived link IP", [("172.16.0.2", "", "Established")], True),
        ("Active, by name", [("172.16.0.2", "spine1", "Active")], False),
        ("Established to another peer", [("172.16.0.9", "spine9", "Established")], False),
        ("no peers", [], False),
    )
    for what, peers, want in cases:
        o = collect(frr, "evpn_bgp_session_up", _summary(peers), peer="spine1", peer_ips=["172.16.0.2"])
        ok &= check("%s %s -> present=%s" % (label, what, want), o.data.get("present") is want, o.data)
    return ok


# ------------------------------------------------------------------ EM-ROUTE / EM-VJSON --
def _routes(entries):
    """A `show bgp l2vpn evpn route json` document; each entry (mac, vni, route_type, [valid flags])."""
    rd = {"rd": "10.255.0.11:2"}
    for i, (mac, vni, rtype, flags) in enumerate(entries):
        rd["[2]:[0]:[48]:[%s]#%d" % (mac, i)] = {
            "paths": [[{"mac": mac, "vni": vni, "routeType": rtype, "valid": f} for f in flags]]}
    return json.dumps({"10.255.0.11:2": rd, "numPrefix": len(entries)})


def em_route(frr, label="EM-ROUTE"):
    ok = True
    doc = _routes([(HOST1, VNI, 2, [True])])
    for kind in ("evpn_mac_route_present", "evpn_mac_route_absent"):
        o = collect(frr, kind, doc, mac=HOST1, vni_i=VNI)
        ok &= check("%s %s: a type-2 route for (mac, vni) is present" % (label, kind), o.data.get("present") is True)
        o = collect(frr, kind, doc, mac=HOST2, vni_i=VNI)
        ok &= check("%s %s: a route for another MAC is not present" % (label, kind), o.data.get("present") is False)
        o = collect(frr, kind, doc, mac=HOST1, vni_i=VNI + 1)
        ok &= check("%s %s: a route in another VNI is not present" % (label, kind), o.data.get("present") is False)
        ok &= check("%s %s: the observation carries no `valid` key (REQ-45E-47)" % (label, kind), "valid" not in o.data)
    o = collect(frr, "evpn_vni_route_present", doc, mac="", vni_i=VNI)
    ok &= check("%s evpn_vni_route_present: a route in the VNI is present" % label, o.data.get("present") is True)
    o = collect(frr, "evpn_vni_route_present", doc, mac="", vni_i=VNI + 1)
    ok &= check("%s evpn_vni_route_present: no route in the VNI is not present" % label, o.data.get("present") is False)
    return ok


def em_vjson(frr, label="EM-VJSON"):
    ok = True
    cases = (
        ("a matching route with a valid path", [(HOST1, VNI, 2, [True])], True, True),
        ("a matching route, first path not valid and second valid", [(HOST1, VNI, 2, [False, True])], True, True),
        ("a matching route whose paths are all not valid", [(HOST1, VNI, 2, [False, False])], True, False),
        ("a valid path on another MAC only", [(HOST2, VNI, 2, [True])], False, False),
        ("a valid path in another VNI only", [(HOST1, VNI + 1, 2, [True])], False, False),
        ("no route", [], False, False),
    )
    for what, entries, present, valid in cases:
        o = collect(frr, "evpn_mac_route_valid", _routes(entries), mac=HOST1, vni_i=VNI)
        ok &= check("%s %s -> present=%s valid=%s" % (label, what, present, valid),
                    o.data.get("present") is present and o.data.get("valid") is valid, o.data)
    return ok


# ------------------------------------------------------------------ EM-VTEXT / EM-DERIVED --
_NH1 = "                    10.255.0.11                   100      0 i\n                    RT:65100:10100 ET:8\n"
_NH2 = "                    192.0.2.254                   100      0 i\n                    RT:65100:10100 ET:8\n"
# host1's two captured two-path routes: its MAC route and its MAC+IP route, each listed valid then not valid
_HOST1_PREFIXES = ("[2]:[0]:[48]:[%s]" % HOST1, "[2]:[0]:[48]:[%s]:[32]:[10.10.10.11]" % HOST1)


def _block(prefix):
    p1 = " *>i %s RD 10.255.0.11:2\n" % prefix
    p2 = "   i %s RD 10.255.0.11:2\n" % prefix
    return p1, p2


def derived(text):
    """The derived variants of ruling 45E-S5-R2, built from the captured lines; None if an anchor is missing.

    Each derivation is applied to both of host1's captured two-path routes (the MAC route and the MAC+IP
    route), so host1's validity is decided by the derived lines alone."""
    out = {"D-SWAP": text, "D-NOPFX": text, "D-SWAP-NOPFX": text, "D-RD": text}
    for prefix in _HOST1_PREFIXES:
        p1, p2 = _block(prefix)
        block = p1 + _NH1 + p2 + _NH2
        if text.count(block) != 1:
            return None
        out["D-SWAP"] = out["D-SWAP"].replace(block, p2 + _NH2 + p1 + _NH1)
        out["D-NOPFX"] = out["D-NOPFX"].replace(block, p1 + _NH1 + "   i\n" + _NH2)
        out["D-SWAP-NOPFX"] = out["D-SWAP-NOPFX"].replace(block, p2 + _NH2 + " *>i\n" + _NH1)
        out["D-RD"] = out["D-RD"].replace(
            block, p2 + _NH2 + "Route Distinguisher: 10.255.0.99:2\n" + " *>i\n" + _NH1)
    out["D-NOSTAR"] = "\n".join((line[:4].replace("*", " ") + line[4:]) for line in text.split("\n"))
    return out


def text_valid(frr, text, mac):
    o = collect(frr, "evpn_mac_route_text", text, vni_i=VNI, validity=True)
    return mac in (o.data.get("valid_macs") or []), o


def em_vtext(frr, text, label="EM-VTEXT"):
    ok = True
    for mac, want, what in ((HOST1, True, "host1's MAC route (paths listed valid, then not valid)"),
                            (HOST2, True, "host2's MAC route"),
                            (UNDECLARED, False, "an undeclared MAC")):
        got, o = text_valid(frr, text, mac)
        ok &= check("%s captured fixture: %s -> valid=%s" % (label, what, want), got is want, o.data.get("valid_macs"))
    o = collect(frr, "evpn_mac_route_text", text, vni_i=VNI, validity=True)
    ok &= check("%s captured fixture: no parse error" % label, not o.data.get("parse_error"), o.data.get("parse_error"))
    o = collect(frr, "evpn_mac_route_text", text, vni_i=VNI)
    ok &= check("%s a request without validity returns no valid_macs (REQ-45E-47)" % label, "valid_macs" not in o.data)
    return ok


def em_derived(frr, variants, only=None, label="EM-DERIVED"):
    ok = True
    for name, want in (("D-SWAP", True), ("D-NOPFX", True), ("D-SWAP-NOPFX", True), ("D-RD", False),
                       ("D-NOSTAR", False)):
        if only and name != only:
            continue
        got, o = text_valid(frr, variants[name], HOST1)
        ok &= check("%s %s (derived, not captured): host1's MAC -> valid=%s" % (label, name, want), got is want,
                    o.data.get("valid_macs"))
        ok &= check("%s %s: no parse error" % (label, name), not o.data.get("parse_error"), o.data.get("parse_error"))
    return ok


# ------------------------------------------------------------------ EM-NV --
_TEXT_LINE = '                if "*" in line[:4] and last_prefix:\n'
_MUTANTS = (
    ("text leg requires a prefix on the valid line", "cassian_nos_frr", _TEXT_LINE,
     '                if "*" in line[:4] and mp and last_prefix:\n', ("derived", "D-SWAP-NOPFX")),
    ("text leg ignores `Route Distinguisher:` boundaries", "cassian_nos_frr",
     '                if line.startswith("Route Distinguisher:"):\n                    last_prefix = None\n',
     "", ("derived", "D-RD")),
    ("text leg reads the first path line of a prefix only", "cassian_nos_frr", _TEXT_LINE,
     '                if mp:\n'
     '                    _first = mp.group(0) not in _seen_first\n'
     '                    _seen_first.append(mp.group(0))\n'
     '                if "*" in line[:4] and last_prefix and mp and _first:\n',
     ("derived", "D-SWAP")),
    ("JSON leg ignores the path's `valid` flag", "cassian_nos_frr",
     '                                and entry.get("valid") is True\n', "", ("vjson", None)),
    ("session collector ignores the state", "cassian_nos_frr",
     '            if rec["state"].lower() != "established":\n                continue\n', "", ("sess", None)),
)


def em_nv(engine_src, text):
    for label, module, old, new, (leg, only) in _MUTANTS:
        src_new = new
        if "_seen_first" in new:
            # the first-path-only mutant keeps a list of prefixes already read
            old2 = "        last_prefix = None\n        for line in text.splitlines():\n"
            frr_text = _read(os.path.join(_SRC, "cassian_nos_frr.py"))
            if frr_text.count(old2) != 1 or frr_text.count(old) != 1:
                check("EM-NV %s: anchors found once" % label, False)
                continue
            mod = types.ModuleType("frr_first_path_mutant")
            mod.__file__ = os.path.join(_SRC, "cassian_nos_frr.py")
            sys.modules[mod.__name__] = mod
            try:
                patched = frr_text.replace(old2, "        last_prefix = None\n        _seen_first = []\n        _first = False\n"
                                                 "        for line in text.splitlines():\n").replace(old, src_new)
                exec(compile(patched, "<frr_first_path_mutant>", "exec"), mod.__dict__)
            finally:
                sys.modules.pop(mod.__name__, None)
            frr_m = mod
        else:
            frr_m = load_mutant(module, old, src_new)
        _QUIET[0] = True
        n0 = len(_FAILED)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                if leg == "derived":
                    variants = derived(text)
                    held = em_derived(frr_m, variants, only=only, label="(mutant)")
                elif leg == "vjson":
                    held = em_vjson(frr_m, label="(mutant)")
                else:
                    held = em_sess(frr_m, label="(mutant)")
        finally:
            _QUIET[0] = False
            del _FAILED[n0:]
        if not held:
            print("MUTATION-FAIL: %s -> red" % label)
        check("EM-NV %s: the leg goes red" % label, not held)
    # the engine mapping mutant: the valid kind mapped on `present`
    old = '                observed = "pass" if valid else "fail"\n'
    if engine_src.count(old) != 1:
        check("EM-NV engine mapping anchor found once", False)
        return
    _QUIET[0] = True
    n0 = len(_FAILED)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            held = em_map(engine_src.replace(old, '                observed = "pass" if present else "fail"\n'),
                          label="(mutant)")
    finally:
        _QUIET[0] = False
        del _FAILED[n0:]
    if not held:
        print("MUTATION-FAIL: engine maps the valid kind on `present` -> EM-MAP red")
    check("EM-NV engine maps the valid kind on `present`: EM-MAP goes red", not held)


def main():
    import cassian_common
    cassian_common._QUIET_DIE = True
    import cassian_nos_frr as frr

    engine_src = _read(os.path.join(_SRC, "cassian_engine.py"))
    text = _read(FIXTURE)
    import hashlib
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    check("EM-VTEXT the fixture is capture run 2 state 1 (45E-S5-R1)",
          digest == "9cf7c8cfd80cdb239a29da28221628960d279f92f7b4a89d56553a9d9274b636", digest)

    em_map(engine_src)
    em_sess(frr)
    em_route(frr)
    em_vjson(frr)
    em_vtext(frr, text)
    variants = derived(text)
    if check("EM-DERIVED host1's two captured two-path routes are each found once", variants is not None):
        em_derived(frr, variants)
        em_nv(engine_src, text)

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_eval_match_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_eval_match_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
