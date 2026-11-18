#!/usr/bin/env python3
"""evpn_authority_parity_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 1 (REQ-45E-29).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Doctrine §1.10 Artifact Authority; Design
Contract v2.1 §12 Artifact contract -- the shape of the authoritative invariant record each EVPN kind writes.

EXISTING OWNER OF THE REST (proof-script ruling 1b; no leg is proved twice):
tests/cmd_evidence_derivation_differential_proof.py owns the session kind's evidence (its rows `evpn_sess/*`)
and the collection-failure records of the route branch. This script compares records of answered reads only,
and the session kind's evidence is not compared here.

HOW. Each leg runs the engine's ACTUAL run_invariant_test body, AST-extracted and bound with
`_evaluate_invariant_attempt` stubbed to an answered read; the record is what the branch hands to record_fn.
Each kind's record is compared LIVE with its twin's, captured the same way; no reference shape is typed in.
The twin of every route kind is evpn_mac_route_present, the kind the route branch was written for; the
session kind is compared with that twin at the contract level, since its branch is a different one.

LEGS (one leg per EVPN kind; a new kind adds a leg)
  AP-KEYS    record_fn's keyword set equals the authority contract (name, kind, src, dst, expected,
             observed, verdict, duration_ms, error, evidence, meta, observed_state) and the twin's, on a
             failing and on a passing record.
  AP-FIELDS  kind == "invariant"; dst == ""; expected mirrors the test's expect; observed and verdict in
             {pass, fail}.
  AP-OS      observed_state is a dict on a failed verdict and None on a passed one. A route kind's dict has
             the twin's keys, with `type` naming the kind; evpn_vni_route_present has no `mac` (its query has
             none, schema §4.6) and evpn_mac_route_valid adds exactly `valid` (REQ-45E-25). The session kind's
             dict carries {type, peer, state, last_reset_reason, source_node} (schema §4.5).
  AP-META    meta carries the twin's keys: {type, mac, vni, present, observed_route_count} for a route kind,
             {type, peer, present, observed_neighbor_count} for the session kind; `type` names the kind.
  AP-EVID    For a route kind, the evidence of an answered read carries the twin's keys {cmd, rc, routes}.
  AP-NV      Non-vacuity: two mutants of the engine's own source, each with one line changed and bound the
             same way. (1) The valid kind's meta gains a key its twin lacks: AP-META goes red. (2) The valid
             kind's observed_state loses `source_node`: AP-OS goes red.

COVERAGE LIMITS (PBE-P2-8). The reads are synthetic and answered; no lab is read. A record's values are not
compared here, only its shape and conventions; the values are the other family scripts' subject.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import contextlib
import io
import os
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

NODE = "leaf2"
HOST1 = "00:11:22:33:44:55"
VNI = 10100
TOPO = {"name": "ap", "nodes": [{"name": "spine1", "type": "frr"}, {"name": "leaf2", "type": "frr"},
                                {"name": "host1", "type": "host", "mac": HOST1}]}
CONTRACT = {"name", "kind", "src", "dst", "expected", "observed", "verdict", "duration_ms", "error",
            "evidence", "meta", "observed_state"}
TWIN = "evpn_mac_route_present"
ROUTE_KINDS = ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present", "evpn_mac_route_valid")

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


class _FakeTime:
    @staticmethod
    def time():
        return 0.0

    @staticmethod
    def sleep(_s):
        return None


class _Completed:
    stdout = "Route Distinguisher: 10.255.0.11:2\n"
    returncode = 0


class _Rt:
    def exec(self, lab, node, cmd, check=False, capture_output=True):
        return _Completed()


def bind(engine_src):
    import cassian_engine
    fn = next(n for n in ast.walk(ast.parse(engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test")
    body = "\n".join(ast.unparse(s) for s in fn.body)
    ns = dict(cassian_engine.__dict__)
    ns.update(time=_FakeTime, lab="ap", topo=TOPO, rt=_Rt())
    exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(body, "    "), ns)
    return ns


def record(ns, kind, satisfied):
    """The record `kind` writes for an answered read, expect: pass; `satisfied` decides observed."""
    def stub(*, inv_type, t, src):
        ev = {"cmd": "stub", "rc": 0, "parse_error": "", "probe_ok": True}
        if kind == "evpn_bgp_session_up":
            ev["neighbors"] = [{"neighbor": "172.16.0.2", "peerName": "spine1",
                                "state": "Established" if satisfied else "Active", "node": src}]
            return True, satisfied, {"peer": "spine1", "present": satisfied, "neighbors": ev["neighbors"]}, ev
        present = (not satisfied) if kind == "evpn_mac_route_absent" else (satisfied or kind == "evpn_mac_route_valid")
        entries = [{"mac": HOST1, "vni": VNI, "route_type": 2, "node": src}] if present else []
        state = {"mac": HOST1, "vni_i": VNI, "present": present, "evidence_entries": entries}
        if kind == "evpn_mac_route_valid":
            state["valid"] = satisfied
        return True, satisfied, state, ev
    ns["_evaluate_invariant_attempt"] = stub
    t = {"type": kind, "node": NODE, "expect": "pass"}
    if kind == "evpn_bgp_session_up":
        t["peer"] = "spine1"
    else:
        t["mac"], t["vni"] = HOST1, VNI
    rec = {}
    ns["_rit"]("ap_" + kind, NODE, t, lambda **kw: rec.update(kw))
    return rec


def legs(ns, label="AP"):
    ok = True
    twin_fail, twin_pass = record(ns, TWIN, False), record(ns, TWIN, True)
    for kind in ("evpn_bgp_session_up",) + ROUTE_KINDS:
        fail, ok_rec = record(ns, kind, False), record(ns, kind, True)
        ok &= check("%s-KEYS %s: record_fn's keywords are the contract's and the twin's (fail and pass)" % (label, kind),
                    set(fail) == CONTRACT == set(twin_fail) and set(ok_rec) == CONTRACT == set(twin_pass),
                    "fail=%s pass=%s" % (sorted(set(fail) ^ CONTRACT), sorted(set(ok_rec) ^ CONTRACT)))
        ok &= check("%s-FIELDS %s: kind invariant, dst empty, expected mirrors expect, observed/verdict in {pass, fail}"
                    % (label, kind),
                    all(r.get("kind") == "invariant" and r.get("dst") == "" and r.get("expected") == "pass"
                        and r.get("observed") in ("pass", "fail") and r.get("verdict") in ("pass", "fail")
                        for r in (fail, ok_rec)) and fail.get("verdict") == "fail" and ok_rec.get("verdict") == "pass")
        fos = fail.get("observed_state")
        ok &= check("%s-OS %s: observed_state a dict on fail, None on pass" % (label, kind),
                    isinstance(fos, dict) and ok_rec.get("observed_state") is None)
        if not isinstance(fos, dict):
            continue
        if kind == "evpn_bgp_session_up":
            want = {"type", "peer", "state", "last_reset_reason", "source_node"}
        else:
            want = set(twin_fail["observed_state"])
            if kind == "evpn_vni_route_present":
                want = want - {"mac"}
            if kind == "evpn_mac_route_valid":
                want = want | {"valid"}
        ok &= check("%s-OS %s: observed_state's keys are the twin's (as the schema states for this kind), type names it"
                    % (label, kind), set(fos) == want and fos.get("type") == kind,
                    "got %s want %s" % (sorted(fos), sorted(want)))
        meta = fail.get("meta") or {}
        if kind == "evpn_bgp_session_up":
            mwant = {"type", "peer", "present", "observed_neighbor_count"}
        else:
            mwant = set(twin_fail["meta"])
        ok &= check("%s-META %s: meta's keys are the twin's convention, type names the kind" % (label, kind),
                    set(meta) == mwant and meta.get("type") == kind, "got %s want %s" % (sorted(meta), sorted(mwant)))
        if kind != "evpn_bgp_session_up":
            ok &= check("%s-EVID %s: an answered read's evidence carries the twin's keys" % (label, kind),
                        set(fail.get("evidence") or {}) == set(twin_fail["evidence"]) == {"cmd", "rc", "routes"},
                        sorted(fail.get("evidence") or {}))
    return ok


def main():
    import cassian_common
    cassian_common._QUIET_DIE = True
    with open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8") as fh:
        engine_src = fh.read()
    legs(bind(engine_src))

    mutants = (
        ("the valid kind's meta gains a key its twin lacks", "AP-META",
         '                    "observed_route_count": len(evidence_entries),\n',
         '                    "observed_route_count": len(evidence_entries),\n'
         '                    **({"valid": bool(valid)} if inv_type == "evpn_mac_route_valid" else {}),\n'),
        ("the valid kind's observed_state loses source_node", "AP-OS",
         '                        observed_state_payload["valid"] = bool(valid)\n',
         '                        observed_state_payload["valid"] = bool(valid)\n'
         '                        observed_state_payload.pop("source_node")\n'),
    )
    for label, leg, old, new in mutants:
        if not check("AP-NV the mutant's anchor is found once (%s)" % label, engine_src.count(old) == 1):
            continue
        _QUIET[0] = True
        n0 = len(_FAILED)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                legs(bind(engine_src.replace(old, new)), label="(mutant)")
            red = [f for f in _FAILED[n0:] if f.startswith("(mutant)-" + leg.split("-")[1])]
        finally:
            _QUIET[0] = False
            del _FAILED[n0:]
        if red:
            print("MUTATION-FAIL: %s -> %s red" % (label, leg))
        check("AP-NV %s: %s goes red" % (label, leg), bool(red))

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_authority_parity_proof, §4.5-e WI-5)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_authority_parity_proof, §4.5-e WI-5)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
