#!/usr/bin/env python3
"""evpn_gen_proof.py -- §4.5-e base, the EVPN-on-FRR proof family: scope amendment 01 A-4 row 8 (REQ-45E-36).

DOCTRINE SURFACES THIS SCRIPT OWNS (proof-script ruling 1a): Design Contract v2.1 §3 "Generate"; Doctrine
§1.5 Explicitness (one derivation of a fabric's BGP session set); Doctrine §1.6 and Design Contract v2.1
§13(a) for `fabric.evpn`.

EXISTING OWNER OF THE REST (proof-script ruling 1b; no leg is proved twice): tests/evpn_rr_next_hop_self_proof.py.
Its L-LEAF and L-SPINE pin every EVPN render byte for byte, which is REQ-45E-17's regression, and its L-CENSUS
pins which `fabric.evpn` files under topologies/ and examples/ resolve. This script repeats neither.

LEGS IN THIS REVISION (§4.5-e WI-4, rule B09; REQ-45E-17; BL-P2-4.5c-227; PBE-1b-9)
  E-CORPUS  The declared corpus resolves: the 18 files below (the 18 RESOLVED lists in
            tests/evpn_rr_next_hop_self_proof.py, L93), each through the product's
            resolve_topology(doc, topo_path=...), as `cassian up` resolves them.
  E-DERIVE  cassian_model.fabric_evpn_session_set returns, for each file, the pinned session set:
            its participants in topology node order, and each participant's peers as
            (peer name, peer IP, route-reflector client), sorted (D07).
  E-EMIT    For every participant, the EVPN section gen_frr_conf renders names exactly the derivation's
            peers, which are the pinned peers: its `neighbor <ip> peer-group EVPN` lines, in order, and its
            `route-reflector-client` lines for the clients and no other peer.
  E-NV      Non-vacuity (handover §15.2, negative row 17). The derivation is replaced by one that drops one
            peer. gen_frr_conf's render then names the reduced set (the generator consumes the derivation;
            one that walked the links itself would not change, and this leg would be red), and E-EMIT and
            E-DERIVE go red against the pin. The real derivation is restored before the result.

P-7 (§4.5-e WI-4, rule B10; REQ-45E-18; BL-P2-4.5c-227; handover §15.2 row 18)
  P7-CENSUS  P-7's own scan of topologies/ and examples/ (every YAML declaring `fabric.evpn.enabled` that
             resolve_topology resolves) yields exactly the 18 declared files.
  P7-EQUAL   For each of the 18, read as `cmd_test` reads it (the resolved topology through a YAML
             round-trip, as `cassian up` writes topology.resolved.yaml), cassian_engine's
             _precheck_fabric_participants names the derivation's participants in topology node order,
             none of them with an empty peer list, and each participant's expected peers equal the peers
             gen_frr_conf renders for that node, in order.
  P7-SELECT  `cmd_test`'s own participant selection (its source between the line that opens
             `bgp_participants` and rule B10's assignment, executed with the asn-gated derivation finding
             no participant, as measured for every fabric topology before B10) yields those participants.
  P7-NV      Non-vacuity (handover §15.2 negative row 18): a participant list that lacks one derived
             participant, or one expected peer, makes P7-EQUAL red; the selection without rule B10's
             lines yields no participant, and P7-SELECT is red.

LEGS THAT ARRIVE LATER, under this script's extension model (a new `fabric.evpn` field adds an emission leg
and a rejection leg): the declaration legs, the L998 negative leg among them (REQ-45E-19), with REQ-45E-36
in WI-5; P-7's SONiC leg with addendum 01.

ORACLE. The pinned session set was read back from gen_frr_conf's renders at cassian-gate 7a60164, before
the derivation existed (src/cassian_model.py sha256
3dd4bcff557db2a4a5c96b14f46bb3684edb74378074eedb22c6f29be2104805): the peer-group and route-reflector-client
lines of each participant, with each peer IP named from that tree's build_node_links. All 18 files carried
the same set. It is static: nothing here recomputes it, and a change to it must be declared again.

COVERAGE LIMITS (PBE-P2-8). This script proves the derivation's output and that the generator renders it;
it does not prove FRR's behaviour, and it reads no lab.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import os
import re
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

CORPUS = (
    "topologies/evpn_bgp_session_up.yaml",
    "topologies/evpn_bgp_session_up_expect_fail.yaml",
    "topologies/evpn_bgp_session_up_misconfigured.yaml",
    "topologies/evpn_mac_route_absent_expect_fail.yaml",
    "topologies/evpn_mac_route_absent_expected_absent_present.yaml",
    "topologies/evpn_mac_route_absent_expected_present.yaml",
    "topologies/evpn_mac_route_present.yaml",
    "topologies/evpn_mac_route_present_expect_fail.yaml",
    "topologies/evpn_runtime_generation.yaml",
    "topologies/evpn_vni_route_absent_expected_present.yaml",
    "topologies/evpn_vni_route_present.yaml",
    "topologies/evpn_vni_route_present_expect_fail.yaml",
    "topologies/ex-evpn-outcome-only.yaml",
    "topologies/neg/h2_invariant_observability_demo.yaml",
    "topologies/neg/h2_truncation_proof.yaml",
    "topologies/pack_local_compatibility_ok.yaml",
    "topologies/pack_resolve_expansion.yaml",
    "topologies/wait-for-evpn-fabric.yaml",
)
# the session set every corpus file carried at 7a60164 (participants in topology node order)
_SESSIONS = {
    "spine1": [("leaf1", "172.16.0.1", True), ("leaf2", "172.16.0.3", True)],
    "leaf1": [("spine1", "172.16.0.0", False)],
    "leaf2": [("spine1", "172.16.0.2", False)],
}
PINNED = {rel: _SESSIONS for rel in CORPUS}
PARTICIPANT_ORDER = ["spine1", "leaf1", "leaf2"]

_FAILED = []
_COUNT = [0]


def check(name, ok, detail=""):
    _COUNT[0] += 1
    print(("PASS   " if ok else "FAIL   ") + name + ("" if ok or not detail else "  -- " + str(detail)))
    if not ok:
        _FAILED.append(name)


def rendered_peers(cfg):
    """(peer IPs in peer-group order, set of route-reflector-client IPs) from one rendered config."""
    ips = re.findall(r"^ neighbor (\S+) peer-group EVPN$", cfg, re.M)
    clients = set(re.findall(r"^  neighbor (\S+) route-reflector-client$", cfg, re.M))
    return ips, clients


def as_render(peers):
    return [ip for _n, ip, _rr in peers], {ip for _n, ip, rr in peers if rr}


def load_corpus(cassian_model):
    import yaml
    from pathlib import Path

    topos = {}
    for rel in CORPUS:
        full = os.path.join(_ROOT, rel)
        try:
            with open(full, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            topos[rel] = cassian_model.resolve_topology(doc, topo_path=Path(full))
        except (OSError, SystemExit) as exc:
            topos[rel] = None
            check("E-CORPUS %s resolves" % rel, False, repr(exc))
            continue
        check("E-CORPUS %s resolves" % rel, True)
    return topos


def derive_ok(cassian_model, rel, topo):
    got = cassian_model.fabric_evpn_session_set(topo)
    norm = None if got is None else {k: [tuple(p) for p in v] for k, v in got.items()}
    ok = norm == PINNED[rel] and list(norm) == PARTICIPANT_ORDER
    return ok, norm


def emit_ok(cassian_model, topo, sessions):
    """Every participant's render names exactly `sessions`' peers; returns (ok, detail)."""
    frr = {n["name"]: n for n in topo.get("nodes", []) if isinstance(n, dict) and n.get("name")}
    bad = []
    for name, peers in sessions.items():
        got = rendered_peers(cassian_model.gen_frr_conf(frr[name], topo))
        want = as_render(peers)
        if got != want:
            bad.append((name, got, want))
    return not bad, bad


def as_cmd_test_reads(topo):
    """The resolved topology as `cmd_test` loads it: topology.resolved.yaml, written by `cassian up`."""
    import yaml
    return yaml.safe_load(yaml.safe_dump(topo, sort_keys=False))


def p7_equal(cassian_model, topo, participants):
    """P7-EQUAL on a participant list [(name, expected peer IPs)]; returns (ok, detail)."""
    order = list((cassian_model.fabric_evpn_session_set(topo) or {}).keys())
    frr = {n["name"]: n for n in topo.get("nodes", []) if isinstance(n, dict) and n.get("name")}
    if participants is None or [n for n, _p in participants] != order or not order:
        return False, ("participants", participants, "derivation order", order)
    bad = []
    for name, peer_ips in participants:
        gen_ips, _clients = rendered_peers(cassian_model.gen_frr_conf(frr[name], topo))
        if not peer_ips or list(peer_ips) != gen_ips:
            bad.append((name, peer_ips, gen_ips))
    return not bad, bad


_SEL_OPEN = "    bgp_participants: list[dict] = []\n"
_SEL_B10 = "    # §4.5-e WI-4, rule B10 (REQ-45E-18; BL-P2-4.5c-227): a fabric.evpn topology takes its precheck\n"
_SEL_CLOSE = "        bgp_participants = [nodes_by_name[_name] for _name, _peer_ips in _fabric_participants]\n"


def selection_text(with_b10=True):
    """`cmd_test`'s participant selection, from the engine's own source; None unless each anchor occurs once."""
    with open(os.path.join(_ROOT, "src", "cassian_engine.py"), encoding="utf-8") as fh:
        src = fh.read()
    if src.count(_SEL_OPEN) != 1 or src.count(_SEL_B10) != 1 or src.count(_SEL_CLOSE) != 1:
        return None
    i, j, k = src.index(_SEL_OPEN), src.index(_SEL_B10), src.index(_SEL_CLOSE)
    if not i < j < k:
        return None
    return textwrap.dedent(src[i:(k + len(_SEL_CLOSE)) if with_b10 else j])


def run_selection(text, helper, topo):
    nodes = [n for n in topo.get("nodes", []) if isinstance(n, dict)]
    ns = {
        "topo": topo,
        "bgp_speakers": [n for n in nodes if n.get("type") == "frr"],
        # the asn-gated derivation finds no participant on a fabric topology (measured; S30-R1)
        "expected_bgp_peers": lambda _name: [],
        "nodes_by_name": {n["name"]: n for n in nodes},
        "_precheck_fabric_participants": helper,
    }
    exec(compile(text, "<cmd_test participant selection>", "exec"), ns)
    return [n["name"] for n in ns["bgp_participants"]]


def p7(cassian_model, topos):
    import yaml
    from pathlib import Path
    import cassian_engine

    scanned = []
    for base in ("topologies", "examples"):
        for root, dirs, files in os.walk(os.path.join(_ROOT, base)):
            dirs.sort()
            for f in sorted(files):
                if not f.endswith((".yaml", ".yml")):
                    continue
                full = os.path.join(root, f)
                try:
                    with open(full, encoding="utf-8") as fh:
                        doc = yaml.safe_load(fh)
                except (OSError, yaml.YAMLError):
                    continue
                ev = ((doc.get("fabric") or {}).get("evpn") if isinstance(doc, dict) else None)
                if not (isinstance(ev, dict) and ev.get("enabled")):
                    continue
                try:
                    cassian_model.resolve_topology(doc, topo_path=Path(full))
                except SystemExit:
                    continue
                scanned.append(os.path.relpath(full, _ROOT).replace(os.sep, "/"))
    check("P7-CENSUS the resolving fabric.evpn files under topologies/ and examples/ are exactly the 18 declared",
          sorted(scanned) == sorted(CORPUS),
          "added %s removed %s" % (sorted(set(scanned) - set(CORPUS)), sorted(set(CORPUS) - set(scanned))))

    helper = getattr(cassian_engine, "_precheck_fabric_participants", None)
    check("P7-EQUAL cassian_engine carries _precheck_fabric_participants (rule B10)", helper is not None)
    if helper is None:
        return
    with_b10, without_b10 = selection_text(True), selection_text(False)
    check("P7-SELECT cmd_test's participant selection is found in the engine, rule B10 inside it",
          with_b10 is not None and without_b10 is not None)
    for rel in CORPUS:
        topo = topos.get(rel)
        if topo is None:
            continue
        seen = as_cmd_test_reads(topo)
        parts = helper(seen)
        ok, bad = p7_equal(cassian_model, topo, parts)
        check("P7-EQUAL %s: participants in node order, each one's expected peers = the generator's" % rel, ok, bad)
        if with_b10 is not None:
            got = run_selection(with_b10, helper, seen)
            check("P7-SELECT %s: cmd_test takes those participants" % rel,
                  bool(got) and got == [n for n, _p in (parts or [])], got)

    rel = CORPUS[0]
    topo = topos.get(rel)
    if topo is None:
        check("P7-NV %s resolves, so the mutants can run" % rel, False)
        return
    parts = helper(as_cmd_test_reads(topo))
    red = not p7_equal(cassian_model, topo, parts[1:])[0]
    if red:
        print("MUTATION-FAIL: a participant list lacking one derived participant -> P7-EQUAL red")
    check("P7-NV a participant list that lacks one derived participant: P7-EQUAL is red", red)
    red = not p7_equal(cassian_model, topo, [(parts[0][0], parts[0][1][:-1])] + parts[1:])[0]
    if red:
        print("MUTATION-FAIL: a participant lacking one expected peer -> P7-EQUAL red")
    check("P7-NV a participant that lacks one expected peer: P7-EQUAL is red", red)
    if without_b10 is not None:
        got = run_selection(without_b10, helper, as_cmd_test_reads(topo))
        if got == []:
            print("MUTATION-FAIL: cmd_test's selection without rule B10 -> no participant, P7-SELECT red")
        check("P7-NV the selection without rule B10's lines yields no participant, so P7-SELECT is red", got == [], got)


def main():
    import cassian_common
    import cassian_model

    cassian_common._QUIET_DIE = True  # a rejected topology raises SystemExit(msg); nothing printed
    topos = load_corpus(cassian_model)

    for rel in CORPUS:
        topo = topos.get(rel)
        if topo is None:
            continue
        ok, got = derive_ok(cassian_model, rel, topo)
        check("E-DERIVE %s: the session set is the pinned one, participants in node order" % rel, ok, got)
        ok, bad = emit_ok(cassian_model, topo, PINNED[rel])
        check("E-EMIT %s: every participant's EVPN peers are the derivation's" % rel, ok, bad)

    # E-NV: a derivation that drops one peer (spine1's last client, in the first corpus file)
    rel = CORPUS[0]
    topo = topos.get(rel)
    real = cassian_model.fabric_evpn_session_set
    if topo is None:
        check("E-NV %s resolves, so the mutant can run" % rel, False)
    else:
        def dropped(t):
            s = real(t)
            if s is None:
                return None
            s = {k: list(v) for k, v in s.items()}
            s["spine1"] = s["spine1"][:-1]
            return s

        before = cassian_model.gen_frr_conf(
            [n for n in topo["nodes"] if n.get("name") == "spine1"][0], topo)
        try:
            cassian_model.fabric_evpn_session_set = dropped
            mutant = dropped(topo)
            after = cassian_model.gen_frr_conf(
                [n for n in topo["nodes"] if n.get("name") == "spine1"][0], topo)
            tracks, _ = emit_ok(cassian_model, topo, mutant)
            emit_red = not emit_ok(cassian_model, topo, PINNED[rel])[0]
            derive_red = not derive_ok(cassian_model, rel, topo)[0]
        finally:
            cassian_model.fabric_evpn_session_set = real
        check("E-NV the mutant derivation changes spine1's render (the generator consumes the derivation)",
              after != before and tracks)
        if emit_red:
            print("MUTATION-FAIL: derivation drops one peer -> E-EMIT red against the pin")
        check("E-NV with one peer dropped, E-EMIT is red against the pin", emit_red)
        if derive_red:
            print("MUTATION-FAIL: derivation drops one peer -> E-DERIVE red against the pin")
        check("E-NV with one peer dropped, E-DERIVE is red against the pin", derive_red)
        check("E-NV the real derivation is restored", cassian_model.fabric_evpn_session_set is real
              and derive_ok(cassian_model, rel, topo)[0])

    p7(cassian_model, topos)

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_gen_proof, §4.5-e WI-4)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_gen_proof, §4.5-e WI-4)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
