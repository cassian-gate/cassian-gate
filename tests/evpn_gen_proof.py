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

DECLARATION (§4.5-e WI-5 piece (iv); REQ-45E-36, REQ-45E-19; scope amendment 01 A-4 row 8). Each misuse is a
copy of the first corpus file with one change, handed to resolve_topology with cassian_common._QUIET_DIE set as
`cassian validate --json` sets it; a rejection is the SystemExit carrying validate's message. Under this
script's extension model each `fabric.evpn` field has an emission leg and a rejection leg:
  D-PLACE    an evpn-shaped key outside `fabric.evpn` (a node's `evpn_vni`) is rejected, naming its path.
  D-KEY      an unsupported key under `fabric.evpn` is rejected, naming it and listing the supported keys.
  D-ENABLED  `enabled` that is not a boolean is rejected. Emission: `enabled: false` renders no EVPN section.
  D-MODE     `mode` other than `vlan-aware` is rejected, naming `vlan-aware`. Emission: rendered with mode
             `vlan-aware`, every participant carries `advertise-all-vni`.
  D-ASN      `asn` 0, above 4294967295 or not an integer is rejected, naming the range. Emission: every
             participant renders `router bgp <asn>` and `neighbor EVPN remote-as <asn>` with the declared asn,
             for the corpus asn and for a changed one.
  D-13A      A representative rejection (D-MODE) carries (a) what is wrong, (b) where (`fabric.evpn.mode`) and
             (c) what would be valid (`'vlan-aware'`); the same misuse resolved twice gives the same bytes.
  L998       The participant-type refusal, narrowed by addendum 01 (REQ-45E-50 supersedes REQ-45E-19 forward;
             addendum 01 §15.2 row 50; proof-script ruling 2): an EVPN participant (a node with `role`) of type
             nft-fw or host, in a copy of the file with its tests removed, is rejected with addendum 01 §6.6 row
             U1, the src/cassian_model.py message "Topology invalid: node '<name>': EVPN participant nodes must
             use type: frr, or type: sonic-vm with role: leaf"; for nft-fw the rejection is also taken through
             `cassian validate --json` (cmd_validate, in process, on a copy of the file in a temporary folder),
             which exits 2 with U1 as its error.

ADDENDUM 01, WI-6 AND WI-4's MODEL SITE (rules B15 and B16; REQ-45E-49 to -56; addendum 01 §15.2 rows 49 to 56).
Each case is the first corpus file with its tests and scenarios removed. `cassian validate --json` runs in process
on a copy in a temporary folder, with the lab folder (cassian_artifacts.LABS_DIR) pointed there as well, because a
passing validate writes its advisory coverage artifact; nothing is written under labs/.
  P-10       leaf1 of type sonic-vm, with host1 (attached to leaf1) and its link removed: the topology resolves,
             and `cassian validate --json` exits 0 with result pass (REQ-45E-49). host2 stays on the FRR leaf2,
             so this is also row 53's positive control.
  U2         spine1 of type sonic-vm is refused with U2 by ensure_valid_topology (REQ-45E-51).
  U3         leaf1 of type sonic-vm with host1 still attached to it is refused with U3 (REQ-45E-53).
  U4         The P-10 topology with leaf1's sonic_mode: preconfigured is refused with U4 (REQ-45E-52). validate
             runs ensure_valid_topology before resolve_topology, whose sonic_config_db rules would refuse that
             node first (src/cassian_engine.py cmd_validate), so the model leg calls ensure_valid_topology.
  TEXT       Through `cassian validate --json`, U2 to U4 exit 2 and each error equals its addendum 01 §6.6 row
             character for character, with the node's or host's name in place of <name>; U1 is L998's CLI
             leg (REQ-45E-54). The rows are quoted below as _U.
  S-SET      fabric_evpn_session_set on the P-10 topology returns the pinned session set: leaf1, now a
             sonic-vm leaf, has the entry an FRR leaf has there, (spine1, 172.16.0.0, False), and spine1 lists
             it as a client (REQ-45E-55; rule B16).
  S-NEG      The P-10 topology without its spine1-leaf1 link is refused by the existing leaf-link rule
             (REQ-45E-55, negative row).
  An all-FRR fabric's session set and renders are unchanged (REQ-45E-56): E-DERIVE and E-EMIT above, unedited,
  with tests/evpn_rr_next_hop_self_proof.py, unedited.
  D-NV       Non-vacuity: three model mutants, one change each, loaded in memory: (1) the participant-type
             refusal (U1) removed: an nft-fw leaf1 (host1 removed, as in P-10) validates, and L998 goes red;
             (2) the mode check removed: D-MODE goes red; (3) rule B16's sonic-vm clause removed from
             fabric_evpn_session_set: leaf1 has no entry, and S-SET goes red. Under none does the real
             module change.

ADDENDUM 01, WI-4's SONiC CONSUMER (rule B17; REQ-45E-55, -57; addendum 01 §15.2 row 55, positive).
  P7S-FIXTURE  P-7's SONiC leg names its fixture by explicit path, tests/fixtures/sonic-4_5e-add01/p7-sonic-leaf.yaml
               (scope amendment 02 SA2-36.1; LOCKED scope A-4 L1247). It is under tests/fixtures/, so P7-CENSUS and
               the census of tests/evpn_rr_next_hop_self_proof.py stay exact. It is the P-10 topology: this script's
               _sonic_leaf(keep_host=False) is its oracle, compared with it apart from its name.
  P7S-EQUAL    Read as cmd_test reads it, the fixture's participants (_precheck_fabric_participants) are the
               derivation's, in topology node order, none with an empty peer list. Each FRR participant's expected
               peers equal its gen_frr_conf render. The sonic-vm leaf1's equal what the engine's own
               _expected_peer_ips returns for it, (172.16.0.0,): that closure is AST-extracted from
               src/cassian_engine.py with _is_bgp_peer and expected_bgp_peers and bound with the names cmd_test
               binds (NOS_PROVIDERS, nodes_by_name, links_by_node, topo). The binding is this script's: it does not
               run cmd_test.
  P7S-NV       Non-vacuity: the same closure with rule B17's three lines removed returns the linked BGP speakers,
               which for a fabric node are none, because no fabric node declares `asn`; P7S-EQUAL is then red.

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


P7S_FIXTURE = "tests/fixtures/sonic-4_5e-add01/p7-sonic-leaf.yaml"
# rule B17's three lines in src/cassian_engine.py's `_expected_peer_ips`, removed whole for P7S-NV
_B17_LINES = (
    "        for _fp_name, _fp_peer_ips in (_precheck_fabric_participants(topo) or ()):\n"
    "            if _fp_name == node_name:\n"
    "                return tuple(_fp_peer_ips)\n")


def engine_expected_peer_ips(topo, without_b17=False):
    """`cmd_test`'s `_expected_peer_ips` from the engine's own source: the closure, with `_is_bgp_peer` and
    `expected_bgp_peers`, AST-extracted and bound with the names cmd_test binds (NOS_PROVIDERS, nodes_by_name,
    links_by_node, topo). With without_b17, rule B17's three lines are removed from the source first. None unless
    each closure, and B17's lines, occur exactly once."""
    import ast
    import cassian_engine
    import cassian_model

    with open(os.path.join(_ROOT, "src", "cassian_engine.py"), encoding="utf-8") as fh:
        src = fh.read()
    if src.count(_B17_LINES) != 1:
        return None
    if without_b17:
        src = src.replace(_B17_LINES, "", 1)
    want = ("_is_bgp_peer", "expected_bgp_peers", "_expected_peer_ips")
    found = {}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name in want:
            found.setdefault(node.name, []).append(node)
    if sorted(found) != sorted(want) or any(len(v) != 1 for v in found.values()):
        return None
    nodes = [n for n in topo.get("nodes", []) if isinstance(n, dict)]
    ns = {"NOS_PROVIDERS": cassian_engine.NOS_PROVIDERS, "nodes_by_name": {n["name"]: n for n in nodes},
          "links_by_node": cassian_model.build_node_links(topo), "topo": topo,
          "_precheck_fabric_participants": cassian_engine._precheck_fabric_participants}
    for name in want:
        exec(compile(ast.Module(body=found[name], type_ignores=[]), "<cassian_engine.py>", "exec"), ns)
    return ns["_expected_peer_ips"]


def p7s_equal(cassian_model, topo, participants, epi):
    """P7S-EQUAL on a participant list [(name, expected peer IPs)] and an `_expected_peer_ips`; returns (ok, detail)."""
    sessions = cassian_model.fabric_evpn_session_set(topo) or {}
    derived = [(n, tuple(ip for _p, ip, _rr in peers)) for n, peers in sessions.items()]
    if not participants or [(n, tuple(p)) for n, p in participants] != derived:
        return False, ("participants", participants, "derivation", derived)
    nodes = {n["name"]: n for n in topo.get("nodes", []) if isinstance(n, dict) and n.get("name")}
    bad = []
    for name, peer_ips in participants:
        if not peer_ips:
            bad.append((name, "no expected peer"))
        elif nodes[name].get("type") == "sonic-vm":
            got = tuple(epi(name))
            if got != tuple(peer_ips):
                bad.append((name, "the SONiC provider's expected peers", got, tuple(peer_ips)))
        else:
            gen_ips, _clients = rendered_peers(cassian_model.gen_frr_conf(nodes[name], topo))
            if list(peer_ips) != gen_ips:
                bad.append((name, "gen_frr_conf", gen_ips, list(peer_ips)))
    if not any(nodes[n].get("type") == "sonic-vm" for n, _p in participants):
        bad.append(("no sonic-vm participant",))
    return not bad, bad


def p7_sonic(cassian_model):
    """P-7's SONiC leg (addendum 01 §15.2 row 55, positive; rule B17; REQ-45E-55, -57)."""
    import yaml
    from pathlib import Path
    import cassian_engine

    full = os.path.join(_ROOT, P7S_FIXTURE)
    try:
        with open(full, encoding="utf-8") as fh:
            fdoc = yaml.safe_load(fh)
    except OSError as exc:
        check("P7S-FIXTURE %s is present" % P7S_FIXTURE, False, repr(exc))
        return
    unnamed = lambda d: {k: v for k, v in d.items() if k != "name"}
    check("P7S-FIXTURE %s is the P-10 topology, its name apart (oracle: _sonic_leaf(keep_host=False))" % P7S_FIXTURE,
          isinstance(fdoc, dict) and unnamed(fdoc) == unnamed(_with(_sonic_leaf(keep_host=False))))
    try:
        topo = cassian_model.resolve_topology(fdoc, topo_path=Path(full))
    except SystemExit as exc:
        check("P7S-FIXTURE %s resolves" % P7S_FIXTURE, False, str(exc))
        return
    seen = as_cmd_test_reads(topo)
    parts = cassian_engine._precheck_fabric_participants(seen)
    epi = engine_expected_peer_ips(seen)
    check("P7S the engine's _expected_peer_ips is found once, rule B17's lines in it once", epi is not None)
    if epi is None:
        return
    ok, bad = p7s_equal(cassian_model, topo, parts, epi)
    check("P7S-EQUAL %s: generator peers = precheck participants = the SONiC provider's expected peers, and the "
          "sonic-vm leaf1's are (172.16.0.0,)" % P7S_FIXTURE, ok and dict(parts or []).get("leaf1") == ("172.16.0.0",),
          bad)
    old = engine_expected_peer_ips(seen, without_b17=True)
    red = old is not None and tuple(old("leaf1")) == () and not p7s_equal(cassian_model, topo, parts, old)[0]
    if red:
        print("MUTATION-FAIL: _expected_peer_ips without rule B17's lines -> the SONiC leaf derives none, P7S-EQUAL red")
    check("P7S-NV without rule B17's lines the SONiC leaf derives none (the linked BGP speakers: no fabric node "
          "declares asn), and P7S-EQUAL is red", red)


_REFUSAL = "EVPN participant nodes must use type: frr, or type: sonic-vm with role: leaf"
# addendum 01 §6.6 rows U1 to U4, character for character (REQ-45E-54); _REFUSAL is U1 after its node prefix
_U = {
    "U1": "Topology invalid: node '<name>': EVPN participant nodes must use type: frr, or type: sonic-vm with role: leaf",
    "U2": "Topology invalid: node '<name>': a sonic-vm node cannot be an EVPN spine; use role: leaf, or type: frr for the route reflector",
    "U3": "Topology invalid: host '<name>': attach names a sonic-vm EVPN leaf; attach hosts to frr leaves (a SONiC leaf takes part in the EVPN control plane and carries no declared host)",
    "U4": "Topology invalid: node '<name>': a sonic-vm node with sonic_mode: preconfigured cannot be an EVPN participant; use sonic_mode: generated",
}


def _doc():
    import yaml
    with open(os.path.join(_ROOT, CORPUS[0]), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolve(model, doc):
    from pathlib import Path
    try:
        return "ok", model.resolve_topology(doc, topo_path=Path(os.path.join(_ROOT, CORPUS[0])))
    except SystemExit as exc:
        return "die", str(exc)


def _with(change):
    import copy
    doc = copy.deepcopy(_doc())
    change(doc)
    return doc


def _participant(doc):
    return next(n for n in doc["nodes"] if n.get("role") == "leaf")


def _set_type(ntype):
    """The participant's type changed; the file's tests and scenarios removed, so nothing else refuses it."""
    def change(doc):
        _participant(doc)["type"] = ntype
        doc["tests"] = []
        doc.pop("scenarios", None)
    return change


def l998_legs(model, label="L998"):
    ok = True
    for ntype in ("nft-fw", "host"):  # narrowed by addendum 01 (REQ-45E-50); a sonic-vm leaf is admitted (B15)
        doc = _with(_set_type(ntype))
        name = _participant(doc)["name"]
        o, msg = _resolve(model, doc)
        want = "Topology invalid: node '%s': %s" % (name, _REFUSAL)
        good = o == "die" and msg == want
        if not good:
            print("        %s %s: %s %s" % (label, ntype, o, msg if o == "die" else "validated"))
        check("%s an EVPN participant of type %s is rejected with U1" % (label, ntype), good)
        ok &= good
    return ok


def l998_cli():
    """The nft-fw refusal through `cassian validate --json`: exit 2, U1 as the error."""
    doc = _with(_set_type("nft-fw"))
    name = _participant(doc)["name"]
    code, payload = _validate_json(doc)
    check("L998 `cassian validate --json` on an nft-fw participant exits 2 with U1",
          code == 2 and payload.get("result") == "fail"
          and payload.get("error") == "Topology invalid: node '%s': %s" % (name, _REFUSAL), (code, payload))


def _validate_json(doc):
    """`cassian validate --json` (cmd_validate, in process) on a copy of doc in a temporary folder. The lab folder
    points there too: a pass writes the advisory coverage artifact, and nothing is written under labs/.
    Returns (exit code, payload)."""
    import argparse
    import contextlib
    import io
    import json
    import tempfile
    from pathlib import Path
    import yaml
    import cassian_artifacts
    import cassian_common
    import cassian_engine

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "case.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False)
        out = io.StringIO()
        prev_quiet, prev_labs = cassian_common._QUIET_DIE, cassian_artifacts.LABS_DIR
        code = None
        try:
            cassian_artifacts.LABS_DIR = Path(tmp) / "labs"
            with contextlib.redirect_stdout(out):
                cassian_engine.cmd_validate(argparse.Namespace(topology=path, json=True, contrib_path=None))
            code = 0
        except SystemExit as exc:
            code = exc.code
        finally:
            cassian_common._QUIET_DIE = prev_quiet
            cassian_artifacts.LABS_DIR = prev_labs
    try:
        payload = json.loads(out.getvalue())
    except ValueError:
        payload = {}
    return code, payload


def _strip(doc):
    doc["tests"] = []
    doc.pop("scenarios", None)


def _seq(*changes):
    def change(doc):
        for c in changes:
            c(doc)
    return change


def _node(doc, name):
    return next(n for n in doc["nodes"] if n.get("name") == name)


def _drop_host1(doc):
    """host1, which is attached to leaf1, removed with its link."""
    doc["nodes"] = [n for n in doc["nodes"] if n.get("name") != "host1"]
    doc["links"] = [l for l in doc["links"]
                    if not any(str(e).split(":")[0] == "host1" for e in l.get("endpoints", []))]


def _sonic_leaf(keep_host):
    """leaf1 of type sonic-vm, tests and scenarios removed; host1 (attached to leaf1) and its link removed unless
    keep_host."""
    def change(doc):
        _set_type("sonic-vm")(doc)
        if not keep_host:
            _drop_host1(doc)
    return change


def _unlink(a, b):
    def change(doc):
        doc["links"] = [l for l in doc["links"]
                        if sorted(str(e).split(":")[0] for e in l.get("endpoints", [])) != sorted((a, b))]
    return change


def _ensure(model, doc):
    try:
        model.ensure_valid_topology(doc)
    except SystemExit as exc:
        return "die", str(exc)
    return "ok", ""


def _u(row, name):
    return _U[row].replace("<name>", name)


def _refusal_cases():
    """(row, the name its message carries, the change) for U2 to U4."""
    return (
        ("U2", "spine1", _seq(_strip, lambda d: _node(d, "spine1").update(type="sonic-vm"))),
        ("U3", "host1", _sonic_leaf(keep_host=True)),
        ("U4", "leaf1", _seq(_sonic_leaf(keep_host=False),
                             lambda d: _node(d, "leaf1").update(sonic_mode="preconfigured"))),
    )


def s_set(model, label="W"):
    o, topo = _resolve(model, _with(_sonic_leaf(keep_host=False)))
    got = model.fabric_evpn_session_set(topo) if o == "ok" else None
    norm = None if got is None else {k: [tuple(p) for p in v] for k, v in got.items()}
    ok = norm == _SESSIONS and list(norm or {}) == PARTICIPANT_ORDER
    check("%s S-SET the P-10 topology's session set is the pinned one: sonic-vm leaf1 has (spine1, 172.16.0.0, "
          "False), and spine1 lists it as a client" % label, ok, norm)
    return ok


def wi6_legs(model, label="W"):
    """Addendum 01 rules B15 and B16 at model level (REQ-45E-49 to -55)."""
    o, topo = _resolve(model, _with(_sonic_leaf(keep_host=False)))
    check("%s P-10 the topology with leaf1 of type sonic-vm (host1 removed, host2 on the FRR leaf2) resolves" % label,
          o == "ok", topo if o != "ok" else "")
    s_set(model, label)
    for row, name, change in _refusal_cases():
        o, msg = _ensure(model, _with(change))
        check("%s %s ensure_valid_topology refuses with addendum 01 §6.6 row %s" % (label, row, row),
              o == "die" and msg == _u(row, name), msg)
    o, msg = _resolve(model, _with(_seq(_sonic_leaf(keep_host=False), _unlink("spine1", "leaf1"))))
    want = "Topology invalid: EVPN leaf 'leaf1' must have an explicit direct link to at least one EVPN RR spine"
    check("%s S-NEG a sonic-vm leaf with no link to a route reflector is refused by the leaf-link rule" % label,
          o == "die" and msg == want, msg)


def wi6_cli():
    """P-10 and TEXT through `cassian validate --json` (REQ-45E-49, -54)."""
    code, payload = _validate_json(_with(_sonic_leaf(keep_host=False)))
    check("W P-10 `cassian validate --json` on the topology with a sonic-vm leaf exits 0 with result pass",
          code == 0 and payload.get("result") == "pass", (code, payload))
    for row, name, change in _refusal_cases():
        code, payload = _validate_json(_with(change))
        check("W TEXT %s `cassian validate --json` exits 2 and its error is addendum 01 §6.6 row %s, character for "
              "character" % (row, row),
              code == 2 and payload.get("result") == "fail" and payload.get("error") == _u(row, name),
              (code, payload))


def _rejects(model, change, *needles):
    o, msg = _resolve(model, _with(change))
    return o == "die" and all(n in msg for n in needles), msg


def declaration_legs(model, label="D"):
    ok = True

    cases = (
        ("PLACE", "an evpn-shaped key on a node (evpn_vni)",
         lambda d: _participant(d).update(evpn_vni=10100), ("EVPN must be declared only at 'fabric.evpn'", "evpn_vni")),
        ("KEY", "an unsupported key under fabric.evpn",
         lambda d: d["fabric"]["evpn"].update(flavour="x"), ("unsupported key(s): flavour", "Supported keys are")),
        ("ENABLED", "enabled: 'yes' (not a boolean)",
         lambda d: d["fabric"]["evpn"].update(enabled="yes"), ("fabric.evpn.enabled must be boolean",)),
        ("MODE", "mode: vlan-based",
         lambda d: d["fabric"]["evpn"].update(mode="vlan-based"), ("fabric.evpn.mode must be 'vlan-aware'",)),
        ("ASN", "asn: 0", lambda d: d["fabric"]["evpn"].update(asn=0),
         ("fabric.evpn.asn must be an integer in range 1..4294967295",)),
        ("ASN", "asn: 4294967296", lambda d: d["fabric"]["evpn"].update(asn=4294967296),
         ("fabric.evpn.asn must be an integer in range 1..4294967295",)),
        ("ASN", "asn: '65100' (a string)", lambda d: d["fabric"]["evpn"].update(asn="65100"),
         ("fabric.evpn.asn must be an integer in range 1..4294967295",)),
    )
    for tag, what, change, needles in cases:
        good, msg = _rejects(model, change, *needles)
        if not good:
            print("        %s-%s %s: %s" % (label, tag, what, msg))
        check("%s-%s %s is rejected, naming %s" % (label, tag, what, " / ".join(needles)), good)
        ok &= good
    return ok


def emission_legs(model):
    frr_of = lambda topo: [n for n in topo["nodes"] if n.get("role")]
    o, topo = _resolve(model, _doc())
    if not check("D-EMIT the first corpus file resolves", o == "ok"):
        return
    asn = topo["fabric"]["evpn"]["asn"]
    cfgs = [model.gen_frr_conf(n, topo) for n in frr_of(topo)]
    check("D-ASN emission: every participant renders `router bgp %s` and `neighbor EVPN remote-as %s`" % (asn, asn),
          cfgs and all(("router bgp %s" % asn) in c and (" neighbor EVPN remote-as %s" % asn) in c for c in cfgs))
    o, topo2 = _resolve(model, _with(lambda d: d["fabric"]["evpn"].update(asn=65200)))
    cfgs2 = [model.gen_frr_conf(n, topo2) for n in frr_of(topo2)] if o == "ok" else []
    check("D-ASN emission: with asn 65200 declared, every participant renders 65200 and not %s" % asn,
          cfgs2 and all("router bgp 65200" in c and " neighbor EVPN remote-as 65200" in c
                        and ("router bgp %s" % asn) not in c for c in cfgs2))
    check("D-MODE emission: every participant carries `advertise-all-vni` (mode vlan-aware)",
          cfgs and all("  advertise-all-vni" in c for c in cfgs))
    o, topo3 = _resolve(model, _with(lambda d: d["fabric"]["evpn"].update(enabled=False)))
    cfgs3 = [model.gen_frr_conf(n, topo3) for n in frr_of(topo3)] if o == "ok" else None
    check("D-ENABLED emission: with enabled: false the topology resolves and no participant renders EVPN",
          cfgs3 is not None and all("l2vpn evpn" not in c and "peer-group EVPN" not in c for c in cfgs3),
          o)


def d13a(model):
    o, msg = _resolve(model, _with(lambda d: d["fabric"]["evpn"].update(mode="vlan-based")))
    check("D-13A (a) what is wrong and (b) where: `fabric.evpn.mode`", o == "die" and "fabric.evpn.mode" in msg, msg)
    check("D-13A (c) what would be valid: 'vlan-aware'", "'vlan-aware'" in msg, msg)
    _o, msg2 = _resolve(model, _with(lambda d: d["fabric"]["evpn"].update(mode="vlan-based")))
    check("D-13A the same misuse gives the same message bytes twice", msg == msg2)


def _model_mutant(old, new):
    import types
    path = os.path.join(_ROOT, "src", "cassian_model.py")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if text.count(old) != 1:
        return None
    mod = types.ModuleType("cassian_model_evpn_gen_mutant")
    mod.__file__ = path
    sys.modules[mod.__name__] = mod
    try:
        exec(compile(text.replace(old, new), "<cassian_model mutant>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(mod.__name__, None)
    return mod


def declaration(cassian_model):
    declaration_legs(cassian_model)
    emission_legs(cassian_model)
    d13a(cassian_model)
    l998_legs(cassian_model)
    l998_cli()
    wi6_legs(cassian_model)
    wi6_cli()

    import contextlib
    import io
    refusal = ('        elif ntype != "frr":\n'
               '            die(f"' + _U["U1"].replace("<name>", "{name}") + '")\n')
    mode = ('    if not isinstance(mode, str) or mode.strip() != "vlan-aware":\n'
            '        die("Topology invalid: fabric.evpn.mode must be \'vlan-aware\'")\n')
    b16 = '            or (node.get("type") == "sonic-vm" and role == "leaf")\n'
    for label, leg, old, run in (
            ("the participant-type refusal (U1) removed", "L998", refusal, lambda m: l998_legs(m, label="(mutant)")),
            ("the mode check removed", "D-MODE", mode, lambda m: declaration_legs(m, label="(mutant)")),
            ("rule B16's sonic-vm clause removed", "S-SET", b16, lambda m: s_set(m, label="(mutant)"))):
        m = _model_mutant(old, "")
        if m is None:
            check("D-NV the mutant's anchor is found once (%s)" % label, False)
            continue
        n0, c0 = len(_FAILED), _COUNT[0]
        with contextlib.redirect_stdout(io.StringIO()):
            run(m)
        red = [f for f in _FAILED[n0:] if f.startswith("(mutant)") and
               (leg != "D-MODE" or f.startswith("(mutant)-MODE"))]
        del _FAILED[n0:]
        _COUNT[0] = c0
        if red:
            print("MUTATION-FAIL: %s -> %s red" % (label, leg))
        check("D-NV %s: %s goes red" % (label, leg), bool(red))
        if leg == "L998":
            o, _msg = _resolve(m, _with(_seq(_set_type("nft-fw"), _drop_host1)))
            check("D-NV under that mutant an nft-fw leaf1 (host1 removed) validates", o == "ok", _msg)


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
    p7_sonic(cassian_model)
    declaration(cassian_model)

    if _FAILED:
        print("RESULT: RED -- %d checks, %d failed (evpn_gen_proof, §4.5-e WI-4, WI-5; addendum 01 WI-6, WI-4's SONiC consumer)" % (_COUNT[0], len(_FAILED)))
        return 1
    print("RESULT: GREEN -- %d checks, 0 failed (evpn_gen_proof, §4.5-e WI-4, WI-5; addendum 01 WI-6, WI-4's SONiC consumer)" % _COUNT[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
