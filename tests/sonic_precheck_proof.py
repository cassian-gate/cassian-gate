#!/usr/bin/env python3
"""tests/sonic_precheck_proof.py — §4.5-c WI-3.

Req-IDs: REQ-45C-8  (BGP convergence precheck dispatched through the provider
                     seam; declared-peer scoping)
         REQ-45C-29 (polling bounds/interval/timeout identical to the FRR leg;
                     deterministic timeout FAIL with per-neighbour evidence;
                     never a hang)

The §6.7.2 assignment for this file is [8, 9, 24, 29]. THIS PACKET LANDS THE
LAB-FREE LEGS ONLY. REQ-45C-9 (--precheck-controlplane) and REQ-45C-24
(undeclared-neighbour asymmetry) have NO assertions here yet and travel with
packets 4-5; the file is born early by founder-ratified amendment so that the
engine dispatch and the provider leg ship with a proof rather than without one.

Host-independent. No lab, no containerlab, no Docker. The provider seam is
driven through a stub `rt` whose `exec` returns canned `show bgp summary json`
payloads, the pattern the four-quadrant proofs use.

Coverage limits (PBE-P2-8), stated rather than implied:
  1. The stub returns payloads in the shape continuation rider rev 11 §2
     records as MEASURED on `sonic-vm:202405` (`peers` keyed by peer IP with a
     `state` field). That measurement is INHERITED. This proof cannot verify
     the guest's actual JSON shape; REQ-45C-22 (VM) settles that.
  2. Timing is exercised with SMALL timeouts against a real clock. This proves
     boundedness and per-neighbour evidence at timeout. It does NOT prove the
     interval is exactly 1s in wall-clock terms -- the interval is asserted
     against the module constant, which is what the FRR leg's own 1s sleep is
     compared to.
  3. Nothing here observes a device. Rendering-to-acceptance is REQ-45C-22.
"""
import ast
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import is_deferred  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _Cp:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class _Rt:
    """Stub runtime. Records argv; replays a scripted sequence of payloads."""

    def __init__(self, payloads):
        self._payloads = list(payloads)
        self.calls = []

    def exec(self, lab, node, argv, check=False, capture_output=False):
        self.calls.append(tuple(argv))
        if self._payloads:
            item = self._payloads.pop(0)
        else:
            item = self._payloads_last if hasattr(self, "_payloads_last") else ("", 0)
        self._payloads_last = item
        body, rc = item
        return _Cp(body, rc)


def _summary(states):
    inner = ", ".join('"%s": {"state": "%s"}' % (ip, st) for ip, st in states.items())
    return '{"ipv4Unicast": {"peers": {%s}}}' % inner


# --- the leg is wired, not deferred -----------------------------------------
check("REQ-45C-8 SONiC convergence_wait is WIRED, not a deferred placeholder",
      not is_deferred(S.SONIC_PROVIDER.convergence_wait),
      "LD-H2 point 2: the decision site switches in the handover landing the leg")
check("NG-9 the read argv is single-sourced (PBE-P2-6)",
      S._BGP_SUMMARY_ARGV == ("vtysh", "-c", "show bgp summary json"),
      "the proof imports the tuple rather than restating the command")
check("REQ-45C-29 poll interval matches the FRR leg's 1s sleep",
      S._CONVERGENCE_POLL_INTERVAL_S == 1,
      "cassian_tests.py wait_for_bgp sleeps 1s per iteration")

# --- positive: every declared peer Established -> returns --------------------
_rt = _Rt([(_summary({"192.0.2.1": "Established", "192.0.2.5": "Established"}), 0)])
_ok = True
try:
    S.convergence_wait(_rt, "lab", "s1", 5, ("192.0.2.1", "192.0.2.5"))
except SystemExit:
    _ok = False
check("REQ-45C-8 all declared peers Established -> returns", _ok)
check("REQ-45C-8 the read goes to the guest via the single-sourced argv",
      _rt.calls and _rt.calls[0] == S._BGP_SUMMARY_ARGV,
      "calls: %s" % (_rt.calls[:1],))

# --- THE SCOPING PROPERTY: stock peers do not block success ------------------
_stock = {"10.0.0.1": "Active", "10.0.0.3": "Connect", "10.0.0.5": "Idle",
          "192.0.2.1": "Established", "192.0.2.5": "Established"}
_rt2 = _Rt([(_summary(_stock), 0)])
_scoped_ok = True
try:
    S.convergence_wait(_rt2, "lab", "s1", 5, ("192.0.2.1", "192.0.2.5"))
except SystemExit:
    _scoped_ok = False
check("REQ-45C-8 SCOPING: un-declared stock peers in Active/Connect/Idle do "
      "NOT block convergence", _scoped_ok,
      "sonic-vm:202405 ships stock neighbours that never establish "
      "(BL-P2-4.5c-9); an all-peers wait could never pass")

# --- NON-VACUITY: a declared peer that is NOT Established DOES block ---------
_rt3 = _Rt([(_summary({"192.0.2.1": "Established", "192.0.2.5": "Active"}), 0)])
_blocked = False
_t0 = time.time()
try:
    S.convergence_wait(_rt3, "lab", "s1", 1, ("192.0.2.1", "192.0.2.5"))
except SystemExit as _e:
    _blocked = (_e.code == 2)
_elapsed = time.time() - _t0
check("REQ-45C-8 NON-VACUITY: a declared peer not Established DOES block, exit 2",
      _blocked, "proves the scoping discriminates rather than always passing")
check("REQ-45C-29 the wait is BOUNDED -- no hang",
      _elapsed < 10, "elapsed %.1fs against a 1s timeout" % _elapsed)

# --- positive test only: unknown states are never enumerated ----------------
_rt4 = _Rt([(_summary({"192.0.2.1": "SomeStateNobodyEnumerated"}), 0)])
_unknown_blocks = False
try:
    S.convergence_wait(_rt4, "lab", "s1", 1, ("192.0.2.1",))
except SystemExit as _e:
    _unknown_blocks = (_e.code == 2)
check("REQ-45C-8 POSITIVE TEST: an unrecognised state is NOT treated as up",
      _unknown_blocks,
      "the FSM oscillates; only `Established` counts (rev 11 §2)")

# --- an absent peer is not-present, not silently up -------------------------
_rt5 = _Rt([(_summary({"192.0.2.1": "Established"}), 0)])
_absent_blocks = False
try:
    S.convergence_wait(_rt5, "lab", "s1", 1, ("192.0.2.1", "192.0.2.9"))
except SystemExit as _e:
    _absent_blocks = (_e.code == 2)
check("Doctrine 1.11 a declared peer absent from the read is NOT silence-as-up",
      _absent_blocks)

# --- unparseable / not-yet-serving is NOT-YET, not a verdict ----------------
check("REQ-45C-29 unparseable output yields no peers rather than a verdict",
      S._peers_from_summary("Error: BGP not running") == {}
      and S._peers_from_summary("") == {},
      "during convergence the bgp container may not be serving yet")
_rt6 = _Rt([("", 1), ("Error: not running", 1),
            (_summary({"192.0.2.1": "Established"}), 0)])
_recovers = True
try:
    S.convergence_wait(_rt6, "lab", "s1", 5, ("192.0.2.1",))
except SystemExit:
    _recovers = False
check("REQ-45C-29 a non-zero rc while starting is NOT-YET, not a fault",
      _recovers and len(_rt6.calls) >= 3,
      "polls: %d" % len(_rt6.calls))

# --- timeout evidence names EVERY non-established declared peer -------------
import io  # noqa: E402
_err = io.StringIO()
_saved, sys.stderr = sys.stderr, _err
_rt7 = _Rt([(_summary({"192.0.2.1": "Active", "192.0.2.5": "Established"}), 0)])
try:
    S.convergence_wait(_rt7, "lab", "s1", 1, ("192.0.2.1", "192.0.2.5", "192.0.2.9"))
except SystemExit:
    pass
finally:
    sys.stderr = _saved
_msg = _err.getvalue()
check("REQ-45C-29 timeout evidence names every non-established declared peer",
      "192.0.2.1" in _msg and "192.0.2.9" in _msg,
      "per-neighbour evidence, not a bare timeout")
check("REQ-45C-29 timeout evidence does NOT name an already-Established peer",
      "192.0.2.5" not in _msg,
      "proves the message discriminates rather than dumping the declaration")
check("REQ-45C-29 timeout message carries the §13 element set",
      all(k in _msg for k in ("ERROR:", "node:", "reason:", "detail:", "required:")))

# --- empty declared set is a loud failure, never a silent pass ---------------
_empty = False
try:
    S.convergence_wait(_Rt([]), "lab", "s1", 1, ())
except SystemExit as _e:
    _empty = (_e.code == 2)
check("Doctrine 1.11 an empty declared-peer set fails loud, exit 2", _empty,
      "a bounded wait with no target would return success observing nothing")

# --- REQ-45C-23 / packet 2: the engine predicates are declaration-driven ----
# AST-extracted from the shipped engine and bound, the pattern the four-quadrant
# proofs use. Proves packet 2's property in CI rather than only in a sandbox.
_eng = os.path.join(_ROOT, "src", "cassian_engine.py")
_tree = ast.parse(io.open(_eng, encoding="utf-8").read())
_wanted = {"_is_bgp_node", "_is_bgp_peer"}
_found = {n.name: n for n in ast.walk(_tree)
          if isinstance(n, ast.FunctionDef) and n.name in _wanted}
check("REQ-45C-8 both declaration-driven predicates exist in the engine",
      set(_found) == _wanted, "found: %s" % sorted(_found))

if set(_found) == _wanted:
    _ns = {"NOS_PROVIDERS": {"frr": object(), "nft-fw": object(),
                             "sonic-vm": object()}}
    for _name in sorted(_wanted):
        exec(compile(ast.Module(body=[_found[_name]], type_ignores=[]),
                     "<engine>", "exec"), _ns)
    _is_node, _is_peer = _ns["_is_bgp_node"], _ns["_is_bgp_peer"]

    def _old_node(n):
        return n.get("type") == "frr"

    def _old_peer(p):
        return bool(p and p.get("type") == "frr" and "asn" in p)

    _mismatch = []
    for _t in ("frr", "host", "linux"):
        for _asn in (True, False):
            _n = {"name": "x", "type": _t}
            if _asn:
                _n["asn"] = 65001
            if _old_node(_n) != _is_node(_n):
                _mismatch.append(("node", _t, _asn))
            if _old_peer(_n) != _is_peer(_n):
                _mismatch.append(("peer", _t, _asn))
    check("REQ-45C-8 ZERO DELTA: all-FRR topologies select the identical "
          "node and peer sets", not _mismatch,
          "12 comparisons; mismatches: %s" % (_mismatch or "none"))

    _sonic = {"name": "s1", "type": "sonic-vm", "asn": 65001}
    check("REQ-45C-8 NON-VACUITY: a sonic-vm node declaring asn IS a "
          "participant under the new predicates",
          _is_node(_sonic) and _is_peer(_sonic),
          "under the old filters it was excluded on BOTH sides -- the peer-side "
          "exclusion is the one that made the precheck silently never run")
    check("REQ-45C-8 an un-provider'd type is still excluded",
          not _is_node({"name": "h1", "type": "host", "asn": 65001})
          and not _is_peer({"name": "h1", "type": "host", "asn": 65001}))

# --- REQ-45C-2 / BR-2: provision reconciles the daemon after applying ---------
# BR-2 requires that provisioning's generated config converges a declared eBGP
# pair to Established. Measured 2026-08-25: `config load` writes ConfigDB and
# bgpcfgd REFUSES the update path -- ERR on an existing peer, silent no-op on
# DEVICE_METADATA.localhost.bgp_asn, WARNING on the set-src template. A restart
# rebuilds FRR from ConfigDB through the ADD path, which works.
_prov_src = ast.parse(io.open(
    os.path.join(_ROOT, "src", "cassian_nos_sonic.py"), encoding="utf-8").read())
_fns = {n.name: n for n in ast.walk(_prov_src) if isinstance(n, ast.FunctionDef)}

check("REQ-45C-2 provision has a reconcile step at all",
      "_reconcile_bgp" in _fns,
      "without it the overlay reaches ConfigDB and never reaches FRR")
check("REQ-45C-2 the reconcile argv is single-sourced (PBE-P2-6)",
      S._BGP_RECONCILE_ARGV == ("sudo", "systemctl", "restart", "bgp"),
      "the proof imports the tuple rather than restating the command")

# ORDER MATTERS: reconciling before the overlay is merged rebuilds from stale
# ConfigDB and looks identical to success.
_prov_body = ast.dump(_fns["provision"]) if "provision" in _fns else ""
_i_load = _prov_body.find("'load'")
_i_rec = _prov_body.find("_reconcile_bgp")
check("REQ-45C-2 reconcile is called AFTER `config load`, not before",
      _i_load != -1 and _i_rec != -1 and _i_load < _i_rec,
      "a rebuild from stale ConfigDB would look exactly like success")

# --- NON-VACUITY: the reconcile fails LOUD, never silently ------------------
_rc_loud = False
try:
    S._reconcile_bgp(_Rt([("", 1)]), "lab", "s1")
except SystemExit as _e:
    _rc_loud = (_e.code == 2)
check("REQ-45C-2 NON-VACUITY: a failed reconcile exits 2, never silence",
      _rc_loud,
      "Doctrine 1.11 -- a merged overlay that never reached FRR must not read clean")

_rc_ok = True
_rt_rec = _Rt([("", 0)])
try:
    S._reconcile_bgp(_rt_rec, "lab", "s1")
except SystemExit:
    _rc_ok = False
check("REQ-45C-2 a successful reconcile returns quietly", _rc_ok)
check("REQ-45C-2 the reconcile reaches the guest via the single-sourced argv",
      _rt_rec.calls and _rt_rec.calls[0] == S._BGP_RECONCILE_ARGV,
      "calls: %s" % (_rt_rec.calls[:1],))

# --- the ruled shape: NO readiness wait here (founder ruling 2026-08-25) -----
check("REQ-45C-29 reconcile does NOT re-poll for readiness",
      "_CONVERGENCE_POLL_INTERVAL_S" not in ast.dump(_fns["_reconcile_bgp"]),
      "nos_ready assigns bgp readiness to convergence_wait; re-polling here "
      "would wait for something already waited for")
check("REQ-45C-2 the during-boot limit is stated in-file, not implied",
      "DURING-BOOT RESTART IS UNMEASURED" in (_fns["_reconcile_bgp"].body[0].value.value
                                              if isinstance(_fns["_reconcile_bgp"].body[0], ast.Expr)
                                              else ""),
      "PBE-P2-8: bgp arrives up to ~90s after CONFIG_DB and provision runs earlier")

# --- REQ-45C-24: undeclared-neighbor asymmetry, named never silent ----------
# CORE-side, founder ruling 2026-08-25: the asymmetry is a TOPOLOGY property and
# the provider seam carries only `expected_peer_ips`, a tuple of IP strings with
# no notion of the far node's declaration (cassian_nos_types.py:215). The three
# closures are AST-extracted from the shipped engine and bound, the pattern the
# four-quadrant proofs use, so this proves the SHIPPED code and not a copy.
_eng_src = io.open(os.path.join(_ROOT, "src", "cassian_engine.py"),
                   encoding="utf-8").read()
_eng_tree = ast.parse(_eng_src)
_want24 = {"_declared_neighbor_names", "_declaration_asymmetries", "_is_bgp_peer"}
_f24 = {n.name: n for n in ast.walk(_eng_tree)
        if isinstance(n, ast.FunctionDef) and n.name in _want24}

check("REQ-45C-24 the asymmetry detector exists in the engine",
      set(_f24) == _want24, "found: %s" % sorted(_f24))

if set(_f24) == _want24:
    _ns = {"NOS_PROVIDERS": {"frr": object(), "sonic-vm": object()}}
    for _n in ("_is_bgp_peer", "_declared_neighbor_names"):
        exec(compile(ast.Module(body=[_f24[_n]], type_ignores=[]), "<engine>", "exec"), _ns)
    _decl = _ns["_declared_neighbor_names"]

    check("REQ-45C-24 declared names are read from bgp.neighbors[].peer",
          _decl({"bgp": {"neighbors": [{"peer": "s2"}, {"peer": "s3"}]}}) == {"s2", "s3"},
          "cassian_model.py:1697 binds peer_name from nbr['peer']")
    check("REQ-45C-24 a node declaring nothing yields the empty set",
          _decl({"name": "s2", "asn": 65002}) == set()
          and _decl({"bgp": {}}) == set() and _decl(None) == set())

    # Bind the detector against the SHIPPED fixture, with the engine's own
    # closure variables supplied exactly as cmd_test builds them.
    def _asym(topo):
        nodes = topo["nodes"]
        ns = dict(_ns)
        ns["nodes_by_name"] = {n["name"]: n for n in nodes}
        ns["bgp_speakers"] = [n for n in nodes
                              if str(n.get("type") or "") in ns["NOS_PROVIDERS"]
                              and "asn" in n]
        lbn = {}
        for l in topo.get("links") or []:
            eps, ips = l["endpoints"], l["ipv4"]
            (n1, i1), (n2, i2) = [(e.split(":", 1)[0], p.split("/")[0])
                                  for e, p in zip(eps, ips)]
            lbn.setdefault(n1, []).append({"peer": n2, "peer_ip": i2})
            lbn.setdefault(n2, []).append({"peer": n1, "peer_ip": i1})
        ns["links_by_node"] = lbn
        ns["_is_bgp_peer"] = _ns["_is_bgp_peer"]
        ns["_declared_neighbor_names"] = _decl
        exec(compile(ast.Module(body=[_f24["_declaration_asymmetries"]], type_ignores=[]),
                     "<engine>", "exec"), ns)
        return ns["_declaration_asymmetries"]()

    _fx = os.path.join(_ROOT, "topologies", "sonic-bgp-asymmetric.yaml")
    check("REQ-45C-24 the negative fixture is present", os.path.isfile(_fx))

    _ASYM = {"nodes": [
        {"name": "s1", "type": "sonic-vm", "asn": 65001,
         "bgp": {"neighbors": [{"peer": "s2", "remote_as": 65002}]}},
        {"name": "s2", "type": "sonic-vm", "asn": 65002}],
        "links": [{"endpoints": ["s1:eth1", "s2:eth1"],
                   "ipv4": ["198.51.100.4/31", "198.51.100.5/31"]}]}
    check("REQ-45C-24 a one-sided declaration IS named, with both parties",
          _asym(_ASYM) == [("s1", "s2")],
          "got %s -- §19.1's evidence shape: 'A declares B; B declares no "
          "matching neighbor'" % (_asym(_ASYM),))

    _SYM = {"nodes": [
        {"name": "s1", "type": "sonic-vm", "asn": 65001,
         "bgp": {"neighbors": [{"peer": "s2", "remote_as": 65002}]}},
        {"name": "s2", "type": "sonic-vm", "asn": 65002,
         "bgp": {"neighbors": [{"peer": "s1", "remote_as": 65001}]}}],
        "links": [{"endpoints": ["s1:eth1", "s2:eth1"],
                   "ipv4": ["198.51.100.0/31", "198.51.100.1/31"]}]}
    check("REQ-45C-24 NON-VACUITY: a SYMMETRIC pair is NOT named",
          _asym(_SYM) == [],
          "a detector that fires on everything names nothing")

    _NEITHER = {"nodes": [
        {"name": "s1", "type": "sonic-vm", "asn": 65001},
        {"name": "s2", "type": "sonic-vm", "asn": 65002}],
        "links": _SYM["links"]}
    check("REQ-45C-24 neither-declares is NOT an asymmetry (stated limit)",
          _asym(_NEITHER) == [],
          "REQ-45C-24's case is 'one side declares... the other does not'")

    _REV = {"nodes": [_ASYM["nodes"][1], _ASYM["nodes"][0]], "links": _ASYM["links"]}
    check("REQ-45C-24 the pair is DIRECTIONAL and node-order independent",
          _asym(_REV) == [("s1", "s2")],
          "the declarer is named first regardless of iteration order")

    check("REQ-45C-24 a non-speaker peer is not named",
          _asym({"nodes": [_ASYM["nodes"][0], {"name": "s2", "type": "host"}],
                 "links": _ASYM["links"]}) == [],
          "_is_bgp_peer gates it -- an unlinked or non-speaking peer is a "
          "different defect class")

# The corrected docstring, pinned so the defect cannot silently return.
check("REQ-45C-24 _expected_peer_ips no longer claims to return DECLARED peers",
      "Peer IPs of the LINKED BGP speakers" in _eng_src
      and '"""Declared peer IPs for `node_name`, deterministic order.' not in _eng_src,
      "corrected in packet 4a; the linked/declared divergence IS REQ-45C-24")

# --- Seam symbols the (VM) legs use, asserted LAB-FREE ----------------------
# Rule 16: the (VM) path cannot run on the dev side, so a wrong symbol name
# would pass here and RED in CI mid-lab on ai-netsim. Assert the names now.

try:
    import cassian_runtime_vm as _RV  # noqa: E402
    _rv_err = ""
except Exception as _e:  # pragma: no cover - import failure is the finding
    _RV = None
    _rv_err = repr(_e)

check("(VM) seam: cassian_runtime_vm.build_runtime is callable",
      _RV is not None and callable(getattr(_RV, "build_runtime", None)),
      _rv_err or "cassian_runtime_vm.py:406")
check("(VM) seam: cassian_nos_sonic._guest_stdout is callable",
      callable(getattr(S, "_guest_stdout", None)),
      "cassian_nos_sonic.py:457 -- stdout only; the guest SSH banner lands on "
      "stderr (F-45C-C3-20) and merging it breaks every parse")


# --- (VM) legs --------------------------------------------------------------
# Founder ruling LD-45C-R1 (2026-08-26, `e8da5c4`), extended GENERALLY the same
# day: a (VM) leg observes the device itself through the product's runtime
# seam. The product records nothing on the success path and is not changed.
#
# The three legs do NOT share an evidence channel:
#   req8  -> live device via rt.exec
#   req24 -> results.json summary.precheck_declaration_asymmetries
#   req29 -> the §13-grade timeout text from the run's captured output
#
# usage, one leg per invocation so each CI sub-step is attributable:
#   sonic_precheck_proof.py                      -> lab-free only, 3 BLOCKED, exit 0
#   sonic_precheck_proof.py req8  <topology> <lab>
#   sonic_precheck_proof.py req24 <results.json>
#   sonic_precheck_proof.py req29 <captured-output-file>

_blocked = []


def blocked(name, reason):
    _blocked.append((name, reason))


def _declared_peers(topo_path):
    """[(node, peer_ip)] declared under bgp.neighbors, matched to link ipv4.

    Read from the topology, not from the device: the point of REQ-45C-8 is
    that every DECLARED peer reached Established, so the declared set is the
    subject and the device is the observation.
    """
    import yaml
    doc = yaml.safe_load(io.open(topo_path, encoding="utf-8").read()) or {}
    by_pair = {}
    for link in doc.get("links") or []:
        if not isinstance(link, dict):
            continue
        eps = [str(e).split(":")[0] for e in (link.get("endpoints") or [])]
        ips = [str(i).split("/")[0] for i in (link.get("ipv4") or [])]
        if len(eps) == 2 and len(ips) == 2:
            by_pair[(eps[0], eps[1])] = ips[1]
            by_pair[(eps[1], eps[0])] = ips[0]
    out = []
    for n in doc.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        bgp = n.get("bgp") if isinstance(n.get("bgp"), dict) else {}
        for nbr in bgp.get("neighbors") or []:
            if not isinstance(nbr, dict):
                continue
            ip = by_pair.get((name, nbr.get("peer")))
            if ip:
                out.append((name, ip))
    return sorted(out)


def _leg_req8(topo_path, lab):
    """LIVE DEVICE. Every declared peer Established, states printed."""
    import yaml
    doc = yaml.safe_load(io.open(topo_path, encoding="utf-8").read()) or {}
    declared = _declared_peers(topo_path)
    check("REQ-45C-8 (VM) NON-VACUITY: the topology declares at least one peer",
          bool(declared), "declared: %r" % (declared,))
    if not declared:
        return
    rt = _RV.build_runtime(doc)
    observed = {}
    for node, peer_ip in declared:
        out = S._guest_stdout(rt, lab, node, ["vtysh", "-c", "show bgp summary"],
                              "REQ-45C-8 (VM) per-neighbour state")
        state = ""
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == peer_ip and len(parts) >= 10:
                state = parts[9]
                break
        observed[(node, peer_ip)] = state
    def _up(s):
        return bool(s) and (s.isdigit() or s.lower() == "established")
    not_up = sorted("%s->%s:%s" % (n, p, st or "(absent)")
                    for (n, p), st in observed.items() if not _up(st))
    check("REQ-45C-8 (VM) every DECLARED peer is Established",
          not not_up,
          "per-neighbour states: " + "; ".join(
              "%s->%s:%s" % (n, p, st or "(absent)")
              for (n, p), st in sorted(observed.items())))


def _leg_req24(results_path):
    """ARTIFACT. Named asymmetry evidence in results.json, not silence."""
    import json
    doc = json.loads(io.open(results_path, encoding="utf-8").read())
    key = "precheck_declaration_asymmetries"
    present = key in (doc.get("summary") or {})
    check("REQ-45C-24 (VM) results.json carries %s" % key, present,
          "cassian_engine.py:10327, landed packet 4a")
    if not present:
        return
    entries = doc["summary"][key]
    # SHAPE READ FROM SOURCE, NOT INFERRED (packet 4b-iv). The engine builds
    # `[{"declares": a, "silent": b} for a, b in _asymmetries]` at
    # cassian_engine.py:10327-10329. The first authoring of this leg asserted
    # a list of STRINGS because "named evidence" sounded like prose; run
    # 33041629461 reported [{'declares': 's1', 'silent': 's2'}] and failed on
    # correct evidence.
    _shaped = (isinstance(entries, list) and len(entries) > 0
               and all(isinstance(e, dict)
                       and str(e.get("declares") or "").strip()
                       and str(e.get("silent") or "").strip()
                       for e in entries))
    check("REQ-45C-24 (VM) asymmetry surfaces as NAMED evidence, not silence",
          _shaped,
          "each entry names BOTH parties -- engine:10327-10329; "
          "entries: %r" % (entries,))


def _leg_req29(capture_path):
    """CAPTURED OUTPUT. Deterministic timeout FAIL naming every non-up peer."""
    text = io.open(capture_path, encoding="utf-8", errors="replace").read()
    marker = "per-neighbour state at timeout"
    check("REQ-45C-29 (VM) timeout produced the §13-grade per-neighbour text",
          marker in text,
          "cassian_nos_sonic.py:767-778; searched %s" % capture_path)
    check("REQ-45C-29 (VM) no hang: the run terminated and produced output",
          bool(text.strip()),
          "an empty capture is a claim about the capture, not the run")
    if marker in text:
        seg = text.split(marker, 1)[1].splitlines()[0]
        check("REQ-45C-29 (VM) the timeout text names at least one peer state",
              ":" in seg, "segment: %s" % seg.strip()[:160])


_vm_args = sys.argv[1:]
if not _vm_args:
    blocked("REQ-45C-8 (VM) converging pair -> precheck PASS with per-neighbor "
            "states",
            "no (VM) argv supplied; run: req8 <topology> <lab>. Wired at 4b-iii")
    blocked("REQ-45C-24 (VM) asymmetric declaration -> named evidence in "
            "precheck output",
            "no (VM) argv supplied; run: req24 <results.json>. Wired at 4b-iii")
    blocked("REQ-45C-29 (VM) non-converging pair -> deterministic timeout FAIL",
            "no (VM) argv supplied; run: req29 <captured-output>. Wired at 4b-iii")
elif _vm_args[0] == "req8" and len(_vm_args) == 3:
    _leg_req8(_vm_args[1], _vm_args[2])
elif _vm_args[0] == "req24" and len(_vm_args) == 2:
    _leg_req24(_vm_args[1])
elif _vm_args[0] == "req29" and len(_vm_args) == 2:
    _leg_req29(_vm_args[1])
else:
    sys.exit("usage: sonic_precheck_proof.py [req8 <topology> <lab> | "
             "req24 <results.json> | req29 <captured-output>]  "
             "(no argv = lab-free legs only)")


# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok2, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok2 else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
for _bn, _br in _blocked:
    print("BLOCKED %s  [%s]" % (_bn, _br))
print("=" * 60)
print("RESULT: %s -- %d checks, %d BLOCKED (WI-3 SONiC precheck%s)"
      % ("PASS" if not _failed else "FAIL", len(_checks), len(_blocked),
         "" if _vm_args else ", lab-free legs"))
if _blocked:
    print("NOTE: %d (VM) leg(s) BLOCKED. A BLOCKED leg is not a pass; the "
          "closure report carries it as a condition (PBE-P2-8)." % len(_blocked))
sys.exit(1 if _failed else 0)
