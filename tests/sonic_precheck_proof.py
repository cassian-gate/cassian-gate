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

# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok2, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok2 else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-3 SONiC precheck, lab-free legs)"
      % ("PASS" if not _failed else "FAIL", len(_checks)))
sys.exit(1 if _failed else 0)
