#!/usr/bin/env python3
"""evpn_precheck_mac_poll_proof.py -- §4.5-d, S24-R5 (BL-P2-4.5c-53's named fix),
with S28-R1 and S28-R2 (BL-P2-4.5c-220's fix), extended for BL-P2-4.5c-216's fix
(S30-R1, S30-R2, S30-R9 to S30-R11, S30-R13 and S30-R15 to S30-R25).

The hosted differential that founder ruling S24-R5 (2026-10-06) binds, as applied
by S25-R4 (2026-10-08): in `cmd_test`'s global control-plane precheck, an EVPN lab
no longer sleeps a fixed 10 s after the BGP-session wait; it polls, within the
existing `precheck_timeout`, for every declared host MAC route (the resolved
`fabric.evpn` host attachments) on every EVPN leaf, through the product's
existing presence read, and fails loud naming what is absent. Non-EVPN labs stay
byte-identical. S24-R5 left replay labs on their sleep; S30-R16 (2026-10-14) polls
them too, at their 60 s bound (P-REPLAY).

S28-R1 and S28-R2 (founder rulings 2026-10-11, an SP #1 bounded-scope amendment of
S26-R3): the poll accepts the declared set only once it is present on every EVPN
leaf on 3 consecutive attempts; an attempt with anything absent starts the count
again. Interval, bound and predicate are unchanged. On timeout the message names
what was absent at the last attempt or, when nothing was, how many consecutive full
attempts were reached out of 3.

Method. Lab-free. The precheck's `try:` body is executed twice from source text,
as a function, against recording stubs and a fake clock:
  BEFORE  the c0fb557 text, frozen below and pinned by sha256 (the oracle never
          changes with the tree);
  AFTER   the same body extracted from the live src/cassian_engine.py between
          two exact anchors.
Topologies come from the committed fixtures through the product's own
`resolve_topology`, round-tripped through YAML as `cassian test` reads them.
`retry_until` is the engine's own (cassian_tests); `die` is cassian_common's.

S30-R1 to S30-R25 (founder rulings 2026-10-14, BL-P2-4.5c-216's fix). Measured
in the session-30 capture: for every `fabric.evpn` topology `cmd_test` derived no
BGP participant, so the block this proof executes was never entered -- the proof
was green because it ran the body, never the entry condition. The entry decision
is now `_precheck_entry`, and the record `_PrecheckRecord`, both module-level in
the engine and exercised here directly (P-REACH, P-GUARD, P-RECORD).

Sections:
  P-ORACLE   the frozen text is the c0fb557 extraction (sha256 pinned).
  P-PREFIX   (restated, S30-R15 and S30-R19) every line of the frozen BEFORE
             text appears in the live body, in order and byte for byte, apart
             from S24-R5's replaced sleep and the FRR session-wait call; that
             call equals BEFORE's with exactly one keyword added, `stats`; the
             replaced sleep stands once, as the else of `if require_evpn_bgp:`.
  P-NONEVPN  a non-EVPN lab: BEFORE and AFTER traces identical (sleep 5).
  P-REPLAY   (restated, S30-R16 and S30-R22) an EVPN replay lab (the engine's
             `{base}-replay-{h8}` name): the same session waits at 60 s, then
             the route poll at bound 60 instead of BEFORE's 15 s sleep; a
             non-EVPN replay lab: traces identical (sleep 5).
  P-EVPN     an EVPN lab, every route present: AFTER has no fixed sleep; it
             reads each leaf x declared MAC on each of 3 attempts, through
             `_evaluate_invariant_attempt(kind evpn_mac_route_present)`, and
             returns after the window (two 1 s intervals).
  P-LATE     a route absent for three attempts, then present: AFTER returns
             after six attempts (three absent, three present), inside the bound.
  P-TIMEOUT  a route never present: BEFORE proceeds silently after its sleep
             (the defect); AFTER dies at the bound naming lab, leaf, host, MAC
             and VNI, with elapsed time and attempts.
  P-WINDOW   the window is the named constant `_evpn_stable_k = 3`, set once
             in the branch (S28-R2), and the poll's accept test reads it (AST).
  P-FLAP     BL-P2-4.5c-220's shape: every route present, then host1's MAC
             gone from leaf2 for one attempt, then back. AFTER restarts its
             count and returns after five attempts; with the window set to 1
             (the single sample S24-R5 accepted) the same fabric is accepted
             at the first attempt, before the loss.
  P-UNSTABLE every route present at the last attempt but never 3 attempts in a
             row: AFTER dies at the bound naming the lab, elapsed time, bound,
             attempts and the consecutive full attempts reached out of 3, and
             lists no absent route.
  P-RESET    a route absent at the last attempt of a flapping fabric: the
             message is the absent-route one, listing only that route.
  P-PRED     the predicate is the read's second element, as REQ-WF-6 consumes
             it: a failed probe that reports present counts as present, a
             clean probe that reports absent counts as absent.
  P-CLOSED   an EVPN lab whose resolved topology declares no host attachment
             fails loud before any read (fail-closed, never a silent pass).
  P-SHAPE    the new call has the REQ-WF-6 call's keywords, kind constant and
             `t` keys (AST over the live engine).
  P-BOUND    the poll's bound is the existing `precheck_timeout` name and its
             interval is 1.0 (AST).
  P-NEUTRAL  the new branch names no NOS (no string constant contains "frr"
             or "sonic"): core stays NOS-neutral.
  P-REACH    (S30-R1, S30-R16) every `fabric.evpn` topology under topologies/
             (recursively) that the product's resolver resolves -- among them
             every one cassian.yml boots -- is entered by `_precheck_entry` with
             NO participant and without the guard, replay-named or not; a scenario
             run without --precheck-controlplane is not; `cmd_test` takes its
             decision from `_precheck_entry` and gates the precheck on it alone
             (AST).
  P-GUARD    (S30-R2) node-level BGP intent with no participant is entered with
             a hard-fail naming the lab and nodes; with a participant, entered
             without it; no intent and no fabric, not entered ("no-bgp-intent");
             the guard is the precheck's first statement and dies (AST, and
             that statement executed).
  P-RECORD   (S30-R9 to S30-R11, S30-R17, S30-R19 to S30-R21, S30-R23 to S30-R25)
             the record the
             live body writes: summary.precheck holds definitions and outcomes,
             timing.precheck the run-variant values; every value enumerated is
             one the rulings name; a provider-driven wait reports no attempts;
             "timeout" only when the waiting code reports it; the tamper digest's
             domain keeps summary.precheck and drops timing.precheck; the record
             is attached right after `results` is created ("not-reached");
             the real `wait_for_bgp` reports its attempts and its timeout through
             `stats` (driven with a fake runtime).

Coverage limits (PBE-P2-8): lab-free; the fake clock stands in for wall time;
the stubs stand in for the runtime, for `wait_for_bgp` (except where P-RECORD
drives the real one) and for a provider's `convergence_wait`. P-REACH reads
`_precheck_entry` with an empty participant list -- the worst case, and the
measured one for every fabric topology; it does not derive participants itself,
and it does not cover topologies the resolver rejects (they never reach the
precheck). A SystemExit inside the precheck from anything but the waits, the
guard and the poll's own refusals (a runtime failure inside the presence read,
say) is recorded `failed` with `failure` null: no ruled value names it, and the
record does not guess one (S30-R24). This proof does NOT
show that the routes converge in CI or on any host, does NOT exercise the FRR
read itself (the read is the product's existing one, unchanged), and does NOT
show the CI acceptance S24-R5 requires (the EVPN step green on consecutive
attempts, then green x2) -- that is read from CI, not from here. Nor does it show
that 3 consecutive attempts outlast the churn a CI fabric shows: BL-P2-4.5c-220's
withdrawal mechanism is not measured (session-28 rulings note).

Reports only; writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import contextlib
import glob
import hashlib
import io
import os
import pathlib
import re
import sys
import time

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import cassian_common  # noqa: E402  (die)
import cassian_engine  # noqa: E402  (_precheck_entry, _PrecheckRecord, _audit_filtered_domain)
import cassian_model  # noqa: E402  (resolve_topology)
import cassian_tests  # noqa: E402  (retry_until, the engine's own import)

ENGINE = os.path.join(_ROOT, "src", "cassian_engine.py")
EVPN_FIXTURE = os.path.join(_ROOT, "topologies", "evpn_mac_route_absent_expected_present.yaml")
NONEVPN_FIXTURE = os.path.join(_ROOT, "topologies", "three-frr-two-hosts-fw-routed.yaml")

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok), detail))


START = '            require_evpn_bgp = bool((((topo.get("fabric") or {}).get("evpn") or {}).get("enabled")))\n'
END = "        except SystemExit:\n"
LAST = "time.sleep(post_precheck_sleep)\n"

# c0fb557, src/cassian_engine.py, the precheck `try:` body between START
# (inclusive) and END (exclusive), dedented by 12. Frozen; never regenerated.
CONTROL_BODY = (
    'require_evpn_bgp = bool((((topo.get("fabric") or {}).get("evpn") or {}).get("enabled")))\n'
    'is_replay_lab = "-replay-" in str(topo.get("name", ""))\n'
    'precheck_timeout = 60 if (require_evpn_bgp and is_replay_lab) else 30\n'
    'post_precheck_sleep = 15 if (require_evpn_bgp and is_replay_lab) else (10 if require_evpn_bgp else 5)\n'
    'for n in bgp_participants:\n'
    '    # §4.5-c WI-3 (REQ-45C-8): precheck dispatched through the\n'
    '    # provider seam. NG-9: FRR keeps the inline wait and its\n'
    '    # `convergence_wait` placeholder stays a placeholder -- the\n'
    '    # bounds, interval and timeout it is given are unchanged\n'
    '    # (REQ-45C-29). A non-FRR participant takes its provider leg;\n'
    '    # if that leg is still `deferred_leg`, the placeholder fails\n'
    '    # LOUD and §13-grade (cassian_nos_types.py:250) rather than\n'
    "    # being handed FRR's vtysh path, which would reach the vrnetlab\n"
    '    # launcher on a vm-runtime node, not the NOS.\n'
    '    _ntype = str(n.get("type") or "")\n'
    '    _prov = NOS_PROVIDERS.get(_ntype)\n'
    '    if _ntype == "frr" or _prov is None:\n'
    '        wait_for_bgp(rt, lab, n["name"], timeout=precheck_timeout, require_evpn=require_evpn_bgp)\n'
    '    else:\n'
    '        _prov.convergence_wait(\n'
    '            rt, lab, n["name"], precheck_timeout, _expected_peer_ips(n["name"])\n'
    '        )\n'
    'time.sleep(post_precheck_sleep)\n'
)
CONTROL_SHA = "0f850cde4e430ed76dee03cd2bda7f14cda79f61029c9ed1ce479aac3b30068f"


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _dedent12(text):
    out = []
    for ln in text.splitlines(True):
        if ln.strip():
            assert ln.startswith(" " * 12), "line not indented by 12: %r" % ln
            out.append(ln[12:])
        else:
            out.append(ln)
    return "".join(out)


ENGINE_SRC = io.open(ENGINE, encoding="utf-8").read()
_i = ENGINE_SRC.find(START)
_j = ENGINE_SRC.find(END, _i) if _i != -1 else -1
LIVE_BODY = _dedent12(ENGINE_SRC[_i:_j]) if (_i != -1 and _j != -1) else ""

# --- P-ORACLE -------------------------------------------------------------------------------
check("P-ORACLE the frozen BEFORE text is the c0fb557 extraction (sha256 pinned)",
      _sha(CONTROL_BODY) == CONTROL_SHA, _sha(CONTROL_BODY))
check("P-ORACLE the START anchor occurs exactly once in the live engine",
      ENGINE_SRC.count(START) == 1, "count=%d" % ENGINE_SRC.count(START))

# --- P-PREFIX (restated: S30-R15, S30-R19) ---------------------------------------------------
# The FRR session-wait call, the one BEFORE line S30-R18 changes (it gains `stats`).
FRR_CALL = '        wait_for_bgp(rt, lab, n["name"], timeout=precheck_timeout, require_evpn=require_evpn_bgp)\n'
_before_lines = CONTROL_BODY.splitlines(True)
_live_lines = LIVE_BODY.splitlines(True)
check("P-PREFIX the BEFORE body ends with the fixed sleep, and holds the FRR call once",
      _before_lines[-1:] == [LAST] and _before_lines.count(FRR_CALL) == 1)


def _in_order(needles, hay):
    """Index in `hay` of each needle, matched in order and byte for byte; None where one is missing."""
    out, j = [], 0
    for ln in needles:
        while j < len(hay) and hay[j] != ln:
            j += 1
        if j == len(hay):
            return None
        out.append(j)
        j += 1
    return out


_kept = [ln for ln in _before_lines[:-1] if ln != FRR_CALL]
_pos = _in_order(_kept, _live_lines)
check("P-PREFIX every other BEFORE line appears in the live body, in order, byte for byte",
      _pos is not None, "first missing: %r" % (next((ln for k, ln in enumerate(_kept)
                                                      if _in_order(_kept[:k + 1], _live_lines) is None), None),))
_frr_live = [ln for ln in _live_lines if ln.lstrip().startswith("wait_for_bgp(")]


def _call(src):
    return ast.parse(src.strip(), mode="eval").body


_ok_call = False
if len(_frr_live) == 1 and _pos is not None:
    _b, _l = _call(FRR_CALL), _call(_frr_live[0])
    _bk = {k.arg: ast.dump(k.value) for k in _b.keywords}
    _lk = {k.arg: ast.dump(k.value) for k in _l.keywords}
    _ok_call = (ast.dump(_b.func) == ast.dump(_l.func)
                and [ast.dump(a) for a in _b.args] == [ast.dump(a) for a in _l.args]
                and {k: v for k, v in _lk.items() if k != "stats"} == _bk
                and set(_lk) - set(_bk) == {"stats"}
                and _frr_live[0][: len(_frr_live[0]) - len(_frr_live[0].lstrip())] == "        ")
    # it stands where BEFORE's did: after the `if _ntype == "frr" ...` line, before its `else:`
    _if_ix = _pos[_kept.index('    if _ntype == "frr" or _prov is None:\n')]
    _else_ix = _pos[_kept.index("    else:\n")]
    _ok_call = _ok_call and _if_ix < _live_lines.index(_frr_live[0]) < _else_ix
check("P-PREFIX the FRR session-wait call is BEFORE's with exactly one keyword added, `stats`, in place",
      _ok_call, "%r" % _frr_live)
_tail = "".join(_live_lines[_pos[-1] + 1:]) if _pos is not None else ""
check("P-PREFIX the replaced sleep stands once, as the else of `if require_evpn_bgp:` (S30-R16)",
      _tail.count("\nif require_evpn_bgp:\n") == 1 and "not is_replay_lab" not in _tail
      and _tail.count("    " + LAST) == 1 and "\nelse:\n" in _tail,
      "tail: %r" % _tail[-80:])


# --- harness --------------------------------------------------------------------------------
def _build(body):
    src = ("def _precheck(topo, rt, lab, bgp_participants, wait_for_bgp, NOS_PROVIDERS,\n"
           "              _expected_peer_ips, time, _evaluate_invariant_attempt, retry_until, die, _pcr):\n")
    src += "".join(("    " + ln) if ln.strip() else ln for ln in body.splitlines(True))
    ns = {}
    exec(compile(src, "<precheck>", "exec"), ns)
    return ns["_precheck"]


class _Clock:
    def __init__(self):
        self.t = 1000.0
        self.trace = []

    def time(self):
        return self.t

    def sleep(self, s):
        self.trace.append(("sleep", float(s)))
        self.t += float(s)


def _run(body, topo, present, parts=None, providers=None, bgp_timeout=(), rec=None):
    """present(attempt, leaf, mac) -> (probe_ok, predicate). Returns (trace, exited, msg, elapsed).
    `bgp_timeout`: node names whose FRR wait times out (S30-R20's report, then the die).
    `rec`: a list that receives the `_PrecheckRecord` after the run (the handler's call
    emulated on SystemExit, as `cmd_test`'s `except SystemExit:` makes it -- AST-checked
    in P-RECORD -- with the body's own `_pc_stats` at the exit, read from its frame;
    `{}` when the body had not yet bound it, as `cmd_test` binds it before the try)."""
    clock = _Clock()
    attempt = {"n": 0, "seen": set()}

    def wait_for_bgp(rt, lab, node, timeout=30, require_evpn=False, stats=None):
        clock.trace.append(("bgp", node, int(timeout), bool(require_evpn)))
        if stats is not None:
            stats["attempts"] = 2 if node in bgp_timeout else 1
        if node in bgp_timeout:
            clock.t += float(timeout) + 1.0
            if stats is not None:
                stats["timed_out"] = True
            cassian_common.die("%s: BGP did not converge within %ss" % (node, timeout))
        return 1

    def _evaluate_invariant_attempt(*, inv_type, t, src):
        key = (src, t["_mac"])
        if key in attempt["seen"]:
            attempt["n"] += 1
            attempt["seen"] = set()
        attempt["seen"].add(key)
        clock.trace.append(("eval", src, t["_mac"], t["_vni_i"], inv_type))
        ok, pred = present(attempt["n"], src, t["_mac"])
        return ok, pred, {}, {}

    if parts is None:
        parts = [n for n in topo.get("nodes", []) if isinstance(n, dict) and n.get("type") == "frr"]
    fn = _build(body)
    saved = (time.time, time.sleep)
    time.time, time.sleep = clock.time, clock.sleep
    cassian_common.LAST_ERROR_MSG = ""
    exited, start = False, clock.t
    pcr = cassian_engine._PrecheckRecord()
    pcr.enter(parts, clock.t)
    err = io.StringIO()
    try:
        _old = sys.stderr
        sys.stderr = err
        try:
            fn(topo, None, str(topo.get("name")), parts, wait_for_bgp, providers or {}, lambda _n: ("10.0.0.1",),
               time, _evaluate_invariant_attempt, cassian_tests.retry_until, cassian_common.die, pcr)
        finally:
            sys.stderr = _old
    except SystemExit as exc:
        exited = True
        tb, pc_stats = exc.__traceback__, {}
        while tb is not None:
            if tb.tb_frame.f_code.co_name == "_precheck":
                pc_stats = tb.tb_frame.f_locals.get("_pc_stats", {})
            tb = tb.tb_next
        pcr.failed(clock.t, pc_stats)
    finally:
        time.time, time.sleep = saved
    if rec is not None:
        rec.append(pcr)
    return clock.trace, exited, str(getattr(cassian_common, "LAST_ERROR_MSG", "") or ""), clock.t - start


def _resolved(path, name=None, strip_hosts=False):
    t = yaml.safe_load(io.open(path, encoding="utf-8").read())
    r = cassian_model.resolve_topology(t, topo_path=__import__("pathlib").Path(path))
    r = yaml.safe_load(yaml.safe_dump(r, sort_keys=False))
    if name:
        r["name"] = name
    if strip_hosts:
        r["fabric"]["evpn"]["host_attachments"] = []
    return r


ALL = lambda n, leaf, mac: (True, True)  # noqa: E731
EVPN = _resolved(EVPN_FIXTURE)
LEAVES = sorted(EVPN["fabric"]["evpn"]["leaf_nodes"])
DECL = sorted((a["mac"], a["host"]) for a in EVPN["fabric"]["evpn"]["host_attachments"])
EXPECT_EVALS = [("eval", leaf, mac, 10100, "evpn_mac_route_present") for leaf in LEAVES for mac, _h in DECL]
check("P-EVPN the committed fixture resolves to 2 leaves x 2 declared MACs",
      LEAVES == ["leaf1", "leaf2"] and [m for m, _h in DECL] == ["00:11:22:33:44:55", "00:11:22:33:44:66"],
      "%s %s" % (LEAVES, DECL))

# --- P-NONEVPN ------------------------------------------------------------------------------
_ne = _resolved(NONEVPN_FIXTURE)
_b, _bx, _, _ = _run(CONTROL_BODY, _ne, ALL)
_a, _ax, _, _ = _run(LIVE_BODY, _ne, ALL)
check("P-NONEVPN BEFORE and AFTER traces identical", _b == _a and not _bx and not _ax, "%s | %s" % (_b, _a))
check("P-NONEVPN the trace ends with the 5 s sleep and holds no EVPN read",
      _a[-1:] == [("sleep", 5.0)] and not any(e[0] == "eval" for e in _a), str(_a))

# --- P-REPLAY (restated: S30-R16, S30-R22) ---------------------------------------------------
_rp = _resolved(EVPN_FIXTURE, name=EVPN["name"] + "-replay-0a1b2c3d")
_b, _bx, _, _ = _run(CONTROL_BODY, _rp, ALL)
_rpr = []
_a, _ax, _, _el = _run(LIVE_BODY, _rp, ALL, rec=_rpr)
check("P-REPLAY BEFORE: timeout 60 with EVPN required, then the 15 s sleep, no EVPN read",
      all(e[2] == 60 and e[3] for e in _b if e[0] == "bgp") and _b[-1:] == [("sleep", 15.0)]
      and not any(e[0] == "eval" for e in _b), str(_b))
check("P-REPLAY AFTER: the same session waits as BEFORE (timeout 60, EVPN required)",
      [e for e in _a if e[0] == "bgp"] == [e for e in _b if e[0] == "bgp"], str(_a))
check("P-REPLAY AFTER: the route poll instead of the 15 s sleep -- 3 attempts, two 1 s intervals, no failure",
      not _ax and [e for e in _a if e[0] == "sleep"] == [("sleep", 1.0)] * 2
      and [e for e in _a if e[0] == "eval"] == EXPECT_EVALS * 3 and _el == 2.0, str(_a))
check("P-REPLAY AFTER: the poll's bound is replay's 60 s",
      _rpr and (_rpr[0].summary.get("settle") or {}).get("bound_s") == 60, str(_rpr[0].summary if _rpr else None))
_rpn = _resolved(NONEVPN_FIXTURE, name="three-frr-two-hosts-fw-routed-replay-0a1b2c3d")
_b, _bx, _, _ = _run(CONTROL_BODY, _rpn, ALL)
_a, _ax, _, _ = _run(LIVE_BODY, _rpn, ALL)
check("P-REPLAY a non-EVPN replay lab: BEFORE and AFTER traces identical (sleep 5)",
      _b == _a and not _bx and not _ax and _a[-1:] == [("sleep", 5.0)], "%s | %s" % (_b, _a))

# --- P-EVPN ---------------------------------------------------------------------------------
_b, _bx, _, _ = _run(CONTROL_BODY, EVPN, ALL)
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, ALL)
check("P-EVPN BEFORE sleeps the fixed 10 s and reads nothing", _b[-1:] == [("sleep", 10.0)]
      and not any(e[0] == "eval" for e in _b), str(_b))
check("P-EVPN AFTER: same BGP waits as BEFORE", [e for e in _a if e[0] == "bgp"] == [e for e in _b if e[0] == "bgp"])
check("P-EVPN AFTER: no fixed sleep; only the poll's two 1 s intervals",
      [e for e in _a if e[0] == "sleep"] == [("sleep", 1.0)] * 2, str(_a))
check("P-EVPN AFTER: each leaf x declared MAC read on each of 3 attempts, kind evpn_mac_route_present, VNI 10100",
      [e for e in _a if e[0] == "eval"] == EXPECT_EVALS * 3, str([e for e in _a if e[0] == "eval"]))
check("P-EVPN AFTER returns without failing, after the 3-attempt window (2.0 s)", not _ax and _el == 2.0,
      "exited=%s elapsed=%s" % (_ax, _el))

# --- P-LATE ---------------------------------------------------------------------------------
_late = lambda n, leaf, mac: (True, not (leaf == "leaf2" and mac.endswith(":66") and n < 3))  # noqa: E731
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, _late)
check("P-LATE AFTER returns after 6 attempts (3 absent, 3 present), 5 one-second intervals, no failure",
      not _ax and sum(1 for e in _a if e[0] == "eval") == 6 * len(EXPECT_EVALS)
      and [e for e in _a if e[0] == "sleep"] == [("sleep", 1.0)] * 5 and _el == 5.0,
      "exited=%s elapsed=%s sleeps=%s" % (_ax, _el, [e for e in _a if e[0] == "sleep"]))

# --- P-TIMEOUT ------------------------------------------------------------------------------
_never = lambda n, leaf, mac: (True, not (leaf == "leaf2" and mac.endswith(":66")))  # noqa: E731
_b, _bx, _, _ = _run(CONTROL_BODY, EVPN, _never)
_a, _ax, _msg, _el = _run(LIVE_BODY, EVPN, _never)
check("P-TIMEOUT BEFORE proceeds silently after its fixed sleep (the defect S24-R5 fixes)",
      not _bx and _b[-1:] == [("sleep", 10.0)])
check("P-TIMEOUT AFTER fails loud at the bound (30 s, the existing precheck_timeout)",
      _ax and 30.0 <= _el <= 31.0, "exited=%s elapsed=%s" % (_ax, _el))
_want = ["EVPN precheck: declared host MAC routes still absent after 30.0s",
         "(bound 30s, 31 attempts)", "in lab " + EVPN["name"],
         "  leaf2: host2 00:11:22:33:44:66 (VNI 10100) is not in the EVPN MAC-route read",
         "Action: "]
check("P-TIMEOUT the message names lab, leaf, host, MAC, VNI, elapsed, bound, attempts and an action",
      all(w in _msg for w in _want), "missing: %s" % [w for w in _want if w not in _msg])
check("P-TIMEOUT the message lists only what is absent",
      _msg.count(" is not in the EVPN MAC-route read") == 1 and "leaf1:" not in _msg, _msg)

# --- P-WINDOW / P-FLAP / P-UNSTABLE / P-RESET (S28-R1, S28-R2) ------------------------------
K_LINE = "_evpn_stable_k = 3\n"
check("P-WINDOW the window is set once in the live branch, as _evpn_stable_k = 3",
      LIVE_BODY.count(K_LINE) == 1 and LIVE_BODY.count("_evpn_stable_k = ") == 1,
      "count=%d" % LIVE_BODY.count(K_LINE))
_kt = ast.parse(LIVE_BODY)
_cmp = [c for c in ast.walk(_kt) if isinstance(c, ast.Compare) and isinstance(c.ops[0], ast.GtE)
        and isinstance(c.comparators[0], ast.Name) and c.comparators[0].id == "_evpn_stable_k"]
check("P-WINDOW the accept test compares the consecutive count with _evpn_stable_k (>=), once",
      len(_cmp) == 1, str([ast.unparse(c) for c in _cmp]))
K1_BODY = LIVE_BODY.replace(K_LINE, "_evpn_stable_k = 1\n", 1) if LIVE_BODY.count(K_LINE) == 1 else ""
check("P-WINDOW the window-1 control body differs from the live body in that line only",
      K1_BODY != "" and K1_BODY != LIVE_BODY and len(K1_BODY) == len(LIVE_BODY))

# BL-P2-4.5c-220's recorded shape: leaf2 read without host1's MAC right after a full sample.
_flap = lambda n, leaf, mac: (True, not (n == 1 and leaf == "leaf2" and mac.endswith(":55")))  # noqa: E731
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, _flap)
check("P-FLAP AFTER restarts its count on the loss and returns after 5 attempts (4.0 s), no failure",
      not _ax and sum(1 for e in _a if e[0] == "eval") == 5 * len(EXPECT_EVALS) and _el == 4.0,
      "exited=%s elapsed=%s evals=%d" % (_ax, _el, sum(1 for e in _a if e[0] == "eval")))
_c, _cx, _, _cel = _run(K1_BODY, EVPN, _flap) if K1_BODY else ([], True, "", -1.0)
check("P-FLAP control: with the window set to 1, the same fabric is accepted at the first attempt, before the loss",
      not _cx and _cel == 0.0 and sum(1 for e in _c if e[0] == "eval") == len(EXPECT_EVALS),
      "exited=%s elapsed=%s" % (_cx, _cel))

_unstable = lambda n, leaf, mac: (True, not (n % 3 == 1 and leaf == "leaf2" and mac.endswith(":55")))  # noqa: E731
_a, _ax, _msg, _el = _run(LIVE_BODY, EVPN, _unstable)
check("P-UNSTABLE AFTER fails loud at the bound (30 s), never reaching 3 in a row",
      _ax and 30.0 <= _el <= 31.0, "exited=%s elapsed=%s" % (_ax, _el))
_want_u = ["EVPN precheck: declared host MAC routes not stable after 30.0s",
           "(bound 30s, 31 attempts)", "in lab " + EVPN["name"],
           "present on every EVPN leaf at the last attempt",
           "on only 2 consecutive full attempt(s) of the 3 required", "Action: "]
check("P-UNSTABLE the message names lab, elapsed, bound, attempts and the consecutive count out of 3",
      all(w in _msg for w in _want_u), "missing: %s" % [w for w in _want_u if w not in _msg])
check("P-UNSTABLE the message lists no absent route", " is not in the EVPN MAC-route read" not in _msg, _msg)

_reset = lambda n, leaf, mac: (True, not (n % 2 == 0 and leaf == "leaf2" and mac.endswith(":55")))  # noqa: E731
_a, _ax, _msg, _el = _run(LIVE_BODY, EVPN, _reset)
check("P-RESET a route absent at the last attempt: the absent-route message, that route only",
      _ax and "still absent after 30.0s" in _msg
      and _msg.count(" is not in the EVPN MAC-route read") == 1
      and "  leaf2: host1 00:11:22:33:44:55 (VNI 10100) is not in the EVPN MAC-route read" in _msg
      and "not stable" not in _msg, _msg)

# --- P-PRED ---------------------------------------------------------------------------------
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, lambda n, leaf, mac: (False, True))
check("P-PRED a failed probe that reports present counts as present (predicate only, as REQ-WF-6)",
      not _ax and _el == 2.0)
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, lambda n, leaf, mac: (True, False))
check("P-PRED a clean probe that reports absent counts as absent", _ax and _el >= 30.0)

# --- P-CLOSED -------------------------------------------------------------------------------
_a, _ax, _msg, _ = _run(LIVE_BODY, _resolved(EVPN_FIXTURE, strip_hosts=True), ALL)
check("P-CLOSED no declared host attachment: fails loud before any read",
      _ax and not any(e[0] == "eval" for e in _a) and "declares no EVPN leaf, no host attachment" in _msg,
      _msg[:120])

# --- P-SHAPE / P-BOUND / P-NEUTRAL (AST over the live engine) --------------------------------
_tree = ast.parse(ENGINE_SRC)


def _calls(node):
    return [c for c in ast.walk(node) if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name) and c.func.id == "_evaluate_invariant_attempt"]


def _kw(call):
    return {k.arg: k.value for k in call.keywords}


_wf = None
for _n in ast.walk(_tree):
    if (isinstance(_n, ast.If) and isinstance(_n.test, ast.Compare)
            and isinstance(_n.test.left, ast.Name) and _n.test.left.id == "wtype"
            and isinstance(_n.test.comparators[0], ast.Constant)
            and _n.test.comparators[0].value == "evpn_mac_route_present" and _calls(_n)):
        _wf = _n
        break
_live_ifs = [_n for _n in ast.walk(_tree)
             if isinstance(_n, ast.If) and isinstance(_n.test, ast.Name) and _n.test.id == "require_evpn_bgp"]
_live_if = _live_ifs[0] if len(_live_ifs) == 1 else None
check("P-SHAPE the REQ-WF-6 site and the new site (`if require_evpn_bgp:`, S30-R16) are both found, once",
      _wf is not None and _live_if is not None and len(_calls(_live_if)) == 1, "sites=%d" % len(_live_ifs))
if _wf is not None and _live_if is not None and len(_calls(_live_if)) == 1:
    _c_wf, _c_new = _calls(_wf)[0], _calls(_live_if)[0]
    _t_wf = None
    for _n in ast.walk(_wf):
        if isinstance(_n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "t_for_helper" for x in _n.targets):
            _t_wf = sorted(k.value for k in _n.value.keys)
    _t_new = sorted(k.value for k in _kw(_c_new)["t"].keys) if isinstance(_kw(_c_new).get("t"), ast.Dict) else None
    check("P-SHAPE same keywords as the REQ-WF-6 call", sorted(_kw(_c_wf)) == sorted(_kw(_c_new)),
          "%s vs %s" % (sorted(_kw(_c_wf)), sorted(_kw(_c_new))))
    check("P-SHAPE same kind constant, evpn_mac_route_present",
          ast.unparse(_kw(_c_wf)["inv_type"]) == ast.unparse(_kw(_c_new)["inv_type"]) == "'evpn_mac_route_present'")
    check("P-SHAPE same `t` keys (_mac, _vni_i)", _t_wf == _t_new == ["_mac", "_vni_i"], "%s %s" % (_t_wf, _t_new))
    _ru = [c for c in ast.walk(_live_if) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
           and c.func.id == "retry_until"]
    check("P-BOUND one retry_until, bound = precheck_timeout, interval = 1.0",
          len(_ru) == 1 and isinstance(_ru[0].args[0], ast.Name) and _ru[0].args[0].id == "precheck_timeout"
          and isinstance(_ru[0].args[1], ast.Constant) and _ru[0].args[1].value == 1.0,
          ast.unparse(_ru[0]) if _ru else "none")
    _consts = [c.value for c in ast.walk(_live_if)
               if isinstance(c, ast.Constant) and isinstance(c.value, str)]
    check("P-NEUTRAL the new branch names no NOS", not [c for c in _consts if "frr" in c.lower() or "sonic" in c.lower()],
          str([c for c in _consts if "frr" in c.lower() or "sonic" in c.lower()]))

# --- cmd_test's AST, shared by P-REACH, P-GUARD and P-RECORD ---------------------------------
_cmd_test = next((n for n in _tree.body if isinstance(n, ast.FunctionDef) and n.name == "cmd_test"), None)


def _is_call(node, func_src):
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == func_src


_gate_if = None
_entry_assign = []
if _cmd_test is not None:
    _entry_assign = [n for n in ast.walk(_cmd_test) if isinstance(n, ast.Assign)
                     and isinstance(n.value, ast.Call) and ast.unparse(n.value.func) == "_precheck_entry"]
    _gate_ifs = [n for n in ast.walk(_cmd_test) if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
                 and n.test.id == "_pc_enter" and n.body and isinstance(n.body[0], ast.Try)]
    _gate_if = _gate_ifs[0] if len(_gate_ifs) == 1 else None
_gate_try = _gate_if.body[0] if _gate_if is not None else None

# --- P-REACH (S30-R1, S30-R16) ----------------------------------------------------------------
# The corpus: every *.yaml under topologies/ that the product's resolver resolves.
_FABRIC, _UNRESOLVED = {}, []
for _p in sorted(glob.glob(os.path.join(_ROOT, "topologies", "**", "*.yaml"), recursive=True)):
    _rel = os.path.relpath(_p, _ROOT).replace(os.sep, "/")
    try:
        _t = yaml.safe_load(io.open(_p, encoding="utf-8").read())
    except Exception:
        continue
    if not isinstance(_t, dict) or not isinstance(_t.get("nodes"), list):
        continue
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            _r = cassian_model.resolve_topology(_t, topo_path=pathlib.Path(_p))
        _r = yaml.safe_load(yaml.safe_dump(_r, sort_keys=False))
    except BaseException:
        _UNRESOLVED.append(_rel)
        continue
    if bool((((_r.get("fabric") or {}).get("evpn") or {}).get("enabled"))):
        _FABRIC[_rel] = _r
_ci_src = io.open(os.path.join(_ROOT, ".github", "workflows", "cassian.yml"), encoding="utf-8").read()
_ci_fabric = sorted(set(re.findall(r"topologies/[A-Za-z0-9_./-]+\.yaml", _ci_src)) & set(_FABRIC))
check("P-REACH the corpus walk finds fabric topologies, among them every one CI boots",
      len(_FABRIC) >= 4 and len(_ci_fabric) >= 4,
      "fabric=%d ci-booted=%s" % (len(_FABRIC), _ci_fabric))
_bad = [k for k, t in sorted(_FABRIC.items())
        if cassian_engine._precheck_entry(t, [], True) != (True, None, None)]
check("P-REACH every fabric topology, with NO participant, is entered without the guard (%d topologies)" % len(_FABRIC),
      _FABRIC and not _bad, str(_bad))
_bad = []
for _k, _t in sorted(_FABRIC.items()):
    _rt = dict(_t)
    _rt["name"] = str(_t.get("name") or "")[:40] + "-replay-0a1b2c3d"
    if cassian_engine._precheck_entry(_rt, [], True) != (True, None, None):
        _bad.append(_k)
check("P-REACH every fabric topology under the engine's replay name is entered too (S30-R16)",
      _FABRIC and not _bad, str(_bad))
_bad = [k for k, t in sorted(_FABRIC.items())
        if cassian_engine._precheck_entry(t, [], False) != (False, "not-selected", None)]
check("P-REACH not selected (a scenario run without --precheck-controlplane): not entered, \"not-selected\"",
      _FABRIC and not _bad, str(_bad))
_ea = _entry_assign[0] if len(_entry_assign) == 1 else None
check("P-REACH cmd_test takes the entry decision from _precheck_entry once, on topo, its participants and the selection",
      _ea is not None and ast.unparse(_ea.targets[0]) == "(_pc_enter, _pc_reason, _pc_guard)"
      and ast.unparse(_ea.value) == "_precheck_entry(topo, bgp_participants, bool(do_global_cp_precheck))",
      ast.unparse(_ea) if _ea is not None else "found %d" % len(_entry_assign))
check("P-REACH the precheck's try is gated on that decision alone (`if _pc_enter:`), and the old gate is gone",
      _gate_try is not None and "do_global_cp_precheck and bgp_participants" not in ENGINE_SRC
      and any(isinstance(s, ast.Assign) and ast.unparse(s.targets[0]) == "require_evpn_bgp" for s in _gate_try.body),
      "gate found=%s" % (_gate_try is not None))

# --- P-GUARD (S30-R2) -------------------------------------------------------------------------
_GT = {"name": "guard-lab", "nodes": [{"name": "r2", "type": "frr", "bgp": {"neighbors": []}},
                                      {"name": "r1", "type": "frr", "asn": 65001},
                                      {"name": "h1", "type": "host"}]}
_ge = cassian_engine._precheck_entry(_GT, [], True)
check("P-GUARD node-level intent, no participant: entered, with a hard-fail naming the lab and the nodes",
      _ge[0] is True and _ge[1] is None and isinstance(_ge[2], str)
      and "lab guard-lab" in _ge[2] and "r1, r2" in _ge[2] and "\nAction: " in _ge[2], repr(_ge))
check("P-GUARD with a participant: entered, no guard",
      cassian_engine._precheck_entry(_GT, [_GT["nodes"][1]], True) == (True, None, None))
check("P-GUARD no intent and no fabric: not entered, \"no-bgp-intent\"",
      cassian_engine._precheck_entry({"name": "x", "nodes": [{"name": "r1", "type": "frr"}]}, [], True)
      == (False, "no-bgp-intent", None))
_GF = dict(EVPN, name="guard-fabric", nodes=list(EVPN["nodes"]) + [{"name": "r9", "type": "frr", "asn": 65009}])
_gf = cassian_engine._precheck_entry(_GF, [], True)
check("P-GUARD a fabric.evpn lab that also declares node-level BGP, no participant: the guard too (S30-R2 has no fabric exemption)",
      _gf[0] is True and isinstance(_gf[2], str) and "lab guard-fabric" in _gf[2] and "r9" in _gf[2], repr(_gf)[:160])
check("P-GUARD intent but not selected: not entered, \"not-selected\" (the guard is the precheck's, not the run's)",
      cassian_engine._precheck_entry(_GT, [], False) == (False, "not-selected", None))
_g0 = _gate_try.body[0] if _gate_try is not None and _gate_try.body else None
check("P-GUARD the guard is the precheck's first statement: record the failure, then die with the guard text",
      isinstance(_g0, ast.If) and ast.unparse(_g0.test) == "_pc_guard is not None" and len(_g0.body) == 2
      and _is_call(_g0.body[0], "_pcr.failing")
      and ast.unparse(_g0.body[0].value.args[0]) == "'bgp-intent-without-participants'"
      and _is_call(_g0.body[1], "die") and ast.unparse(_g0.body[1].value) == "die(_pc_guard)",
      ast.unparse(_g0)[:160] if _g0 is not None else "none")
# The guard statement as written, executed: it records, dies, and the handler's record says why.
_gpcr, _gexit = cassian_engine._PrecheckRecord(), False
if isinstance(_g0, ast.If):
    _gpcr.enter([], 0.0)
    _gns = {"_pc_guard": _ge[2], "_pcr": _gpcr, "die": cassian_common.die}
    _old = sys.stderr
    sys.stderr = io.StringIO()
    try:
        exec(compile(ast.Module(body=[_g0], type_ignores=[]), "<guard>", "exec"), _gns)
    except SystemExit:
        _gexit = True
        _gpcr.failed(1.0, {})
    finally:
        sys.stderr = _old
check("P-GUARD executed: it dies, and the record reads failed / bgp-intent-without-participants, nothing waited",
      _gexit and _gpcr.summary["outcome"] == "failed" and _gpcr.summary["failure"] == "bgp-intent-without-participants"
      and _gpcr.summary["session_wait"] == [] and _gpcr.summary["settle"] is None, str(_gpcr.summary))

# --- P-RECORD (S30-R9 to S30-R11, S30-R17, S30-R19 to S30-R21, S30-R23 to S30-R25) ----------
_DECL = [{"host": "host1", "mac": "00:11:22:33:44:55", "vni": 10100},
         {"host": "host2", "mac": "00:11:22:33:44:66", "vni": 10100}]


def _rec(topo, present, **kw):
    r = []
    _run(LIVE_BODY, topo, present, rec=r, **kw)
    return r[0]


def _settle(outcome, absent=()):
    return {"kind": "evpn-route-poll", "leaves": ["leaf1", "leaf2"], "declared": _DECL, "k_required": 3,
            "bound_s": 30, "interval_s": 1, "outcome": outcome, "absent_at_last": list(absent)}


def _waits(names, outcomes, leg="frr", bound=30):
    return [{"node": n, "leg": leg, "bound_s": bound, "interval_s": 1, "outcome": o} for n, o in zip(names, outcomes)]


SEEN = []  # every record produced below, for the closed-set check


def _seen(r):
    SEEN.append(r)
    return r


# 1 -- a fabric lab as measured (no participant): the poll accepts.
_r = _seen(_rec(EVPN, ALL, parts=[]))
check("P-RECORD fabric lab, no participant, accepted: summary.precheck as ruled",
      _r.summary == {"entered": True, "not_entered_reason": None, "participants": [], "session_wait": [],
                     "settle": _settle("accepted"), "outcome": "passed", "failure": None}, str(_r.summary))
check("P-RECORD ... and timing.precheck holds the run-variant values (3 attempts, 3 consecutive, 2000 ms)",
      _r.timing == {"duration_ms": 2000, "session_wait": [],
                    "settle": {"elapsed_ms": 2000, "attempts": 3, "final_consecutive": 3}}, str(_r.timing))
# 2 -- participants present (the harness's frr nodes): one FRR wait each, attempts reported through `stats`.
_r = _seen(_rec(EVPN, ALL))
_pn = [n["name"] for n in EVPN["nodes"] if n.get("type") == "frr"]
check("P-RECORD with FRR participants: sorted names; one wait each, in the order waited (S30-R23); established, bound 30",
      _r.summary["participants"] == sorted(_pn) and _r.summary["session_wait"] == _waits(_pn, ["established"] * 3)
      and _r.summary["outcome"] == "passed", str(_r.summary))
check("P-RECORD ... each FRR wait's attempts come from wait_for_bgp's `stats` (attempts_reported true)",
      _r.timing["session_wait"] == [{"node": n, "elapsed_ms": 0, "attempts": 1, "attempts_reported": True} for n in _pn],
      str(_r.timing["session_wait"]))
# 3 -- the same outcome reached later: summary.precheck identical, timing.precheck not.
_rl = _seen(_rec(EVPN, _late, parts=[]))
_ra = _seen(_rec(EVPN, ALL, parts=[]))
check("P-RECORD same outcome, different run (P-LATE's fabric): summary.precheck identical, timing.precheck differs",
      _rl.summary == _ra.summary and _rl.timing != _ra.timing
      and _rl.timing["settle"] == {"elapsed_ms": 5000, "attempts": 6, "final_consecutive": 3}, str(_rl.timing))
# 4 -- timeout-absent.
_r = _seen(_rec(EVPN, _never, parts=[]))
check("P-RECORD a route never present: timeout-absent, naming it; failed / evpn-route-timeout",
      _r.summary["settle"] == _settle("timeout-absent", [{"leaf": "leaf2", "host": "host2",
                                                           "mac": "00:11:22:33:44:66", "vni": 10100}])
      and _r.summary["outcome"] == "failed" and _r.summary["failure"] == "evpn-route-timeout"
      and _r.timing["settle"]["attempts"] == 31 and _r.timing["settle"]["final_consecutive"] == 0,
      "%s | %s" % (_r.summary, _r.timing))
# 5 -- timeout-unstable.
_r = _seen(_rec(EVPN, _unstable, parts=[]))
check("P-RECORD present at the last attempt, never 3 in a row: timeout-unstable, nothing absent; evpn-route-timeout",
      _r.summary["settle"] == _settle("timeout-unstable") and _r.summary["failure"] == "evpn-route-timeout"
      and _r.timing["settle"]["final_consecutive"] == 2, "%s | %s" % (_r.summary, _r.timing))
# 6 -- an FRR session wait that times out: "timeout" because wait_for_bgp reported it (S30-R20).
_r = _seen(_rec(EVPN, ALL, bgp_timeout=("leaf1",)))
check("P-RECORD an FRR session wait reporting a timeout: that wait \"timeout\", no entry after it (S30-R23); session-timeout",
      _r.summary["session_wait"] == _waits(_pn[:2], ["established", "timeout"])
      and _r.summary["settle"] is None and _r.summary["outcome"] == "failed"
      and _r.summary["failure"] == "session-timeout", str(_r.summary))
check("P-RECORD ... and its attempts are recorded although it died (S30-R18)",
      _r.timing["session_wait"][1] == {"node": _pn[1], "elapsed_ms": 31000, "attempts": 2, "attempts_reported": True},
      str(_r.timing["session_wait"]))


# The stub above stands in for wait_for_bgp; the real function's report (S30-R13, S30-R18,
# S30-R20) is driven here with a fake runtime and the fake clock.
class _CP:
    def __init__(self, stdout, returncode=0):
        self.stdout, self.returncode = stdout, returncode


class _RT:
    """`show bgp summary` answers from `states` in turn (the last repeats); EVPN peers established."""

    def __init__(self, states):
        self.states, self.n = list(states), 0

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        if cmd[-1] == "show bgp l2vpn evpn summary json":
            return _CP('{"peers": {"10.0.0.1": {"state": "Established"}}}')
        s = self.states[min(self.n, len(self.states) - 1)]
        self.n += 1
        return _CP("Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n"
                   "10.0.0.1 4 65002 10 10 0 0 0 00:01:00 %s 0 N/A\n" % s)


def _wfb(states, timeout, stats, require_evpn=False):
    clock = _Clock()
    saved = (time.time, time.sleep)
    time.time, time.sleep = clock.time, clock.sleep
    old, sys.stderr = sys.stderr, io.StringIO()
    try:
        return cassian_tests.wait_for_bgp(_RT(states), "lab", "r1", timeout=timeout, require_evpn=require_evpn,
                                          **({} if stats is None else {"stats": stats})), False
    except SystemExit:
        return None, True
    finally:
        sys.stderr = old
        time.time, time.sleep = saved


_st = {}
check("P-RECORD wait_for_bgp (the real function): returns its attempt count and reports it through `stats`",
      _wfb(["Idle", "Active", "5"], 30, _st) == (3, False) and _st == {"attempts": 3}, str(_st))
_st = {}
check("P-RECORD wait_for_bgp (the real function): on its timeout, `stats` holds the attempts and timed_out, then it dies",
      _wfb(["Idle"], 2, _st) == (None, True) and _st == {"attempts": 4, "timed_out": True}, str(_st))
check("P-RECORD wait_for_bgp (the real function): without `stats`, unchanged for its other caller (EVPN leg too)",
      _wfb(["Idle", "Established"], 30, None, require_evpn=True) == (2, False))


class _Prov:
    """A provider leg: `convergence_wait` waits 3 s on the fake clock, then returns or dies with `msg`."""

    def __init__(self, msg=None):
        self.msg = msg

    def convergence_wait(self, rt, lab, node, timeout, peer_ips):
        time.sleep(3)
        if self.msg is not None:
            cassian_common.die(self.msg)


_SV = [{"name": "s1", "type": "sonic-vm"}]
_r = _seen(_rec(_ne, ALL, parts=_SV, providers={"sonic-vm": _Prov()}))
check("P-RECORD a provider-driven wait: its leg, established; elapsed measured, attempts null, not reported (S30-R11)",
      _r.summary["session_wait"] == _waits(["s1"], ["established"], leg="sonic-vm")
      and _r.timing["session_wait"] == [{"node": "s1", "elapsed_ms": 3000, "attempts": None, "attempts_reported": False}],
      "%s | %s" % (_r.summary["session_wait"], _r.timing["session_wait"]))
_r = _seen(_rec(_ne, ALL, parts=_SV, providers={"sonic-vm": _Prov("s1: BGP did not converge within 30s")}))
check("P-RECORD a provider wait that dies -- even with timeout words in its message: \"failed\" / session-failed (no parsing)",
      _r.summary["session_wait"] == _waits(["s1"], ["failed"], leg="sonic-vm")
      and _r.summary["failure"] == "session-failed" and _r.summary["outcome"] == "failed"
      and _r.timing["session_wait"][0]["attempts"] is None, str(_r.summary))
# 7 -- the fail-closed refusal before any read.
_r = _seen(_rec(_resolved(EVPN_FIXTURE, strip_hosts=True), ALL, parts=[]))
check("P-RECORD no declared host: failed / evpn-declaration-incomplete, no settle record",
      _r.summary["outcome"] == "failed" and _r.summary["failure"] == "evpn-declaration-incomplete"
      and _r.summary["settle"] is None, str(_r.summary))
# 8 -- the fixed sleep (non-EVPN, replay or not).
_r = _seen(_rec(_ne, ALL))
_rr = _seen(_rec(_rpn, ALL))
check("P-RECORD a non-EVPN lab: settle fixed-sleep 5 s, passed; its elapsed in timing.precheck",
      _r.summary["settle"] == {"kind": "fixed-sleep", "seconds": 5} and _r.summary["outcome"] == "passed"
      and _r.timing["settle"] == {"elapsed_ms": 5000} and _rr.summary["settle"] == {"kind": "fixed-sleep", "seconds": 5},
      "%s | %s" % (_r.summary["settle"], _r.timing))
# 9 -- not reached, not entered (S30-R17, S30-R21).
_res = {"summary": {"started_at": 1.0}}
_nr = cassian_engine._PrecheckRecord()
_nr.attach(_res)
_nrs = dict(_res["summary"]["precheck"])
SEEN.append(_nr)
check("P-RECORD before the decision: \"not-reached\", not entered, and no timing.precheck",
      _nrs == {"entered": False, "not_entered_reason": "not-reached", "participants": [], "session_wait": [],
               "settle": None, "outcome": "not-entered", "failure": None} and "timing" not in _res, str(_res))
_ne_rec = cassian_engine._PrecheckRecord()
_ne_rec.attach(_res)
_ne_rec.not_entered("no-bgp-intent")
SEEN.append(_ne_rec)
check("P-RECORD not entered: the reason in summary.precheck (the same object results carries), still no timing.precheck",
      _res["summary"]["precheck"]["not_entered_reason"] == "no-bgp-intent"
      and _res["summary"]["precheck"]["outcome"] == "not-entered" and "timing" not in _res, str(_res))
_en = cassian_engine._PrecheckRecord()
_res2 = {"summary": {}}
_en.attach(_res2)
_en.enter([], 0.0)
_en.attach(_res2)
check("P-RECORD entered: attach places timing.precheck beside summary.precheck",
      _res2["timing"]["precheck"] is _en.timing and _res2["summary"]["precheck"] is _en.summary, str(_res2))
# 10 -- the enumerated values form the ruled set, and every ruled value is reached above.
RULED = {
    "not_entered_reason": {None, "not-selected", "no-bgp-intent", "not-reached"},
    "session_wait.outcome": {"established", "timeout", "failed"},
    "settle.kind": {"evpn-route-poll", "fixed-sleep"},
    "settle.outcome": {"accepted", "timeout-absent", "timeout-unstable"},
    "outcome": {"passed", "failed", "not-entered"},
    "failure": {None, "bgp-intent-without-participants", "session-timeout", "session-failed",
                "evpn-route-timeout", "evpn-declaration-incomplete"},
}
_got = {k: set() for k in RULED}
for _x in SEEN + [_gpcr]:
    _s = _x.summary
    _got["not_entered_reason"].add(_s["not_entered_reason"])
    _got["outcome"].add(_s["outcome"])
    _got["failure"].add(_s["failure"])
    _got["session_wait.outcome"].update(w["outcome"] for w in _s["session_wait"])
    if _s["settle"] is not None:
        _got["settle.kind"].add(_s["settle"]["kind"])
        if "outcome" in _s["settle"]:
            _got["settle.outcome"].add(_s["settle"]["outcome"])
_got["not_entered_reason"].add(cassian_engine._precheck_entry({"nodes": []}, [], False)[1])
check("P-RECORD every value recorded above is a ruled value, and every ruled value is recorded above",
      _got == RULED, str({k: sorted(map(str, _got[k] ^ RULED[k])) for k in RULED if _got[k] != RULED[k]}))
# The literal values the record and the entry decision can write: none outside the ruled set.
_lit = set()
for _top in [n for n in _tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
             and n.name in ("_PrecheckRecord", "_precheck_entry")]:
    _par = {}
    for _a in ast.walk(_top):
        for _c in ast.iter_child_nodes(_a):
            _par[_c] = _a
    for _c in ast.walk(_top):
        if not (isinstance(_c, ast.Constant) and isinstance(_c.value, str)):
            continue
        _pp = _par.get(_c)
        if isinstance(_pp, ast.Expr):                                         # a docstring
            continue
        if isinstance(_pp, ast.Dict) and any(_c is _k for _k in _pp.keys):   # a key
            continue
        if isinstance(_pp, ast.Subscript) and _pp.slice is _c:               # a key read or written
            continue
        if isinstance(_pp, ast.Call) and isinstance(_pp.func, ast.Attribute) and _pp.func.attr in ("get", "setdefault"):
            continue
        if isinstance(_pp, ast.Attribute):                                    # ", ".join
            continue
        if isinstance(_pp, ast.arg):                                          # an annotation
            continue
        if isinstance(_pp, ast.BoolOp) and _c.value == "":                    # `or ""`, a name's fallback
            continue
        if isinstance(_pp, ast.Compare) and _pp.left is _c and isinstance(_pp.ops[0], ast.In):  # "asn" in n
            continue
        _lit.add(_c.value)
_vocab = set().union(*[{v for v in s if v is not None} for s in RULED.values()]) | {"frr"}
_fl = {a.value.args[0].value for a in ast.walk(_cmd_test) if _is_call(a, "_pcr.failing")} if _cmd_test else set()
check("P-RECORD the literal values in _PrecheckRecord, _precheck_entry and cmd_test's failing() calls are all ruled",
      _lit <= _vocab and _fl <= RULED["failure"] and _fl == {"bgp-intent-without-participants",
                                                              "evpn-declaration-incomplete"},
      "outside: %s failing=%s" % (sorted(_lit - _vocab), sorted(_fl)))
# 11 -- the tamper digest's domain keeps summary.precheck and drops timing.precheck (S30-R10).
_full = _seen(_rec(EVPN, _never, parts=[]))
_dom = cassian_engine._audit_filtered_domain({"summary": {"precheck": _full.summary}, "timing": {"precheck": _full.timing}})
check("P-RECORD the tamper digest's domain keeps summary.precheck whole and drops timing.precheck",
      _dom == {"summary": {"precheck": _full.summary}}, str(_dom)[:200])
# 12 -- where cmd_test attaches and closes the record (AST).
_res_ix = None
_body = _cmd_test.body if _cmd_test is not None else []
for _i, _st in enumerate(_body):
    if (isinstance(_st, (ast.Assign, ast.AnnAssign)) and isinstance(getattr(_st, "value", None), ast.Dict)
            and ast.unparse(_st.targets[0] if isinstance(_st, ast.Assign) else _st.target) == "results"):
        _res_ix = _i
        break
check("P-RECORD the record is created and attached right after `results` is (S30-R17)",
      _res_ix is not None and ast.unparse(_body[_res_ix + 1]) == "_pcr = _PrecheckRecord()"
      and ast.unparse(_body[_res_ix + 2]) == "_pcr.attach(results)",
      "results at stmt %s" % _res_ix)
_dec = [n for n in _body if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "_pc_enter"
        and not isinstance(n.body[0], ast.Try)]
check("P-RECORD the decision is recorded: entered -> enter() and attach(); otherwise not_entered(reason)",
      len(_dec) == 1 and [ast.unparse(s) for s in _dec[0].body] == ["_pcr.enter(bgp_participants, time.time())",
                                                                    "_pcr.attach(results)"]
      and [ast.unparse(s) for s in _dec[0].orelse] == ["_pcr.not_entered(_pc_reason)"],
      ast.unparse(_dec[0])[:200] if _dec else "none")
_h = [h for h in (_gate_try.handlers if _gate_try is not None else [])
      if h.type is not None and ast.unparse(h.type) == "SystemExit"]
check("P-RECORD the precheck's SystemExit handler closes the record first, with the body's _pc_stats",
      len(_h) == 1 and ast.unparse(_h[0].body[0]) == "_pcr.failed(time.time(), _pc_stats)",
      ast.unparse(_h[0].body[0]) if _h else "none")
_ann = [i for i, s in enumerate(_body) if isinstance(s, ast.AnnAssign) and ast.unparse(s.target) == "_pc_stats"]
_gix = [i for i, s in enumerate(_body) if s is _gate_if]
check("P-RECORD `_pc_stats` is bound to {} in cmd_test before the precheck's try (the handler reads it on every exit)",
      len(_ann) == 1 and len(_gix) == 1 and _ann[0] < _gix[0] and ast.unparse(_body[_ann[0]].value) == "{}",
      "ann=%s gate=%s" % (_ann, _gix))
_hw = [n for n in ast.walk(_cmd_test) if isinstance(n, ast.FunctionDef) and n.name == "_gate_write_hard_failure_results"] \
    if _cmd_test is not None else []
_hwb = _hw[0].body if len(_hw) == 1 else []
_hri = [i for i, s in enumerate(_hwb) if isinstance(s, ast.AnnAssign) and ast.unparse(s.target) == "results"]
check("P-RECORD the gate-mode hard-failure writer attaches the \"not-reached\" record right after its `results` (S30-R9, S30-R17, S30-R25)",
      len(_hri) == 1 and ast.unparse(_hwb[_hri[0] + 1]) == "_PrecheckRecord().attach(results)",
      "writers=%d results at %s" % (len(_hw), _hri))
check("P-RECORD the try body closes the record as passed, as its last statement",
      _gate_try is not None and ast.unparse(_gate_try.body[-1]) == "_pcr.passed(time.time())",
      ast.unparse(_gate_try.body[-1]) if _gate_try is not None else "none")

fails =[n for n, ok, _d in checks if not ok]
for n, ok, d in checks:
    print("%s   %s%s" % ("PASS" if ok else "FAIL", n, ("  -- " + d) if (d and not ok) else ""))
print("RESULT: %s -- %d checks, %d failed (S24-R5 EVPN precheck MAC-route poll)"
      % ("GREEN" if not fails else "RED", len(checks), len(fails)))
sys.exit(1 if fails else 0)
