#!/usr/bin/env python3
"""evpn_precheck_mac_poll_proof.py -- §4.5-d, S24-R5 (BL-P2-4.5c-53's named fix).

The hosted differential that founder ruling S24-R5 (2026-10-06) binds, as applied
by S25-R4 (2026-10-08): in `cmd_test`'s global control-plane precheck, an EVPN lab
that is not a replay lab no longer sleeps a fixed 10 s after the BGP-session wait;
it polls, within the existing `precheck_timeout`, for every declared host MAC
route (the resolved `fabric.evpn` host attachments) on every EVPN leaf, through
the product's existing presence read, and fails loud naming what is absent.
Non-EVPN and replay labs stay byte-identical.

Method. Lab-free. The precheck's `try:` body is executed twice from source text,
as a function, against recording stubs and a fake clock:
  BEFORE  the c0fb557 text, frozen below and pinned by sha256 (the oracle never
          changes with the tree);
  AFTER   the same body extracted from the live src/cassian_engine.py between
          two exact anchors.
Topologies come from the committed fixtures through the product's own
`resolve_topology`, round-tripped through YAML as `cassian test` reads them.
`retry_until` is the engine's own (cassian_tests); `die` is cassian_common's.

Sections:
  P-ORACLE   the frozen text is the c0fb557 extraction (sha256 pinned).
  P-PREFIX   the live body equals the frozen one up to its last statement;
             only `time.sleep(post_precheck_sleep)` is replaced, by an
             if/else whose else is that same statement.
  P-NONEVPN  a non-EVPN lab: BEFORE and AFTER traces identical (sleep 5).
  P-REPLAY   an EVPN replay lab (the engine's `{base}-replay-{h8}` name):
             traces identical (timeout 60, sleep 15).
  P-EVPN     an EVPN lab, every route present: AFTER has no fixed sleep and
             reads each leaf x declared MAC once, through
             `_evaluate_invariant_attempt(kind evpn_mac_route_present)`.
  P-LATE     a route absent for three attempts, then present: AFTER returns
             after four attempts, well inside the bound.
  P-TIMEOUT  a route never present: BEFORE proceeds silently after its sleep
             (the defect); AFTER dies at the bound naming lab, leaf, host, MAC
             and VNI, with elapsed time and attempts.
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

Coverage limits (PBE-P2-8): lab-free; the fake clock stands in for wall time;
the stubs stand in for the runtime and for `wait_for_bgp`. This proof does NOT
show that the routes converge in CI or on any host, does NOT exercise the FRR
read itself (the read is the product's existing one, unchanged), and does NOT
show the CI acceptance S24-R5 requires (the EVPN step green on consecutive
attempts, then green x2) -- that is read from CI, not from here.

Reports only; writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import ast
import hashlib
import io
import os
import sys
import time

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

import cassian_common  # noqa: E402  (die)
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

# --- P-PREFIX -------------------------------------------------------------------------------
_prefix = CONTROL_BODY[: -len(LAST)] if CONTROL_BODY.endswith(LAST) else None
_rest = LIVE_BODY[len(_prefix):] if (_prefix is not None and LIVE_BODY.startswith(_prefix)) else ""
check("P-PREFIX the BEFORE body ends with the fixed sleep", _prefix is not None)
check("P-PREFIX the live body equals BEFORE up to that statement, byte for byte",
      _prefix is not None and LIVE_BODY.startswith(_prefix))
check("P-PREFIX the replacement is one if/else whose else is the same statement",
      _rest.count("\nif require_evpn_bgp and not is_replay_lab:\n") == 1
      and _rest.endswith("\nelse:\n    " + LAST)
      and _rest.count(LAST) == 1,
      "replacement tail: %r" % _rest[-60:])


# --- harness --------------------------------------------------------------------------------
def _build(body):
    src = ("def _precheck(topo, rt, lab, bgp_participants, wait_for_bgp, NOS_PROVIDERS,\n"
           "              _expected_peer_ips, time, _evaluate_invariant_attempt, retry_until, die):\n")
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


def _run(body, topo, present):
    """present(attempt, leaf, mac) -> (probe_ok, predicate). Returns (trace, exited, msg, elapsed)."""
    clock = _Clock()
    attempt = {"n": 0, "seen": set()}

    def wait_for_bgp(rt, lab, node, timeout=30, require_evpn=False):
        clock.trace.append(("bgp", node, int(timeout), bool(require_evpn)))

    def _evaluate_invariant_attempt(*, inv_type, t, src):
        key = (src, t["_mac"])
        if key in attempt["seen"]:
            attempt["n"] += 1
            attempt["seen"] = set()
        attempt["seen"].add(key)
        clock.trace.append(("eval", src, t["_mac"], t["_vni_i"], inv_type))
        ok, pred = present(attempt["n"], src, t["_mac"])
        return ok, pred, {}, {}

    parts = [n for n in topo.get("nodes", []) if isinstance(n, dict) and n.get("type") == "frr"]
    fn = _build(body)
    saved = (time.time, time.sleep)
    time.time, time.sleep = clock.time, clock.sleep
    cassian_common.LAST_ERROR_MSG = ""
    exited, start = False, clock.t
    err = io.StringIO()
    try:
        _old = sys.stderr
        sys.stderr = err
        try:
            fn(topo, None, str(topo.get("name")), parts, wait_for_bgp, {}, lambda _n: (),
               time, _evaluate_invariant_attempt, cassian_tests.retry_until, cassian_common.die)
        finally:
            sys.stderr = _old
    except SystemExit:
        exited = True
    finally:
        time.time, time.sleep = saved
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

# --- P-REPLAY -------------------------------------------------------------------------------
_rp = _resolved(EVPN_FIXTURE, name=EVPN["name"] + "-replay-0a1b2c3d")
_b, _bx, _, _ = _run(CONTROL_BODY, _rp, ALL)
_a, _ax, _, _ = _run(LIVE_BODY, _rp, ALL)
check("P-REPLAY BEFORE and AFTER traces identical", _b == _a and not _bx and not _ax, "%s | %s" % (_b, _a))
check("P-REPLAY timeout 60 with EVPN required, then the 15 s sleep, no EVPN read",
      all(e[2] == 60 and e[3] for e in _a if e[0] == "bgp") and _a[-1:] == [("sleep", 15.0)]
      and not any(e[0] == "eval" for e in _a), str(_a))

# --- P-EVPN ---------------------------------------------------------------------------------
_b, _bx, _, _ = _run(CONTROL_BODY, EVPN, ALL)
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, ALL)
check("P-EVPN BEFORE sleeps the fixed 10 s and reads nothing", _b[-1:] == [("sleep", 10.0)]
      and not any(e[0] == "eval" for e in _b), str(_b))
check("P-EVPN AFTER: same BGP waits as BEFORE", [e for e in _a if e[0] == "bgp"] == [e for e in _b if e[0] == "bgp"])
check("P-EVPN AFTER: no fixed sleep at all", not any(e[0] == "sleep" for e in _a), str(_a))
check("P-EVPN AFTER: each leaf x declared MAC read once, kind evpn_mac_route_present, VNI 10100",
      [e for e in _a if e[0] == "eval"] == EXPECT_EVALS, str([e for e in _a if e[0] == "eval"]))
check("P-EVPN AFTER returns without failing", not _ax and _el == 0.0, "exited=%s elapsed=%s" % (_ax, _el))

# --- P-LATE ---------------------------------------------------------------------------------
_late = lambda n, leaf, mac: (True, not (leaf == "leaf2" and mac.endswith(":66") and n < 3))  # noqa: E731
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, _late)
check("P-LATE AFTER returns after 4 attempts, 3 one-second intervals, no failure",
      not _ax and sum(1 for e in _a if e[0] == "eval") == 4 * len(EXPECT_EVALS)
      and [e for e in _a if e[0] == "sleep"] == [("sleep", 1.0)] * 3 and _el == 3.0,
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

# --- P-PRED ---------------------------------------------------------------------------------
_a, _ax, _, _el = _run(LIVE_BODY, EVPN, lambda n, leaf, mac: (False, True))
check("P-PRED a failed probe that reports present counts as present (predicate only, as REQ-WF-6)",
      not _ax and _el == 0.0)
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
_live_if = None
for _n in ast.walk(_tree):
    if (isinstance(_n, ast.If) and isinstance(_n.test, ast.BoolOp)
            and ast.dump(_n.test) == ast.dump(ast.parse("require_evpn_bgp and not is_replay_lab", mode="eval").body)):
        _live_if = _n
        break
check("P-SHAPE the REQ-WF-6 site and the new site are both found",
      _wf is not None and _live_if is not None and len(_calls(_live_if)) == 1)
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

fails = [n for n, ok, _d in checks if not ok]
for n, ok, d in checks:
    print("%s   %s%s" % ("PASS" if ok else "FAIL", n, ("  -- " + d) if (d and not ok) else ""))
print("RESULT: %s -- %d checks, %d failed (S24-R5 EVPN precheck MAC-route poll)"
      % ("GREEN" if not fails else "RED", len(checks), len(fails)))
sys.exit(1 if fails else 0)
