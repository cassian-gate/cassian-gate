#!/usr/bin/env python3
"""S30-R5 readiness packet -- FRR's `nos_ready` leg (BL-P2-4.5c-226).

Founder rulings S31-R10 to S31-R19 (the fourth and fifth session-31 rulings
notes). When a lab comes up, every daemon an FRR node's generated `daemons`
file enables must be listed by `vtysh -c 'show daemons'` within 30 s, polled
every second; otherwise the lab fails as a provision failure naming the node
and the daemons:

    provision: <node>: FRR daemon not running after 30s: <daemon>[, <daemon>]

with two further failures in the same form when the daemons file cannot be
read or enables no daemon (S31-R18). The provider hands the message to core,
whose dispatch renders it through `die` with the hard-failure exit code; the
gate's hard-failure record maps the `provision:` prefix to phase PROVISION.

Legs, each checked in both directions:
  (1) the predicate, lab-free, against a fake runtime and a fake clock: all
      present; one missing until the bound; two missing, named in file order;
      late but within the bound; at the bound; ospfd required when declared
      and only then; vtysh not answering; standard error ignored; the daemons
      file unreadable or enabling nothing; FRR's option keys are not daemons.
  (2) the dispatch, through the real `_provision_nos_providers`: FRR's
      `nos_ready` is wired (S31-R17's counterpart) and reached although FRR's
      `provision` is deferred; nft-fw, with both deferred, is still skipped;
      the failure reaches core as `die` (exit 1, LAST_ERROR_MSG set); an exit
      that is not a readiness message passes through unchanged.
  (3) the gate: `_gate_hard_failure_phase` maps `provision:` to PROVISION
      during deploy and keeps the existing RESOLVE mapping; the gate's
      hard-failure branch uses it; the summary prints the PROVISION lines.
  (4) Docker (S31-R16): the pinned image, started privileged as containerlab
      starts lab containers, with the generated daemons file mounted where a
      lab mounts it. `nos_ready` passes with every enabled daemon running;
      zebra is then killed by its pid file and `nos_ready` fails naming zebra
      within a bound shortened inside this proof only. This leg needs a
      container runtime; it fails rather than skipping.

COVERAGE LIMIT (PBE-P2-8): this proves the leg's behaviour against a fake
runtime and against one bare FRR container. It does NOT prove that every
`cassian up` path reaches the dispatch (`cmd_up` step 5b), nor anything about
a daemon that dies after the check, nor that the wait is recorded (S31-R13
routes the waits to the §4.5-e scope document).
"""
import ast
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, _SRC)

import cassian_common as CM  # noqa: E402
import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402
import cassian_nos_frr as F  # noqa: E402
import cassian_tests as T  # noqa: E402
from cassian_nos_types import NosProvider, deferred_leg, is_deferred  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


NODE = "r1"
GEN = M.gen_frr_daemons(None)
GEN_OSPF = M.gen_frr_daemons({"nodes": [{"name": NODE, "type": "frr", "ospf": {"area": "0.0.0.0"}}]})
ALL_UP = " mgmtd zebra bgpd staticd watchfrr\n"
NOTICES = ("% Can't open configuration file /etc/frr/vtysh.conf due to 'No such file or directory'.\n"
           "Configuration file[/etc/frr/frr.conf] processing failure: 11\n")


class _CP:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class _FakeRuntime:
    """Serves the daemons file and a scripted sequence of `show daemons`
    answers (the last answer repeats). Records every argv."""

    def __init__(self, daemons=GEN, answers=(_CP(0, ALL_UP),), daemons_rc=0):
        self.calls = []
        self._daemons = _CP(daemons_rc, daemons if daemons_rc == 0 else "",
                            "" if daemons_rc == 0 else "cat: /etc/frr/daemons: No such file")
        self._answers = list(answers)
        self.polls = 0

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        if list(argv) == list(F._DAEMONS_READ_ARGV):
            return self._daemons
        if list(argv) == list(F._SHOW_DAEMONS_ARGV):
            cp = self._answers[min(self.polls, len(self._answers) - 1)]
            self.polls += 1
            return cp
        raise AssertionError("unexpected argv %r" % (argv,))


class _FakeTime:
    """A clock the leg's sleeps advance; nothing waits for real."""

    def __init__(self):
        self.now = 1000.0
        self.slept = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.now += s
        self.slept += s


@contextlib.contextmanager
def _fake_clock():
    real = F.time
    clock = _FakeTime()
    F.time = clock
    try:
        yield clock
    finally:
        F.time = real


def _run(rt):
    """Run F.nos_ready under the fake clock: (exit code or None, clock)."""
    with _fake_clock() as clock:
        try:
            F.nos_ready(rt, "lab", NODE)
        except SystemExit as exc:
            return exc.code, clock
    return None, clock


def _without(name):
    return _CP(0, " " + " ".join(d for d in ALL_UP.split() if d != name) + "\n")


def _msg(detail):
    return "provision: %s: %s" % (NODE, detail)


BOUND = F.NOS_READY_BOUND_S

# --- leg 1: the predicate --------------------------------------------------------

check("(1) S31-R10's bound and poll interval: 30 s, every 1 s",
      (F.NOS_READY_BOUND_S, F.NOS_READY_POLL_S) == (30, 1),
      "bound=%r poll=%r" % (F.NOS_READY_BOUND_S, F.NOS_READY_POLL_S))
check("(1) the generated daemons file enables exactly zebra and bgpd",
      F.enabled_daemons(GEN) == ("zebra", "bgpd"), repr(F.enabled_daemons(GEN)))
check("(1) with OSPF declared, it enables zebra, bgpd and ospfd",
      F.enabled_daemons(GEN_OSPF) == ("zebra", "bgpd", "ospfd"), repr(F.enabled_daemons(GEN_OSPF)))

rt = _FakeRuntime()
code, clock = _run(rt)
check("(1a) all present: passes at the first poll, no wait", code is None and rt.polls == 1
      and clock.slept == 0, "code=%r polls=%d slept=%r" % (code, rt.polls, clock.slept))
check("(1a) it reads the mounted daemons file, then asks vtysh",
      rt.calls == [list(F._DAEMONS_READ_ARGV), list(F._SHOW_DAEMONS_ARGV)]
      and F._DAEMONS_READ_ARGV == ("cat", "/etc/frr/daemons")
      and F._SHOW_DAEMONS_ARGV == ("vtysh", "-c", "show daemons"), repr(rt.calls))

rt = _FakeRuntime(answers=(_without("zebra"),))
code, clock = _run(rt)
check("(1b) zebra missing until the bound: fails naming zebra, S31-R12's message",
      code == _msg("FRR daemon not running after 30s: zebra"), repr(code))
check("(1b) it polled every second for the whole bound (31 reads, 30 s)",
      rt.polls == BOUND + 1 and clock.slept == BOUND, "polls=%d slept=%r" % (rt.polls, clock.slept))

rt = _FakeRuntime(answers=(_CP(0, " mgmtd staticd watchfrr\n"),))
code, _ = _run(rt)
check("(1c) two missing: both named, in the daemons file's order",
      code == _msg("FRR daemon not running after 30s: zebra, bgpd"), repr(code))

rt = _FakeRuntime(answers=[_without("zebra")] * 5 + [_CP(0, ALL_UP)])
code, clock = _run(rt)
check("(1d) late but within the bound (listed at +5 s): passes",
      code is None and rt.polls == 6 and clock.slept == 5, "code=%r polls=%d" % (code, rt.polls))

rt = _FakeRuntime(answers=[_without("zebra")] * BOUND + [_CP(0, ALL_UP)])
code, clock = _run(rt)
check("(1e) listed exactly at the bound (+30 s): passes",
      code is None and rt.polls == BOUND + 1, "code=%r polls=%d" % (code, rt.polls))
rt = _FakeRuntime(answers=[_without("zebra")] * (BOUND + 1) + [_CP(0, ALL_UP)])
code, _ = _run(rt)
check("(1e) listed one poll after the bound: fails (control)",
      code == _msg("FRR daemon not running after 30s: zebra"), repr(code))

rt = _FakeRuntime(daemons=GEN_OSPF, answers=(_CP(0, ALL_UP),))
code, _ = _run(rt)
check("(1f) OSPF declared, ospfd not running: fails naming ospfd",
      code == _msg("FRR daemon not running after 30s: ospfd"), repr(code))
rt = _FakeRuntime(daemons=GEN_OSPF, answers=(_CP(0, " mgmtd zebra bgpd ospfd staticd watchfrr\n"),))
code, _ = _run(rt)
check("(1f) OSPF declared, ospfd running: passes", code is None, repr(code))
rt = _FakeRuntime(daemons=GEN, answers=(_CP(0, ALL_UP),))
code, _ = _run(rt)
check("(1f) OSPF not declared: ospfd not required", code is None, repr(code))

rt = _FakeRuntime(answers=[_CP(1, "")] * 3 + [_CP(0, ALL_UP)])
code, _ = _run(rt)
check("(1g) vtysh not answering counts as nothing listed, then passes once it answers",
      code is None and rt.polls == 4, "code=%r polls=%d" % (code, rt.polls))
rt = _FakeRuntime(answers=(_CP(1, ALL_UP),))
code, _ = _run(rt)
check("(1g) a non-zero vtysh exit is never read as a list, even with output",
      code == _msg("FRR daemon not running after 30s: zebra, bgpd"), repr(code))

rt = _FakeRuntime(answers=(_CP(0, ALL_UP, NOTICES),))
code, _ = _run(rt)
check("(1h) vtysh's notices on standard error do not matter", code is None, repr(code))
rt = _FakeRuntime(answers=(_CP(0, " mgmtd staticd watchfrr\n", "zebra bgpd\n"),))
code, _ = _run(rt)
check("(1h) daemon names on standard error are not read as listed",
      code == _msg("FRR daemon not running after 30s: zebra, bgpd"), repr(code))

rt = _FakeRuntime(daemons_rc=1)
code, _ = _run(rt)
check("(1i) S31-R18: daemons file unreadable -> its message, and vtysh is not asked",
      code == _msg("FRR daemons file not readable: /etc/frr/daemons") and rt.polls == 0, repr(code))
rt = _FakeRuntime(daemons=GEN.replace("=yes", "=no"))
code, _ = _run(rt)
check("(1i) S31-R18: no daemon enabled -> its message, and vtysh is not asked",
      code == _msg("no FRR daemon enabled in /etc/frr/daemons") and rt.polls == 0, repr(code))
check("(1j) S31-R18: option keys are not daemons; duplicates count once",
      F.enabled_daemons("vtysh_enable=yes\nzebra=yes\nzebra_options=\"-A 127.0.0.1\"\n"
                        "# bgpd=yes\nzebra=yes\nBGPD=yes\n bgpd=yes \n") == ("zebra", "bgpd"),
      repr(F.enabled_daemons("vtysh_enable=yes\nzebra=yes\n")))

# --- leg 2: the dispatch ---------------------------------------------------------

check("(2a) FRR's nos_ready is wired, not a placeholder (S31-R17's counterpart)",
      not is_deferred(F.FRR_PROVIDER.nos_ready) and F.FRR_PROVIDER.nos_ready is F.nos_ready)
check("(2a) FRR's provision is still deferred, so this leg exercises the new dispatch",
      is_deferred(F.FRR_PROVIDER.provision))
check("(2a) the registry serves this provider for type frr", E.NOS_PROVIDERS.get("frr") is F.FRR_PROVIDER)


def _dispatch(rt, node_type, quiet=True):
    """Run the real _provision_nos_providers for one node: (exit code or None,
    stderr text, LAST_ERROR_MSG after)."""
    err = io.StringIO()
    old_q, old_last = CM.QUIET_RUN, CM.LAST_ERROR_MSG
    CM.QUIET_RUN = quiet
    CM.LAST_ERROR_MSG = "untouched"
    code = None
    try:
        with _fake_clock(), contextlib.redirect_stderr(err):
            try:
                E._provision_nos_providers(rt, "lab", {"nodes": [{"name": NODE, "type": node_type}]})
            except SystemExit as exc:
                code = exc.code
        return code, err.getvalue(), CM.LAST_ERROR_MSG
    finally:
        CM.QUIET_RUN, CM.LAST_ERROR_MSG = old_q, old_last


rt = _FakeRuntime()
code, err, last = _dispatch(rt, "frr")
check("(2b) an FRR node is dispatched for nos_ready although provision is deferred",
      code is None and rt.calls == [list(F._DAEMONS_READ_ARGV), list(F._SHOW_DAEMONS_ARGV)],
      "code=%r calls=%r" % (code, rt.calls))
check("(2b) and provision is not reached (its placeholder would exit 2)", code is None, repr(code))

rt = _FakeRuntime()
code, err, last = _dispatch(rt, "nft-fw")
check("(2c) nft-fw, both legs deferred, is still skipped: nothing runs",
      code is None and rt.calls == [], "code=%r calls=%r" % (code, rt.calls))

rt = _FakeRuntime(answers=(_without("zebra"),))
code, err, last = _dispatch(rt, "frr")
_want = _msg("FRR daemon not running after 30s: zebra")
check("(2d) the failure reaches core as die: exit 1, the hard-failure band (CLI reference §6)",
      code == 1, repr(code))
check("(2d) die records the message for the gate's hard-failure record",
      last == _want, repr(last))
check("(2d) die renders it once, with core's ERROR: prefix",
      err.count("ERROR: " + _want) == 1 and err.count(_want) == 1, repr(err[-200:]))


def _fake_provider(leg):
    return NosProvider(
        node_type="proof-fake-nos", default_image=None, runtime_requirement=None, capabilities={},
        gen_node_config=deferred_leg("gen_node_config", "proof fake"),
        provision=deferred_leg("provision", "proof fake"), nos_ready=leg,
        convergence_wait=deferred_leg("convergence_wait", "proof fake"),
        collect=deferred_leg("collect", "proof fake"), candidate=None, status_bgp_summary=None,
        status_routes=None, collect_targets=(),
        doctor_checks=deferred_leg("doctor_checks", "proof fake"),
        exec_command_rule=deferred_leg("exec_command_rule", "proof fake"),
        exec_allowed_forms="proof fake", state_profiles={},
        state_argv_allow=deferred_leg("state_argv_allow", "proof fake"))


for _label, _exit, _want_code in (("SystemExit(2), SONiC's idiom", 2, 2),
                                  ("a message without the provision: prefix", "other: x", "other: x")):
    def _leg(rt, lab, node, _e=_exit):
        raise SystemExit(_e)
    real = E.NOS_PROVIDERS
    try:
        E.NOS_PROVIDERS = {"proof-fake-nos": _fake_provider(_leg)}
        code, err, last = _dispatch(_FakeRuntime(), "proof-fake-nos")
    finally:
        E.NOS_PROVIDERS = real
    check("(2e) %s passes through unchanged, and nothing is recorded" % _label,
          code == _want_code and last == "untouched" and "ERROR:" not in err,
          "code=%r last=%r" % (code, last))

# --- leg 3: the gate's phase -----------------------------------------------------

_P = E._gate_hard_failure_phase
for gp, msg, want in (("deploy", "provision: r1: FRR daemon not running after 30s: zebra", "provision"),
                      ("deploy", "provision: r1: FRR daemons file not readable: /etc/frr/daemons", "provision"),
                      ("deploy", "coverage: invariant x", "resolve"),
                      ("deploy", "schema: bad", "resolve"),
                      ("deploy", "invalid yaml: x", "resolve"),
                      ("deploy", "topology invalid: x", "resolve"),
                      ("deploy", "containerlab deploy failed", "deploy"),
                      ("deploy", "", "deploy"),
                      (" Deploy ", "Provision: r1: x", "provision"),
                      ("test", "provision: r1: x", "test"),
                      ("test", "coverage: x", "test")):
    check("(3a) phase(%r, %r) is %r" % (gp, msg[:28], want), _P(gp, msg) == want, repr(_P(gp, msg)))

_eng = io.open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8").read()
_cmd_test = next((n for n in ast.walk(ast.parse(_eng))
                  if isinstance(n, ast.FunctionDef) and n.name == "cmd_test"), None)
_uses = [n for n in ast.walk(_cmd_test) if isinstance(n, ast.Assign)
         and ast.unparse(n) == "phase_report = _gate_hard_failure_phase(gate_phase, err_msg)"] if _cmd_test else []
_writes = [n for n in ast.walk(_cmd_test) if isinstance(n, ast.Call)
           and ast.unparse(n.func) == "_gate_write_hard_failure_results"
           and any(k.arg == "phase" and ast.unparse(k.value) == "str(phase_report)" for k in n.keywords)] if _cmd_test else []
check("(3b) the gate's hard-failure branch takes its phase from _gate_hard_failure_phase",
      len(_uses) == 1 and len(_writes) == 1, "uses=%d writes=%d" % (len(_uses), len(_writes)))
check("(3b) no second, inline copy of the mapping is left in cmd_test",
      not [n for n in ast.walk(_cmd_test) if isinstance(n, ast.Call)
           and ast.unparse(n) == "em.startswith('coverage:')"] if _cmd_test else False)

_block = T.render_gate_result_block({
    "result": "fail", "tests": [], "scenarios": [], "events": [],
    "hard_failure": {"occurred": True, "phase": "provision", "error": "ERROR: " + _want},
    "summary": {"total": 0, "passed": 0, "failed": 0}})
check("(3c) the summary prints the PROVISION phase, the reason and what was skipped",
      "Failure phase: PROVISION\nReason: %s\nExecution: resolve+generate+deploy succeeded; "
      "provision failed (test skipped)\n" % _want in _block, _block[-300:])

# --- leg 4: Docker ---------------------------------------------------------------

_LAB, _NODE = "frrnosreadyproof", "r1"
_CN = "clab-%s-%s" % (_LAB, _NODE)
if shutil.which("docker") is None:
    check("(4) Docker leg: docker not found. This leg needs a container runtime; "
          "it fails rather than skipping.", False)
else:
    from cassian_runtime_container import get_runtime  # noqa: E402
    _tmp = tempfile.mkdtemp(prefix="frr-nos-ready-")
    _daemons = os.path.join(_tmp, "daemons")
    with open(_daemons, "w", encoding="utf-8") as fh:
        fh.write(GEN)
    os.chmod(_tmp, 0o755)
    os.chmod(_daemons, 0o644)
    subprocess.run(["docker", "rm", "-f", _CN], capture_output=True, text=True)
    _old_q, _old_bound = CM.QUIET_RUN, F.NOS_READY_BOUND_S
    try:
        _up = subprocess.run(
            ["docker", "run", "-d", "--privileged", "--name", _CN,
             "-v", "%s:/etc/frr/daemons:ro" % _daemons, F.FRR_DEFAULT_IMAGE],
            capture_output=True, text=True)
        check("(4) the pinned image started privileged, the generated daemons file mounted "
              "(rc=%d) %s" % (_up.returncode, _up.stderr.strip()[:160]), _up.returncode == 0)
        if _up.returncode == 0:
            CM.QUIET_RUN = True
            _rt = get_runtime(None)
            _t0 = time.monotonic()
            _code = None
            try:
                F.nos_ready(_rt, _LAB, _NODE)
            except SystemExit as exc:
                _code = exc.code
            check("(4a) every enabled daemon running: nos_ready passes (30 s bound)",
                  _code is None, "exit=%r after %.1fs" % (_code, time.monotonic() - _t0))
            _kill = subprocess.run(
                ["docker", "exec", _CN, "sh", "-c", "kill -9 $(cat /var/run/frr/zebra.pid)"],
                capture_output=True, text=True)
            check("(4b) zebra killed by its pid file (rc=%d) %s" % (_kill.returncode, _kill.stderr.strip()[:120]),
                  _kill.returncode == 0)
            F.NOS_READY_BOUND_S = 3   # shortened inside this proof only (S31-R15, S31-R16)
            _t0 = time.monotonic()
            _code = None
            try:
                F.nos_ready(_rt, _LAB, _NODE)
            except SystemExit as exc:
                _code = exc.code
            _el = time.monotonic() - _t0
            check("(4c) zebra dead: nos_ready fails naming zebra, and only zebra",
                  _code == "provision: %s: FRR daemon not running after 3s: zebra" % _NODE, repr(_code))
            check("(4c) it failed at the shortened bound, well inside watchfrr's 60 s restart",
                  3 <= _el < 30, "%.1fs" % _el)
    finally:
        CM.QUIET_RUN, F.NOS_READY_BOUND_S = _old_q, _old_bound
        subprocess.run(["docker", "rm", "-f", _CN], capture_output=True, text=True)
        shutil.rmtree(_tmp, ignore_errors=True)

check("(4) the shortened bound is restored", F.NOS_READY_BOUND_S == 30, repr(F.NOS_READY_BOUND_S))

# --- report ----------------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n, ("  [%s]" % _d) if (_d and not _ok) else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d of %d check(s) (S30-R5 FRR nos_ready)" % (len(_failed), len(_checks)))
    sys.exit(1)
print("RESULT: PASS -- %d checks (S30-R5 FRR nos_ready)" % len(_checks))
