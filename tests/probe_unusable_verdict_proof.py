#!/usr/bin/env python3
"""probe_unusable_verdict_proof.py -- HS-7, Stage-1 gap item (d)(2), `cassian checks`.

WI-13 (finding F-S1D2-C3-5; founder rulings of 2026-10-27: WI-13 D1 to D8, recorded in the
second session-1 rulings note, and the D3 amendment (a), recorded in the third) -- PO-30.
WI-14 (findings F-S1D2-C3-6 and F-S1D2-C3-10; founder rulings E1 to E6 of 2026-10-27, recorded in
the third session-1 rulings note, and ruling 1, recorded in the fourth) -- PO-31, below.

PO-30. A dataplane probe that cannot run is never read as the network's answer. On the ping
and tcp test paths and in scenario wait_for, a probe fails whatever `expect` says when:
  * a precondition fails -- the source node is not running; the tool is absent
    (`command -v` exits 1 or 127); `command -v` cannot run at all (any other exit, e.g. 255
    when ssh to a sonic-vm guest fails); a declared src_if is not an interface of the node;
    a declared src_ip is not one of its addresses; or
  * after a non-zero probe, the exit status is outside the tool's range (ping 0/1/2,
    nc 0/1), or the node stopped during the probe.
A network answer (reply, no reply, no route) keeps its four-quadrant verdict, unchanged.

Legs:
  O  ORACLE     each WI-13 site (run_ping_test, run_tcp_test, wait_for_predicate) is the live
                function with exactly the WI-13 edits reversed, and the reversal reproduces the
                cassian-gate@02669cd extraction byte for byte (sha256 pinned). The WI-13 edits
                are therefore the only change at these sites.
  V  VERDICT    the live run_ping_test and run_tcp_test, executed from their source text in the
                engine's namespace against a mock runtime, for every probe outcome x expect:
                each verdict, error text and `probe_unusable` evidence key is as ruled.
  W  WAIT       the live wait_for_predicate's ping and tcp branches: a broken probe raises
                "wait_for <kind>: probe unusable: <reason>" for both expects; a network answer
                does not raise and keeps its verdict.
                V and W also check every reason text as ruled (D3 as amended by (a)): the
                last non-empty stderr line is quoted, not the first, so a sonic-vm guest's ssh
                transport lines (written before the command's own) are never quoted as the cause.
  D  DETECTION  the 02669cd forms (the O-leg oracles) run on the same cases: a broken probe
                under expect: fail PASSES on both paths. The defect PO-30 closes is reproduced,
                so V and W are not vacuous.
  K  DOCKER     the preconditions on the container images Cassian runs (the frr default image,
                and the host and nft-fw images), each command in a throwaway container
                (--rm --pull never --network none): the live helpers return no reason for a
                healthy probe, the ruled reason for a missing tool, a missing src_if and a
                non-local src_ip, and no reason for an in-range network answer. An absent
                docker or image is a FAIL, never a skip.

PO-31. An exec whose output was not judged fails whatever `expect` says: the call raised; the
command exited non-zero; or, on exit 0, the assertion could not be evaluated (output not JSON, a
missing path, an ordering on a non-number). An answer whose assertion evaluated keeps its
four-quadrant verdict; a backend that reports no exit status is judged on its output.
  O  ORACLE     also run_exec_test: the live function with exactly the WI-14 edits reversed is
                its cassian-gate@02669cd extraction (sha256 pinned).
  X  EXEC       the live run_exec_test against a mock runtime, for seventeen outcomes (M1 to
                M17, from the measurements of 2026-10-27) x expect: each verdict, error text,
                `exec_unusable` evidence key and `stderr_excerpt` (present exactly when the output
                was not judged) as ruled.
  E  DETECTION  the 02669cd form passes the five F-S1D2-C3-6 false passes, the F-S1D2-C3-10
                unevaluable assertions under expect: fail, and the two absent-object reads that
                are now failed loudly; every judged answer keeps its 02669cd verdict.
  R  RENDER     DC v2.1 section 13(b)(c) (rulings note 3 section 4, E4): a failed exec renders
                identity, expectation and observed state through the real
                cassian_tests._format_test_summary, with stderr_excerpt exactly when the output
                was not judged.

COVERAGE LIMIT (sonic-vm). The guest path is not exercised here: no lab run (founder ruling
D4). It was measured on 2026-10-27 on a live sonic-vm guest (SONiC 202405.1033627-fecd4ec81,
lab s1d2-c3-measure on ai-netsim): every precondition and exit code as ruled, nc absent from
the guest. The VM CI steps run ping from a sonic-vm source (sonic-mixed-linux) through the
same helpers.

Each leg runs on its own: a leg that raises is a FAIL ("<leg> leg ran to completion") and the
other legs still run and report.

Exit 0 on all-pass; exit 1 on any failure.
"""
import ast
import hashlib
import os
import subprocess
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

import cassian_common as C  # noqa: E402

C._QUIET_DIE = True
import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402

checks = []


def check(name, cond, detail=""):
    checks.append((name, bool(cond), detail))


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def leg(label, fn):
    """Run one leg. A leg that raises records a FAIL and every other leg still runs and reports,
    so a regressed engine shows which checks fail, not a traceback."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- recorded as a failed check, never swallowed
        check("%s leg ran to completion" % label, False, "%s: %s" % (type(exc).__name__, exc))


CP = subprocess.CompletedProcess

# ------------------------------------------------------------------- O: oracle
# sha256 of each site's 02669cd extraction (AST line span, textwrap.dedent'ed).
ORACLE_SHA256 = {
    "run_ping_test": "8e8a903395e13533cff2261d4793c91fe00f0f70cb46ac28d93799147bdf7560",
    "run_tcp_test": "530526104b971e70bf3c4b1bc5384aaf785272f39ed616af1d5a4d17f513e0da",
    "wait_for_predicate": "a449ade439eda82b43d943085b6071ad5759a2eecbb493d2544d69a65932efaf",
}
# The WI-13 edits, as (02669cd text, WI-13 text) pairs at the engine's own indentation.
WI13_EDITS = {
    "run_ping_test": [
        (r'''        if expected == "fail":
            # v1 gate semantics: expected fail is fail-fast (single attempt)
            ok, last_cp = attempt()
            attempts = 1
            dur_ms = 0
        else:
            ok, last_cp, attempts, dur_ms = retry_until(retry_timeout_s, retry_interval_s, attempt)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        err = "" if verdict == "pass" else _format_ping_ctx(expected_s=expected, observed_s=observed)
''',
         r'''        # WI-13 (F-S1D2-C3-5): a probe that cannot run is not the network's answer.
        _unusable = _probe_unusable(rt, lab, src, "ping", src_if=src_if, src_ip=src_ip)
        if _unusable is not None:
            ok, last_cp, attempts, dur_ms = False, None, 0, 0
        elif expected == "fail":
            # v1 gate semantics: expected fail is fail-fast (single attempt)
            ok, last_cp = attempt()
            attempts = 1
            dur_ms = 0
        else:
            ok, last_cp, attempts, dur_ms = retry_until(retry_timeout_s, retry_interval_s, attempt)
        if _unusable is None and not ok:
            _unusable = _probe_exit_unexplained(rt, lab, src, "ping", last_cp)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed and _unusable is None) else "fail"

        if _unusable is not None:
            err = f"ping probe unusable on {src}: {_unusable}; never read as unreachable"
        else:
            err = "" if verdict == "pass" else _format_ping_ctx(expected_s=expected, observed_s=observed)
'''),
        (r'''            evidence={
                "cmd": "ping",
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
                "dst_ip": str(dst_ip),
            },
''',
         r'''            evidence={
                "cmd": "ping",
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
                "dst_ip": str(dst_ip),
                **({"probe_unusable": _unusable} if _unusable is not None else {}),
            },
'''),
    ],
    "run_tcp_test": [
        (r'''        start = time.time()
        if expected == "pass" and timeout_s > 0:
            ok, last_cp, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        else:
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            ok, last_cp, attempts = (cp.returncode == 0), cp, 1
            dur_ms = int((time.time() - start) * 1000)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"
''',
         r'''        start = time.time()
        # WI-13 (F-S1D2-C3-5): a probe that cannot run is not the network's answer.
        _unusable = _probe_unusable(rt, lab, src, "nc")
        if _unusable is not None:
            ok, last_cp, attempts, dur_ms = False, None, 0, 0
        elif expected == "pass" and timeout_s > 0:
            ok, last_cp, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        else:
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            ok, last_cp, attempts = (cp.returncode == 0), cp, 1
            dur_ms = int((time.time() - start) * 1000)
        if _unusable is None and not ok:
            _unusable = _probe_exit_unexplained(rt, lab, src, "nc", last_cp)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed and _unusable is None) else "fail"
'''),
        (r'''            evidence={"cmd": "nc -z"},
            duration_ms=dur_ms,
            error="" if verdict == "pass" else f"tcp mismatch (expected {expected}, observed {observed})",
''',
         r'''            evidence={"cmd": "nc -z", **({"probe_unusable": _unusable} if _unusable is not None else {})},
            duration_ms=dur_ms,
            error=(f"tcp probe unusable on {src}: {_unusable}; never read as unreachable" if _unusable is not None
                   else ("" if verdict == "pass" else f"tcp mismatch (expected {expected}, observed {observed})")),
'''),
    ],
    "wait_for_predicate": [
        (r'''                cp = rt.exec(lab, str(src).strip(), ping_cmd, check=False)
                last_cp = cp
                ping_ok = (cp.returncode == 0)
''',
         r'''                # WI-13 (F-S1D2-C3-5): a probe that cannot run fails the step, whatever expect says.
                _unusable = _probe_unusable(rt, lab, str(src).strip(), "ping", src_if=src_if, src_ip=src_ip)
                if _unusable is not None:
                    raise ValueError(f"wait_for ping: probe unusable: {_unusable}")
                cp = rt.exec(lab, str(src).strip(), ping_cmd, check=False)
                last_cp = cp
                ping_ok = (cp.returncode == 0)
                if not ping_ok:
                    _unusable = _probe_exit_unexplained(rt, lab, str(src).strip(), "ping", cp)
                    if _unusable is not None:
                        raise ValueError(f"wait_for ping: probe unusable: {_unusable}")
'''),
        (r'''                # Deterministic connect check; attempt timeout is explicit via -w
                cp = rt.exec(
                    lab,
                    str(src).strip(),
                    ["sh", "-lc", f"nc -z -w {per_attempt_timeout_s} {dst_ip} {port_i}"],
                    check=False,
                )
                last_cp = cp
                tcp_ok = (cp.returncode == 0)
''',
         r'''                # WI-13 (F-S1D2-C3-5): a probe that cannot run fails the step, whatever expect says.
                _unusable = _probe_unusable(rt, lab, str(src).strip(), "nc")
                if _unusable is not None:
                    raise ValueError(f"wait_for tcp: probe unusable: {_unusable}")
                # Deterministic connect check; attempt timeout is explicit via -w
                cp = rt.exec(
                    lab,
                    str(src).strip(),
                    ["sh", "-lc", f"nc -z -w {per_attempt_timeout_s} {dst_ip} {port_i}"],
                    check=False,
                )
                last_cp = cp
                tcp_ok = (cp.returncode == 0)
                if not tcp_ok:
                    _unusable = _probe_exit_unexplained(rt, lab, str(src).strip(), "nc", cp)
                    if _unusable is not None:
                        raise ValueError(f"wait_for tcp: probe unusable: {_unusable}")
'''),
    ],
}

ENG_SRC = open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8").read()
_LINES = ENG_SRC.splitlines(keepends=True)
_FN = {n.name: n for n in ast.walk(ast.parse(ENG_SRC)) if isinstance(n, ast.FunctionDef)}


def raw(name):
    n = _FN[name]
    return "".join(_LINES[n.lineno - 1:n.end_lineno])


LIVE, OLD = {}, {}


def _leg_o():
    for _name, _pairs in WI13_EDITS.items():
        _live = raw(_name)
        _old = _live
        _ok = True
        for _before, _after in _pairs:
            _ok = _ok and _old.count(_after) == 1
            _old = _old.replace(_after, _before, 1)
        LIVE[_name] = textwrap.dedent(_live)
        OLD[_name] = textwrap.dedent(_old)
        check("O %s is the 02669cd extraction with exactly the WI-13 edits applied (sha256 pinned)" % _name,
              _ok and sha(OLD[_name]) == ORACLE_SHA256[_name], sha(OLD[_name]))


leg("O", _leg_o)


# ------------------------------------------------------------------- mock runtime
class MockRT:
    """`probe` is the (rc, stdout, stderr) the probe command returns; `running` lists successive
    is_running answers (the last repeats); `tool_rc` is `command -v`'s exit; `if_ok` is
    `ip link show dev`'s; `addrs` is `ip -o addr show`'s stdout; `tool_err` its stderr."""

    def __init__(self, probe, running=(True,), tool_rc=0, tool_err="", if_ok=True, addrs=""):
        self.probe, self.running, self.tool_rc, self.tool_err = probe, list(running), tool_rc, tool_err
        self.if_ok, self.addrs = if_ok, addrs

    def is_running(self, lab, node):
        return self.running[0] if len(self.running) == 1 else self.running.pop(0)

    def exec(self, lab, node, cmd, *, check=False, capture_output=True, interactive=False, timeout_s=None):
        j = " ".join(cmd)
        if cmd[:2] == ["sh", "-c"] and cmd[2].startswith("command -v"):
            return CP(cmd, self.tool_rc, "/usr/bin/tool\n" if self.tool_rc == 0 else "", self.tool_err)
        if "command -v nc >/dev/null" in j:  # ensure_nc (scenario tcp)
            return CP(cmd, 0, "", "")
        if cmd[:3] == ["ip", "link", "show"]:
            return CP(cmd, 0 if self.if_ok else 1, "", "" if self.if_ok else 'Device "x" does not exist.')
        if cmd[:3] == ["ip", "-o", "addr"]:
            return CP(cmd, 0, self.addrs, "")
        rc, out, err = self.probe
        return CP(cmd, rc, out, err)


SONIC_PRE = ("Warning: Permanently added 'clab-lab-s1' (RSA) to the list of known hosts.\n"
             "Debian GNU/Linux 12 \\n \\l\n\n")
ADDRS = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
         "2: eth1    inet 10.0.0.1/30 brd 10.0.0.3 scope global eth1\\       valid_lft forever\n")
# name, mock factory, test extras, verdict wanted for expect pass / expect fail, reason (None: usable)
CASES = [
    ("reply", lambda: MockRT((0, "2 received", "")), {}, ("pass", "fail"), None),
    ("no reply", lambda: MockRT((1, "0 received", "")), {}, ("fail", "pass"), None),
    ("no route (iputils exit 2)", lambda: MockRT((2, "", "ping: connect: Network is unreachable")), {},
     ("fail", "pass"), None),
    ("node not running", lambda: MockRT((1, "", "No such container"), running=(False,)), {},
     ("fail", "fail"), "node 'n1' is not running"),
    ("tool absent (127)", lambda: MockRT((127, "", "sh: tool: not found"), tool_rc=127), {},
     ("fail", "fail"), "%s is not available on node 'n1'"),
    ("tool absent (1)", lambda: MockRT((127, "", ""), tool_rc=1), {}, ("fail", "fail"),
     "%s is not available on node 'n1'"),
    ("shell unreachable (ssh 255)", lambda: MockRT((255, "", ""), tool_rc=255,
                                                    tool_err="ssh: connect to host clab-lab-s1 port 22: Connection refused\n"),
     {}, ("fail", "fail"),
     "cannot run a command on node 'n1' (exited 255: ssh: connect to host clab-lab-s1 port 22: Connection refused)"),
    ("exit outside range (126)", lambda: MockRT((126, "", "OCI runtime exec failed")), {}, ("fail", "fail"),
     "%s exited 126 (OCI runtime exec failed)"),
    ("exit outside range on a guest (127)", lambda: MockRT((127, "", SONIC_PRE + "bash: line 1: x: command not found\n")),
     {}, ("fail", "fail"), "%s exited 127 (bash: line 1: x: command not found)"),
    ("stopped during the probe", lambda: MockRT((1, "", ""), running=(True, False)), {}, ("fail", "fail"),
     "node 'n1' stopped during the probe"),
]
PING_ONLY = [
    ("src_if missing", lambda: MockRT((2, "", "ping: SO_BINDTODEVICE nosuchif0: No such device"), if_ok=False),
     {"src_if": "nosuchif0"}, ("fail", "fail"), "src_if 'nosuchif0' is not an interface of node 'n1'"),
    ("src_if present, no reply", lambda: MockRT((1, "", "")), {"src_if": "eth1"}, ("fail", "pass"), None),
    ("src_ip not local", lambda: MockRT((2, "", "ping: bind: Cannot assign requested address"), addrs=ADDRS),
     {"src_ip": "203.0.113.77"}, ("fail", "fail"), "src_ip '203.0.113.77' is not an address of node 'n1'"),
    ("src_ip local, no reply", lambda: MockRT((1, "", ""), addrs=ADDRS), {"src_ip": "10.0.0.1"}, ("fail", "pass"), None),
]


def _tcp_case(mk):
    """nc has no exit 2: the iputils no-route case maps to nc's own 'no answer' (exit 1)."""
    rt = mk()
    if rt.probe[0] == 2:
        rt.probe = (1, "", rt.probe[2])
    return rt


def ns_with(text, rt, cap):
    ns = dict(E.__dict__)
    ns.update(rt=rt, lab="lab", topo={"nodes": []},
              node_ip_or_die=lambda n: "10.0.0.2", start_listener=lambda d, p: None,
              retry_until=lambda to, iv, fn: (lambda r: (r[0], r[1], 1, 0))(fn()),
              record_test=lambda **kw: cap.update(kw))
    exec(compile(text, "<probe_unusable_verdict_proof>", "exec"), ns)
    return ns


def run_ping(text, rt, extras, expect):
    cap = {}
    ns = ns_with(text, rt, cap)
    t = {"expect": expect, "dst": "10.0.0.2", "timeout_s": 1, **extras}
    ns["run_ping_test"](test_name="t", src="n1", dst="10.0.0.2", t=t, record_fn=lambda **kw: cap.update(kw))
    return cap.get("verdict"), cap  # run_ping_test returns its record; the verdict is the record's


def run_tcp(text, rt, expect):
    cap = {}
    ns = ns_with(text, rt, cap)
    t = {"expect": expect, "port": 80, "listener": False, "timeout_s": 1}
    v = ns["run_tcp_test"](test_name="t", src="n1", dst="n2", t=t, record_fn=lambda **kw: cap.update(kw))
    return v, cap


def run_wait(text, rt, kind, expect, extras=None):
    ns = ns_with(text, rt, {})
    ns["retry_until"] = E.retry_until
    wf = {"type": kind, "from": "n1", "to": "10.0.0.2", "expect": expect, "timeout": 1, "interval_s": 0.05,
          **({"port": 80} if kind == "tcp" else {}), **(extras or {})}
    try:
        res = ns["wait_for_predicate"](wf)
    except ValueError as exc:
        return "raise", str(exc)
    except TypeError:
        # F-S20-2 (observed, not changed): an expect: pass wait that times out raises TypeError
        # in its meta block, in every form; the scenario runner records the step as failed.
        return "verdict", "fail (F-S20-2 timeout)"
    return "verdict", res[5]


def want_reason(reason, tool):
    return None if reason is None else (reason % tool if "%s" in reason else reason)


# ------------------------------------------------------------------- V: verdicts and texts
def _leg_v():
    for name, mk, extras, (want_p, want_f), reason in CASES + PING_ONLY:
        r = want_reason(reason, "ping")
        for expect, want in (("pass", want_p), ("fail", want_f)):
            v, rec = run_ping(LIVE["run_ping_test"], mk(), extras, expect)
            ev = rec.get("evidence", {})
            ok = v == want and rec.get("verdict") == want and ev.get("probe_unusable") == r
            if r is not None:
                ok = ok and rec.get("error") == "ping probe unusable on n1: %s; never read as unreachable" % r
            check("V ping %-36s expect %-4s -> %s%s" % (name, expect, want, "" if r is None else " (unusable)"), ok,
                  "%r %r" % (v, rec.get("error")))
    for name, mk, extras, (want_p, want_f), reason in CASES:
        r = want_reason(reason, "nc")
        for expect, want in (("pass", want_p), ("fail", want_f)):
            v, rec = run_tcp(LIVE["run_tcp_test"], _tcp_case(mk), expect)
            ev = rec.get("evidence", {})
            ok = v == want and rec.get("verdict") == want and ev.get("probe_unusable") == r
            if r is not None:
                ok = ok and rec.get("error") == "tcp probe unusable on n1: %s; never read as unreachable" % r
            check("V tcp  %-36s expect %-4s -> %s%s" % (name, expect, want, "" if r is None else " (unusable)"), ok,
                  "%r %r" % (v, rec.get("error")))


leg("V", _leg_v)


# ------------------------------------------------------------------- W: scenario wait_for
def _leg_w():
    for kind, tool in (("ping", "ping"), ("tcp", "nc")):
        for name, mk, extras, (want_p, want_f), reason in CASES + (PING_ONLY if kind == "ping" else []):
            r = want_reason(reason, tool)
            for expect, want in (("pass", want_p), ("fail", want_f)):
                rt = mk() if kind == "ping" else _tcp_case(mk)
                got = run_wait(LIVE["wait_for_predicate"], rt, kind, expect, extras if kind == "ping" else None)
                if r is None:
                    ok = got == ("verdict", want) or (expect == "pass" and want == "fail"
                                                       and got == ("verdict", "fail (F-S20-2 timeout)"))
                else:
                    ok = got == ("raise", "wait_for %s: probe unusable: %s" % (kind, r))
                check("W wait_for %-4s %-36s expect %-4s -> %s" % (kind, name, expect,
                                                                  "raises" if r is not None else want), ok, repr(got))


leg("W", _leg_w)


# ------------------------------------------------------------------- D: detection
def _leg_d():
    _missed = []
    for name, mk, extras, _w, reason in CASES + PING_ONLY:
        if reason is None:
            continue
        v, _rec = run_ping(OLD["run_ping_test"], mk(), extras, "fail")
        if v != "pass":
            _missed.append("ping " + name)
        if not extras:
            v, _rec = run_tcp(OLD["run_tcp_test"], _tcp_case(mk), "fail")
            if v != "pass":
                _missed.append("tcp " + name)
            for kind in ("ping", "tcp"):
                rt = mk() if kind == "ping" else _tcp_case(mk)
                if run_wait(OLD["wait_for_predicate"], rt, kind, "fail") != ("verdict", "pass"):
                    _missed.append("wait_for %s %s" % (kind, name))
    check("D the 02669cd forms pass every broken probe under expect: fail (test paths and wait_for): "
          "the defect is reproduced, so V and W are not vacuous", not _missed, ", ".join(_missed))


leg("D", _leg_d)


# ------------------------------------------------------------------- K: docker
class DockerRT:
    """Each command in a throwaway container of `image` (no network, no pull)."""

    def __init__(self, image):
        self.image = image

    def is_running(self, lab, node):
        return True

    def exec(self, lab, node, cmd, *, check=False, capture_output=True, interactive=False, timeout_s=None):
        argv = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", cmd[0],
                self.image, *cmd[1:]]
        return subprocess.run(argv, capture_output=True, text=True, timeout=120)


IMAGES = {"frr": M.nos_default_image("frr"), "host": "wbitt/network-multitool:latest",
          "nft-fw": "ghcr.io/cassian-gate/nft-fw:latest"}


def _leg_k():
    try:
        _docker = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                                 capture_output=True, text=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _docker = False
    check("K docker is reachable (a missing docker is a FAIL, not a skip)", _docker)
    for role, image in IMAGES.items():
        present = _docker and subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
        check("K %s image present: %s" % (role, image), present)
        if present:
            leg("K %s" % role, lambda role=role, image=image: _k_image(role, image))


def _k_image(role, image):
    """The K checks on one image (its own leg, so one image that raises does not hide the others)."""
    rt = DockerRT(image)
    for tool in ("ping", "nc"):
        check("K %s: %s probe usable" % (role, tool), E._probe_unusable(rt, "lab", "n1", tool) is None)
    check("K %s: a missing tool is 'not available'" % role,
          E._probe_unusable(rt, "lab", "n1", "nosuchtool-hs7") == "nosuchtool-hs7 is not available on node 'n1'")
    check("K %s: src_if lo usable" % role, E._probe_unusable(rt, "lab", "n1", "ping", src_if="lo") is None)
    check("K %s: src_if nosuchif0 is not an interface" % role,
          E._probe_unusable(rt, "lab", "n1", "ping", src_if="nosuchif0")
          == "src_if 'nosuchif0' is not an interface of node 'n1'")
    check("K %s: src_ip 127.0.0.1 usable" % role, E._probe_unusable(rt, "lab", "n1", "ping", src_ip="127.0.0.1") is None)
    check("K %s: src_ip 203.0.113.77 is not an address" % role,
          E._probe_unusable(rt, "lab", "n1", "ping", src_ip="203.0.113.77")
          == "src_ip '203.0.113.77' is not an address of node 'n1'")
    _cp = rt.exec("lab", "n1", ["ping", "-c", "1", "-W", "1", "192.0.2.1"])
    check("K %s: ping with no route exits inside the range (rc %s) and is a network answer" % (role, _cp.returncode),
          _cp.returncode in (1, 2) and E._probe_exit_unexplained(rt, "lab", "n1", "ping", _cp) is None)
    _cp = rt.exec("lab", "n1", ["sh", "-lc", "nc -z -w 1 127.0.0.1 9"])
    check("K %s: nc to a closed port exits inside the range (rc %s) and is a network answer" % (role, _cp.returncode),
          _cp.returncode == 1 and E._probe_exit_unexplained(rt, "lab", "n1", "nc", _cp) is None)


leg("K", _leg_k)


# =================================================================== PO-31 (WI-14)
# WI-14 (findings F-S1D2-C3-6 and F-S1D2-C3-10; founder rulings E1 to E6 of 2026-10-27, rulings
# note 3, and ruling 1 of rulings note 4): an exec whose output was not judged -- the call
# raised, the command exited non-zero, or the assertion could not be evaluated -- fails
# whatever `expect` says. Exit 0 with an assertion that evaluated keeps its four-quadrant
# verdict; a backend that reports no exit status is judged on its output.
import json  # noqa: E402

import cassian_tests as T  # noqa: E402

ORACLE_SHA256["run_exec_test"] = "f71ebdcc0374f23d25b918e82f2558263fb9a1c3bf18854dcb6966417a659306"
# The WI-14 edits, as (02669cd text, WI-14 text) pairs at the engine's own indentation.
WI14_EDITS = [
    (r'''        verdict = "pass" if observed == expected else "fail"

''',
     r'''        verdict = "pass" if observed == expected else "fail"

        # Stage-1 gap item (d)(2) WI-14 (F-S1D2-C3-6). The command's exit status was ignored, so a
        # command that did not answer (unknown command, stopped daemon, ssh down) left empty or
        # error output that a not_contains, or any expect: fail, read as a pass; an exec that
        # raised (timeout) also passed under expect: fail. Measured 2026-10-27 on every allowed
        # exec form of every node type that has one: each answer exits 0, including the routing
        # shell's answers about absent objects; a non-zero exit is a command error, a stopped
        # daemon or a transport failure -- or, for SONiC's show CLI and nft, an absent object,
        # which the exit status cannot tell apart from a usage error. An exec that raised or
        # exited non-zero is never judged on its output: verdict fail whatever expect says. A
        # backend that reports no exit status (rt.exec returning str) is judged on its output.
        # F-S1D2-C3-10: an assertion that could not be evaluated on an answer (output not JSON,
        # a missing path, an ordering on a non-number) is not judged either; its error is the
        # evaluator's own.
        _exec_unusable = exec_error or None
        if _exec_unusable is None and isinstance(returncode, int) and not isinstance(returncode, bool) \
                and returncode != 0:
            _exec_unusable = f"exited {returncode}"
            observed = "fail"
            eval_error = f"exec command exited {returncode} on {src}; its output is not judged"
        if _exec_unusable is not None or eval_error:
            verdict = "fail"

'''),
    (r'''            "returncode": returncode,
            "truncated": _truncated,
''',
     r'''            "returncode": returncode,
            "truncated": _truncated,
            **({"exec_unusable": _exec_unusable} if _exec_unusable is not None else {}),
'''),
    (r'''            if eval_error:
                observed_state_payload["eval_error"] = eval_error
''',
     r'''            if eval_error:
                observed_state_payload["eval_error"] = eval_error
            if _exec_unusable is not None:
                # WI-14: the output was not judged, so the reason is in stderr (a stopped
                # daemon, a usage error, the transport); render it in the failure block.
                observed_state_payload["stderr_excerpt"] = stderr[:_EXEC_EVIDENCE_CAP]
'''),
]


def _leg_o14():
    _live = raw("run_exec_test")
    _old = _live
    _ok = True
    for _before, _after in WI14_EDITS:
        _ok = _ok and _old.count(_after) == 1
        _old = _old.replace(_after, _before, 1)
    LIVE["run_exec_test"] = textwrap.dedent(_live)
    OLD["run_exec_test"] = textwrap.dedent(_old)
    check("O run_exec_test is the 02669cd extraction with exactly the WI-14 edits applied (sha256 pinned)",
          _ok and sha(OLD["run_exec_test"]) == ORACLE_SHA256["run_exec_test"], sha(OLD["run_exec_test"]))


leg("O", _leg_o14)


class ExecRT:
    """`r` is (rc, stdout, stderr) for a CompletedProcess, ("str", text) for a backend that
    returns a string, or "timeout" for a call that raises."""

    def __init__(self, r):
        self.r = r

    def exec(self, lab, node, cmd, *, check=False, capture_output=True, interactive=False, timeout_s=None):
        if self.r == "timeout":
            raise subprocess.TimeoutExpired(cmd, timeout_s or 30)
        if self.r[0] == "str":
            return self.r[1]
        rc, out, err = self.r
        return CP(cmd, rc, out, err)


GUEST = SONIC_PRE.rstrip("\n") + "\n"
FIELD_IDLE = {"field": {"path": ["ipv4Unicast", "peers", "10.0.0.2", "state"], "op": "==", "value": "Idle"}}
# tag, runtime outcome, assertion, verdict for expect pass / expect fail, how the output is taken:
#   "judged" (exit 0, evaluated), "exited" (non-zero exit), "raised" (the call raised),
#   "unevaluable" (exit 0, the assertion could not be evaluated: the evaluator's own text)
EXEC_CASES = [
    ("M1 answer, assertion holds", (0, "FRRouting 10.7.1", ""), {"contains": "FRRouting"}, ("pass", "fail"),
     "judged", None),
    ("M2 answer about an absent object", (0, "% Network not in table\n", ""), {"not_contains": "203.0.113.200/32"},
     ("pass", "fail"), "judged", None),
    ("M3 empty answer on a guest", (0, "", GUEST), {"not_contains": "203.0.113.200"}, ("pass", "fail"), "judged", None),
    ("M4 daemon not running", (1, "", "ospfd is not running\n"), {"not_contains": "10.0.0.1"}, ("fail", "fail"),
     "exited", None),
    ("M5 unknown command", (1, "% Unknown command: show bgp nbr\n", ""), {"contains": "Established"},
     ("fail", "fail"), "exited", None),
    ("M6 usage error on a guest", (2, "", GUEST + "Error: Got unexpected extra argument (json)\n"),
     {"not_contains": "Active"}, ("fail", "fail"), "exited", None),
    ("M7 neighbour not configured on a guest", (2, "", GUEST + "Error:  Bgp neighbor 203.0.113.200 not configured\n"),
     {"contains": "Established"}, ("fail", "fail"), "exited", None),
    ("M8 absent nft table", (1, "", "Error: No such file or directory\n"), {"contains": "table inet t"},
     ("fail", "fail"), "exited", None),
    ("M9 transport down", (255, "", "ssh: connect to host x port 22: Connection refused\n"),
     {"not_contains": "Established"}, ("fail", "fail"), "exited", None),
    ("M10 the call timed out", "timeout", {"not_contains": "x"}, ("fail", "fail"), "raised", None),
    ("M11 backend with no exit status", ("str", "FRRouting 10.7.1"), {"contains": "FRRouting"}, ("pass", "fail"),
     "judged", None),
    ("M12 empty JSON object, missing path", (0, "{}", ""), FIELD_IDLE, ("fail", "fail"), "unevaluable",
     "field: path segment 'ipv4Unicast' missing or parent not a dict"),
    ("M13 output not JSON", (0, "BGP table version is 3\n", ""), FIELD_IDLE, ("fail", "fail"), "unevaluable",
     "field: stdout is not valid JSON"),
    ("M14 ordering on a string", (0, '{"x": "abc"}', ""), {"field": {"path": ["x"], "op": ">=", "value": 1}},
     ("fail", "fail"), "unevaluable", "field: ordering comparison requires numeric operands"),
    ("M15 field evaluated, predicate false", (0, '{"ipv4Unicast": {"peers": {"10.0.0.2": {"state": "Active"}}}}', ""),
     FIELD_IDLE, ("fail", "pass"), "judged", None),
    ("M16 field == across types (judged)", (0, '{"x": 5}', ""), {"field": {"path": ["x"], "op": "==", "value": "5"}},
     ("fail", "pass"), "judged", None),
    ("M17 no exit status, missing path", ("str", "{}"), FIELD_IDLE, ("fail", "fail"), "unevaluable",
     "field: path segment 'ipv4Unicast' missing or parent not a dict"),
]


def run_exec(text, r, assertion, expect):
    cap = {}
    ns = ns_with(text, ExecRT(r), cap)
    t = {"kind": "exec", "command": "show ip route", "assertion": assertion, "expect": expect}
    v = ns["run_exec_test"](test_name="t", src="s1", t=t, record_fn=lambda **kw: cap.update(kw))
    return v, cap


def _exec_record_ok(rec, r, how, expect, want, text):
    ev = rec.get("evidence") or {}
    os_ = rec.get("observed_state") or {}
    if rec.get("verdict") != want:
        return False
    if how == "exited":
        rc = r[0]
        return (ev.get("exec_unusable") == "exited %d" % rc and rec.get("observed") == "fail"
                and rec.get("error") == "exec command exited %d on s1; its output is not judged" % rc
                and os_.get("returncode") == rc and os_.get("stderr_excerpt") == r[2])
    if how == "raised":
        return (str(ev.get("exec_unusable") or "").startswith("exec failed: ") and rec.get("observed") == "fail"
                and rec.get("error") == ev.get("exec_unusable") and os_.get("stderr_excerpt") == "")
    if how == "unevaluable":
        return ("exec_unusable" not in ev and rec.get("observed") == "fail" and rec.get("error") == text
                and os_.get("eval_error") == text and "stderr_excerpt" not in os_)
    # judged
    if "exec_unusable" in ev or "stderr_excerpt" in os_:
        return False
    if want == "pass":
        return rec.get("error") == ""
    return rec.get("error") == "exec assertion not satisfied (observed %s, expected %s)" % (
        rec.get("observed"), expect)


# ------------------------------------------------------------------- X: exec verdicts and texts
def _leg_x():
    for name, r, assertion, (want_p, want_f), how, text in EXEC_CASES:
        for expect, want in (("pass", want_p), ("fail", want_f)):
            v, rec = run_exec(LIVE["run_exec_test"], r, assertion, expect)
            check("X exec %-40s expect %-4s -> %s (%s)" % (name, expect, want, how),
                  v == want and _exec_record_ok(rec, r, how, expect, want, text),
                  "%r %r %r" % (v, rec.get("error"), (rec.get("evidence") or {}).get("exec_unusable")))


leg("X", _leg_x)


# ------------------------------------------------------------------- E: exec detection
def _leg_e():
    false_passes = [("M4", "pass"), ("M5", "fail"), ("M6", "pass"), ("M9", "pass"), ("M10", "fail")]
    unevaluable = [("M12", "fail"), ("M13", "fail"), ("M14", "fail"), ("M17", "fail")]
    absent_loud = [("M7", "fail"), ("M8", "fail")]
    by_tag = {c[0].split()[0]: c for c in EXEC_CASES}

    def old_verdict(tag, expect):
        c = by_tag[tag]
        return run_exec(OLD["run_exec_test"], c[1], c[2], expect)[0]

    for label, cells in (("the five F-S1D2-C3-6 false passes", false_passes),
                         ("the F-S1D2-C3-10 unevaluable assertions under expect: fail", unevaluable),
                         ("absent objects reported by a non-zero exit, now failed loudly", absent_loud)):
        missed = ["%s/%s" % c for c in cells if old_verdict(*c) != "pass"]
        check("E the 02669cd form passes %s (%s): the defect is reproduced, so X is not vacuous"
              % (label, ", ".join("%s/%s" % c for c in cells)), not missed, ", ".join(missed))
    same = []
    for name, r, assertion, _w, how, _t in EXEC_CASES:
        if how != "judged":
            continue
        for expect in ("pass", "fail"):
            if run_exec(OLD["run_exec_test"], r, assertion, expect)[0] != run_exec(LIVE["run_exec_test"], r, assertion,
                                                                                   expect)[0]:
                same.append("%s/%s" % (name.split()[0], expect))
    check("E every judged answer keeps its 02669cd verdict (M1, M2, M3, M11, M15, M16, both expects)",
          not same, ", ".join(same))


leg("E", _leg_e)


# ------------------------------------------------------------------- R: render (DC v2.1 section 13(b)(c))
def _summary_for(rec):
    t = {"name": rec["name"], "kind": rec["kind"], "from": rec["src"], "to": rec["dst"],
         "expected": rec["expected"], "observed": rec["observed"], "verdict": rec["verdict"],
         "duration_ms": rec["duration_ms"], "error": rec["error"], "evidence": rec["evidence"],
         "meta": rec.get("meta")}
    if rec.get("observed_state") is not None:
        t["observed_state"] = rec["observed_state"]
    res = {"lab": "hs7", "result": "fail", "summary": {"total": 1, "passed": 0, "failed": 1},
           "tests": [t], "scenarios": [], "events": []}
    return T._format_test_summary(res).split("\n")


def _leg_r():
    by_tag = {c[0].split()[0]: c for c in EXEC_CASES}
    for tag, expect in (("M4", "pass"), ("M6", "fail"), ("M10", "pass"), ("M12", "fail")):
        _n, r, assertion, _w, how, text = by_tag[tag]
        _v, rec = run_exec(LIVE["run_exec_test"], r, assertion, expect)
        lines = _summary_for(rec)
        os_ = rec.get("observed_state") or {}
        want = [" - t (exec) s1-> : %s" % rec["error"], "    exec:", "      command: show ip route",
                "      assertion: %s" % json.dumps(assertion, sort_keys=True),
                "      expected: %s" % expect, "    observed:", "      eval_error: %s" % os_.get("eval_error"),
                "      returncode: %s" % ("null" if os_.get("returncode") is None else os_.get("returncode"))]
        missing = [w for w in want if w not in lines]
        has_stderr = any(ln.startswith("      stderr_excerpt:") for ln in lines)
        stderr_ok = has_stderr if how in ("exited", "raised") else not has_stderr
        check("R %s expect %s renders identity, expectation and observed state (%s)" % (tag, expect, how),
              not missing and stderr_ok, "missing %r stderr_excerpt=%s" % (missing, has_stderr))


leg("R", _leg_r)


# ------------------------------------------------------------------- result
ok = True
for name, passed, detail in checks:
    print("[%s] %s%s" % ("PASS" if passed else "FAIL", name, "" if passed or not detail else "  -- " + detail))
    ok = ok and passed
print("=" * 60)
print("RESULT: %s (%d checks)" % ("PASS" if ok else "FAIL", len(checks)))
sys.exit(0 if ok else 1)
