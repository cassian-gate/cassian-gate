#!/usr/bin/env python3
"""WI-1 packet 2c -- SONiC provision supply path (REQ-45C-1/-42, R-C3-12/-14).

Lab-free. A FakeRuntime replays the guest transcript measured on
sonic-vm:202405 (2026-08-18), so the supply sequence is provable on hosted CI.
COVERAGE LIMIT (PBE-P2-8): this proves the SEQUENCE Cassian issues and the
payload it builds. It does NOT prove the guest merges rather than replaces --
that is settled by the §18(8) VM probe and the REQ-45C-5 provisioning proof.

S29-R7 (founder ruling 2026-10-13; BL-P2-4.5c-224): `provision` now ends with a
bounded wait for the guest's routing daemons, polling the provider's own RIB
read. The fake answers that read with the RIB table captured from the guest at
H1-b3 (`tests/fixtures/sonic-4_5d-h1b3/h1b3_rib_table_after.out`), and the W
legs below drive the wait in both directions -- daemons that answer late, and
daemons that never answer -- on a fake clock, so no leg sleeps. COVERAGE LIMIT:
the fake clock proves the bound and the interval as counted reads and sleeps,
not wall-clock time; the gap the wait absorbs is measured on the guest by
`tests/sonic_rib_collection_live_proof.py` (VM), which is its regression test.
"""
import contextlib
import inspect
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_sonic as S  # noqa: E402
from cassian_artifacts import write_json_canonical  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _CP:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = "Debian GNU/Linux 12 \\n \\l\n"


_PORT_TABLE = {f"Ethernet{i * 4}": {"index": str(i)} for i in range(32)}

# The guest's RIB as captured at H1-b3 (byte-exact fixture, never retyped).
_RIB_TABLE = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                                  "sonic-4_5d-h1b3", "h1b3_rib_table_after.out"),
                     encoding="utf-8").read()
_RIB_JOINED = " ".join(S._RIB_ARGV)


class FakeRuntime:
    def __init__(self, hwsku="Force10-S6000", fail_on=None, rib_script=None):
        self.calls = []
        self._hwsku = hwsku
        self._fail_on = fail_on
        # (rc, stdout) answers to the RIB read, in order; the last repeats.
        self._rib = list(rib_script) if rib_script else [(0, _RIB_TABLE)]

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        if self._fail_on and self._fail_on in joined:
            return _CP(rc=1, out="")
        if "DEVICE_METADATA.localhost.hwsku" in joined:
            return _CP(out=self._hwsku + "\n")
        if "--var-json" in joined and "PORT" in joined:
            return _CP(out=json.dumps(_PORT_TABLE))
        if joined == _RIB_JOINED:
            rc, out = self._rib.pop(0) if len(self._rib) > 1 else self._rib[0]
            return _CP(rc=rc, out=out)
        return _CP(out="")


class _Clock:
    """Fake clock for the wait: `time()` reads it, `sleep()` advances it."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def _on_fake_clock(fn):
    """Run fn() with the provider's clock replaced; return (exit code or None,
    stderr text, clock). The real clock is restored whatever happens."""
    real, clock, err, code = S.time, _Clock(), io.StringIO(), None
    S.time = clock
    try:
        with contextlib.redirect_stderr(err):
            fn()
    except SystemExit as e:
        code = e.code
    finally:
        S.time = real
    return code, err.getvalue(), clock


def _rib_reads(rt):
    return [c for c in rt.calls if " ".join(c) == _RIB_JOINED]


TOPO = {
    "name": "sonic-supply-proof",
    "nodes": [{"name": "s1", "type": "sonic-vm", "router_id": "192.0.2.11"}],
    "links": [{"endpoints": ["s1:eth1", "r1:eth1"],
               "ipv4": ["192.0.2.0/31", "192.0.2.1/31"]}],
}
NODE = TOPO["nodes"][0]

# --- probe ------------------------------------------------------------------
rt = FakeRuntime()
facts = S.probe_facts(rt, "lab", "s1")
check("R-C3-13 probe returns the guest's hwsku",
      facts["hwsku"] == "Force10-S6000")
check("R-C3-13 probe derives the port order from the guest PORT table",
      facts["port_order"] == S._SONIC_PORT_MAPS["Force10-S6000"],
      "32/32")
check("F-45C-C3-20 NON-VACUITY: the stderr banner never reaches the parse",
      "Debian" not in facts["hwsku"],
      "stdout-only capture; merging stderr would break JSON parsing")

# --- supply sequence --------------------------------------------------------
rt = FakeRuntime()
applied = S.provision(rt, "lab", "s1", NODE, TOPO)
check("R-C3-14 provision returns the mapping it applied",
      isinstance(applied, dict) and list(applied) == ["config_db.json"])

_stage = [c for c in rt.calls if c[:2] == ["sh", "-c"]]
_load = [c for c in rt.calls if "config" in c and "load" in c]
check("R-C3-12 overlay is staged through the exec verb", len(_stage) == 1)
check("R-C3-12 overlay is applied with `config load -y`",
      len(_load) == 1 and _load[0][-1] == "-y" and "sudo" in _load[0])
check("R-C3-12 NON-VACUITY: copy_to_node is never called",
      not any("copy" in " ".join(c) for c in rt.calls),
      "REQ-45a-8/B10 UNSUP stands; §4.5-f owns guest file transfer")
check("R-C3-12 staging precedes apply",
      rt.calls.index(_stage[0]) < rt.calls.index(_load[0]))

# --- S29-R7 / BL-P2-4.5c-224: provision ends by waiting for the daemons ------
_rec = list(S._BGP_RECONCILE_ARGV)
check("W1 S29-R7 provision's last guest call is the RIB read, after the reconcile",
      rt.calls and rt.calls[-1] == list(S._RIB_ARGV) and _rec in rt.calls
      and rt.calls.index(_rec) < len(rt.calls) - 1,
      "last call %s" % (rt.calls[-1:],))
check("W1 S29-R7 a guest that answers at once is read exactly once",
      len(_rib_reads(rt)) == 1, "reads %d" % len(_rib_reads(rt)))

# --- payload is canonical ---------------------------------------------------
_overlay = applied["config_db.json"]
_tmp = os.path.join(os.path.dirname(__file__), "_supply_tmp")
os.makedirs(_tmp, exist_ok=True)
try:
    from pathlib import Path
    _p = Path(_tmp) / "canonical.json"
    write_json_canonical(_p, _overlay)
    _canonical = _p.read_text(encoding="utf-8")
    _staged = _stage[0][2]
    check("REQ-45C-42 transport payload is byte-identical to the canonical form",
          _canonical in _staged,
          "%d bytes; provider serialization does not diverge from the serializer"
          % len(_canonical))
finally:
    try:
        os.remove(os.path.join(_tmp, "canonical.json"))
        os.rmdir(_tmp)
    except OSError:
        pass

# --- rejection legs ---------------------------------------------------------
_caught = False
try:
    S.provision(FakeRuntime(fail_on="--var-json"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("REQ-45C-5 a failed PORT probe fails loud, exit 2", _caught)

_caught = False
try:
    S.provision(FakeRuntime(fail_on="printf"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("R-C3-12 a failed staging write fails loud, exit 2", _caught)

_caught = False
try:
    S.provision(FakeRuntime(fail_on="config load"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("R-C3-12 a failed `config load` fails loud, exit 2", _caught,
      "a silent apply failure would leave the node unaddressed")

_caught = False
try:
    S.provision(FakeRuntime(hwsku="Bogus-Platform-9000"), "lab", "s1", NODE, TOPO)
except SystemExit:
    _caught = True
check("R-C3-13 an unlisted HwSKU is SUPPORTED end to end, not refused",
      not _caught, "derivation is authoritative; the table is a drift witness")

# --- S29-R7 / BL-P2-4.5c-224: the wait, both directions ------------------------
# Every W leg is guarded: on a provider without the wait it records a FAIL with
# the exception, never a traceback (a crash is not a verdict).
def _leg(name, thunk):
    try:
        ok, detail = thunk()
    except Exception as e:  # noqa: BLE001
        ok, detail = False, "raised %r" % (e,)
    check(name, ok, detail)


def _w2_order():
    src = inspect.getsource(S.provision)
    i_rec, i_wait, i_ret = (src.find("_reconcile_bgp(rt, lab, node)"),
                            src.find("_await_routing_daemon(rt, lab, node)"), src.rfind("return out"))
    return -1 < i_rec < i_wait < i_ret, "rec=%d wait=%d return=%d" % (i_rec, i_wait, i_ret)


def _w2_bound():
    d = inspect.signature(S._await_routing_daemon).parameters["timeout"].default
    return d == S._ROUTING_DAEMON_WAIT_S == 30, "default %r, constant %r" % (d, S._ROUTING_DAEMON_WAIT_S)


def _w2_parity():
    import ast
    eng = ast.parse(io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src",
                                         "cassian_engine.py"), encoding="utf-8").read())
    pt = [n.value for n in ast.walk(eng) if isinstance(n, ast.Assign) and len(n.targets) == 1
          and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "precheck_timeout"]
    ok = (len(pt) == 1 and isinstance(pt[0], ast.IfExp) and isinstance(pt[0].orelse, ast.Constant)
          and pt[0].orelse.value == S._ROUTING_DAEMON_WAIT_S)
    return ok, "engine precheck_timeout orelse %r" % (pt[0].orelse.value if ok or (pt and isinstance(
        getattr(pt[0], "orelse", None), ast.Constant)) else None,)


def _w2_interval():
    src = inspect.getsource(S._await_routing_daemon)
    return (S._CONVERGENCE_POLL_INTERVAL_S == 1 and "sleep(_CONVERGENCE_POLL_INTERVAL_S)" in src
            and "_sonic_read(rt, lab, node, _RIB_ARGV)" in src and "_rib_prefixes(out)" in src), ""


def _w_run(script, timeout=None):
    rt_ = FakeRuntime(rib_script=script)
    kw = {} if timeout is None else {"timeout": timeout}
    code, err, clk = _on_fake_clock(lambda: S._await_routing_daemon(rt_, "lab", "s1", **kw))
    return code, err, clk, len(_rib_reads(rt_))


def _w3():
    code, err, clk, n = _w_run([(1, ""), (0, ""), (0, "{ not json"), (0, _RIB_TABLE)])
    return (code is None and n == 4 and clk.sleeps == [1, 1, 1],
            "exit %r, reads %d, sleeps %r" % (code, n, clk.sleeps))


def _w4():
    code, err, clk, n = _w_run([(1, "")])
    return code == 2 and n == 31 and clk.now == 30, "exit %r, reads %d, elapsed %r" % (code, n, clk.now)


def _w4_text():
    code, err, clk, n = _w_run([(1, "")])
    return ("vtysh -c show ip route json" in err and "within 30s" in err
            and "last result: RIB read failed (rc 1)" in err), err.strip().replace("\n", " | ")[:300]


def _w5():
    code, err, clk, n = _w_run([(0, "")])
    return code == 2 and "last result: empty RIB read" in err, "exit %r" % (code,)


def _w6():
    code, err, clk, n = _w_run([(1, "")], timeout=0)
    return code == 2 and n == 1 and clk.sleeps == [], "exit %r, reads %d, sleeps %r" % (code, n, clk.sleeps)


def _w7_late():
    rt_, box = FakeRuntime(rib_script=[(1, ""), (1, ""), (0, _RIB_TABLE)]), {}
    code, err, clk = _on_fake_clock(lambda: box.setdefault("a", S.provision(rt_, "lab", "s1", NODE, TOPO)))
    n = len(_rib_reads(rt_))
    return code is None and isinstance(box.get("a"), dict) and n == 3, "exit %r, reads %d" % (code, n)


def _w7_never():
    rt_ = FakeRuntime(rib_script=[(1, "")])
    code, err, clk = _on_fake_clock(lambda: S.provision(rt_, "lab", "s1", NODE, TOPO))
    return code == 2 and "routing daemons did not answer" in err, "exit %r" % (code,)


_leg("W2 S29-R7 provision calls the wait after the reconcile and before it returns", _w2_order)
_leg("W2 S29-R7 the bound defaults to _ROUTING_DAEMON_WAIT_S, which is 30", _w2_bound)
_leg("W2 S29-R7 the bound is the BGP precheck's own non-EVPN bound, reused not invented", _w2_parity)
_leg("W2 S29-R7 the interval is _CONVERGENCE_POLL_INTERVAL_S (1 s), and the read and its "
     "parser are the RIB kinds' own (PBE-P2-6)", _w2_interval)
# W3: daemons that answer late -- the measured shape (rc 1, 0 B), then two
# answers that are not a table, then the table. The wait returns.
_leg("W3 S29-R7 daemons that answer late: the wait returns once the table is served", _w3)
# W4: daemons that never answer -- bounded, then a §13-grade failure naming the read.
_leg("W4 S29-R7 NON-VACUITY: daemons that never answer fail loud, exit 2, after the bound", _w4)
_leg("W4 S29-R7 the failure names the read, the bound and the last result", _w4_text)
# W5: an empty answer with rc 0 is NOT-YET, never ready.
_leg("W5 S29-R7 NON-VACUITY: an rc-0 empty answer is not a served table", _w5)
# W6: a zero bound still issues exactly one read and never sleeps.
_leg("W6 S29-R7 a zero bound issues one read and no sleep", _w6)
# W7: through provision itself -- the wiring, not only the function.
_leg("W7 S29-R7 provision returns its applied mapping once the daemons answer", _w7_late)
_leg("W7 S29-R7 NON-VACUITY: provision on a guest whose daemons never answer fails loud, exit 2",
     _w7_never)

# --- report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n,
                         ("  [%s]" % _d) if _d else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d check(s) (WI-1 SONiC provision supply)"
          % len(_failed))
    sys.exit(1)
print("RESULT: PASS -- %d checks (WI-1 SONiC provision supply)" % len(_checks))
