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

S37-R9 (founder ruling 2026-10-21; BL-P2-4.5c-236) amends S29-R7 forward: the
wait returns only once the table carries every connected prefix the overlay
declares, because the guest's stock routes make a non-empty table first. TOPO
therefore declares the addresses of the guest the H1-b3 table was captured
from (`topologies/probe-sonic-bgp-pair.yaml`'s s1: loopback 192.0.2.11, link
198.51.100.0/31), so the captured table carries the declared prefixes; the
"stock-only" tables the X legs use are derived from that capture by removing
keys, never retyped. `tests/sonic_status_collect_proof.py` (VM) is the second
regression test.

§4.5-e handover addendum 01, rules B18 to B20 (REQ-45E-58, -63, -64; §15.2 rows 58,
63 and 64): the B18 and B20 legs at the end run the engine's own dispatch,
`_provision_nos_providers`, on the resolved LD-1 topology of
`tests/fixtures/sonic-4_5e-add01/p7-sonic-leaf.yaml`, with a recording provider
whose `provision` returns the SONiC provider's own generation. They prove that a
sonic-vm EVPN participant is handed its session-set peers in memory, that every
other node is handed its own mapping, that an operator cannot supply the key,
and that the engine's loop writes the fragment's record. A row-64 leg pins the
guest-call sequence `provision` makes for the non-EVPN node s1 to the one
measured at `9663477`.

§4.5-e handover addendum 01, rule B21 (REQ-45E-65 to -71; §15.2 rows 65 to 71;
rulings 45E-S11-R1 to -R3): the B21 legs at the end run the provider's own
`provision` on the mapping the dispatch hands leaf1, against a recording
stand-in guest, on the fake clock: the push and its argv, the first read-back,
the session wait in both directions, the three failure texts of §6.6 rows U5
to U7, one reconcile restart per call, and a second `provision`. Ruling
45E-S11-R4 (packet 4a; row 86, D24): each of the three reads that gives no
answer -- a non-zero exit, nothing printed, or, for the two JSON reads, output
that is not a JSON object -- is reported as no answer, never as absent or not
found; two in-proof mutants restore packet 4's forms. COVERAGE LIMIT
(PBE-P2-8): the stand-in's answers carry the shapes probe record 01 measured,
but they are built here, not captured; the guest's own answers are the LIVE
proof's (§15.2 rows 67 and 70).
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
               "ipv4": ["198.51.100.0/31", "198.51.100.1/31"]}],
}
NODE = TOPO["nodes"][0]
# S37-R9: the connected prefixes TOPO declares for s1, and the captured table
# with them removed (what the guest serves before its addresses are installed),
# and with only the two routes attempt 2 of CI run 39554772668 read first.
DECLARED = ["192.0.2.11/32", "198.51.100.0/31"]
_RIB_DOC = json.loads(_RIB_TABLE)
_RIB_STOCK = json.dumps({k: v for k, v in _RIB_DOC.items() if k not in DECLARED})
_RIB_TWO = json.dumps({k: v for k, v in _RIB_DOC.items() if k in ("0.0.0.0/0", "10.0.0.0/24")})

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
                            src.find("_await_routing_daemon(rt, lab, node,"), src.rfind("return out"))
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


def _w_run(script, timeout=None, expected=None):
    rt_ = FakeRuntime(rib_script=script)
    kw = {} if timeout is None else {"timeout": timeout}
    if expected is not None:
        kw["expected"] = expected
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


# --- S37-R9 / BL-P2-4.5c-236: the wait also waits for the declared prefixes ----
def _x1_prefixes():
    got = S._declared_connected_prefixes(applied["config_db.json"])
    return got == DECLARED, "declared %r" % (got,)


def _x1_shapes():
    ov = {"LOOPBACK_INTERFACE": {"Loopback0": {}, "Loopback0|192.0.2.81/32": {}},
          "INTERFACE": {"Ethernet0": {}, "Ethernet0|198.51.100.33/31": {},
                        "Ethernet4|2001:db8::1/64": {}, "Ethernet8|not-an-address": {}},
          "PORT": {"Ethernet0|10.9.9.9/32": {}}}
    got = S._declared_connected_prefixes(ov)
    return (got == ["192.0.2.81/32", "198.51.100.32/31"] and S._declared_connected_prefixes(None) == []
            and S._declared_connected_prefixes({}) == []), "got %r" % (got,)


def _x2_control():
    stock = json.loads(_RIB_STOCK)
    return (len(stock) == len(_RIB_DOC) - 2 and not set(DECLARED) & set(stock)
            and set(DECLARED) <= set(_RIB_DOC) and S._rib_prefixes(_RIB_STOCK)[1] == ""
            and sorted(json.loads(_RIB_TWO)) == ["0.0.0.0/0", "10.0.0.0/24"]), \
        "stock %d keys, capture %d" % (len(stock), len(_RIB_DOC))


def _x3_late():
    code, err, clk, n = _w_run([(0, _RIB_TWO), (0, _RIB_STOCK), (0, _RIB_TABLE)], expected=DECLARED)
    return code is None and n == 3 and clk.sleeps == [1, 1], "exit %r, reads %d, sleeps %r" % (code, n, clk.sleeps)


def _x4_never():
    code, err, clk, n = _w_run([(0, _RIB_STOCK)], expected=DECLARED)
    return (code == 2 and n == 31 and clk.now == 30
            and "lacks the declared prefixes" in err
            and "not in the table: 192.0.2.11/32, 198.51.100.0/31" in err), \
        "exit %r, reads %d, elapsed %r; %s" % (code, n, clk.now, err.strip().replace("\n", " | ")[:200])


def _x5_partial():
    part = json.dumps({k: v for k, v in _RIB_DOC.items() if k != "198.51.100.0/31"})
    code, err, clk, n = _w_run([(0, part)], timeout=3, expected=DECLARED)
    return code == 2 and "not in the table: 198.51.100.0/31" in err and "192.0.2.11/32," not in err, \
        "exit %r; %s" % (code, err.strip().replace("\n", " | ")[:200])


def _x6_empty_expected():
    code, err, clk, n = _w_run([(0, _RIB_STOCK)], expected=[])
    return code is None and n == 1, "exit %r, reads %d" % (code, n)


def _x7_provision_late():
    rt_, box = FakeRuntime(rib_script=[(0, _RIB_TWO), (0, _RIB_STOCK), (0, _RIB_TABLE)]), {}
    code, err, clk = _on_fake_clock(lambda: box.setdefault("a", S.provision(rt_, "lab", "s1", NODE, TOPO)))
    n = len(_rib_reads(rt_))
    return code is None and isinstance(box.get("a"), dict) and n == 3, "exit %r, reads %d" % (code, n)


def _x7_provision_never():
    rt_ = FakeRuntime(rib_script=[(0, _RIB_TWO)])
    code, err, clk = _on_fake_clock(lambda: S.provision(rt_, "lab", "s1", NODE, TOPO))
    return (code == 2 and "lacks the declared prefixes" in err
            and "192.0.2.11/32, 198.51.100.0/31" in err), "exit %r" % (code,)


_leg("X1 S37-R9 the declared connected prefixes are the overlay's loopback /32 and link network", _x1_prefixes)
_leg("X1 S37-R9 a key without an address, an IPv6 address, a malformed address and a table other "
     "than LOOPBACK_INTERFACE and INTERFACE declare no prefix", _x1_shapes)
_leg("X2 S37-R9 control: the stock-only table is the capture less exactly the two declared prefixes, "
     "and is itself a table the parser accepts", _x2_control)
# X3: two stock routes (what attempt 2's status read held), then the stock
# table, then the declared prefixes. The wait returns only on the third read.
_leg("X3 S37-R9 a table without the declared prefixes is not ready; the wait returns once they arrive",
     _x3_late)
# X4: never -- bounded, then a §13-grade failure naming the missing prefixes.
_leg("X4 S37-R9 NON-VACUITY: a served table that never carries them fails loud, exit 2, after the "
     "bound, naming both", _x4_never)
_leg("X5 S37-R9 a table carrying one declared prefix of two names only the missing one", _x5_partial)
_leg("X6 S37-R9 with nothing declared, the first served table is ready (S29-R7's predicate)",
     _x6_empty_expected)
# X7: through provision itself -- the overlay's prefixes reach the wait.
_leg("X7 S37-R9 provision returns once the declared prefixes are in the table", _x7_provision_late)
_leg("X7 S37-R9 NON-VACUITY: provision on a guest whose table never carries them fails loud, exit 2",
     _x7_provision_never)

# --- §4.5-e addendum 01: rules B18 to B20 (REQ-45E-58, -63, -64; §15.2 rows 58, 63 and 64) -------------------
# The engine's dispatch, `_provision_nos_providers`, runs for real on the LD-1 topology of
# tests/fixtures/sonic-4_5e-add01/p7-sonic-leaf.yaml (sonic-vm leaf1; FRR spine1, the route reflector; FRR leaf2),
# resolved and read back as `cmd_up` reads topology.resolved.yaml. The registry holds one recording provider for
# sonic-vm: its `provision` records the node mapping it is handed and returns the SONiC provider's own generation
# for it, which the engine's loop writes. So the engine's key and the provider's are bound by behaviour. Every leg
# is guarded by `_eleg`: on a tree without these rules, or on a loud exit, it records a FAIL, never a traceback.
import copy  # noqa: E402
import hashlib  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

import yaml  # noqa: E402

import cassian_common as C  # noqa: E402
import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402

_P7 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sonic-4_5e-add01",
                   "p7-sonic-leaf.yaml")
_P7_DOC = yaml.safe_load(io.open(_P7, encoding="utf-8").read())
_EFACTS = {"hwsku": "Force10-S6000", "port_order": S._SONIC_PORT_MAPS["Force10-S6000"]}
_ELINES = ["router bgp 65100", "address-family l2vpn evpn", "neighbor 172.16.0.0 activate",
           "advertise-all-vni"]
_FRAG = os.path.join("lab", "leaf1", "frr_evpn_fragment.json")
_CDB = os.path.join("lab", "leaf1", "config_db.json")
_KEY = getattr(S, "_EVPN_SESSION_PEERS_KEY", None)
_EVPN_TABLES = ("VLAN", "VXLAN_TUNNEL", "VXLAN_EVPN_NVO", "VXLAN_TUNNEL_MAP", "BGP_NEIGHBOR")
_seen = []
_cache = {}


def _eleg(name, thunk):
    try:
        ok, detail = thunk()
    except (Exception, SystemExit) as e:  # noqa: BLE001
        ok, detail = False, "raised %r" % (e,)
    check(name, ok, detail)


def _etopo():
    if "topo" not in _cache:
        _cache["topo"] = yaml.safe_load(yaml.safe_dump(
            M.resolve_topology(copy.deepcopy(_P7_DOC), topo_path=_Path(_P7)), sort_keys=False))
        _cache["before"] = json.dumps(_cache["topo"], sort_keys=True)
    return _cache["topo"]


def _eleaf():
    return next(n for n in _etopo()["nodes"] if n.get("name") == "leaf1")


def _rec_provision(rt_, lab, name, node_d, topo):
    _seen.append((name, node_d))
    return S.gen_node_config(node_d, topo, _EFACTS)


_REC = types.SimpleNamespace(node_type="sonic-vm", runtime_requirement="vm",
                             nos_ready=lambda rt_, lab, node: None, provision=_rec_provision)


def _dispatch(topo, fn=None):
    """Run the engine's dispatch (or `fn`, a mutant of it) with the recording provider. Returns
    ({node: the mapping handed to provision}, {path under the run directory: bytes written})."""
    del _seen[:]
    tmp = tempfile.mkdtemp(prefix="prov-b18-")
    real = (E.NOS_PROVIDERS, E.verify_sonic_vm_ready, E.node_cfg_dir)
    try:
        E.NOS_PROVIDERS = {"sonic-vm": _REC}
        E.verify_sonic_vm_ready = lambda rt_, lab, node: None
        E.node_cfg_dir = lambda lab, node: _Path(tmp) / lab / node
        (fn or E._provision_nos_providers)(FakeRuntime(), "lab", topo)
        written = {}
        for top, _dirs, files in os.walk(tmp):
            for f in files:
                p = os.path.join(top, f)
                written[os.path.relpath(p, tmp)] = io.open(p, "rb").read()
        return dict(_seen), written
    finally:
        E.NOS_PROVIDERS, E.verify_sonic_vm_ready, E.node_cfg_dir = real
        shutil.rmtree(tmp, ignore_errors=True)


def _evpn_run():
    if "run" not in _cache:
        _cache["run"] = _dispatch(_etopo())
    return _cache["run"]


def _canonical_bytes(obj):
    tmp = tempfile.mkdtemp(prefix="prov-canon-")
    try:
        p = _Path(tmp) / "x.json"
        write_json_canonical(p, obj)
        return p.read_bytes()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _handed_peers(handed):
    got = handed.get("leaf1")
    return got.get(_KEY) if isinstance(got, dict) and _KEY is not None else None


def _b18_positive():
    handed, _w = _evpn_run()
    peers = _handed_peers(handed)
    return peers == [("spine1", "172.16.0.0")], "leaf1 handed %r" % (peers,)


def _b18_set():
    sset = M.fabric_evpn_session_set(_etopo()) or {}
    mine = [(p, ip) for p, ip, _rr in sset.get("leaf1", [])]
    return mine == _handed_peers(_evpn_run()[0]) == [("spine1", "172.16.0.0")], "set %r" % (sset.get("leaf1"),)


def _b18_copy():
    handed, _w = _evpn_run()
    got, own = handed.get("leaf1"), _eleaf()
    _h, written = _evpn_run()
    ok = (isinstance(got, dict) and got is not own and _KEY is not None and _KEY not in own
          and {k: v for k, v in got.items() if k != _KEY} == own
          and json.dumps(_etopo(), sort_keys=True) == _cache["before"]
          and bool(written) and not any(_KEY.encode("utf-8") in b for b in written.values()))
    return ok, "copy %s; leaf1's own keys %s; files written %d" % (got is not own, sorted(own), len(written))


def _b18_other():
    handed, _w = _dispatch(TOPO)
    return handed.get("s1") is NODE and (_KEY or "") not in NODE, "s1 handed its own mapping: %s" % (
        handed.get("s1") is NODE,)


def _b18_mutant():
    src = inspect.getsource(E._provision_nos_providers)
    line = "applied = prov.provision(rt, lab_name, name, node_d, topo)"
    if src.count(line) != 1:
        return False, "B18's hand-over line found %d times" % src.count(line)
    ns = {}
    exec(compile(src.replace(line, "applied = prov.provision(rt, lab_name, name, n, topo)"),
                 "<b18-mutant>", "exec"), E.__dict__, ns)
    handed, written = _dispatch(_etopo(), fn=ns["_provision_nos_providers"])
    red = _handed_peers(handed) is None and _FRAG not in written and _CDB in written
    if red:
        print("MUTATION-FAIL: the engine's dispatch without rule B18's hand-over -> leaf1 is handed no peers "
              "and no fragment is written")
    return red, "mutant: leaf1 handed %r; written %s" % (_handed_peers(handed), sorted(written))


def _b20_written():
    _h, written = _evpn_run()
    frag = written.get(_FRAG)
    return (frag == _canonical_bytes({"lines": _ELINES}) and sorted(written) == sorted([_CDB, _FRAG])), \
        "written %s; fragment %r" % (sorted(written), (frag or b"")[:160])


def _b20_only_provider():
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
    names = sorted(f for f in os.listdir(src_dir) if f.endswith(".py")
                   and "frr_evpn_fragment.json" in io.open(os.path.join(src_dir, f), encoding="utf-8").read())
    return names == ["cassian_nos_sonic.py"], "src/ files naming it: %s" % names


def _no_evpn(out):
    ov = (out or {}).get("config_db.json") or {}
    return (list(out or {}) == ["config_db.json"] and not any(t in ov for t in _EVPN_TABLES)
            and "bgp_asn" not in ov.get("DEVICE_METADATA", {}).get("localhost", {}))


def _b18_negative():
    out = S.gen_node_config(_eleaf(), _etopo(), _EFACTS)
    return _no_evpn(out), "entries %s; tables %s" % (list(out), sorted(out.get("config_db.json", {})))


def _b18_negative_nv():
    # A provider that derived the peers from the links would render them without being handed any.
    leaf = dict(_eleaf())
    leaf[_KEY] = [(p, ips[1]) for p, ips in sorted(S._bgp_link_ips_for_node("leaf1", _etopo()).items())]
    red = not _no_evpn(S.gen_node_config(leaf, _etopo(), _EFACTS))
    if red:
        print("MUTATION-FAIL: a provider deriving its peers from the links -> the negative leg is red")
    return red, "links give %r" % (leaf[_KEY],)


def _validate(doc):
    real = C._QUIET_DIE
    C._QUIET_DIE = True
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            M.ensure_valid_topology(doc)
        return None
    except SystemExit as e:
        return str(e.code)
    finally:
        C._QUIET_DIE = real


def _b18_unsuppliable():
    doc = copy.deepcopy(_P7_DOC)
    next(n for n in doc["nodes"] if n["name"] == "leaf1")[_KEY] = [["spine1", "172.16.0.0"]]
    ctl, msg = _validate(copy.deepcopy(_P7_DOC)), _validate(doc)
    return ctl is None and msg is not None and str(_KEY) in msg, "control %r; with the key %r" % (ctl, msg)


_eleg("B18 REQ-45E-58 the engine hands sonic-vm leaf1 its session-set peers, (name, IP) in the set's order",
      _b18_positive)
_eleg("B18 REQ-45E-58 those peers are the model's session set for leaf1 (PBE-1b-9: derived once, in the model)",
      _b18_set)
_eleg("B18 REQ-45E-58 the mapping handed over is a copy: leaf1's own mapping and the topology are unchanged, and "
      "no file the dispatch writes holds the key", _b18_copy)
_eleg("B18 REQ-45E-58 any other node is handed its own mapping, exactly as before", _b18_other)
_eleg("B18 NON-VACUITY: the engine's dispatch with rule B18's hand-over reverted hands leaf1 no peers and writes "
      "no fragment", _b18_mutant)
_eleg("B18 REQ-45E-58 an operator cannot supply the key: validate refuses it on a node and names it; the same "
      "topology without it validates", _b18_unsuppliable)
_eleg("B18 REQ-45E-58 NEGATIVE: leaf1's mapping without the peers, in the same EVPN topology, renders no fragment "
      "and no EVPN table", _b18_negative)
_eleg("B18 NON-VACUITY: a provider deriving the peers from the links fails that negative leg", _b18_negative_nv)
_eleg("B20 REQ-45E-63 the engine's loop writes frr_evpn_fragment.json for leaf1 beside config_db.json, byte-equal "
      "to write_json_canonical of {\"lines\": [...]}, and nothing else", _b20_written)
_eleg("B20 REQ-45E-63 NEGATIVE: in src/ only the SONiC provider names frr_evpn_fragment.json", _b20_only_provider)

# §15.2 row 64 (REQ-45E-64): the guest calls `provision` makes for the non-EVPN sonic-vm node s1, in order, as at
# `9663477`. Pinned, never recomputed: patch/45e-s10/measure-seq.py ran this file's own fake against the trees at
# 9663477 and 92ad60f (both with cassian_nos_sonic.py at 7c518f0d, the handover's §14.1 digest at 9663477),
# twice each, on 2026-11-25, and measured this sha256 of the sequence's JSON (sort_keys) and this count: the mode
# read, the hwsku read, the PORT read, the staging write, `config load`, the BGP restart, the RIB read.
_SEQ_AT_9663477 = ("65c71fa62949193e346ef9d40eb200b238edd45002e8afb521f2b2825e3ef843", 7)


def _seq_digest(calls):
    return hashlib.sha256(json.dumps(calls, sort_keys=True).encode("utf-8")).hexdigest(), len(calls)


def _s1_sequence():
    rt_ = FakeRuntime()
    out = S.provision(rt_, "lab", "s1", NODE, TOPO)
    return rt_.calls, out


def _b64_sequence():
    calls, out = _s1_sequence()
    got = _seq_digest(calls)
    return (got == _SEQ_AT_9663477 and list(out) == ["config_db.json"]), "sequence %s; heads %s; mapping %s" % (
        got, [c[:2] for c in calls], list(out))


def _b64_sequence_nv():
    calls, _out = _s1_sequence()
    added = calls + [["vtysh", "-c", "configure terminal"]]
    return (_seq_digest(calls) == _SEQ_AT_9663477 and _seq_digest(added) != _SEQ_AT_9663477), \
        "with one call added: %s" % (_seq_digest(added),)


_eleg("B18 to B21 REQ-45E-64 regression: for the non-EVPN sonic-vm node s1, provision returns config_db.json only "
      "and makes the guest calls measured at 9663477, in order (sha256 65c71fa6, 7 calls)", _b64_sequence)
_eleg("REQ-45E-64 NON-VACUITY: that comparison reads the same sequence with one guest call added as differing",
      _b64_sequence_nv)

# §4.5-e handover addendum 01, rule B21 (REQ-45E-65 to -71; §15.2 rows 65 to 71; rulings 45E-S11-R1 to -R3): the
# provider's own `provision` on leaf1, run on the mapping the engine's dispatch hands it (rule B18, above), against a
# recording stand-in guest, on the fake clock. The stand-in's answers carry the shapes probe record 01 measured; they
# are built here, never retyped captures: the EVPN summary keyed `peers` -> address -> `state` (§6.1, call [003]);
# the neighbour read keyed by the address, with `neighborCapabilities.multiprotocolExtensions.l2VpnEvpn` an object
# whose one key reads true (§6.3, call [028]; the probe's reader, batch C L62-L69), plus a second `l2VpnEvpn` object
# under another capability (as batch C L568 shows one), which here reads negotiated so that a reader at the wrong
# path is caught; and the `bgpd` running configuration with the block as §7 prints it. The RIB answer is the H1-b3
# capture with leaf1's declared prefixes keyed onto one captured entry (derived, as the X legs derive theirs).
_NL = chr(10)
_PUSH_MEASURED = ["vtysh", "-c", "configure terminal", "-c", "router bgp 65100", "-c", "address-family l2vpn evpn",
                  "-c", "neighbor 172.16.0.0 activate", "-c", "advertise-all-vni"]
_READBACK_ARGV = ["vtysh", "-c", "show running-config bgpd"]
_SUMMARY_JOINED = "vtysh -c show bgp l2vpn evpn summary json"
_NBR_JOINED = "vtysh -c show bgp neighbors 172.16.0.0 json"
_RUNNING_OK = _NL.join([
    "!", "router bgp 65100", " neighbor 172.16.0.0 remote-as 65100",
    " address-family ipv4 unicast", "  network 192.0.2.150/32", " exit-address-family",
    " address-family l2vpn evpn", "  neighbor 172.16.0.0 activate", "  advertise-all-vni", " exit-address-family",
    "exit", "!"]) + _NL
_RUNNING_ONE_ABSENT = _RUNNING_OK.replace("  advertise-all-vni" + _NL, "")
# The line present, but in another address-family block: a whole-file match would accept it (D23).
_RUNNING_ELSEWHERE = _RUNNING_ONE_ABSENT.replace("  network 192.0.2.150/32" + _NL,
                                                 "  network 192.0.2.150/32" + _NL + "  advertise-all-vni" + _NL)
_REQ_U5_U6 = "required: report this with the guest's running configuration, then run cassian up again" + _NL
_U5 = _NL.join(["ERROR: SONiC EVPN configuration push failed", "node: leaf1",
                "reason: `vtysh` exited 1 while applying the EVPN lines",
                "detail: the EVPN lines were not applied, so this node takes no part in the EVPN control plane"]) \
    + _NL + _REQ_U5_U6
_U6 = _NL.join(["ERROR: SONiC EVPN configuration is not in force", "node: leaf1",
                "reason: 1 of 4 EVPN lines are absent from the running configuration after the push",
                "detail: absent: advertise-all-vni"]) + _NL + _REQ_U5_U6
# 45E-S11-R4's read-back failure (rulings note 2 §3): its own text, never U6's absent lines.
_NOANS_HEAD = "ERROR: SONiC EVPN configuration could not be read back" + _NL + "node: leaf1" + _NL
_NOANS_TAIL = "detail: nothing was read, so whether the EVPN lines are in force is not known" + _NL + _REQ_U5_U6
_NOANS_EMPTY = (_NOANS_HEAD + "reason: the running configuration read after the push printed nothing" + _NL
                + _NOANS_TAIL)
_NOANS_RC1 = (_NOANS_HEAD + "reason: `vtysh` exited 1 reading the running configuration after the push" + _NL
              + _NOANS_TAIL)
_U7_DETAIL = ("detail: the EVPN lines are in force, but the EVPN family did not negotiate with these peers, so EVPN "
              "checks on this node would read no routes from them" + _NL)
_U7_REQUIRED = "required: check the peer's EVPN configuration for this node, then run cassian up again" + _NL
_U7 = (_NL.join(["ERROR: SONiC EVPN session did not negotiate after the push", "node: leaf1",
                 "reason: 172.16.0.0: Established, EVPN family advertised; after 30s (bound 30s)"]) + _NL
       + _U7_DETAIL + _U7_REQUIRED)


class _EvpnGuest(FakeRuntime):
    """Recording stand-in guest for rule B21. `polls`: the peer's (state, capability key) at each EVPN summary
    read, the last repeating; a state of None leaves the peer out of the summary."""

    def __init__(self, rib, push_rc=0, running=_RUNNING_OK, polls=(("Established", "advertisedAndReceived"),),
                 running_rc=0, summary=None, neighbour=None):
        FakeRuntime.__init__(self, rib_script=[(0, rib)])
        self.push_rc, self.running, self.polls, self.summaries = push_rc, running, list(polls), 0
        # 45E-S11-R4's cases: the read-back's return code; for the summary and the neighbour read, an override
        # (rc, stdout, polls): stdout None keeps the built answer, so a non-zero exit with a full answer can be
        # stated; polls names the summary polls it applies on (None: every poll).
        self.running_rc, self.summary, self.neighbour = running_rc, summary, neighbour

    def _answer(self, override, built):
        if override is None or (override[2] is not None and self.summaries not in override[2]):
            return _CP(out=built)
        return _CP(rc=override[0], out=built if override[1] is None else override[1])

    def _poll(self):
        return self.polls[min(max(self.summaries - 1, 0), len(self.polls) - 1)]

    def exec(self, lab, node, argv, check=False, capture_output=True, interactive=False, timeout_s=None):
        joined = " ".join(argv)
        if list(argv[:3]) == ["vtysh", "-c", "configure terminal"]:
            self.calls.append(list(argv))
            return _CP(rc=self.push_rc)
        if list(argv) == _READBACK_ARGV:
            self.calls.append(list(argv))
            return _CP(rc=self.running_rc, out=self.running)
        if joined == _SUMMARY_JOINED:
            self.calls.append(list(argv))
            self.summaries += 1
            state, _cap = self._poll()
            peers = {} if state is None else {"172.16.0.0": {"hostname": "spine1", "state": state, "pfxRcd": 0}}
            return self._answer(self.summary, json.dumps({"routerId": "192.0.2.150", "as": 65100, "peers": peers}))
        if joined == _NBR_JOINED:
            self.calls.append(list(argv))
            state, cap = self._poll()
            fams = {"ipv4Unicast": {"advertisedAndReceived": True}}
            if cap:
                fams["l2VpnEvpn"] = {cap: True}
            return self._answer(self.neighbour, json.dumps({"172.16.0.0": {
                "bgpState": state or "Idle", "neighborCapabilities": {
                    "multiprotocolExtensions": fams,
                    "otherCapability": {"l2VpnEvpn": {"advertisedAndReceived": True}}}}}))
        return FakeRuntime.exec(self, lab, node, argv, check, capture_output, interactive, timeout_s)


def _leaf_handed():
    return _evpn_run()[0].get("leaf1")


def _leaf_rib():
    if "rib" not in _cache:
        overlay = S.gen_node_config(_leaf_handed(), _etopo(), _EFACTS)["config_db.json"]
        one = _RIB_DOC["192.0.2.11/32"]
        _cache["rib"] = json.dumps(dict(_RIB_DOC, **{p: one for p in S._declared_connected_prefixes(overlay)}))
    return _cache["rib"]


def _b21_run(guest, calls=1):
    """`provision` leaf1 `calls` times on `guest`, on the fake clock: (exit code or None, stderr, clock)."""
    def go():
        for _ in range(calls):
            S.provision(guest, "lab", "leaf1", _leaf_handed(), _etopo())
    return _on_fake_clock(go)


def _joined(guest):
    return [" ".join(c) for c in guest.calls]


def _bgp_starts(calls):
    return [c for c in calls if "bgp" in c and any(w in c for w in ("start", "restart", "reload"))]


def _b21_order():
    g = _EvpnGuest(_leaf_rib())
    code, err, _clk = _b21_run(g)
    c, j = g.calls, _joined(g)
    ok = (code is None and len(c) == 11 and c[3][:2] == ["sh", "-c"] and c[4][:3] == ["sudo", "config", "load"]
          and tuple(c[5]) == S._BGP_RECONCILE_ARGV and j[6] == _RIB_JOINED and c[7] == _PUSH_MEASURED
          and c[8] == _READBACK_ARGV and j[9] == _SUMMARY_JOINED and j[10] == _NBR_JOINED
          and tuple(_READBACK_ARGV) == getattr(S, "_EVPN_RUNNING_CONFIG_ARGV", None))
    return ok, "exit %r; calls %d; heads %s; stderr %r" % (code, len(c), [x[:3] for x in c], err[-200:])


def _b21_order_nv():
    g = _EvpnGuest(_leaf_rib())
    _b21_run(g)
    c = list(g.calls)
    if len(c) != 11:
        return False, "calls %d" % len(c)
    swapped = c[:5] + [c[7], c[6], c[5]] + c[8:]
    red = not (tuple(swapped[5]) == S._BGP_RECONCILE_ARGV and swapped[7] == _PUSH_MEASURED)
    return red, "the order check reads the push before the restart as wrong: %s" % red


def _b21_no_file():
    g = _EvpnGuest(_leaf_rib())
    code, _err, _clk = _b21_run(g)
    writes = [c for c in g.calls if c[:2] == ["sh", "-c"]]
    rule = S._sonic_exec_command_rule(list(_PUSH_MEASURED))
    ok = (code is None and len(writes) == 1 and not any("advertise-all-vni" in " ".join(w) for w in writes)
          and _PUSH_MEASURED in g.calls and rule[0] is False)
    return ok, "writes %d; the operator's exec rule on the push: %r" % (len(writes), rule)


def _b21_push_rc():
    g = _EvpnGuest(_leaf_rib(), push_rc=1)
    code, err, _clk = _b21_run(g)
    after = g.calls[g.calls.index(_PUSH_MEASURED) + 1:] if _PUSH_MEASURED in g.calls else None
    return code == 2 and _U5 in err and after == [], "exit %r; calls after the push %r; stderr %r" % (
        code, after, err[-400:])


def _b21_readback_absent():
    g = _EvpnGuest(_leaf_rib(), running=_RUNNING_ONE_ABSENT)
    code, err, _clk = _b21_run(g)
    return code == 2 and _U6 in err and _SUMMARY_JOINED not in _joined(g), "exit %r; stderr %r" % (code, err[-400:])


def _b21_readback_elsewhere():
    g = _EvpnGuest(_leaf_rib(), running=_RUNNING_ELSEWHERE)
    code, err, _clk = _b21_run(g)
    return code == 2 and _U6 in err, "exit %r; stderr %r" % (code, err[-400:])


def _b21_readback_elsewhere_nv():
    red = "advertise-all-vni" in _RUNNING_ELSEWHERE and "advertise-all-vni" not in _RUNNING_ONE_ABSENT
    return red, "a whole-file match finds the line in the decoy and not in the plain absence: %s" % red


def _readback_case(**kw):
    g = _EvpnGuest(_leaf_rib(), **kw)
    code, err, _clk = _b21_run(g)
    return code, err, _SUMMARY_JOINED in _joined(g)


def _b21_readback_unanswered():
    seen = [_readback_case(running=r) for r in ("", _NL, "  " + _NL + _NL)]
    ok = all(c == 2 and _NOANS_EMPTY in e and "absent" not in e and not s for c, e, s in seen)
    return ok, " | ".join("exit %r; session read %s; stderr %r" % (c, s, e[-240:]) for c, e, s in seen)


def _b21_readback_rc():
    seen = [_readback_case(running=r, running_rc=1) for r in (_RUNNING_OK, "")]
    ok = all(c == 2 and _NOANS_RC1 in e and "absent" not in e and not s for c, e, s in seen)
    return ok, " | ".join("exit %r; session read %s; stderr %r" % (c, s, e[-240:]) for c, e, s in seen)


def _b21_wait_late():
    g = _EvpnGuest(_leaf_rib(), polls=(("Idle", None), ("Established", "advertisedAndReceived")))
    code, err, clk = _b21_run(g)
    j = _joined(g)
    ok = (code is None and j.count(_SUMMARY_JOINED) == 2 and j.count(_NBR_JOINED) == 1
          and clk.sleeps == [S._CONVERGENCE_POLL_INTERVAL_S])
    return ok, "exit %r; summaries %d; neighbour reads %d; sleeps %r" % (
        code, j.count(_SUMMARY_JOINED), j.count(_NBR_JOINED), clk.sleeps)


def _b21_wait_bound():
    g = _EvpnGuest(_leaf_rib(), polls=(("Established", "advertised"),))
    code, err, clk = _b21_run(g)
    j = _joined(g)
    ok = (code == 2 and _U7 in err and j.count(_SUMMARY_JOINED) == 31 and j.count(_NBR_JOINED) == 31
          and clk.sleeps == [S._CONVERGENCE_POLL_INTERVAL_S] * 30)
    return ok, "exit %r; summaries %d; sleeps %d; stderr %r" % (code, j.count(_SUMMARY_JOINED), len(clk.sleeps),
                                                              err[-420:])


def _b21_not_read():
    g = _EvpnGuest(_leaf_rib(), polls=(("Idle", None),))
    code, err, _clk = _b21_run(g)
    line = "reason: 172.16.0.0: Idle, EVPN family not-read; after 30s (bound 30s)" + _NL
    return (code == 2 and line in err and _NBR_JOINED not in _joined(g)), "exit %r; neighbour reads %d; %r" % (
        code, _joined(g).count(_NBR_JOINED), err[-300:])


def _b21_not_present():
    g = _EvpnGuest(_leaf_rib(), polls=((None, None),))
    code, err, _clk = _b21_run(g)
    line = "reason: 172.16.0.0: not-present, EVPN family not-read; after 30s (bound 30s)" + _NL
    return code == 2 and line in err, "exit %r; %r" % (code, err[-300:])


_U7_HEAD = "ERROR: SONiC EVPN session did not negotiate after the push" + _NL + "node: leaf1" + _NL
_NOANS_STATE = "reason: 172.16.0.0: no-answer, EVPN family not-read; after 30s (bound 30s)" + _NL
_NOANS_FAMILY = "reason: 172.16.0.0: Established, EVPN family no-answer; after 30s (bound 30s)" + _NL
# Output that is not in the reader's format (rulings note 2 §5): a stand-in error line, nothing, a JSON array.
_UNFORMATTED = ("% Unknown command" + _NL, "", "[]")


def _wait_case(**kw):
    g = _EvpnGuest(_leaf_rib(), **kw)
    code, err, clk = _b21_run(g)
    j = _joined(g)
    return code, err, j.count(_SUMMARY_JOINED), j.count(_NBR_JOINED), len(clk.sleeps)


def _b21_summary_rc():
    c, e, s, n, z = _wait_case(summary=(1, None, None))
    ok = c == 2 and (_U7_HEAD + _NOANS_STATE + _U7_DETAIL + _U7_REQUIRED) in e and (s, n, z) == (31, 0, 30)
    return ok, "exit %r; summaries %d; neighbour reads %d; sleeps %d; stderr %r" % (c, s, n, z, e[-320:])


def _b21_summary_unformatted():
    seen = [_wait_case(summary=(0, out, None)) for out in _UNFORMATTED]
    ok = all(c == 2 and _NOANS_STATE in e and n == 0 for c, e, s, n, z in seen)
    return ok, " | ".join("exit %r; neighbour reads %d; %r" % (c, n, e[-200:]) for c, e, s, n, z in seen)


def _b21_neighbour_rc():
    c, e, s, n, z = _wait_case(neighbour=(1, None, None))
    ok = c == 2 and (_U7_HEAD + _NOANS_FAMILY + _U7_DETAIL + _U7_REQUIRED) in e and (s, n, z) == (31, 31, 30)
    return ok, "exit %r; summaries %d; neighbour reads %d; sleeps %d; stderr %r" % (c, s, n, z, e[-320:])


def _b21_neighbour_unformatted():
    seen = [_wait_case(neighbour=(0, out, None)) for out in _UNFORMATTED]
    ok = all(c == 2 and _NOANS_FAMILY in e and "family absent" not in e for c, e, s, n, z in seen)
    return ok, " | ".join("exit %r; %r" % (c, e[-200:]) for c, e, s, n, z in seen)


def _b21_no_answer_then_negotiated():
    c, e, s, n, z = _wait_case(summary=(0, "", {1}))
    return c is None and (s, n, z) == (2, 1, 1), "exit %r; summaries %d; neighbour reads %d; sleeps %d" % (c, s, n, z)


def _b21_restarts():
    seen = []
    for kw in (dict(), dict(polls=(("Idle", None), ("Established", "advertisedAndReceived"))), dict(push_rc=1),
               dict(running=_RUNNING_ONE_ABSENT), dict(polls=(("Established", "advertised"),)),
               dict(running=""), dict(running_rc=1), dict(summary=(1, None, None)), dict(neighbour=(1, None, None))):
        g = _EvpnGuest(_leaf_rib(), **kw)
        _b21_run(g)
        seen.append(_bgp_starts(g.calls) == [list(S._BGP_RECONCILE_ARGV)])
    g = _EvpnGuest(_leaf_rib())
    _b21_run(g, calls=2)
    two = _bgp_starts(g.calls) == [list(S._BGP_RECONCILE_ARGV)] * 2
    return all(seen) and two, "one restart per call, per leg: %r; two calls: %s" % (seen, two)


def _b21_restarts_nv():
    g = _EvpnGuest(_leaf_rib())
    _b21_run(g)
    added = g.calls + [list(S._BGP_RECONCILE_ARGV)]
    red = _bgp_starts(g.calls) == [list(S._BGP_RECONCILE_ARGV)] and _bgp_starts(added) != [list(S._BGP_RECONCILE_ARGV)]
    return red, "the count reads one added restart as a second start: %s" % red


def _b21_second():
    g = _EvpnGuest(_leaf_rib())
    code, _err, _clk = _b21_run(g, calls=2)
    c = g.calls
    rs = [i for i, x in enumerate(c) if tuple(x) == S._BGP_RECONCILE_ARGV]
    ps = [i for i, x in enumerate(c) if x == _PUSH_MEASURED]
    bs = [i for i, x in enumerate(c) if x == _READBACK_ARGV]
    ok = (code is None and len(rs) == len(ps) == len(bs) == 2 and rs[0] < ps[0] < bs[0] < rs[1] < ps[1] < bs[1])
    return ok, "restarts %r; pushes %r; read-backs %r" % (rs, ps, bs)


def _mutant(name, replacement, leg):
    """Run `leg` with the provider's `name` replaced; the leg must go red."""
    real = getattr(S, name, None)
    if real is None:
        return False, "the provider has no %s" % name
    setattr(S, name, replacement)
    try:
        ok, detail = leg()
    finally:
        setattr(S, name, real)
    return (not ok), detail


def _every_peer_reads(rt_, lab, node, peer_ips):
    _rc, raw = S._sonic_read(rt_, lab, node, S._EVPN_SUMMARY_ARGV)
    caps = {ip: S._evpn_capability_value(S._sonic_read(rt_, lab, node, tuple(S._evpn_neighbor_argv(ip)))[1], ip)
            for ip in peer_ips}
    return S._peers_from_summary(raw), caps


def _any_path_capability(raw, peer_ip):
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "l2VpnEvpn" and isinstance(v, dict) and v.get("advertisedAndReceived") is True:
                    return "advertisedAndReceived"
                hit = walk(v)
                if hit:
                    return hit
        return None
    try:
        return walk(json.loads(raw)) or "advertised"
    except Exception:
        return "absent"


def _b21_not_read_nv():
    red, detail = _mutant("_evpn_session_reads", _every_peer_reads, _b21_not_read)
    if red:
        print("MUTATION-FAIL: a wait that makes the neighbour read for a peer not Established -> the not-read leg "
              "is red")
    return red, detail


def _b21_wait_removed_nv():
    red, detail = _mutant("_await_evpn_sessions", lambda *a, **k: None, _b21_wait_bound)
    if red:
        print("MUTATION-FAIL: provision without the session wait -> the bound leg is red")
    return red, detail


def _b21_wrong_path_nv():
    red, detail = _mutant("_evpn_capability_value", _any_path_capability, _b21_wait_bound)
    if red:
        print("MUTATION-FAIL: a capability reader at the wrong path reads the decoy as negotiated -> the bound leg "
              "is red")
    return red, detail


def _old_readback(rt_, lab, node, lines):
    """Packet 4's read-back (cassian-gate@4ec9c72): its return code discarded, so a read with no answer counted
    every line absent."""
    _rc, running = S._sonic_read(rt_, lab, node, S._EVPN_RUNNING_CONFIG_ARGV)
    absent = S._absent_fragment_lines(running, lines)
    if absent:
        S._fail("SONiC EVPN configuration is not in force", node,
                "%d of %d EVPN lines are absent from the running configuration after the push" % (
                    len(absent), len(lines)),
                "absent: " + "; ".join(absent),
                "report this with the guest's running configuration, then run cassian up again")


def _b21_readback_rc_nv():
    red, detail = _mutant("_read_back_evpn_fragment", _old_readback, _b21_readback_rc)
    if red:
        print("MUTATION-FAIL: a read-back that discards its return code -> the exit-1 read-back leg is red")
    return red, detail


def _b21_rc_blind_nv():
    real = getattr(S, "_evpn_json_answer", None)
    if real is None:
        return False, "the provider has no _evpn_json_answer"
    red1, d1 = _mutant("_evpn_json_answer", lambda rc, raw: real(0, raw), _b21_summary_rc)
    red2, d2 = _mutant("_evpn_json_answer", lambda rc, raw: real(0, raw), _b21_neighbour_rc)
    if red1 and red2:
        print("MUTATION-FAIL: a JSON reader that discards the return code -> the exit-1 summary and neighbour legs "
              "are red")
    return red1 and red2, d1 + " | " + d2


_eleg("B21 REQ-45E-65 provision on leaf1: the mode assertion's reads, the staging write, config load, one reconcile "
      "restart, the routing-daemon wait, then the push, the read-back, the summary and the neighbour read, in that "
      "order; the push's argv is the measured form; the read-back's argv is row 67's, held once in the provider",
      _b21_order)
_eleg("B21 NON-VACUITY: that order check reads the push before the restart as wrong (predicate only)", _b21_order_nv)
_eleg("B21 REQ-45E-65 NEGATIVE: no file is written for the fragment (one staging write, the overlay's), and the "
      "operator's exec rule does not admit the push", _b21_no_file)
_eleg("B21 REQ-45E-66, -69 the push returns 1: provision fails at once, exit 2, with U5 and 45E-S11-R3's detail, "
      "and issues nothing after the push", _b21_push_rc)
_eleg("B21 REQ-45E-67, -69 return code 0 and one fragment line absent: provision fails, exit 2, with U6 naming that "
      "line, before any session read", _b21_readback_absent)
_eleg("B21 REQ-45E-67 a fragment line present only in another address-family block counts absent (D23)",
      _b21_readback_elsewhere)
_eleg("B21 NON-VACUITY: a whole-file match finds that line, so the leg above tells the two apart (predicate only)",
      _b21_readback_elsewhere_nv)
_eleg("B21 45E-S11-R4 (re-aimed from packet 4's leg 'a read-back with no answer counts every line absent: U6, 4 "
      "of 4'): a read-back that exits 0 and prints nothing, or white space only, fails, exit 2, with its own text, "
      "never U6's absent lines, and makes no session read", _b21_readback_unanswered)
_eleg("B21 45E-S11-R4 a read-back that exits 1 fails, exit 2, with its own text naming the code, even when it printed "
      "the whole block, and makes no session read", _b21_readback_rc)
_eleg("B21 REQ-45E-68 the peer reads Idle, then Established with advertisedAndReceived: provision returns after that "
      "poll (2 summaries, 1 neighbour read, 1 sleep)", _b21_wait_late)
_eleg("B21 REQ-45E-68, -69 the peer stays Established with advertised: provision fails at the 30 s bound, exit 2, "
      "with U7 naming the peer, its state, its value and the elapsed seconds (31 reads, 30 sleeps)", _b21_wait_bound)
_eleg("B21 45E-S11-R1 a peer not Established gets no neighbour read, and U7 prints EVPN family not-read",
      _b21_not_read)
_eleg("B21 45E-S11-R2 a peer the summary does not list prints not-present", _b21_not_present)
_eleg("B21 45E-S11-R4 an EVPN summary read that exits 1, even with a full answer, prints no-answer as the peer's "
      "state at the 30 s bound (31 summaries, 30 sleeps), with no neighbour read", _b21_summary_rc)
_eleg("B21 45E-S11-R4 an EVPN summary read that exits 0 with output that is not JSON, nothing, or JSON that is not an "
      "object prints no-answer as the peer's state (rulings note 2 §5)", _b21_summary_unformatted)
_eleg("B21 45E-S11-R4 a neighbour read that exits 1, even reading negotiated, prints EVPN family no-answer at the "
      "bound (31 neighbour reads)", _b21_neighbour_rc)
_eleg("B21 45E-S11-R4 a neighbour read that exits 0 with output that is not JSON, nothing, or JSON that is not an "
      "object prints EVPN family no-answer, never absent (rulings note 2 §5)", _b21_neighbour_unformatted)
_eleg("B21 45E-S11-R4 regression: a read with no answer is polled again: a summary that prints nothing on the first "
      "poll, then negotiated, returns after that poll (2 summaries, 1 neighbour read, 1 sleep)",
      _b21_no_answer_then_negotiated)
_eleg("B21 REQ-45E-70 across every leg, one _BGP_RECONCILE_ARGV per provision call and no other start of bgp",
      _b21_restarts)
_eleg("B21 NON-VACUITY: that count reads one added restart as a second start (predicate only)", _b21_restarts_nv)
_eleg("B21 REQ-45E-71 a second provision on the same guest restarts, pushes and reads back again, in that order",
      _b21_second)
_eleg("B21 NON-VACUITY: a wait that reads the neighbour for a peer not Established fails the not-read leg",
      _b21_not_read_nv)
_eleg("B21 NON-VACUITY: provision without the session wait fails the bound leg", _b21_wait_removed_nv)
_eleg("B21 NON-VACUITY: a capability reader at the wrong path fails the bound leg", _b21_wrong_path_nv)
_eleg("B21 NON-VACUITY: a read-back that discards its return code (packet 4's form) fails the exit-1 read-back leg",
      _b21_readback_rc_nv)
_eleg("B21 NON-VACUITY: a JSON reader that discards the return code fails the exit-1 summary and neighbour legs",
      _b21_rc_blind_nv)

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
