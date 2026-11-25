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
measured at `9663477`. COVERAGE LIMIT (PBE-P2-8): the provider's own
`provision` is not run on an EVPN participant here; its push, read-backs and
session wait are rule B21's.
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
