#!/usr/bin/env python3
"""HS-8 -- unusable-read sweep proof (Stage-1 gap item (d)(2), WI-15 script 2; PO-32, REQ-S1D2-42, C-32).

Founder rulings: S1D2-S9-R1 to -R6 (rulings note 17); S1D2-S10-R6 (rulings note 21); S1D2-S18-R1 to -R5
(rulings note 31); the shared unusable-read rule of S1D2-S1-R18 (rulings note 4).

REQ-S1D2-42 (S1D2-S18-R2: the text of rulings note 17 section 4 reading 4, where `-R1` is S1D2-S9-R1): "on every
check and node type the catalogue marks implemented, on the test path and in scenario `wait_for`, a read that
produced no answer (`-R1`) fails whatever `expect` says and carries evidence `read_unusable`; an answer in the
reader's format keeps its verdict. Failure: any such cell passes, or an answering read changes verdict."

Legs
  F  FORMAT   the in-file FORMAT table declares the reader's format of exactly the cells the catalogue marks
              implemented: a cell missing from it, or an entry for a cell that is not implemented, fails the proof.
  S  SWEEP    every implemented (check, node type) cell on the test path, under both expects, in each failure mode
              its declared format admits: the read raised; it exited 255 with a stderr line; and, for a JSON reader
              only, output that is not JSON and empty output (S1D2-S9-R4; S1D2-S10-R6 (i), (iii)). A cell that
              PASSES is a silent false pass and fails the proof. A raise or a non-zero exit is loud: counted, not
              judged (S1D2-S9-R4). A cell the harness cannot drive fails the proof.
  W  WAIT     every type wait_for_predicate dispatches (read from its source), on every node type where that check
              is implemented, the same modes, under both expects: a step that PASSES fails the proof.
  U  UNUSABLE every test-path cell recorded `fail` carries evidence `read_unusable`.
  A  ANSWER   every answer the in-file ANSWERS table gives a json or text cell (output in that reader's own format,
              which the reader classifies as answered), on the test path and in wait_for, under both expects: the
              outcome on the live code equals the outcome with `_read_unusable` disabled, no record carries
              `read_unusable`, and every cell reaches a verdict on at least one of its answers (S1D2-S18-R3).
  A2 SHAPE    S1D2-S18-R5: on every implemented interface_state cell, valid JSON outside that reader's own format
              (`{}`, `[]`, a list of two interfaces, an operstate outside the seven kernel values) is no answer: it
              fails under both expects and carries `read_unusable`; with `_read_unusable` disabled, `expect: fail`
              passes on it (the leg's control).
  R  RENDER   every unanswered test-path cell whose record is a collection failure, rendered through the real
              cassian_tests._format_test_summary: its `<type> collection failed on '<node>': <reason>` line, and,
              for an invariant record, no observed_state and the absence block (E4; S1D2-S18-R4).
  M  MUTANTS  the S and W sweep again, each in a subprocess, with one decision disabled in memory:
              `_read_unusable` returns None; the providers' `_output_is_not_json` returns False; the probe
              helpers `_probe_unusable` and `_probe_exit_unexplained` return None; and FRR's route_prefix reader
              (`ip -4 route show`, a text reader no shared decision covers) declares every completed read answered,
              by an anchored one-line edit of its source. Each mutant must make named cells pass silently and its
              sweep fail; the unmutated sweep above is the control (S1D2-S18-R3, C-32).

Coverage limits (PBE-P2-8), stated so a PASS is not read as more than it is:
  1. A mock runtime and one two-node topology stub (n1 of the type under test, n2 an frr peer). No device, no
     lab; what a real device prints when a read gives no answer is not exercised here.
  2. FORMAT is a hand declaration, bound to the catalogue's implemented cells by leg F but not derived from the
     readers' code: a reader whose declared format is wrong is swept in the wrong modes.
  3. The text reader (FRR route_prefix, `ip -4 route show`) is swept for a raise and exit 255 only: for it, empty
     output is the route's absence, an answer (S1D2-S10-R6 (i)), and any text is in its format.
  4. ping, tcp and exec are swept for a raise and exit 255 only; their unusable-read texts are WI-13's and
     WI-14's, rendered by HS-7 (tests/probe_unusable_verdict_proof.py), not by leg R.
  5. Loud cells are counted, not judged: a raise escaping the check function or an exit 2 (rows BL-P2-S1D2-45 and
     -53). A wait_for with expect: pass that never succeeds no longer raises TypeError: row BL-P2-4.5c-243 is
     fixed in the 4.5-e base (REQ-45E-12, rule B06), and such a wait is a failed outcome.
  6. Each mutant shows that the sweep fails when that one decision is disabled. A future site that bypasses every
     shared decision is caught by the sweep itself on the live code, not by a mutant.
  7. Leg A's answers are the ANSWERS table's, one to three per cell, hand-written in each reader's format; other
     in-format answers (a "no BGP instance" body, a table with many rows) are not swept. A wait_for with
     expect: pass on an answer that never satisfies it is a failed outcome, no longer a TypeError (row
     BL-P2-4.5c-243, fixed by REQ-45E-12): compared, not judged.
  8. The failure modes are injected at the runtime's exec seam. A read that does not go through rt.exec is not
     reached by any mode, and is visible here only as a cell that does not fail.
  9. JSON in the wrong shape is not a sweep mode. Whether it is an answer is the reader's own declaration
     (probe_ok, S1D2-S18-R5); this proof meets it in leg A2 for interface_state, and where ANSWERS avoids `{}`
     because a reader's format rules it out.

usage: python tests/unusable_read_sweep_proof.py           (the proof; PYTHONPATH=src, from the repo root)
       python tests/unusable_read_sweep_proof.py --cells   (prints the implemented cells, for FORMAT)
       python tests/unusable_read_sweep_proof.py --mutant <name>   (leg M's child; a name in MUTANTS)
"""
import ast
import collections
import contextlib
import inspect
import io
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import cassian_catalogue as C  # noqa: E402
import cassian_engine as E  # noqa: E402
import cassian_nos_frr as NOS_FRR  # noqa: E402
import cassian_nos_sonic as NOS_SONIC  # noqa: E402
import cassian_tests as T  # noqa: E402

# The reader's format of every (check, node type) cell the catalogue marks implemented (leg F binds it).
#   json  -- a JSON reader: swept for raise, exit 255, output that is not JSON and empty output
#   text  -- a text reader: swept for raise and exit 255 (coverage limit 3)
#   probe -- the ping/tcp dataplane probe: raise and exit 255 (coverage limit 4)
#   exec  -- a user-declared command: raise and exit 255 (coverage limit 4)
FORMAT = {
    ("bgp_as_path", "frr"): "json", ("bgp_as_path", "sonic-vm"): "json",
    ("bgp_community", "frr"): "json", ("bgp_community", "sonic-vm"): "json",
    ("bgp_localpref_equals", "frr"): "json", ("bgp_localpref_equals", "sonic-vm"): "json",
    ("bgp_med_equals", "frr"): "json", ("bgp_med_equals", "sonic-vm"): "json",
    ("bgp_neighbor", "frr"): "json", ("bgp_neighbor", "sonic-vm"): "json",
    ("bgp_session_up", "frr"): "json", ("bgp_session_up", "sonic-vm"): "json",
    ("evpn_bgp_session_up", "frr"): "json",
    ("evpn_mac_route_absent", "frr"): "json",
    ("evpn_mac_route_present", "frr"): "json",
    ("evpn_vni_route_present", "frr"): "json",
    ("exec", "frr"): "exec", ("exec", "nft-fw"): "exec", ("exec", "sonic-vm"): "exec",
    ("interface_state", "frr"): "json", ("interface_state", "nft-fw"): "json",
    ("ospf_neighbor_up", "frr"): "json",
    ("ping", "frr"): "probe", ("ping", "nft-fw"): "probe", ("ping", "sonic-vm"): "probe",
    ("route_absent", "frr"): "json", ("route_absent", "sonic-vm"): "json",
    ("route_advertised_to", "frr"): "json", ("route_advertised_to", "sonic-vm"): "json",
    ("route_not_advertised_to", "frr"): "json", ("route_not_advertised_to", "sonic-vm"): "json",
    ("route_prefix", "frr"): "text", ("route_prefix", "sonic-vm"): "json",
    ("route_present", "frr"): "json", ("route_present", "sonic-vm"): "json",
    ("tcp", "frr"): "probe", ("tcp", "nft-fw"): "probe",
}

MODES = {"json": ("raise", "rc255", "garbage", "empty"), "text": ("raise", "rc255"),
         "probe": ("raise", "rc255"), "exec": ("raise", "rc255")}
EXPECTS = ("pass", "fail")

# Leg A's answers: output in the reader's own format, which the reader classifies as answered (probe_ok True,
# S1D2-S9-R2). A json cell answers `{}` and the text cell empty output (the route's absence, S1D2-S10-R6 (i)),
# except where the reader's format rules `{}` out or `{}` ends before a verdict:
IFACE_UP = '[{"ifname": "eth1", "flags": ["BROADCAST", "UP", "LOWER_UP"], "operstate": "UP"}]'
RIB_HAS = '{"10.9.9.0/24": [{"prefix": "10.9.9.0/24"}]}'
RIB_OTHER = '{"10.8.8.0/24": [{"prefix": "10.8.8.0/24"}]}'
BGP_PFX = '{"prefix": "10.9.9.0/24", "paths": [{"metric": 100, "locPrf": 100, "bestpath": {"overall": true}}]}'
ADV_HAS = '{"advertisedRoutes": {"10.9.9.0/24": {"prefix": "10.9.9.0/24"}}}'
ADV_NONE = '{"advertisedRoutes": {}}'
ANSWERS = {
    # the engine's interface_state reader (`ip -j link show <if>`) takes one JSON list holding one interface
    # object with a closed-set operstate (H5 B-RT06); on `{}` it leaves probe_ok False: no answer (S1D2-S18-R5)
    ("interface_state", "frr"): (IFACE_UP,), ("interface_state", "nft-fw"): (IFACE_UP,),
    # SONiC's one RIB read takes a non-empty JSON object keyed by IPv4 prefixes; `{}` is its "empty RIB read",
    # probe_ok False (cassian_nos_sonic._rib_prefixes)
    ("route_present", "sonic-vm"): (RIB_HAS, RIB_OTHER), ("route_absent", "sonic-vm"): (RIB_HAS, RIB_OTHER),
    ("route_prefix", "sonic-vm"): (RIB_HAS, RIB_OTHER),
    ("route_present", "frr"): ("{}", RIB_HAS), ("route_absent", "frr"): ("{}", RIB_HAS),
    # `{}` is an answer here but ends in exit 2 (the evidence-normalization misuse exit); the second answer
    # reaches a verdict
    ("bgp_med_equals", "frr"): ("{}", BGP_PFX), ("bgp_med_equals", "sonic-vm"): ("{}", BGP_PFX),
    ("bgp_localpref_equals", "frr"): ("{}", BGP_PFX), ("bgp_localpref_equals", "sonic-vm"): ("{}", BGP_PFX),
    ("route_advertised_to", "sonic-vm"): ("{}", ADV_HAS, ADV_NONE),
    ("route_not_advertised_to", "sonic-vm"): ("{}", ADV_HAS, ADV_NONE),
}


def answers(cid, nt, fmt):
    return ANSWERS.get((cid, nt), ("{}",) if fmt == "json" else ("",))


# Leg M's mutants. FRR's route_prefix read flag is decided from the exit code in the reader itself (WI-15 script 1a);
# its mutant edits that one line in memory, so exit 255 reads as an answer again.
MUTANTS = ("read_unusable", "output_is_not_json", "probe", "route_prefix_read_flag")
ROUTE_PREFIX_FLAG = "probe_ok=(rc in (0, None))),"

# Leg A2's outputs: valid JSON outside the interface_state reader's own format (S1D2-S18-R5).
SHAPES = ("{}", "[]", '[{"ifname": "eth1", "operstate": "UP"}, {"ifname": "eth2", "operstate": "UP"}]',
          '[{"ifname": "eth1", "flags": ["UP", "LOWER_UP"], "operstate": "SIDEWAYS"}]')
ABSENCE = "detail: (structured failure detail unavailable for this invariant type)"

ENG = (SRC / "cassian_engine.py").read_text(encoding="utf-8")
_LINES = ENG.splitlines(keepends=True)
_CT = [n for n in ast.parse(ENG).body if isinstance(n, ast.FunctionDef) and n.name == "cmd_test"][0]
CHILD = {n.name: textwrap.dedent("".join(_LINES[n.lineno - 1:n.end_lineno]))
         for n in _CT.body if isinstance(n, ast.FunctionDef)}

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


class CP:
    def __init__(self, rc, out, err):
        self.returncode, self.stdout, self.stderr, self.args = rc, out, err, []


class ModeRT:
    """A runtime whose every read fails in one mode, or answers `answer` with exit 0."""

    def __init__(self, mode, answer=None):
        self.mode, self.answer, self.calls = mode, answer, []

    def is_running(self, *a, **k):
        return True

    def exec(self, lab, node, argv, *a, **k):
        self.calls.append(argv)
        if self.mode == "answer":
            return CP(0, self.answer, "")
        if self.mode == "raise":
            raise RuntimeError("HS-8 runtime: transport down")
        if self.mode == "rc255":
            return CP(255, "", "ssh: connect to host n1: Connection refused")
        if self.mode == "empty":
            return CP(0, "", "")
        return CP(0, "<<HS-8: output that is not JSON>>", "")

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: self.exec(None, None, [name])


def topo_for(nt):
    return {"name": "lab", "nodes": [{"name": "n1", "type": nt}, {"name": "n2", "type": "frr"}],
            "links": [{"endpoints": ["n1:eth1", "n2:eth1"], "ipv4": ["10.0.0.1/31", "10.0.0.2/31"]}]}


OVERRIDES = {}


def make_ns(rt, nt, cap, real_retry=False):
    ns = dict(E.__dict__)
    for name, text in CHILD.items():
        try:
            exec(compile(text, "<hs8:%s>" % name, "exec"), ns)
        except Exception:
            pass
    ns.update(rt=rt, lab="lab", topo=topo_for(nt), _ip_j_capability_cache={},
              node_ip_or_die=lambda n: "10.0.0.2", start_listener=lambda d, p: None,
              record_test=lambda **kw: cap.update(kw))
    if not real_retry:
        ns["retry_until"] = lambda to, iv, fn: (lambda r: (r[0], r[1], 1, 0))(fn())
    ns.update(OVERRIDES)
    return ns


VAL = {"node": "n2", "ipv4": "10.0.0.2", "ip": "10.0.0.2", "cidr": "10.9.9.0/24", "mac": "aa:bb:cc:00:00:01",
       "integer": 100, "as_path_regex": "^65002$", "community": "65000:1", "community_list": "65000:1",
       "string": "eth1", "exec_assertion": {"contains": "FRRouting"}}


def build_t(cid, kind, expect):
    t = {"name": "hs8", "kind": kind, "expect": expect, "timeout_s": 0}
    if kind == "invariant":
        t["type"] = cid
    for p in C.CHECK_PARAMETERS[cid].get("params", C.CHECK_PARAMETERS[cid].get("parameters", ())):
        if not p[4]:
            continue
        nm, ty = p[0], p[1][0]
        v = VAL.get(ty, "x")
        if nm in ("node", "src"):
            v = "n1"
        if nm == "command":
            v = 'vtysh -c "show version"'
        if nm == "port":
            v = 179
        t[nm] = v
    return t


def run_test_path(cid, kind, nt, rt, expect):
    """(outcome, record): outcome is the verdict, EXIT(n), RAISE(type), HARNESS(...) or NOREC."""
    cap = {}
    ns = make_ns(rt, nt, cap)
    t = build_t(cid, kind, expect)
    rf = lambda **kw: cap.update(kw)  # noqa: E731
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            if kind == "ping":
                t["dst"] = "10.0.0.2"
                ns["run_ping_test"](test_name="hs8", src="n1", dst="10.0.0.2", t=t, record_fn=rf)
            elif kind == "tcp":
                ns["run_tcp_test"](test_name="hs8", src="n1", dst="n2", t=t, record_fn=rf)
            elif kind == "bgp_neighbor":
                ns["run_bgp_neighbor_test"](test_name="hs8", src="n1", dst=t["dst"], t=t, record_fn=rf)
            elif kind == "route_prefix":
                ns["run_route_prefix_test"](test_name="hs8", src="n1", t=t, record_fn=rf)
            elif kind == "exec":
                ns["run_exec_test"](test_name="hs8", src="n1", t=t, record_fn=rf)
            else:
                ns["run_invariant_test"](test_name="hs8", src="n1", t=t, record_fn=rf)
    except NameError as e:
        return "HARNESS(%s)" % e, cap
    except SystemExit as e:
        return "EXIT(%s)" % e.code, cap
    except Exception as e:
        return "RAISE(%s)" % type(e).__name__, cap
    return (cap.get("verdict") or "NOREC"), cap


WF = {"ping": {"to": "10.0.0.2"}, "tcp": {"to": "n2", "port": 179}, "bgp_session_up": {"dst": "10.0.0.2"},
      "route_present": {"prefix": "10.9.9.0/24"}, "route_advertised_to": {"peer": "n2", "prefix": "10.9.9.0/24"},
      "evpn_bgp_session_up": {"peer": "n2"}, "evpn_vni_route_present": {"vni": 100},
      "evpn_mac_route_present": {"mac": "aa:bb:cc:00:00:01", "vni": 100},
      "route_prefix": {"src": "n1", "prefix": "10.9.9.0/24"}}


def wait_types():
    """The constant types wait_for_predicate compares `wtype` against, read from its source."""
    fn = ast.parse(CHILD["wait_for_predicate"])
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "wtype":
            for comp in node.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                    out.add(comp.value)
                elif isinstance(comp, ast.Tuple):
                    out.update(e.value for e in comp.elts if isinstance(e, ast.Constant))
    return out


def run_wait(wtype, nt, rt, expect):
    ns = make_ns(rt, nt, {}, real_retry=True)
    wf = {"type": wtype, "from": "n1", "expect": expect, "timeout": 1, "interval_s": 0.2, **WF[wtype]}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            res = ns["wait_for_predicate"](wf)
    except NameError as e:
        return "HARNESS(%s)" % e
    except (ValueError, RuntimeError):
        return "RAISE"
    except TypeError:
        return "TYPEERR"
    except SystemExit as e:
        return "EXIT(%s)" % e.code
    except Exception as e:
        return "RAISE(%s)" % type(e).__name__
    return res[5]


def implemented_cells():
    nts = [n["type"] for n in C._node_types()]
    status = {}
    for c in C._checks(C._node_types()):
        for nt, cell in (c.get("status") or {}).items():
            status[(c["id"], nt)] = cell.get("state") if isinstance(cell, dict) else cell
    return [(cid, kind, nt) for cid, kind in C._check_universe() for nt in nts
            if status.get((cid, nt)) == "implemented"]


def kind_of(cid):
    return dict(C._check_universe())[cid]


def sweep():
    """Legs S and W on the code as it stands (with any OVERRIDES). Returns (silent, loud, failed, gaps, records)."""
    silent, gaps, failed, records = [], [], 0, []
    loud = collections.Counter()
    for cid, kind, nt in implemented_cells():
        fmt = FORMAT.get((cid, nt))
        if fmt is None:
            continue
        for mode in MODES[fmt]:
            for exp in EXPECTS:
                out, rec = run_test_path(cid, kind, nt, ModeRT(mode), exp)
                cell = ("test", cid, nt, mode, exp)
                if out == "pass":
                    silent.append(cell)
                elif out == "fail":
                    failed += 1
                    records.append((cell, kind, rec))
                elif out.startswith("HARNESS") or out == "NOREC":
                    gaps.append(cell + (out,))
                else:
                    loud[out.split("(")[0]] += 1
    for wtype in sorted(wait_types()):
        cid = wtype
        for nt in [n["type"] for n in C._node_types()]:
            fmt = FORMAT.get((cid, nt))
            if fmt is None:
                continue
            for mode in MODES[fmt]:
                for exp in EXPECTS:
                    out = run_wait(wtype, nt, ModeRT(mode), exp)
                    cell = ("wait", wtype, nt, mode, exp)
                    if out == "pass":
                        silent.append(cell)
                    elif out == "fail":
                        failed += 1
                    elif str(out).startswith("HARNESS"):
                        gaps.append(cell + (out,))
                    else:
                        loud[str(out).split("(")[0]] += 1
    return silent, loud, failed, gaps, records


def mutant_main(name):
    if name == "read_unusable":
        OVERRIDES["_read_unusable"] = lambda read_ok, evidence: None
    elif name == "output_is_not_json":
        NOS_FRR._output_is_not_json = lambda out: False
        NOS_SONIC._output_is_not_json = lambda out: False
    elif name == "probe":
        OVERRIDES["_probe_unusable"] = lambda *a, **k: None
        OVERRIDES["_probe_exit_unexplained"] = lambda *a, **k: None
    elif name == "route_prefix_read_flag":
        text = inspect.getsource(NOS_FRR._collect_route_prefix)
        if text.count(ROUTE_PREFIX_FLAG) != 1:
            raise SystemExit("mutant route_prefix_read_flag: anchor %r not found exactly once" % ROUTE_PREFIX_FLAG)
        exec(compile(text.replace(ROUTE_PREFIX_FLAG, "probe_ok=True),"), "<hs8:mutant>", "exec"), NOS_FRR.__dict__)
        NOS_FRR._COLLECT_HANDLERS["route_prefix"] = NOS_FRR._collect_route_prefix
    else:
        raise SystemExit("unknown mutant %r" % name)
    silent, loud, failed, gaps, _ = sweep()
    for s in silent:
        print("SILENT", *s)
    print("MUTANT %s silent=%d failed=%d loud=%d gaps=%d" % (name, len(silent), failed, sum(loud.values()), len(gaps)))
    sys.exit(1 if silent else 0)


def main():
    cells = implemented_cells()
    keys = {(cid, nt) for cid, _k, nt in cells}
    missing = sorted(keys - set(FORMAT))
    stale = sorted(set(FORMAT) - keys)
    bad = sorted(k for k, v in FORMAT.items() if v not in MODES)
    check("F FORMAT declares exactly the %d implemented cells (catalogue)" % len(keys),
          not missing and not stale and not bad, "missing=%s stale=%s bad=%s" % (missing, stale, bad))
    wt = wait_types()
    check("W wait_for_predicate's types are the types this proof drives", wt == set(WF),
          "engine=%s proof=%s" % (sorted(wt), sorted(WF)))

    silent, loud, failed, gaps, records = sweep()
    check("S/W no cell passes on a read that produced no answer (test path and wait_for)", not silent,
          "silent=%s" % silent[:6])
    check("S/W the harness drives every cell", not gaps, "gaps=%s" % gaps[:6])
    print("    counts: fail=%d loud=%s silent=%d gaps=%d" % (failed, dict(loud), len(silent), len(gaps)))

    no_key = [c for c, _k, r in records if "read_unusable" not in (r.get("evidence") or {})]
    check("U every test-path cell recorded fail carries evidence read_unusable", not no_key and records,
          "fail records=%d without the key=%s" % (len(records), no_key[:6]))

    diffs, keyed, unjudged, n, judged = [], [], [], 0, collections.Counter()
    a_stale = sorted(k for k in ANSWERS if FORMAT.get(k) not in ("json", "text"))
    for cid, kind, nt in cells:
        fmt = FORMAT.get((cid, nt))
        if fmt not in ("json", "text"):
            continue
        verdicts = set()
        for answer in answers(cid, nt, fmt):
            for exp in EXPECTS:
                live, rec = run_test_path(cid, kind, nt, ModeRT("answer", answer), exp)
                OVERRIDES["_read_unusable"] = lambda read_ok, evidence: None
                try:
                    mut, _ = run_test_path(cid, kind, nt, ModeRT("answer", answer), exp)
                finally:
                    OVERRIDES.pop("_read_unusable", None)
                n += 1
                judged[live.split("(")[0]] += 1
                if live in ("pass", "fail"):
                    verdicts.add(live)
                if live != mut:
                    diffs.append(("test", cid, nt, answer[:20], exp, live, mut))
                if "read_unusable" in (rec.get("evidence") or {}):
                    keyed.append(("test", cid, nt, answer[:20], exp))
        if not verdicts:
            unjudged.append(("test", cid, nt))
    for wtype in sorted(wt):
        for nt in [x["type"] for x in C._node_types()]:
            fmt = FORMAT.get((wtype, nt))
            if fmt not in ("json", "text"):
                continue
            verdicts = set()
            for answer in answers(wtype, nt, fmt):
                for exp in EXPECTS:
                    live = run_wait(wtype, nt, ModeRT("answer", answer), exp)
                    OVERRIDES["_read_unusable"] = lambda read_ok, evidence: None
                    try:
                        mut = run_wait(wtype, nt, ModeRT("answer", answer), exp)
                    finally:
                        OVERRIDES.pop("_read_unusable", None)
                    n += 1
                    judged["wait " + str(live).split("(")[0]] += 1
                    if live in ("pass", "fail"):
                        verdicts.add(live)
                    if live != mut:
                        diffs.append(("wait", wtype, nt, answer[:20], exp, live, mut))
            if not verdicts:
                unjudged.append(("wait", wtype, nt))
    print("    answers: reads=%d outcomes=%s" % (n, dict(sorted(judged.items()))))
    check("A ANSWERS names only json or text cells", not a_stale, "stale=%s" % a_stale)
    check("A an answer keeps its outcome with _read_unusable disabled (%d answering reads)" % n,
          n and not diffs, "differ=%s" % diffs[:6])
    check("A no answering read carries read_unusable", not keyed, "keyed=%d %s" % (len(keyed), keyed[:6]))
    check("A every answering cell reaches a verdict on one of its answers (test path and wait_for)",
          n and not unjudged, "unjudged=%s" % unjudged[:6])

    shape_bad, shape_n, shape_ctl = [], 0, 0
    for cid, kind, nt in cells:
        if cid != "interface_state":
            continue
        for answer in SHAPES:
            for exp in EXPECTS:
                live, rec = run_test_path(cid, kind, nt, ModeRT("answer", answer), exp)
                OVERRIDES["_read_unusable"] = lambda read_ok, evidence: None
                try:
                    mut, _ = run_test_path(cid, kind, nt, ModeRT("answer", answer), exp)
                finally:
                    OVERRIDES.pop("_read_unusable", None)
                shape_n += 1
                if live != "fail" or "read_unusable" not in (rec.get("evidence") or {}):
                    shape_bad.append((cid, nt, answer[:20], exp, live))
                if exp == "fail" and mut == "pass":
                    shape_ctl += 1
    check("A2 interface_state JSON outside its reader's format is no answer (S1D2-S18-R5)",
          shape_n and not shape_bad and shape_ctl == shape_n // 2,
          "reads=%d bad=%s expect-fail passes with the rule off=%d" % (shape_n, shape_bad[:6], shape_ctl))

    rendered, bad_render = 0, []
    for cell, kind, rec in records:
        err = str(rec.get("error") or "")
        if " collection failed on " not in err:
            continue
        t = {"name": rec.get("name"), "kind": rec.get("kind"), "from": rec.get("src"), "to": rec.get("dst"),
             "expected": rec.get("expected"), "observed": rec.get("observed"), "verdict": rec.get("verdict"),
             "duration_ms": 0, "error": rec.get("error"), "evidence": rec.get("evidence"), "meta": rec.get("meta"),
             "observed_state": rec.get("observed_state")}
        doc = {"lab": "hs8", "result": "fail", "summary": {"total": 1, "passed": 0, "failed": 1},
               "tests": [t], "scenarios": [], "events": []}
        lines = T._format_test_summary(doc).splitlines()
        rendered += 1
        cf = any(" collection failed on 'n1': " in ln for ln in lines)
        ok = cf
        if rec.get("kind") == "invariant":
            ok = ok and rec.get("observed_state") is None and any(ln.strip() == ABSENCE for ln in lines)
        if not ok:
            bad_render.append(cell)
    check("R each collection-failure record renders its collection failure (and, for an invariant, the absence block)",
          rendered and not bad_render, "rendered=%d bad=%s" % (rendered, bad_render[:6]))

    for name in MUTANTS:
        r = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--mutant", name],
                           capture_output=True, text=True, timeout=1800,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        named = [ln[len("SILENT "):] for ln in r.stdout.splitlines() if ln.startswith("SILENT ")]
        tail = (r.stdout.strip().splitlines() or [""])[-1]
        check("M mutant %s: named cells pass silently and its sweep fails" % name,
              r.returncode == 1 and named, "rc=%s silent=%d e.g. %s | %s" % (r.returncode, len(named), named[:2], tail))

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cells":
        for cid, kind, nt in implemented_cells():
            print("CELL", cid, kind, nt)
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[1] == "--mutant":
        mutant_main(sys.argv[2])
    main()
