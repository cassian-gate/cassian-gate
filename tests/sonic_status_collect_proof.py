#!/usr/bin/env python3
"""SONiC status and collect proof (REQ-45D-19 / REQ-45D-20; handover §9 row 11).

This file is (VM) in the scope's §9 table. Its LAB-FREE legs land first, with the
REQ-45D-19/-20 code (founder ruling S27-R4's order); the live legs land with the (VM)
packet and are reported BLOCKED here until then -- a BLOCKED leg is not a pass.

Founder rulings bound here (2026-10-09): S27-R8 (cmd_status's record and human-output
guards read the capability declaration; expectations stay FRR-derived), S27-R9 (a
provider that does not declare a status leg IMPL keeps today's silence; a None leg is
never called), S27-R10 (SONiC collect targets bgp-summary.txt and vtysh-ip-route.txt;
"the core writer" is cmd_collect's write()), S27-R12 (SONiC copies of FRR's three text
functions, proven output-identical; JSON paths mapped to FRR's shape).

Proof obligations (lab-free):
  SC-WIRE    both status legs callable; both tokens declared IMPL; collect targets are
             exactly (bgp-summary.txt, vtysh-ip-route.txt), in that order; every
             registered provider declaring a status token IMPL has that leg callable
             (the declaration the guard reads never points at a None leg).
  SC-PARITY  each SONiC copy returns output EQUAL to its FRR original on every input
             in a fixed set covering each branch (S27-R12).
  SC-SUMMARY the summary leg over the captured guest `show bgp summary json`
             (tests/fixtures/sonic-4_5d-h1b1/bgp_summary.out): observed EQUALS FRR's
             JSON parser over the same bytes; parser_mode json; data keys EQUAL FRR's.
  SC-ROUTES  the routes leg over the captured full-table RIB read
             (tests/fixtures/sonic-4_5d-h1b3/h1b3_rib_table_after.out): observed EQUALS
             FRR's JSON parser over the same bytes; parser_mode json; data keys EQUAL FRR's.
  SC-STATUS  `cassian status --bgp --routes --json` on a stub lab (r1 frr, s1 sonic-vm,
             f1 nft-fw): s1 carries bgp and routes records, f1 carries neither, nothing
             raises (B09). Human mode prints s1's BGP line (S27-R8).
  SC-UNSUP   the same run with SONiC's legs set to None and its two tokens removed:
             s1 carries no record, the run completes, and a leg that would raise if
             called is never called (S27-R9).
  SC-COLLECT `cassian collect` on the same stub lab writes s1.bgp-summary.txt and
             s1.vtysh-ip-route.txt through core's writer with the targets' content;
             no SONiC target writes a file itself (REQ-45D-20, B10).
  SC-NV      non-vacuity, each counter-example taken from a failure condition:
             a mutated capture changes observed (value checks can fail); a copy that
             differs is caught by the parity comparator; a target that writes its own
             file is caught by the write tracer; an IMPL token with a None leg would be
             called (the guard is what keeps it silent).

Coverage limits, stated in-file (PBE-P2-8):
  - Lab-free. The stub runtime replays captured guest output; no guest is contacted.
    The live legs (`status --routes` on a booted guest, the collect artifact on a
    booted guest) are the (VM) packet's and are BLOCKED here.
  - SC-PARITY's inputs are a fixed set; outputs equal on it do not prove equality on
    every possible input. Both functions are verbatim bodies; the set exercises each
    branch.
  - FRR's JSON parser falls back to peerState/pfxRcd when a peer has no `state`; the
    SONiC reader does not (stated in the leg's docstring). The captured output carries
    `state` on every peer, so SC-SUMMARY's equality holds on it, not on that shape.
  - The write tracer covers builtins.open in a write mode, io.open, os.open with write
    flags, and pathlib's write_text/write_bytes; another write route is uncovered.

Exit 0 when every check passes (BLOCKED legs are listed); exit 1 otherwise.
"""
import argparse
import builtins
import contextlib
import copy
import dataclasses
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402
import cassian_nos_frr as F  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import CAP_IMPL, capability_for  # noqa: E402

if len(sys.argv) > 1:
    print("The (VM) legs of this proof land with the (VM) packet; no live argv is accepted yet.")
    sys.exit(2)

FIX_SUMMARY = os.path.join(ROOT, "tests", "fixtures", "sonic-4_5d-h1b1", "bgp_summary.out")
FIX_RIB = os.path.join(ROOT, "tests", "fixtures", "sonic-4_5d-h1b3", "h1b3_rib_table_after.out")
SUMMARY_JSON = open(FIX_SUMMARY, encoding="utf-8").read()
RIB_JSON = open(FIX_RIB, encoding="utf-8").read()

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


# ---- inputs for the text paths (each branch of the three copied functions) ----
SUM_TEXT = (
    "BGP router identifier 10.1.0.1, local AS number 65100 vrf-id 0\n"
    "BGP table version 4\n"
    "\n"
    "Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc\n"
    "10.0.0.1        4      65200        12        12        0    0    0 00:01:02            3        2 ARISTA01T2\n"
    "10.0.0.3        4      65200         0         0        0    0    0    never      Connect        0 ARISTA02T2\n"
    "10.0.0.5        4      65200         0         0        0    0    0    never       Active        0 N/A\n"
    "fc00::2         4      65200         0         0        0    0    0    never       Active        0 N/A\n"
    "\n"
    "Total number of neighbors 4\n"
)
SUM_NOHEADER = "10.0.0.7 4 65001 5 5 0 0 0 00:00:09 Established\n10.0.0.9 4 65001 0 0 0 0 0 never Idle\n"
SUM_INPUTS = [SUM_TEXT, SUM_NOHEADER, "", "No BGP neighbors found\n", "% Unknown command\n"]
RT_TEXT = (
    "Codes: K - kernel route, C - connected, S - static, B - BGP\n"
    "\n"
    "K>* 0.0.0.0/0 [0/202] via 10.250.0.1, eth0, 00:10:00\n"
    "C>* 10.0.0.0/31 is directly connected, Ethernet0, 00:09:59\n"
    "B>* 192.0.2.0/24 [20/0] via 10.0.0.1, Ethernet0, 00:01:02\n"
    "C>* 10.1.0.1/32 is directly connected, Loopback0, 00:09:59\n"
)
RT_INPUTS = [RT_TEXT, "", "% Unknown command\n", "garbage 300.1.2.3/40 here\n"]
NORM_INPUTS = SUM_INPUTS + ["pre-table line\n" + SUM_TEXT, SUM_TEXT.replace("Up/Down", "UpDown")]


def parity(fa, fb, inputs):
    return all(fa(x) == fb(x) for x in inputs)


# ---- a recording stub runtime (lab-free) -------------------------------------
class _CP:
    def __init__(self, out, rc=0):
        self.stdout = out
        self.stderr = "BANNER: authorised use only\n"
        self.returncode = rc


class StubRuntime:
    def __init__(self, by_node):
        self.by_node = by_node
        self.calls = []

    def exists_id(self, cname):
        return True

    def is_running_id(self, cname):
        return True

    def is_running(self, lab, node):
        return True

    def node_id(self, lab, node):
        return "clab-%s-%s" % (lab, node)

    def sh(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append((node, "sh", cmd))
        return _CP("sh-out %s %s\n" % (node, cmd))

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append((node, "exec", " ".join(cmd)))
        return _CP(self.by_node.get(node, {}).get(" ".join(cmd), ""))


FRR_SUMMARY_JSON = ('{"ipv4Unicast":{"peers":{"10.0.0.0":{"state":"Established","remoteAs":65100,'
                    '"pfxRcd":1}}}}')
OUTPUTS = {
    "r1": {"vtysh -c show bgp summary json": FRR_SUMMARY_JSON,
           "vtysh -c show ip route json": '{"10.9.9.0/24":[{"protocol":"connected"}]}',
           "vtysh -c show bgp summary": SUM_TEXT},
    "s1": {"vtysh -c show bgp summary json": SUMMARY_JSON,
           "vtysh -c show ip route json": RIB_JSON,
           "vtysh -c show bgp summary": SUM_TEXT,
           "vtysh -c show ip route": RT_TEXT},
}

# ---- SC-WIRE -------------------------------------------------------------------
P = S.SONIC_PROVIDER
check("SC-WIRE status_bgp_summary and status_routes are callable",
      callable(P.status_bgp_summary) and callable(P.status_routes))
for tok in ("status_bgp_summary", "status_routes"):
    check("SC-WIRE %s declared IMPL" % tok, capability_for(P, tok).state == CAP_IMPL)
check("SC-WIRE collect targets are exactly bgp-summary.txt, vtysh-ip-route.txt (S27-R10)",
      tuple(t.artifact_name for t in P.collect_targets) == ("bgp-summary.txt", "vtysh-ip-route.txt"))
_mismatch = [(k, tok) for k, prov in sorted(M.NOS_PROVIDERS.items())
             for tok in ("status_bgp_summary", "status_routes")
             if capability_for(prov, tok).state == CAP_IMPL and not callable(getattr(prov, tok))]
check("SC-WIRE every registered provider that declares a status leg IMPL has that leg callable "
      "(%d providers)" % len(M.NOS_PROVIDERS), not _mismatch, repr(_mismatch))

# ---- SC-PARITY (S27-R12) ---------------------------------------------------------
check("SC-PARITY show bgp summary text parser equals FRR's on %d inputs" % len(SUM_INPUTS),
      parity(S._sonic_parse_bgp_summary_text, F.parse_frr_bgp_summary_neighbors, SUM_INPUTS))
check("SC-PARITY show ip route text parser equals FRR's on %d inputs" % len(RT_INPUTS),
      parity(S._sonic_parse_ip_route_text, F.parse_frr_show_ip_route_prefixes, RT_INPUTS))
check("SC-PARITY bgp-summary normaliser equals FRR's on %d inputs" % len(NORM_INPUTS),
      parity(S._sonic_normalize_bgp_summary, F.normalize_bgp_summary, NORM_INPUTS))
_txt = F.parse_frr_bgp_summary_neighbors(SUM_TEXT)
check("SC-PARITY the input set reaches both branches (established and not)",
      any(v["established"] for v in _txt.values()) and any(not v["established"] for v in _txt.values()))
check("SC-PARITY the no-header input reaches the fallback branch",
      F.parse_frr_bgp_summary_neighbors(SUM_NOHEADER).get("10.0.0.7", {}).get("established") is True)

# ---- SC-SUMMARY / SC-ROUTES (captured guest output) --------------------------------
_rt = StubRuntime(OUTPUTS)
_so = P.status_bgp_summary(_rt, "lab", "s1", want_raw=False)
_fo = F._status_bgp_summary(StubRuntime({"r1": OUTPUTS["s1"]}), "lab", "r1", want_raw=False)
check("SC-SUMMARY observed equals FRR's JSON parser over the same captured bytes",
      _so.data["observed"] == F.parse_frr_bgp_summary_neighbors_json(SUMMARY_JSON),
      "%d peers" % len(_so.data["observed"]))
check("SC-SUMMARY the capture yields peers and none Established (stock neighbours)",
      len(_so.data["observed"]) > 0 and not any(v["established"] for v in _so.data["observed"].values()))
check("SC-SUMMARY parser_mode json", _so.data["parser_mode"] == "json")
check("SC-SUMMARY data keys equal FRR's leg", set(_so.data) == set(_fo.data), sorted(_so.data))
check("SC-SUMMARY evidence keys equal FRR's leg", set(_so.evidence) == set(_fo.evidence))
_ro = P.status_routes(StubRuntime(OUTPUTS), "lab", "s1")
_fr = F._status_routes(StubRuntime({"r1": OUTPUTS["s1"]}), "lab", "r1")
check("SC-ROUTES observed equals FRR's JSON parser over the same captured bytes",
      _ro.data["observed"] == F.parse_frr_show_ip_route_prefixes_json(RIB_JSON),
      "%d prefixes" % len(_ro.data["observed"]))
check("SC-ROUTES parser_mode json", _ro.data["parser_mode"] == "json")
check("SC-ROUTES data keys equal FRR's leg", set(_ro.data) == set(_fr.data), sorted(_ro.data))
check("SC-SUMMARY / SC-ROUTES probes read stdout only (the banner never reaches a parse)",
      "BANNER" not in json.dumps(sorted(_so.data["observed"])) and _ro.data["rt_json"] == RIB_JSON.strip())

# ---- SC-STATUS / SC-UNSUP / SC-COLLECT on a stub lab --------------------------------
WORK = tempfile.mkdtemp(prefix="ssc-proof-")
E._bind_workspace_labs_dir(pathlib.Path(WORK))
LAB = "sscproof"
TOPO = {
    "name": LAB,
    "nodes": [{"name": "r1", "type": "frr", "router_id": "192.0.2.51"},
              {"name": "s1", "type": "sonic-vm", "runtime": "vm", "image": "local/sonic-vm:202405",
               "router_id": "192.0.2.52"},
              {"name": "f1", "type": "nft-fw"}],
    "links": [{"endpoints": ["r1:eth1", "s1:eth1"]}, {"endpoints": ["r1:eth2", "f1:eth1"]}],
}
_ld = E.lab_dir(LAB)
_ld.mkdir(parents=True, exist_ok=True)
(_ld / "topology.resolved.yaml").write_text(yaml.safe_dump(TOPO), encoding="utf-8")


def status_run(by_node, json_mode):
    ns = argparse.Namespace(lab=LAB, bgp=True, bgp_verbose=False, strict=False, interfaces=False,
                            summary=False, json=json_mode, routes=True, routes_verbose=False)
    buf, err, exc = io.StringIO(), io.StringIO(), None
    saved = E.get_runtime
    E.get_runtime = lambda *a, **k: StubRuntime(by_node)
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            E.cmd_status(ns)
    except BaseException as ex:  # noqa: BLE001 -- recorded, judged below
        exc = ex
    finally:
        E.get_runtime = saved
    return buf.getvalue(), exc


_out, _exc = status_run(OUTPUTS, True)
_doc = json.loads(_out) if _out.strip().startswith("{") else {}
_recs = {n["name"]: n for n in _doc.get("nodes", [])}
check("SC-STATUS --json completes without an exception", _exc is None, repr(_exc))
check("SC-STATUS s1 (sonic-vm) carries bgp and routes records",
      "bgp" in _recs.get("s1", {}) and "routes" in _recs.get("s1", {}))
check("SC-STATUS s1's bgp record holds the observed sessions with parser json",
      _recs.get("s1", {}).get("bgp", {}).get("parser_mode") == "json"
      and not _recs.get("s1", {}).get("bgp", {}).get("error"))
check("SC-STATUS r1 (frr) still carries both records", "bgp" in _recs.get("r1", {}) and "routes" in _recs.get("r1", {}))
check("SC-STATUS f1 (nft-fw, no status legs) carries neither (today's silence)",
      "bgp" not in _recs.get("f1", {}) and "routes" not in _recs.get("f1", {}))
_hout, _hexc = status_run(OUTPUTS, False)
_s1_block = _hout.split("  - s1")[1].split("  - ")[0] if "  - s1" in _hout else ""
check("SC-STATUS human mode prints s1's BGP line (expected peers FRR-derived: BGP (none))",
      _hexc is None and "BGP (none)" in _s1_block, repr(_s1_block[:120]))

_calls = []


def _boom(*a, **k):
    _calls.append(a)
    raise AssertionError("a status leg that is not declared IMPL was called")


def with_provider(prov, fn):
    saved_e, saved_m = E.NOS_PROVIDERS, M.NOS_PROVIDERS
    m = dict(saved_m)
    m["sonic-vm"] = prov
    E.NOS_PROVIDERS = m
    M.NOS_PROVIDERS = m
    try:
        return fn()
    finally:
        E.NOS_PROVIDERS, M.NOS_PROVIDERS = saved_e, saved_m


_caps = {k: v for k, v in P.capabilities.items() if k not in ("status_bgp_summary", "status_routes")}
_none_prov = dataclasses.replace(P, status_bgp_summary=None, status_routes=None, capabilities=_caps)
_boom_prov = dataclasses.replace(P, status_bgp_summary=_boom, status_routes=_boom, capabilities=_caps)
_u_out, _u_exc = with_provider(_none_prov, lambda: status_run(OUTPUTS, True))
_u_recs = {n["name"]: n for n in (json.loads(_u_out).get("nodes", []) if _u_out.strip().startswith("{") else [])}
check("SC-UNSUP None legs, tokens absent: the run completes", _u_exc is None, repr(_u_exc))
check("SC-UNSUP None legs: s1 carries no bgp or routes record",
      "s1" in _u_recs and "bgp" not in _u_recs["s1"] and "routes" not in _u_recs["s1"])
_b_out, _b_exc = with_provider(_boom_prov, lambda: status_run(OUTPUTS, False))
check("SC-UNSUP a leg that raises if called is never called when undeclared",
      _b_exc is None and not _calls, "calls=%d" % len(_calls))

# write tracer: any file write while a SONiC collect target runs is a provider-side write
_in_target = [False]
_writes = []
_orig = {"open": builtins.open, "io_open": io.open, "os_open": os.open,
         "wt": pathlib.Path.write_text, "wb": pathlib.Path.write_bytes}


def _note(what, target):
    if _in_target[0]:
        _writes.append((what, str(target)))


def _t_open(file, mode="r", *a, **k):
    if any(c in mode for c in "wax+"):
        _note("open", file)
    return _orig["open"](file, mode, *a, **k)


def _t_os_open(path, flags, *a, **k):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
        _note("os.open", path)
    return _orig["os_open"](path, flags, *a, **k)


def _t_wt(self, *a, **k):
    _note("write_text", self)
    return _orig["wt"](self, *a, **k)


def _t_wb(self, *a, **k):
    _note("write_bytes", self)
    return _orig["wb"](self, *a, **k)


def traced_targets(targets):
    out = []
    for t in targets:
        def run(rt, lab, node, _r=t.run):
            _in_target[0] = True
            try:
                return _r(rt, lab, node)
            finally:
                _in_target[0] = False
        out.append(dataclasses.replace(t, run=run))
    return tuple(out)


def collect_run(prov):
    _writes.clear()
    tprov = dataclasses.replace(prov, collect_targets=traced_targets(prov.collect_targets))
    saved_rt, saved_run = E.get_runtime, E.run
    E.get_runtime = lambda *a, **k: StubRuntime(OUTPUTS)
    E.run = lambda *a, **k: _CP("[]")
    builtins.open, io.open, os.open = _t_open, _t_open, _t_os_open
    pathlib.Path.write_text, pathlib.Path.write_bytes = _t_wt, _t_wb
    exc = None
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with_provider(tprov, lambda: E.cmd_collect(argparse.Namespace(lab=LAB)))
    except BaseException as ex:  # noqa: BLE001
        exc = ex
    finally:
        builtins.open, io.open, os.open = _orig["open"], _orig["io_open"], _orig["os_open"]
        pathlib.Path.write_text, pathlib.Path.write_bytes = _orig["wt"], _orig["wb"]
        E.get_runtime, E.run = saved_rt, saved_run
    return exc, list(_writes)


_cexc, _cw = collect_run(P)
_art = E.lab_dir(LAB) / "artifacts"
_bgp_art = _art / "s1.bgp-summary.txt"
_rib_art = _art / "s1.vtysh-ip-route.txt"
check("SC-COLLECT cmd_collect completes on the stub lab", _cexc is None, repr(_cexc))
check("SC-COLLECT s1.bgp-summary.txt carries the normalised summary, through core's writer",
      _bgp_art.exists() and _bgp_art.read_text(encoding="utf-8") == S._sonic_normalize_bgp_summary(SUM_TEXT))
check("SC-COLLECT s1.vtysh-ip-route.txt carries the routing daemon's table, through core's writer",
      _rib_art.exists() and _rib_art.read_text(encoding="utf-8") == RT_TEXT.rstrip() + "\n")
check("SC-COLLECT the core kernel-table artifact s1.ip-route.txt is a separate file (S27-R10)",
      (_art / "s1.ip-route.txt").exists() and (_art / "s1.ip-route.txt").read_text(encoding="utf-8") != _rib_art.read_text(encoding="utf-8"))
check("SC-COLLECT no SONiC target wrote a file itself", not _cw, repr(_cw[:3]))
check("SC-COLLECT the SSH banner (stderr) reaches no artifact",
      "BANNER" not in _bgp_art.read_text(encoding="utf-8") and "BANNER" not in _rib_art.read_text(encoding="utf-8"))

# ---- SC-NV ----------------------------------------------------------------------
_mut = json.loads(SUMMARY_JSON)
_first = sorted(_mut["ipv4Unicast"]["peers"])[0]
_mut["ipv4Unicast"]["peers"][_first]["state"] = "Established"
_mo = P.status_bgp_summary(StubRuntime({"s1": dict(OUTPUTS["s1"], **{"vtysh -c show bgp summary json": json.dumps(_mut)})}),
                           "lab", "s1")
check("SC-NV a mutated capture changes observed (the value checks can fail)",
      _mo.data["observed"] != _so.data["observed"] and _mo.data["observed"][_first]["established"] is True)
check("SC-NV the parity comparator catches a copy that differs",
      not parity(lambda x: S._sonic_normalize_bgp_summary(x) + "x", F.normalize_bgp_summary, NORM_INPUTS))


def _writer(rt, lab, node):
    (E.lab_dir(LAB) / "artifacts" / "s1.handrolled.txt").write_text("x", encoding="utf-8")
    return S._sonic_collect_bgp_summary_artifact(rt, lab, node)


_bad = dataclasses.replace(P, collect_targets=(dataclasses.replace(P.collect_targets[0], run=_writer),))
_nexc, _nw = collect_run(_bad)
check("SC-NV a target that writes its own file is caught by the write tracer",
      _nexc is None and any("s1.handrolled.txt" in w[1] for w in _nw), repr(_nw[:2]))
_impl_none = dataclasses.replace(P, status_bgp_summary=None, status_routes=None)
_n_out, _n_exc = with_provider(_impl_none, lambda: status_run(OUTPUTS, True))
_n_recs = {n["name"]: n for n in (json.loads(_n_out).get("nodes", []) if _n_out.strip().startswith("{") else [])}
check("SC-NV with the tokens still IMPL, a None leg IS reached (recorded as an error): the guard is "
      "what keeps SC-UNSUP silent", "error" in _n_recs.get("s1", {}).get("bgp", {}))

shutil.rmtree(WORK, ignore_errors=True)

blocked.append(("SC-LIVE-ROUTES (VM): `cassian status --routes` on a booted SONiC guest",
                "lands with the (VM) packet"))
blocked.append(("SC-LIVE-COLLECT (VM): collect artifacts for a booted SONiC node with zero sessions",
                "lands with the (VM) packet"))

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
for name, why in blocked:
    print("[BLOCKED] %s -- %s" % (name, why))
print("=" * 60)
print("cases:", len(checks), "blocked:", len(blocked))
print("RESULT:", "PASS" if ok else "FAIL", "(a BLOCKED leg is not a pass)")
sys.exit(0 if ok else 1)
