#!/usr/bin/env python3
"""SONiC status and collect proof (REQ-45D-19 / REQ-45D-20; handover §9 row 11).

This file is (VM) in the scope's §9 table. Its LAB-FREE legs landed first, with the
REQ-45D-19/-20 code (founder ruling S27-R4's order). Its live legs land with the (VM)
packet, VM-5, under founder rulings S36-R1 to S36-R3 of 2026-10-20 (the session-36
rulings note, cassian-gate-internal@ecb5da5, Ledger §159): one fixture, one boot
(S27-R4, LD-45D-6) -- topologies/sonic-status-collect.yaml, one frr node and one sonic-vm
guest with a declared loopback and link addresses and no BGP declared. Without live argv
the live legs are reported BLOCKED -- a BLOCKED leg is not a pass.

Founder rulings bound here (2026-10-09): S27-R8 (cmd_status's record and human-output
guards read the capability declaration; expectations stay FRR-derived), S27-R9 (a
provider that does not declare a status leg IMPL keeps today's silence; a None leg is
never called), S27-R10 (SONiC collect targets bgp-summary.txt and vtysh-ip-route.txt;
"the core writer" is cmd_collect's write()), S27-R12 (SONiC copies of FRR's three text
functions, proven output-identical; JSON paths mapped to FRR's shape).
Founder ruling S29-R4 (2026-10-12; BL-P2-4.5c-223) is bound by SC-RUNTIME.

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
  SC-RUNTIME cmd_status and cmd_collect pass the lab's topology to get_runtime, as
             cmd_test does (S29-R4): through a stub that answers as the guest for a
             node the topology resolves to runtime vm and as the vrnetlab wrapper
             otherwise, s1's bgp and routes records and s1.bgp-summary.txt carry the
             guest's output; r1's records are unchanged; the declared collateral
             (s1's --interfaces lines, s1.ip-addr.txt) reads the guest too. Each
             call site, reverted to the bare form in a copy of the engine, makes
             its own leg FAIL; an AST read shows one get_runtime call per command,
             with `topo`.
  SC-NV      non-vacuity, each counter-example taken from a failure condition:
             a mutated capture changes observed (value checks can fail); a copy that
             differs is caught by the parity comparator; a target that writes its own
             file is caught by the write tracer; an IMPL token with a None leg would be
             called (the guard is what keeps it silent).
  F          the live fixture's shape, derived values only: one frr node and one sonic-vm
             guest at runtime vm, one link carrying both addresses, no node declaring
             BGP (no `asn`, no `bgp`), so the guest has no session; the fixture
             validates.
  NV-LIVE    REQ-45D-31 two-directional non-vacuity for each predicate the live legs
             apply to the product's output: a complete synthetic observation satisfies
             it, and a mutation in each direction -- too much and too little -- is
             detected. Printed in handover §18's literal form, `MUTATION-FAIL: too-much
             (<label>)` and `MUTATION-FAIL: too-little (<label>)` (S35-R3).

Live legs (`live <topo> <lab>`, on a lab already up; S36-R2):
  L1  REQ-45D-19 (VM): `cassian status <lab> --routes --json` exits 0, and s1's routes
      record has parser_mode json, no error, and observed prefixes that include the
      declared loopback /32 and the declared link /31.
  L2  REQ-45D-19 (VM): `cassian status <lab> --routes --routes-verbose`, human mode,
      exits 0, and s1's block carries its raw route lines, which carry the declared
      loopback.
  L3  REQ-45D-20 (VM): `cassian collect <lab>` exits 0; s1.bgp-summary.txt and
      s1.vtysh-ip-route.txt exist and are non-empty while no BGP session is
      established on s1 (read by the provider's own status leg through the product's
      runtime), and the route artifact carries both declared prefixes.
  L4  the guest-not-wrapper control: through the product's substrate_exec, which
      reaches the vrnetlab launcher that wraps the guest, the launcher answers
      `uname -s`, while the same reads sent there -- the two route reads, the summary
      read and `ip -br a` -- carry neither declared prefix nor the guest's declared
      link address; and S29-R4's collateral s1.ip-addr.txt, written by L3's collect,
      carries that address. So L1 to L3 read the guest.

usage:
  sonic_status_collect_proof.py                    lab-free legs; L1-L4 BLOCKED; exit 0 if green
  sonic_status_collect_proof.py live <topo> <lab>  lab-free legs, then L1-L4 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - Lab-free legs: the stub runtime replays captured guest output; no guest is
    contacted.
  - SC-PARITY's inputs are a fixed set; outputs equal on it do not prove equality on
    every possible input. Both functions are verbatim bodies; the set exercises each
    branch.
  - FRR's JSON parser falls back to peerState/pfxRcd when a peer has no `state`; the
    SONiC reader does not (stated in the leg's docstring). The captured output carries
    `state` on every peer, so SC-SUMMARY's equality holds on it, not on that shape.
  - The write tracer covers builtins.open in a write mode, io.open, os.open with write
    flags, and pathlib's write_text/write_bytes; another write route is uncovered.
  - SC-RUNTIME's stub applies build_runtime's dispatch rule through M.node_runtime_map;
    it does not run build_runtime, ContainerRuntime or VmRuntime. Its wrapper reply
    (rc 127, no stdout) is a stand-in: what the vrnetlab wrapper returns for a guest
    command has not been measured. The legs before SC-RUNTIME replace get_runtime
    with a stub that ignores its argument.
  - Live legs: one boot of one fixture with no BGP declared, on one SONiC image. They
    prove `cassian status --routes` and `cassian collect` read the guest through the
    product's path; they do not prove a status read with an established session
    (row 15's proof does), and a SONiC node's expected routes stay FRR-derived
    (S27-R8), so L1 judges observed prefixes, not the record's `ok`.
  - L3 judges "no session established" by the provider's status leg, not by parsing
    the artifact, whose normaliser is FRR's (S27-R10, S27-R12); the artifact's content
    is checked for presence only.
  - L4 reads the launcher through substrate_exec; it does not inspect the wrapper chain.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
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

ARGV = sys.argv[1:]
if ARGV and not (ARGV[0] == "live" and len(ARGV) == 3):
    sys.exit("usage: sonic_status_collect_proof.py [live <topo> <lab>]")

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

# ---- SC-RUNTIME (founder ruling S29-R4, 2026-10-12; BL-P2-4.5c-223) ------------------
# cmd_status and cmd_collect build their runtime from the lab's topology, as cmd_test
# does, so a vm-runtime node's status legs and collect targets read the guest. The stub
# keeps build_runtime's dispatch rule: a node the topology resolves to runtime "vm"
# (M.node_runtime_map, the field build_runtime reads) answers from the guest; a SONiC
# node reached without that topology answers as the vrnetlab wrapper would for a guest
# command -- rc 127, no stdout. The legs above replace get_runtime with a stub that
# ignores its argument, so they cannot see which runtime was built; this leg can.
import ast  # noqa: E402
import importlib.util  # noqa: E402

RT_WRAPPER_NODES = {n["name"] for n in TOPO["nodes"] if n.get("type") == "sonic-vm"}
RT_GUEST_IF = "Ethernet0        UP             198.51.100.0/31"
RT_OUTPUTS = copy.deepcopy(OUTPUTS)
RT_OUTPUTS["s1"]["sh -lc ip -br a"] = RT_GUEST_IF


class TargetStubRuntime(StubRuntime):
    def __init__(self, by_node, topo):
        super().__init__(by_node)
        self.vm_nodes = {k for k, v in M.node_runtime_map(topo).items() if v == "vm"}

    def _wrapper(self, node):
        return node in RT_WRAPPER_NODES and node not in self.vm_nodes

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append((node, "exec", " ".join(cmd)))
        if self._wrapper(node):
            return _CP("", rc=127)
        return _CP(self.by_node.get(node, {}).get(" ".join(cmd), ""))

    def sh(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append((node, "sh", cmd))
        return _CP("%s %s %s\n" % ("wrapper" if self._wrapper(node) else "target", node, cmd))


_rt_args = []


def _selecting_get_runtime(topo=None, *a, **k):
    _rt_args.append(topo)
    return TargetStubRuntime(RT_OUTPUTS, topo)


def runtime_leg(mod):
    """cmd_status --bgp --routes --interfaces --json, then cmd_collect, on the stub lab,
    through engine module `mod` with get_runtime replaced by the selecting stub."""
    del _rt_args[:]
    shutil.rmtree(E.lab_dir(LAB) / "artifacts", ignore_errors=True)
    saved = (mod.get_runtime, mod.run)
    mod.get_runtime = _selecting_get_runtime
    mod.run = lambda *a, **k: _CP("[]")
    ns = argparse.Namespace(lab=LAB, bgp=True, bgp_verbose=False, strict=False, interfaces=True,
                            summary=False, json=True, routes=True, routes_verbose=False)
    buf, sexc, cexc = io.StringIO(), None, None
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            try:
                mod.cmd_status(ns)
            except BaseException as ex:  # noqa: BLE001 -- recorded, judged below
                sexc = ex
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                mod.cmd_collect(argparse.Namespace(lab=LAB))
            except BaseException as ex:  # noqa: BLE001
                cexc = ex
    finally:
        mod.get_runtime, mod.run = saved
    out = buf.getvalue()
    recs = {n["name"]: n for n in (json.loads(out).get("nodes", []) if out.strip().startswith("{") else [])}
    art = E.lab_dir(LAB) / "artifacts"

    def _read(name):
        p = art / name
        return p.read_text(encoding="utf-8") if p.exists() else None

    return {"recs": recs, "sexc": sexc, "cexc": cexc, "args": list(_rt_args),
            "bgp_art": _read("s1.bgp-summary.txt"), "ipaddr_art": _read("s1.ip-addr.txt")}


GUEST_PEERS = sorted(F.parse_frr_bgp_summary_neighbors_json(SUMMARY_JSON))
GUEST_BGP_ART = S._sonic_normalize_bgp_summary(SUM_TEXT)
GUEST_IPADDR_ART = "target s1 ip -br a\n"


def status_ok(r):
    s1 = r["recs"].get("s1", {})
    return (r["sexc"] is None and s1.get("bgp", {}).get("observed") == GUEST_PEERS
            and s1.get("bgp", {}).get("parser_mode") == "json"
            and s1.get("routes", {}).get("parser_mode") == "json"
            and len(s1.get("routes", {}).get("observed") or []) > 0)


def collect_ok(r):
    return r["cexc"] is None and r["bgp_art"] == GUEST_BGP_ART


def topo_args_ok(r):
    return len(r["args"]) == 2 and all(M.node_runtime_map(a).get("s1") == "vm" for a in r["args"])


def get_runtime_calls(src):
    """{function: [(positional args, keyword names)]} for every get_runtime call in the two commands."""
    tree = ast.parse(src)
    out = {}
    for fn in ("cmd_status", "cmd_collect"):
        defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn]
        out[fn] = [([ast.unparse(a) for a in c.args], [k.arg for k in c.keywords])
                   for d in defs for c in ast.walk(d)
                   if isinstance(c, ast.Call) and getattr(c.func, "id", None) == "get_runtime"]
    return out


def ast_ok(src):
    return get_runtime_calls(src) == {"cmd_status": [(["topo"], [])], "cmd_collect": [(["topo"], [])]}


_ENGINE_SRC = open(E.__file__, encoding="utf-8").read()


def reverted(fn):
    """The engine source with `fn`'s get_runtime call reverted to the bare form, or None
    when the site is not in the fixed form (one call, `get_runtime(topo)` on its line)."""
    tree = ast.parse(_ENGINE_SRC)
    defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn]
    calls = [c for d in defs for c in ast.walk(d)
             if isinstance(c, ast.Call) and getattr(c.func, "id", None) == "get_runtime"]
    lines = _ENGINE_SRC.split("\n")
    if len(calls) != 1 or lines[calls[0].lineno - 1].count("get_runtime(topo)") != 1:
        return None
    i = calls[0].lineno - 1
    lines[i] = lines[i].replace("get_runtime(topo)", "get_runtime()")
    return "\n".join(lines)


def engine_copy(src, tag):
    spec = importlib.util.spec_from_loader("cassian_engine_s29r4_" + tag, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = E.__file__
    exec(compile(src, E.__file__, "exec"), mod.__dict__)
    mod._bind_workspace_labs_dir(pathlib.Path(WORK))
    return mod


_r = runtime_leg(E)
check("SC-RUNTIME get_runtime receives the lab's topology in both commands (s1 resolves to vm)",
      topo_args_ok(_r), "args: %s" % [sorted(M.node_runtime_map(a).items()) if a else a for a in _r["args"]])
check("SC-RUNTIME s1's bgp record carries the guest's sessions, parser json", status_ok(_r),
      "observed=%s" % (_r["recs"].get("s1", {}).get("bgp", {}).get("observed"),))
check("SC-RUNTIME s1.bgp-summary.txt carries the guest's normalised summary", collect_ok(_r))
check("SC-RUNTIME r1 (frr) bgp and routes records equal SC-STATUS's",
      all(_r["recs"].get("r1", {}).get(k) == _recs.get("r1", {}).get(k) for k in ("bgp", "routes")))
check("SC-RUNTIME declared collateral: s1's --interfaces lines are the guest's",
      _r["recs"].get("s1", {}).get("interfaces") == [RT_GUEST_IF])
check("SC-RUNTIME declared collateral: s1.ip-addr.txt is the guest's output",
      _r["ipaddr_art"] == GUEST_IPADDR_ART, repr(_r["ipaddr_art"]))
check("SC-RUNTIME each command makes exactly one get_runtime call, with `topo`",
      ast_ok(_ENGINE_SRC), repr(get_runtime_calls(_ENGINE_SRC)))

# ---- SC-RUNTIME non-vacuity: the stub discriminates, and each reverted site fails ------
_stub_none = TargetStubRuntime(RT_OUTPUTS, None).exec(LAB, "s1", ["vtysh", "-c", "show bgp summary json"])
_stub_topo = TargetStubRuntime(RT_OUTPUTS, TOPO).exec(LAB, "s1", ["vtysh", "-c", "show bgp summary json"])
check("SC-RUNTIME NV the stub answers as the wrapper without the topology and as the guest with it",
      _stub_none.returncode == 127 and _stub_none.stdout == "" and _stub_topo.stdout == SUMMARY_JSON)
_src_s, _src_c = reverted("cmd_status"), reverted("cmd_collect")
check("SC-RUNTIME NV both sites are in the fixed form, so each can be reverted",
      _src_s is not None and _src_c is not None)
if _src_s is not None and _src_c is not None:
    _rs = runtime_leg(engine_copy(_src_s, "status"))
    check("SC-RUNTIME NV cmd_status reverted to get_runtime(): its leg FAILS and collect's still passes",
          not status_ok(_rs) and collect_ok(_rs) and not ast_ok(_src_s),
          "s1 bgp=%s" % (_rs["recs"].get("s1", {}).get("bgp", {}).get("observed"),))
    _rc = runtime_leg(engine_copy(_src_c, "collect"))
    check("SC-RUNTIME NV cmd_collect reverted to get_runtime(): its leg FAILS and status's still passes",
          not collect_ok(_rc) and status_ok(_rc) and not ast_ok(_src_c),
          "bgp_art=%r" % (_rc["bgp_art"],))
    check("SC-RUNTIME NV a reverted site passes no topology (the recorded argument is None)",
          _rs["args"][0] is None and _rc["args"][1] is None)

shutil.rmtree(WORK, ignore_errors=True)

# ==== VM-5 (founder rulings S36-R1 to S36-R3, 2026-10-20): F, NV-LIVE, live legs ======
import ipaddress  # noqa: E402
import subprocess  # noqa: E402

SRC = os.path.join(ROOT, "src")
FIXTURE = os.path.join(ROOT, "topologies", "sonic-status-collect.yaml")
VERBOSE_MARK = "--- show ip route ---"
LAUNCHER_PROBE = ["uname", "-s"]
LAUNCHER_READS = (["vtysh", "-c", "show ip route json"], ["vtysh", "-c", "show ip route"],
                  ["vtysh", "-c", "show bgp summary"], ["sh", "-lc", "ip -br a"])
BGP_ART, RIB_ART, IPADDR_ART = "bgp-summary.txt", "vtysh-ip-route.txt", "ip-addr.txt"


def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    links = [lk for lk in (doc.get("links") or []) if isinstance(lk, dict)]
    if len(son) != 1 or len(frr) != 1 or len(nodes) != 2 or len(links) != 1:
        return None
    sn, rn = son[0]["name"], frr[0]["name"]
    eps = [str(e).split(":", 1)[0] for e in (links[0].get("endpoints") or [])]
    ips = links[0].get("ipv4") or []
    if sorted(eps) != sorted([sn, rn]) or len(ips) != 2:
        return None
    try:
        s_if = ipaddress.ip_interface(str(ips[eps.index(sn)]))
        loop = ipaddress.ip_network("%s/32" % son[0].get("router_id"))
    except ValueError:
        return None
    return {"s": son[0], "s_name": sn, "r_name": rn, "loopback": str(loop),
            "link": str(s_if.network), "s_addr": str(s_if.ip),
            "bgp_declared": sorted(str(n.get("name")) for n in nodes.values() if "asn" in n or "bgp" in n)}


# ---- predicates applied to the product's output (each one has a two-directional NV) -------
def _node(doc, node):
    return {n.get("name"): n for n in ((doc or {}).get("nodes") or [])}.get(node) or {}


def routes_json_ok(doc, node, prefixes):
    """L1: the node's routes record: parser json, no error, every declared prefix observed."""
    r = _node(doc, node).get("routes") or {}
    return (r.get("parser_mode") == "json" and "error" not in r
            and set(prefixes) <= set(r.get("observed") or []))


def node_block(human, node):
    """The lines of `node`'s block in cassian status's human output (`  - <node> ...` up to the next node)."""
    out, inside = [], False
    for ln in human.split("\n"):
        if ln.startswith("  - "):
            inside = ln[4:].split(" ", 1)[0] == node
            continue
        if inside:
            if not ln.startswith("      ") and ln.strip():
                inside = False
                continue
            out.append(ln)
    return out


def verbose_ok(human, node, prefix):
    """L2: the node's block carries one raw route-lines section, and its lines carry the prefix."""
    blk = node_block(human, node)
    marks = [k for k, ln in enumerate(blk) if ln.strip() == VERBOSE_MARK]
    if len(marks) != 1:
        return False
    return any(prefix in ln for ln in blk[marks[0] + 1:])


def artifacts_ok(arts, node, prefixes):
    """L3: both of the node's collect artifacts exist and are non-empty, and the route
    artifact carries every declared prefix. `arts`: file name -> text."""
    b, r = arts.get("%s.%s" % (node, BGP_ART)), arts.get("%s.%s" % (node, RIB_ART))
    return bool(b and b.strip()) and bool(r and r.strip()) and all(p in r for p in prefixes)


def zero_sessions_ok(observed):
    """L3's condition: the provider's status read answered, and no session is established."""
    return isinstance(observed, dict) and not any(v.get("established") for v in observed.values())


def launcher_lacks(probe, outs, values):
    """L4: the launcher answers a plain command (probe = (rc, text)), and none of its outputs
    for the guest's reads carries a guest value."""
    return probe[0] == 0 and bool(probe[1].strip()) and all(
        v not in out for (_rc, out) in outs for v in values)


def guest_addr_ok(ipaddr_art, addr):
    """L4: the collateral artifact s1.ip-addr.txt, written by collect, carries the guest's address."""
    return bool(ipaddr_art) and addr in ipaddr_art


def cassian(*args, timeout=1800):
    r = subprocess.run([sys.executable, os.path.join(SRC, "cassian.py")] + list(args), cwd=ROOT,
                       env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    out = _text(r.stdout)
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for ln in out.rstrip("\n").split("\n")[-25:]:
        print("     | " + ln)
    return r.returncode, out


# ---- F: the fixture --------------------------------------------------------------------
FDOC = (yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}) if os.path.isfile(FIXTURE) else {}
FD = declared(FDOC)
check("F one frr node and one sonic-vm node, one link carrying both addresses", FD is not None)
if FD is not None:
    check("F the sonic-vm node runs as vm (one guest)", FD["s"].get("runtime") == "vm")
    check("F no node declares BGP (no asn, no bgp): zero sessions by construction", not FD["bgp_declared"],
          "%s" % FD["bgp_declared"])
    check("F the declared loopback and the declared link prefix are distinct", FD["loopback"] != FD["link"])
_rc, _out = cassian("validate", FIXTURE)
check("F the fixture validates", _rc == 0, "rc=%d" % _rc)


# ---- NV-LIVE: two-directional non-vacuity per predicate (synthetic, device-independent) ---
def nv(label, pred, complete, too_much, too_little):
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok_ = bool(a and not b and not c)
    check("NV-LIVE %s: complete passes, too-much and too-little are detected" % label, ok_,
          "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok_:
        print("  MUTATION-FAIL: too-much (%s)" % label)
        print("  MUTATION-FAIL: too-little (%s)" % label)


SN, RN = "s1", "r1"
LO, LK, AD = "192.0.2.250/32", "198.51.100.250/31", "198.51.100.251"
_NF = "OCI runtime exec failed: exec: \"vtysh\": executable file not found in $PATH"


def sdoc(routes=None, node=SN):
    rec = {"name": node, "type": "sonic-vm", "running": True}
    if routes is not None:
        rec["routes"] = routes
    return {"nodes": [{"name": RN, "type": "frr", "running": True}, rec]}


_R = {"expected": [], "observed": sorted([LO, LK, "10.250.0.0/24"]), "missing": [], "ok": True,
      "parser_mode": "json"}
nv("routes_json_ok", lambda x: routes_json_ok(x, SN, (LO, LK)), sdoc(_R),
   sdoc(dict(_R, error="vtysh: connection refused")), sdoc(dict(_R, observed=[LK, "10.250.0.0/24"])))
nv("routes_json_ok (parser)", lambda x: routes_json_ok(x, SN, (LO, LK)), sdoc(_R),
   sdoc(dict(_R, parser_mode="text")), sdoc(None))
_HB = "  - %s       (clab-x-%s) : running\n"
_VB = "      %s\n      {\n      \"%s\":[\n      }\n" % (VERBOSE_MARK, LO)
nv("verbose_ok", lambda x: verbose_ok(x, SN, LO), _HB % (RN, RN) + _HB % (SN, SN) + _VB,
   _HB % (RN, RN) + _VB + _HB % (SN, SN),
   _HB % (RN, RN) + _HB % (SN, SN) + _VB.replace(LO, LK))
_ARTS = {"%s.%s" % (SN, BGP_ART): "No BGP neighbors found\n",
         "%s.%s" % (SN, RIB_ART): "C>* %s is directly connected, Loopback0\nC>* %s is directly connected, "
                                  "Ethernet0\n" % (LO, LK)}
nv("artifacts_ok", lambda x: artifacts_ok(x, SN, (LO, LK)), _ARTS,
   {k.replace(SN + ".", RN + "."): v for k, v in _ARTS.items()},
   dict(_ARTS, **{"%s.%s" % (SN, RIB_ART): "C>* %s is directly connected, Loopback0\n" % LO}))
nv("artifacts_ok (summary)", lambda x: artifacts_ok(x, SN, (LO, LK)), _ARTS,
   dict(_ARTS, **{"%s.%s" % (SN, BGP_ART): "\n"}), {"%s.%s" % (SN, RIB_ART): _ARTS["%s.%s" % (SN, RIB_ART)]})
nv("zero_sessions_ok", zero_sessions_ok, {"10.0.0.1": {"established": False, "raw": "Active"}},
   {"10.0.0.1": {"established": True, "raw": "Established"}}, None)
nv("launcher_lacks", lambda x: launcher_lacks(x[0], x[1], (LO, LK, AD)),
   ((0, "Linux\n"), [(127, _NF), (127, _NF), (127, _NF), (0, "eth0 UP 172.20.20.3/24\n")]),
   ((0, "Linux\n"), [(0, '{"%s":[]}' % LO), (127, _NF), (127, _NF), (0, "eth0 UP 172.20.20.3/24\n")]),
   ((1, ""), [(127, ""), (127, ""), (127, ""), (127, "")]))
nv("guest_addr_ok", lambda x: guest_addr_ok(x, AD), "Ethernet0 UP %s/31\n" % AD,
   "eth0 UP 172.20.20.3/24\neth1 UP\n", None)


# ---- live legs ---------------------------------------------------------------------------
def read_artifacts(lab):
    d = os.path.join(ROOT, "labs", "clab-%s" % lab, "artifacts")
    out = {}
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p):
                out[f] = open(p, encoding="utf-8", errors="replace").read()
    return out


def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != FDOC.get("name") or FD is None:
        check("LIVE argv names the status-and-collect fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn, prefixes = FD["s_name"], (FD["loopback"], FD["link"])

    rc, out = cassian("status", lab, "--routes", "--json")
    try:
        doc = json.loads(out[out.index("{"):])
    except Exception:  # noqa: BLE001 -- judged below
        doc = {}
    print("     %s routes record: %s" % (sn, json.dumps(_node(doc, sn).get("routes"), sort_keys=True)))
    check("L1 REQ-45D-19 (VM): `cassian status %s --routes --json` exits 0; %s's routes record: parser json, "
          "no error, %s and %s observed" % (lab, sn, prefixes[0], prefixes[1]),
          rc == 0 and routes_json_ok(doc, sn, prefixes), "rc=%d" % rc)

    rc, out = cassian("status", lab, "--routes", "--routes-verbose")
    check("L2 REQ-45D-19 (VM): `cassian status %s --routes --routes-verbose` exits 0, and %s's raw route lines "
          "carry %s" % (lab, sn, prefixes[0]), rc == 0 and verbose_ok(out, sn, prefixes[0]),
          "rc=%d; block %r" % (rc, node_block(out, sn)[:3]))

    for f in (BGP_ART, RIB_ART, IPADDR_ART):  # never judge a previous run's artifact
        p = os.path.join(ROOT, "labs", "clab-%s" % lab, "artifacts", "%s.%s" % (sn, f))
        if os.path.exists(p):
            os.remove(p)
    rc, out = cassian("collect", lab)
    arts = read_artifacts(lab)
    for f in sorted(arts):
        if f.startswith(sn + "."):
            body = arts[f].rstrip("\n").split("\n")
            print("     artifact %s (%d bytes):" % (f, len(arts[f].encode("utf-8"))))
            for ln in body[:15]:
                print("       | " + ln)
    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(FDOC)
    sobs = S.SONIC_PROVIDER.status_bgp_summary(rt, lab, sn, want_raw=False)
    observed = sobs.data.get("observed")
    print("     %s sessions by the provider's status leg (parser %s): %s"
          % (sn, sobs.data.get("parser_mode"), json.dumps(observed, sort_keys=True)))
    check("L3 REQ-45D-20 (VM): `cassian collect %s` exits 0; %s.%s and %s.%s exist and are non-empty with no "
          "session established, and the route artifact carries %s and %s"
          % (lab, sn, BGP_ART, sn, RIB_ART, prefixes[0], prefixes[1]),
          rc == 0 and artifacts_ok(arts, sn, prefixes) and zero_sessions_ok(observed),
          "rc=%d; artifacts %s" % (rc, sorted(f for f in arts if f.startswith(sn + "."))))

    def launcher(cmd):
        cp = rt.substrate_exec(lab, sn, cmd, check=False, capture_output=True, timeout_s=30)
        o = _text(cp.stdout) + _text(getattr(cp, "stderr", ""))
        print("     launcher(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                    "\n".join("       " + ln for ln in o.rstrip("\n").split("\n")[:12])))
        return cp.returncode, o

    probe = launcher(LAUNCHER_PROBE)
    outs = [launcher(c) for c in LAUNCHER_READS]
    check("L4 the guest-not-wrapper control: the launcher answers `%s`; the same reads through substrate_exec "
          "carry neither prefix nor %s, and %s.%s, written by collect, carries %s"
          % (" ".join(LAUNCHER_PROBE), FD["s_addr"], sn, IPADDR_ART, FD["s_addr"]),
          launcher_lacks(probe, outs, prefixes + (FD["s_addr"],))
          and guest_addr_ok(arts.get("%s.%s" % (sn, IPADDR_ART)), FD["s_addr"]),
          "probe rc=%s; rcs %s" % (probe[0], [o[0] for o in outs]))
    if not (checks and all(p for n, p in checks if n.startswith(("L1 ", "L2 ", "L3 ")))):
        print("FINDING (S36-R1): a live status or collect leg did not read the guest as declared on this "
              "boot; the packet lands nothing and returns to the founder as a new card.")


if not ARGV:
    for leg in ("L1 REQ-45D-19 status --routes --json", "L2 REQ-45D-19 status --routes --routes-verbose",
                "L3 REQ-45D-20 collect with zero sessions", "L4 guest-not-wrapper control"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
else:
    live(ARGV[1], ARGV[2])

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
for name, why in blocked:
    print("[BLOCKED] %s -- %s" % (name, why))
print("=" * 60)
print("cases:", len(checks), "blocked:", len(blocked))
print("RESULT:", "PASS" if ok else "FAIL", "(a BLOCKED or NOT ATTEMPTED leg is not a pass)")
sys.exit(0 if ok else 1)
