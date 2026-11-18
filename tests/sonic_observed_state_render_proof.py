"""
REQ-45D-21 -- SONiC observed-state render proof (hosted, lab-free).

Phase 2 §4.5-d, H1-b1 script 2. Lands with H1-b1 by founder ruling (i) of
2026-09-25 and is extended in H1-b2 / H1-b3. Covers bgp_neighbor through its
test-record line by founder ruling of 2026-09-28 (Decision 1 (ii)). Extended in
H1-b2 script 2 to the advertised pair, REQ-45D-13 / -14 (ruling (i); founder
ruling 1 of 2026-09-29). Extended in H1-b3 script 2b-i to the route pair,
REQ-45D-11 / -12, and to route_prefix, REQ-45D-2, through its test-record line
(founder ruling of 2026-10-05). Authors no governance; numbers no precedent.

Property (handover REQ-45D-21, DC v2.1 §13(c), §14 item 9): for every SONiC-
collected kind, a failure renders SONiC's ACTUAL observed state in
results.summary.txt through the EXISTING core render, with NO NOS branch. The
mechanism is key parity: SONiC's Observation.data carries the keys FRR's handler
fills for the kind (FRR's keys derived at run time over the same bytes -- keys
only, never values: SONiC's correctness is proven from SONiC's own evidence,
founder statement of 2026-09-26).

Sections:
  R-SEAM    static (AST): the engine's _evaluate_invariant_attempt copies
            _obs.data wholesale into observed_state for each of the five
            H1-b1 invariant kinds and in the advertised pair's one shared
            branch, with no node-type constant in that branch;
            run_bgp_neighbor_test reads data["observed"] into its error line;
            the two render functions carry no node-type string constant.
  R-RENDER  per invariant kind: a failed record built as the engine builds it
            renders an `observed:` block whose keys equal FRR's and whose lines
            equal the block rendered from SONiC's own data.
  R-NEIGH   bgp_neighbor: the failed record's line carries SONiC's observed
            value (an Established variant of the captured summary, expected
            'down'), through the unchanged `failed_tests` line.
  R-RPFX    route_prefix: the failed record's line carries SONiC's observed
            value, derived by the core from data["routes"], through the
            unchanged `failed_tests` line, in both directions.
  R-ENGINE  BL-P2-4.5c-238 (REQ-45E-8): the engine's OWN record for a SONiC
            observation -- bgp_session_up through the engine's scenario wait
            path (_evaluate_invariant_attempt + wait_for_predicate, extracted
            from the shipped engine source), on a neighbour absent from the
            captured summary so last_error is non-empty -- carries the keys
            FRR's handler fills over the same bytes, and renders through
            _format_test_summary with the keys a record built from FRR's own
            data renders. Shown red on V21a (an engine-side branch keyed on
            startswith("son") that drops last_error after the copy) and V21b
            (last_error dropped for every NOS after the copy), each rebuilt
            in-process from the shipped engine source.
  R-NV      mutations that MUST fail: a dropped key and a renamed key per
            invariant kind, a dropped `observed` for bgp_neighbor and a dropped
            `routes` for route_prefix. Each
            prints MUTATION-FAIL when the proof detects it.

Coverage limits (PBE-P2-8): R-SEAM has two limits of its own (BL-P2-4.5c-238).
(i) Its "no NOS branch" check intersects the string constants of each branch
with the four exact NOS names in NOS_CONSTANTS, so an engine-side NOS branch
keyed on any other string -- for example a startswith("son") test -- is not
seen. (ii) _copies_obs_data checks only that the copy statement
`observed_state = dict(_obs.data)` exists, not what happens to observed_state
after it, so an engine-side key drop after the copy is not seen. R-ENGINE
covers both on the engine's scenario wait path for bgp_session_up, the one
kind whose data carries last_error; it exercises no other kind's engine path.
Further: lab-free; one image (local/sonic-vm:202405, FRR
8.5.4); the records are built in-process in the engine's shape, not by running
the engine's retry driver; truncation is not exercised (the payloads are far
below the cap). The advertised pair's failing observations are the captured
reads in which each kind fails -- BEFORE (test prefix not yet advertised) for
route_advertised_to, AFTER (advertised) for route_not_advertised_to -- from
tests/fixtures/sonic-4_5d-h1b2/, values citing capture procedure rev 2 §1. The
route pair's and route_prefix's observations are reads of
tests/fixtures/sonic-4_5d-h1b3/h1b3_rib_table_after.out at capture procedure
4_5d-h1b3-rib rev 1 §1 prefixes (the static prefix, present; the absent
control). The (VM) legs are the handover §18's, not asserted here.
Exit 0 on all-pass; exit 1 on any failure.
"""
import ast
import inspect
import json
import os
import sys
from types import SimpleNamespace

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
sys.path.insert(0, _SRC)

import cassian_nos_frr as FRR  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
import cassian_tests as T  # noqa: E402
from cassian_nos_types import ObservationRequest  # noqa: E402

FIX = os.path.join(_HERE, "fixtures", "sonic-4_5d-h1b1")
PREFIX = "198.51.100.0/24"          # capture procedure §1 (f87f87d1…ba35a)
NEIGHBOR = "10.0.0.1"               # session-8 note §5: stock neighbour
INV_KINDS = ("bgp_session_up", "bgp_localpref_equals", "bgp_med_equals",
             "bgp_community", "bgp_as_path")
NOS_CONSTANTS = ("sonic-vm", "sonic", "frr", "nft-fw")

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


SUMMARY = load("bgp_summary.out")
AFTER = load("h1b1v_prefix_after.out")

FIX2 = os.path.join(_HERE, "fixtures", "sonic-4_5d-h1b2")
ADV_PEER = "198.51.100.1"           # capture procedure rev 2 §1 (2e7ca8bd…e68f)
ADV_PREFIX = "203.0.113.0/24"       # capture procedure rev 2 §1
ADV_KINDS = ("route_advertised_to", "route_not_advertised_to")


def load2(name):
    with open(os.path.join(FIX2, name), encoding="utf-8") as fh:
        return fh.read()


ADV_BEFORE = load2("h1b2_adv_before.out")
ADV_AFTER = load2("h1b2_adv_after.out")

FIX3 = os.path.join(_HERE, "fixtures", "sonic-4_5d-h1b3")
RIB_STATIC = "198.18.0.0/24"        # capture procedure 4_5d-h1b3-rib rev 1 §1 (d89089c9…96ca)
RIB_ABSENT = "198.18.1.0/24"        # capture procedure rev 1 §1: the absent control
RIB_KINDS = ("route_present", "route_absent")
RIB_PREFIX = {"route_present": RIB_ABSENT,   # fails: the absent control is not in the RIB
              "route_absent": RIB_STATIC}    # fails: the static prefix is in the RIB


def load3(name):
    with open(os.path.join(FIX3, name), encoding="utf-8") as f:
        return f.read()


RIB_AFTER = load3("h1b3_rib_table_after.out")


def stdout_for(kind):
    """The captured read each kind's FAILING observation comes from."""
    if kind == "route_advertised_to":
        return ADV_BEFORE           # fails: the test prefix is not yet advertised
    if kind == "route_not_advertised_to":
        return ADV_AFTER            # fails: the test prefix is advertised
    if kind in RIB_KINDS:
        return RIB_AFTER            # fails at RIB_PREFIX[kind]
    return AFTER if kind != "bgp_session_up" else SUMMARY


class FakeRt:
    def __init__(self, stdout):
        self.stdout = stdout

    def exec(self, lab, node, argv, check=False, **_kw):
        return SimpleNamespace(returncode=0, stdout=self.stdout, stderr="banner")


def _req(kind):
    if kind in ADV_KINDS:
        return ObservationRequest(kind=kind, params={"peer_ip": ADV_PEER, "prefix": ADV_PREFIX})
    if kind in ("bgp_neighbor", "bgp_session_up"):
        return ObservationRequest(kind=kind, params={"neighbor": NEIGHBOR})
    if kind in RIB_KINDS:
        return ObservationRequest(kind=kind, params={"prefix": RIB_PREFIX[kind]})
    return ObservationRequest(kind=kind, params={"prefix": PREFIX})


def sonic_obs(kind, stdout):
    return S.collect(FakeRt(stdout), "lab", "s1", _req(kind))


def frr_data_keys(kind, stdout):
    return sorted(FRR._COLLECT_HANDLERS[kind](FakeRt(stdout), "lab", "s1", _req(kind)).data)


def _results(record):
    return {"lab": "r45d21", "result": "fail",
            "summary": {"total": 1, "passed": 0, "failed": 1}, "tests": [record]}


def inv_record(kind, observed_state):
    """A failed invariant record in the engine's shape (observed_state is
    dict(_obs.data), asserted in R-SEAM)."""
    return {"name": "r-" + kind, "kind": "invariant", "from": "s1", "to": "",
            "verdict": "fail", "error": "FAIL: %s did not hold" % kind,
            "observed_state": observed_state, "observed_state_truncated": False,
            "meta": {"type": kind}, "expected": ""}


def rendered_block(summary_text):
    """The `observed:` block lines of the one failed record, and its keys."""
    lines = summary_text.splitlines()
    try:
        i = lines.index("    observed:")
    except ValueError:
        return [], []
    block = [lines[i]]
    for ln in lines[i + 1:]:
        if not ln.startswith("      "):
            break
        block.append(ln)
    keys = sorted({ln[6:].split(":", 1)[0] for ln in block[1:]
                   if ln.startswith("      ") and not ln.startswith("        ")})
    return block, keys


def parity_holds(kind, observed_state, stdout):
    text = T._format_test_summary(_results(inv_record(kind, observed_state)))
    block, keys = rendered_block(text)
    return (keys == frr_data_keys(kind, stdout)
            and block == T._format_observed_state_block(dict(observed_state), False))


# ----------------------------------------------------------------- R-SEAM
_eng_src = open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8").read()
_eng = ast.parse(_eng_src)
_fn = {n.name: n for n in ast.walk(_eng) if isinstance(n, ast.FunctionDef)}


def _branch_for(fn, kind):
    for n in ast.walk(fn):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name) and n.test.left.id == "inv_type"
                and len(n.test.comparators) == 1
                and isinstance(n.test.comparators[0], ast.Constant)
                and n.test.comparators[0].value == kind):
            return n
    return None


def _copies_obs_data(branch):
    for n in ast.walk(ast.Module(body=branch.body, type_ignores=[])):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "observed_state"
                and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                and n.value.func.id == "dict" and len(n.value.args) == 1
                and ast.unparse(n.value.args[0]) == "_obs.data"):
            return True
    return False


def _branch_in(fn, kinds):
    """The one `if inv_type in (<kinds>):` branch whose constants are exactly kinds."""
    for n in ast.walk(fn):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name) and n.test.left.id == "inv_type"
                and len(n.test.ops) == 1 and isinstance(n.test.ops[0], ast.In)
                and isinstance(n.test.comparators[0], ast.Tuple)
                and all(isinstance(e, ast.Constant) for e in n.test.comparators[0].elts)
                and {e.value for e in n.test.comparators[0].elts} == set(kinds)):
            return n
    return None


def _str_consts(node):
    return {c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, str)}


_ev = _fn.get("_evaluate_invariant_attempt")
check("R-SEAM engine _evaluate_invariant_attempt present", _ev is not None)
for k in INV_KINDS:
    br = _branch_for(_ev, k) if _ev else None
    check("R-SEAM %s: branch copies _obs.data wholesale into observed_state" % k,
          br is not None and _copies_obs_data(br))
    check("R-SEAM %s: branch names no node type (no NOS branch)" % k,
          br is not None and not (_str_consts(ast.Module(body=br.body, type_ignores=[]))
                                  & set(NOS_CONSTANTS)))
_adv_br = _branch_in(_ev, ADV_KINDS) if _ev else None
check("R-SEAM advertised pair: one shared branch copies _obs.data wholesale into observed_state",
      _adv_br is not None and _copies_obs_data(_adv_br))
check("R-SEAM advertised pair: branch names no node type (no NOS branch)",
      _adv_br is not None and not (_str_consts(ast.Module(body=_adv_br.body, type_ignores=[]))
                                   & set(NOS_CONSTANTS)))
_rib_br = _branch_in(_ev, RIB_KINDS) if _ev else None
check("R-SEAM route pair: one shared branch copies _obs.data wholesale into observed_state",
      _rib_br is not None and _copies_obs_data(_rib_br))
check("R-SEAM route pair: branch names no node type (no NOS branch)",
      _rib_br is not None and not (_str_consts(ast.Module(body=_rib_br.body, type_ignores=[]))
                                   & set(NOS_CONSTANTS)))
_rp = _fn.get("run_route_prefix_test")
_rp_src = ast.get_source_segment(_eng_src, _rp) if _rp else ""
check("R-SEAM run_route_prefix_test derives observed from data['routes'] into its mismatch line",
      'present = bool(_obs.data.get("routes"))' in _rp_src
      and 'observed = "pass" if present else "fail"' in _rp_src
      and "route_prefix mismatch (expected {expected}, observed {observed})" in _rp_src)
check("R-SEAM run_route_prefix_test names no node type (no NOS branch)",
      _rp is not None and not (_str_consts(_rp) & set(NOS_CONSTANTS)))
_bn = _fn.get("run_bgp_neighbor_test")
_bn_src = ast.get_source_segment(_eng_src, _bn) if _bn else ""
check("R-SEAM run_bgp_neighbor_test reads data['observed'] into its mismatch line",
      'last_obs.data.get("observed")' in _bn_src
      and "bgp neighbor mismatch (expected {expected}, observed {observed})" in _bn_src)
for fname in ("_format_test_summary", "_format_observed_state_block"):
    tree = ast.parse(inspect.getsource(getattr(T, fname)))
    check("R-SEAM render %s carries no node-type string constant" % fname,
          not (_str_consts(tree) & set(NOS_CONSTANTS)))

# --------------------------------------------------------------- R-RENDER
check("R-RENDER route_advertised_to: its observation is a failing state (test prefix not advertised)",
      sonic_obs("route_advertised_to", stdout_for("route_advertised_to")).data.get("present") is False)
check("R-RENDER route_not_advertised_to: its observation is a failing state (test prefix advertised)",
      sonic_obs("route_not_advertised_to", stdout_for("route_not_advertised_to")).data.get("present") is True)
check("R-RENDER route_present: its observation is a failing state (the absent control is not in the RIB)",
      sonic_obs("route_present", stdout_for("route_present")).data.get("present") is False)
check("R-RENDER route_absent: its observation is a failing state (the static prefix is in the RIB)",
      sonic_obs("route_absent", stdout_for("route_absent")).data.get("present") is True)
for k in INV_KINDS + ADV_KINDS + RIB_KINDS:
    stdout = stdout_for(k)
    o = sonic_obs(k, stdout)
    check("R-RENDER %s: SONiC observation collected without parse error" % k,
          not o.evidence.get("parse_error"))
    check("R-RENDER %s: rendered observed keys equal FRR's; lines equal SONiC's own block" % k,
          parity_holds(k, dict(o.data), stdout))

# ---------------------------------------------------------------- R-NEIGH
_doc = json.loads(SUMMARY)


def _set_state(d, state):
    if isinstance(d, dict):
        peers = d.get("peers")
        if isinstance(peers, dict) and NEIGHBOR in peers:
            peers[NEIGHBOR]["state"] = state
        for v in d.values():
            _set_state(v, state)


_set_state(_doc, "Established")
UP_SUMMARY = json.dumps(_doc)
_no = sonic_obs("bgp_neighbor", UP_SUMMARY)
_observed = str(_no.data.get("observed") or "down")


def neigh_line(obs_data):
    observed = str(obs_data.get("observed") or "down")
    rec = {"name": "r-bgp_neighbor", "kind": "bgp_neighbor", "from": "s1", "to": NEIGHBOR,
           "verdict": "fail", "expected": "down", "observed": observed,
           "error": "bgp neighbor mismatch (expected down, observed %s)" % observed}
    text = T._format_test_summary(_results(rec))
    return [ln for ln in text.splitlines() if ln.startswith(" - r-bgp_neighbor ")]


check("R-NEIGH bgp_neighbor: keys equal FRR's over the same bytes",
      sorted(_no.data) == frr_data_keys("bgp_neighbor", UP_SUMMARY))
check("R-NEIGH bgp_neighbor: SONiC reads the Established neighbour as up",
      _observed == "up" and not _no.evidence.get("parse_error"))
_nl = neigh_line(dict(_no.data))
check("R-NEIGH bgp_neighbor: the failed_tests line carries SONiC's observed value",
      len(_nl) == 1 and _nl[0].endswith(": bgp neighbor mismatch (expected down, observed up)"))
check("R-NEIGH bgp_neighbor: no observed: block for a test kind (R27 unchanged)",
      "    observed:" not in T._format_test_summary(_results(
          {"name": "r-bgp_neighbor", "kind": "bgp_neighbor", "verdict": "fail",
           "error": "x", "observed_state": dict(_no.data)})))

# ---------------------------------------------------------------- R-RPFX
# REQ-45D-2, founder ruling of 2026-10-05 (Decision 1 (ii)'s method): route_prefix is
# a test kind; its failure surfaces as the record's observed value in the
# failed_tests line, derived by the core from the provider's data["routes"] (R-SEAM).
def rpfx_obs(prefix):
    return S.collect(FakeRt(RIB_AFTER), "lab", "s1",
                     ObservationRequest(kind="route_prefix", params={"prefix": prefix}))


def rpfx_line(obs_data, expected):
    present = bool(obs_data.get("routes"))          # the engine's rule (R-SEAM)
    observed = "pass" if present else "fail"
    verdict = "pass" if observed == expected else "fail"
    rec = {"name": "r-route_prefix", "kind": "route_prefix", "from": "s1", "to": "",
           "verdict": verdict, "expected": expected, "observed": observed,
           "error": "" if verdict == "pass" else
           "route_prefix mismatch (expected %s, observed %s)" % (expected, observed)}
    text = T._format_test_summary(_results(rec))
    return [ln for ln in text.splitlines() if ln.startswith(" - r-route_prefix ")]


_rs, _ra = rpfx_obs(RIB_STATIC), rpfx_obs(RIB_ABSENT)
check("R-RPFX route_prefix: keys equal FRR's over the same bytes",
      sorted(_rs.data) == sorted(FRR._COLLECT_HANDLERS["route_prefix"](
          FakeRt(RIB_AFTER), "lab", "s1",
          ObservationRequest(kind="route_prefix", params={"prefix": RIB_STATIC})).data))
check("R-RPFX route_prefix: SONiC reads the static prefix as present and the absent control as "
      "absent, no parse error",
      bool(_rs.data.get("routes")) and not _ra.data.get("routes")
      and not _rs.evidence.get("parse_error") and not _ra.evidence.get("parse_error"))
_rl_s = rpfx_line(dict(_rs.data), "fail")
_rl_a = rpfx_line(dict(_ra.data), "pass")
check("R-RPFX route_prefix: the failed_tests line carries SONiC's observed value (static prefix, expect fail)",
      len(_rl_s) == 1 and _rl_s[0].endswith(": route_prefix mismatch (expected fail, observed pass)"))
check("R-RPFX route_prefix: the failed_tests line carries SONiC's observed value (absent control, expect pass)",
      len(_rl_a) == 1 and _rl_a[0].endswith(": route_prefix mismatch (expected pass, observed fail)"))
check("R-RPFX route_prefix: no observed: block for a test kind (R27 unchanged)",
      "    observed:" not in T._format_test_summary(_results(
          {"name": "r-route_prefix", "kind": "route_prefix", "verdict": "fail",
           "error": "x", "observed_state": dict(_rs.data)})))

# ------------------------------------------------------------------- R-NV
for k in INV_KINDS + ADV_KINDS + RIB_KINDS:
    stdout = stdout_for(k)
    data = dict(sonic_obs(k, stdout).data)
    victim = sorted(data)[0]
    dropped = {kk: vv for kk, vv in data.items() if kk != victim}
    renamed = {(kk + "_x" if kk == victim else kk): vv for kk, vv in data.items()}
    for label, mutant in (("key-drop", dropped), ("key-rename", renamed)):
        detected = not parity_holds(k, mutant, stdout)
        if detected:
            print("MUTATION-FAIL: %s %s (%s)" % (label, k, victim))
        check("R-NV %s %s is detected" % (label, k), detected)
_nd = {kk: vv for kk, vv in _no.data.items() if kk != "observed"}
_det = neigh_line(_nd) != _nl
if _det:
    print("MUTATION-FAIL: key-drop bgp_neighbor (observed)")
check("R-NV key-drop bgp_neighbor (observed) is detected", _det)
_rd = {kk: vv for kk, vv in _rs.data.items() if kk != "routes"}
_rdet = rpfx_line(_rd, "fail") != _rl_s
if _rdet:
    print("MUTATION-FAIL: key-drop route_prefix (routes)")
check("R-NV key-drop route_prefix (routes) is detected", _rdet)

# -------------------------------------------------------------- R-ENGINE
# BL-P2-4.5c-238 (REQ-45E-8; §4.5-d closure record §5 R-a): the engine's own record path.
import contextlib  # noqa: E402
import io  # noqa: E402
import re  # noqa: E402
import textwrap  # noqa: E402

import cassian_engine as E  # noqa: E402

ABSENT_NEIGHBOR = "10.255.255.1"    # not in the captured summary: last_error is filled
_V21_ANCHOR = ('            st_norm = str(observed_state.get("state") or "").strip().lower()\n'
               '            predicate_ok = bool(observed_state.get("peer_present") and st_norm == "established")\n')


def _eng_seg(src, name):
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(defs) != 1:
        return None
    return textwrap.dedent("".join(lines[defs[0].lineno - 1:defs[0].end_lineno]))


def _wait_step(meta, wait_type, observed, verdict, expect):
    return {"type": "wait_for", "wait_type": wait_type, "wait_for": None, "expected": expect,
            "observed": observed, "verdict": verdict, "duration_ms": 12, "meta": meta}


def _render_keys(step):
    res = {"lab": "r45e8", "result": "pass", "summary": {"total": 0, "passed": 0, "failed": 0},
           "tests": [], "scenarios": [{"id": "s-r45e8", "verdict": "pass", "duration_ms": 12, "steps": [step]}]}
    line = [ln for ln in T._format_test_summary(res).splitlines() if "type=bgp_session_up" in ln]
    return sorted(set(re.findall(r"(\w+)=", line[0]))) if len(line) == 1 else None


def engine_wait(eng_src, ntype="sonic-vm"):
    """bgp_session_up through the given engine source's own scenario wait path, on a node of
    ntype reading the captured summary. Returns (recorded observed_state, rendered keys), or
    (None, None) when the path cannot be extracted or raises."""
    ns = dict(E.__dict__)
    ns.update(topo={"nodes": [{"name": "s1", "type": ntype}]}, rt=FakeRt(SUMMARY), lab="lab")
    try:
        for name in ("_evaluate_invariant_attempt", "wait_for_predicate"):
            seg = _eng_seg(eng_src, name)
            if seg is None:
                return None, None
            exec(compile(seg, "<R-ENGINE:%s>" % name, "exec"), ns)
        w = {"type": "bgp_session_up", "from": "s1", "neighbor": ABSENT_NEIGHBOR, "expect": "fail",
             "timeout": 1, "interval_s": 0.05}
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            wt, _ex, observed, _dur, meta, verdict = ns["wait_for_predicate"](w)
    except Exception:  # noqa: BLE001 -- an engine that cannot run the path fails the leg
        return None, None
    ostate = (meta.get("evidence") or {}).get("observed_state")
    return ostate, _render_keys(_wait_step(meta, wt, observed, verdict, "fail"))


def engine_leg_ok(eng_src):
    ostate, rkeys = engine_wait(eng_src)
    return (isinstance(ostate, dict) and sorted(ostate) == _FRR_KEYS
            and rkeys is not None and rkeys == _REF_KEYS)


_FRR_DATA = FRR._COLLECT_HANDLERS["bgp_session_up"](
    FakeRt(SUMMARY), "lab", "s1",
    ObservationRequest(kind="bgp_session_up", params={"neighbor": ABSENT_NEIGHBOR})).data
_FRR_KEYS = sorted(_FRR_DATA)
_REF_KEYS = _render_keys(_wait_step({"type": "bgp_session_up", "from": "s1", "succeeded": False,
                                     "evidence": {"observed_state": dict(_FRR_DATA)}},
                                    "bgp_session_up", "fail", "pass", "fail"))
_ENG_SRC_R = open(E.__file__, encoding="utf-8").read()
check("R-ENGINE FRR's handler fills last_error for the absent neighbour, and a record built from "
      "FRR's own data renders it", bool(str(_FRR_DATA.get("last_error") or "").strip())
      and _REF_KEYS is not None and "last_error" in _REF_KEYS)
_os, _rk = engine_wait(_ENG_SRC_R)
check("R-ENGINE the engine's own scenario record for a SONiC observation carries FRR's keys "
      "and renders FRR's keys through _format_test_summary", engine_leg_ok(_ENG_SRC_R))
for _tag, _ins in (
        ("V21a", '            if str(_nos_ntype(topo, src)).startswith("son"):\n'
                 '                observed_state.pop("last_error", None)\n'),
        ("V21b", '            observed_state.pop("last_error", None)\n')):
    _ok_anchor = _ENG_SRC_R.count(_V21_ANCHOR) == 1
    _mut = _ENG_SRC_R.replace(_V21_ANCHOR, _ins + _V21_ANCHOR) if _ok_anchor else None
    _det = _ok_anchor and not engine_leg_ok(_mut)
    if _det:
        print("MUTATION-FAIL: %s (last_error dropped after the copy)" % _tag)
    check("R-ENGINE NV %s is detected by the engine-path leg" % _tag, _det)

# ---------------------------------------------------------------- summary
for name, ok in checks:
    print(("[PASS] " if ok else "[FAIL] ") + name)
print("=" * 60)
print("cases: %d" % len(checks))
_failed = [n for n, ok in checks if not ok]
print("RESULT: " + ("PASS" if not _failed else "FAIL (%d)" % len(_failed)))
sys.exit(0 if not _failed else 1)
