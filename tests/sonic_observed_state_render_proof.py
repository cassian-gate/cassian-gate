"""
REQ-45D-21 -- SONiC observed-state render proof (hosted, lab-free).

Phase 2 §4.5-d, H1-b1 script 2. Lands with H1-b1 by founder ruling (i) of
2026-09-25 and is extended in H1-b2 / H1-b3. Covers bgp_neighbor through its
test-record line by founder ruling of 2026-09-28 (Decision 1 (ii)). Authors no
governance; numbers no precedent.

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
            invariant kinds, with no node-type constant in that branch;
            run_bgp_neighbor_test reads data["observed"] into its error line;
            the two render functions carry no node-type string constant.
  R-RENDER  per invariant kind: a failed record built as the engine builds it
            renders an `observed:` block whose keys equal FRR's and whose lines
            equal the block rendered from SONiC's own data.
  R-NEIGH   bgp_neighbor: the failed record's line carries SONiC's observed
            value (an Established variant of the captured summary, expected
            'down'), through the unchanged `failed_tests` line.
  R-NV      mutations that MUST fail: a dropped key and a renamed key per
            invariant kind, and a dropped `observed` for bgp_neighbor. Each
            prints MUTATION-FAIL when the proof detects it.

Coverage limits (PBE-P2-8): lab-free; one image (local/sonic-vm:202405, FRR
8.5.4); the records are built in-process in the engine's shape, not by running
the engine's retry driver; truncation is not exercised (the payloads are far
below the cap). The (VM) legs are the handover §18's, not asserted here.
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


class FakeRt:
    def __init__(self, stdout):
        self.stdout = stdout

    def exec(self, lab, node, argv, check=False, **_kw):
        return SimpleNamespace(returncode=0, stdout=self.stdout, stderr="banner")


def _req(kind):
    if kind in ("bgp_neighbor", "bgp_session_up"):
        return ObservationRequest(kind=kind, params={"neighbor": NEIGHBOR})
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
for k in INV_KINDS:
    o = sonic_obs(k, AFTER if k != "bgp_session_up" else SUMMARY)
    stdout = AFTER if k != "bgp_session_up" else SUMMARY
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

# ------------------------------------------------------------------- R-NV
for k in INV_KINDS:
    stdout = AFTER if k != "bgp_session_up" else SUMMARY
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

# ---------------------------------------------------------------- summary
for name, ok in checks:
    print(("[PASS] " if ok else "[FAIL] ") + name)
print("=" * 60)
print("cases: %d" % len(checks))
_failed = [n for n, ok in checks if not ok]
print("RESULT: " + ("PASS" if not _failed else "FAIL (%d)" % len(_failed)))
sys.exit(0 if not _failed else 1)
