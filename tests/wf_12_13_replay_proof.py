#!/usr/bin/env python3
"""wf_12_13_replay_proof.py — §4.12 WI-3 fold (BL-1b3-1) PO-B3-fold.

A committed, CI-safe, LAB-FREE WF-12/13 byte-identity replay regression. Replaces
the §4.3 PO-2 leg that ran through `verify_phase1.sh` (a lab deploy) and so was not
reproducible from committed artifacts (BL-§4.3-V1 / Finding B). TM-CI-1 preserved.

  REQ-WF-12  cassian `test` TEST-path render is byte-identical on replay.
  REQ-WF-13  existing declared-tests `wait_for` types (ping/tcp/route_prefix) render
             byte-identical; the legacy block is drift-guarded against a committed golden.
  TM-CI-1    the regression is lab-free; `verify_phase1.sh` is reintroduced nowhere;
             this proof is itself wired into the public CI gate.

Method (PBE-1b-8): render the real cassian_tests surfaces over committed synthetic
fixtures, twice, and assert byte-identity; non-vacuity guards against a trivial
constant. No container, no `cassian up/test/down`, no `verify_phase1.sh`.

Run:  PYTHONPATH=src python3 tests/wf_12_13_replay_proof.py
"""
import copy
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import cassian_tests as ct  # noqa: E402

checks: list[tuple[str, bool]] = []


def check(name: str, ok: object) -> None:
    checks.append((name, bool(ok)))


# ----- lab-free TEST-path render harness (same approach as the WI-1 b6 proof) -----
def _render_summary(results: dict, lab: str = "wf12demo") -> str:
    tmp = pathlib.Path(tempfile.mkdtemp()) / f"clab-{lab}"
    tmp.mkdir(parents=True, exist_ok=True)
    orig = ct.lab_dir
    try:
        ct.lab_dir = lambda _l: tmp
        return ct.write_test_summary_artifact(lab, results).read_text(encoding="utf-8")
    finally:
        ct.lab_dir = orig


# ===== Committed fixtures =====
# WF-13: declared-tests scenario path exercising the legacy ping/tcp/route_prefix block.
SCEN = {
    "scenarios": [
        {"id": "s1", "verdict": "pass", "steps": [
            {"type": "run", "ref": "t_core"},
            {"type": "wait_for", "wait_for": {"type": "ping", "from": "h1", "to": "h2", "expect": "ok"}},
            {"type": "wait_for", "wait_for": {"type": "tcp", "from": "h1", "to_ip": "10.0.0.2", "expect": "open"}},
            {"type": "wait_for", "wait_for": {"type": "route_prefix", "from": "r1", "to": "10.0.0.0/24", "expect": "present"}},
            {"type": "fault", "action": "link_down", "target": "r1-r2"},
        ]},
        {"id": "s2", "verdict": "pass", "steps": [
            {"type": "wait_for", "wait_for": {"type": "ping", "from": "h2", "to": "h1", "expect": "ok"}},
        ]},
    ]
}
# WF-12: TEST-path summary fixture.
TEST = {"result": "pass", "topology": {"name": "wf12demo"},
        "tests": [{"name": "t1", "verdict": "pass"}, {"name": "t2", "verdict": "pass"}],
        "scenarios": [{"id": "s1", "verdict": "pass"}]}

# ----- REQ-WF-13: declared-tests render replay byte-identity -----
r1 = ct._render_scenarios_summary(copy.deepcopy(SCEN))
r2 = ct._render_scenarios_summary(copy.deepcopy(SCEN))
check("REQ-WF-13 scenarios render is byte-identical on replay", r1 == r2)

# ----- REQ-WF-13: legacy ping/tcp/route_prefix lines drift-guarded (committed golden) -----
GOLDEN_LINES = [
    "    [1] run test=t_core",
    "    [2] wait_for ping h1->h2 expect=ok",
    "    [3] wait_for tcp h1->10.0.0.2 expect=open",
    "    [4] wait_for route_prefix r1->10.0.0.0/24 expect=present",
    "    [5] fault link_down r1-r2",
]
_r1_lines = r1.splitlines()
for gl in GOLDEN_LINES:
    check(f"REQ-WF-13 golden line preserved: {gl.strip()}", gl in _r1_lines)
check("REQ-WF-13 scenario headers rendered", "scenario s1: PASS" in r1 and "scenario s2: PASS" in r1)

# ----- REQ-WF-12: TEST-path summary render replay byte-identity -----
t1 = _render_summary(copy.deepcopy(TEST))
t2 = _render_summary(copy.deepcopy(TEST))
check("REQ-WF-12 TEST-path summary is byte-identical on replay", t1 == t2)

# ----- Non-vacuity: distinct input -> distinct render (not a trivial constant) -----
SCEN_ALT = copy.deepcopy(SCEN)
SCEN_ALT["scenarios"][0]["steps"][1]["wait_for"]["to"] = "h9"  # ping target h2 -> h9
check("NV WF-13 distinct scenario input -> distinct render",
      ct._render_scenarios_summary(SCEN_ALT) != r1)
TEST_ALT = copy.deepcopy(TEST)
TEST_ALT["tests"] = [TEST_ALT["tests"][0]]  # 2 declared tests -> 1; changes "Tests executed: N"
check("NV WF-12 distinct test input -> distinct render", _render_summary(TEST_ALT) != t1)

# ----- TM-CI-1: lab-free CI posture preserved + this regression is CI-wired -----
gate = (ROOT / ".github" / "workflows" / "cassian.yml").read_text(encoding="utf-8")
check("TM-CI-1 verify_phase1.sh reintroduced nowhere in cassian.yml",
      "verify_phase1.sh" not in gate)
check("TM-CI-1 scripts/verify_phase1.sh absent from the repo",
      not (ROOT / "scripts" / "verify_phase1.sh").exists())
check("fold is CI-wired: wf_12_13_replay_proof.py present in the gate",
      "wf_12_13_replay_proof.py" in gate)

# §4.5-b (REQ-45b-18 / §14.4 conditional entry): the three NOS provider-structure
# proofs are gate-wired in lockstep with the cassian.yml step that runs them.
for _p in ("nos_leaf_import_proof.py", "nos_deny_by_default_proof.py",
           "nos_census_instrument.py"):
    check(f"§4.5-b proof is CI-wired: {_p} present in the gate", _p in gate)

# §4.5-c (§14.4 conditional lockstep; Ledger BL-P2-4.5c-11): the four lab-free
# SONiC base-lifecycle proofs are gate-wired in lockstep with the cassian.yml
# step that runs them. A proof that never gates enforces nothing.
# Coverage limit (PBE-P2-8), stated rather than implied: this is a substring test
# over cassian.yml. It proves each proof is NAMED in the gate. It does NOT prove
# the step executes, that the runner reaches it, or that the proof passes.
for _p in ("sonic_leaf_import_proof.py", "sonic_configgen_determinism_proof.py",
           "sonic_provision_supply_proof.py", "sonic_image_lifecycle_proof.py",
           "sonic_lifecycle_proof.py", "sonic_status_probe_sequence_proof.py"):
    check(f"§4.5-c proof is CI-wired: {_p} present in the gate", _p in gate)

fails = [n for n, ok in checks if not ok]
print(f"PO-B3-fold (WF-12/13 replay): {len(checks) - len(fails)}/{len(checks)} checks passed.")
for n, ok in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
if fails:
    sys.exit(f"PO-B3-fold FAILED ({len(fails)} check(s)).")
print("PO-B3-fold OK.")
