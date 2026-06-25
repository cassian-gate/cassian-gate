#!/usr/bin/env python3
"""ai_change_reference_case_proof.py -- Phase 1b 4.9 lab-free behavioral-model proof.

Proves the AI-change canonical reference case WITHOUT deploying a lab:

  [1] positive: committed as-shipped passing evidence  -> verdict pass
  [2] negative: committed as-shipped failing evidence  -> genuine FAIL, failed item
      PRESENT and NOT not_executed (silence != pass; REQ-4_9-4)
  [3] DC 13(c) PRESENT-half via the live _format_observed_state_block render boundary
  [4] DC 13(c) ABSENT-half  via the live _format_observed_state_absence_block render
      boundary (+ committed absent-half data condition) -- both halves from first
      authoring (Amendment A1)
  [5] verdict-core replay-identity: _extract_verdict_core is invariant to timing
  [6] Doctrine 1.12: no AI-privileged path in the engine verdict surface (REQ-4_9-5)
  [7] lab-free: the harness spawns no lab / clab / subprocess deploy

Authority: src/cassian_tests.py (render) + src/cassian_engine.py (no-AI-branch).
No src/ edits (REQ-4_9-12). cassian-test-alone CI posture (4.7). Self-verifying:
__main__ exits nonzero on any failed check (Doctrine 20).
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(SRC))

from cassian_tests import (  # noqa: E402  (path set above)
    _format_observed_state_block,
    _format_observed_state_absence_block,
    _format_test_summary,
)

EVID = REPO_ROOT / "contrib" / "topologies" / "ai-change-reference-case"
ENGINE = SRC / "cassian_engine.py"

# REQ-4_9-5 / Doctrine 1.12: AI-origin branch tokens that must not appear in the
# engine verdict surface (the gate treats AI-authored and human-authored changes
# identically; there is no privileged path).
_AI_TOKEN_RE = re.compile(
    r"ai[_-]?origin|ai[_-]?authored|authored[_-]?by|source[_-]?is[_-]?ai|"
    r"ai[_-]?generated|ai[_-]?candidate|origin[_-]?(ai|human)",
    re.IGNORECASE,
)

# Nondeterministic timing fields excluded from the verdict core.
_TIMING_SUMMARY_KEYS = (
    "duration_ms",
    "started_at",
    "finished_at",
    "resolved_topology_mtime",
)

_failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if cond:
        print(f"  PASS  {msg}")
    else:
        print(f"  FAIL  {msg}")
        _failures.append(msg)


def _load(variant: str, verdict: str) -> dict:
    p = EVID / variant / verdict / "evidence" / "results.json"
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def _extract_verdict_core(results: dict) -> dict:
    """Return the verdict-relevant core with all nondeterministic timing removed.

    A deterministic gate produces byte-identical cores across replays of the same
    topology; only timing varies. Stripping timing here makes the core invariant to
    run-to-run timing, so two replays yield identical cores (replay-identity).
    """
    r = copy.deepcopy(results)
    summ = r.get("summary")
    if isinstance(summ, dict):
        for k in _TIMING_SUMMARY_KEYS:
            summ.pop(k, None)
    r.pop("timing", None)
    for t in r.get("tests") or []:
        if isinstance(t, dict):
            t.pop("duration_ms", None)
    return r


def test_positive_evidence() -> None:
    print("[1] positive: committed passing evidence => verdict pass")
    for variant in ("core-builtin-bgp", "udi-bgp-variant"):
        d = _load(variant, "passing")
        check(d.get("result") == "pass", f"{variant}/passing result==pass")
        check((d.get("overall") or {}).get("verdict") == "pass",
              f"{variant}/passing overall.verdict==pass")
        check(int((d.get("summary") or {}).get("failed") or 0) == 0,
              f"{variant}/passing summary.failed==0")


def test_negative_evidence() -> None:
    print("[2] negative: committed failing evidence => genuine FAIL, present, not not_executed")
    for variant in ("core-builtin-bgp", "udi-bgp-variant"):
        d = _load(variant, "failing")
        check(d.get("result") == "fail", f"{variant}/failing result==fail")
        tests = d.get("tests") or []
        failed = [t for t in tests if isinstance(t, dict) and t.get("verdict") == "fail"]
        check(len(failed) >= 1, f"{variant}/failing has a verdict==fail record present")
        ne = [t for t in tests if isinstance(t, dict) and t.get("verdict") == "not_executed"]
        check(len(ne) == 0,
              f"{variant}/failing has NO not_executed record (genuine fail, not silent drop)")
        check(int((d.get("summary") or {}).get("not_executed") or 0) == 0,
              f"{variant}/failing summary.not_executed==0")


def test_present_half() -> None:
    print("[3] DC 13(c) PRESENT-half via live _format_observed_state_block")
    obs = {"state": "not-established", "peer": "10.0.0.2", "returncode": 0}
    lines = _format_observed_state_block(obs, False)
    txt = "\n".join(lines)
    check(bool(lines) and lines[0].strip() == "observed:",
          "present block opens with 'observed:'")
    check("peer: 10.0.0.2" in txt, "present block renders observed key:value (peer)")
    check("state: not-established" in txt, "present block renders observed key:value (state)")
    # no-drift: committed udi-failing (kind:exec, dict observed_state) re-renders the present-half
    d = _load("udi-bgp-variant", "failing")
    summ_txt = _format_test_summary(d)
    check("    observed:" in summ_txt,
          "udi-failing live re-render contains a present 'observed:' block (no-drift)")
    check("stdout_excerpt:" in summ_txt,
          "udi-failing present-half renders the observed state (stdout_excerpt)")


def test_absent_half() -> None:
    print("[4] DC 13(c) ABSENT-half via live _format_observed_state_absence_block")
    lines = _format_observed_state_absence_block(
        {"type": "bgp_session_up", "peer": "10.0.0.2"}, "r1", "r2", "pass"
    )
    txt = "\n".join(lines)
    check(bool(lines) and lines[0].strip() == "observed:",
          "absence block opens with 'observed:'")
    check("type: bgp_session_up" in txt, "absence block renders (a) type")
    check("expected: pass" in txt, "absence block renders (b) expected")
    check("structured failure detail unavailable" in txt,
          "absence block renders (c) explicit detail-unavailable (silence != success)")
    # via the full formatter (kind:invariant, no observed_state)
    constructed = {
        "lab": "x",
        "result": "fail",
        "summary": {"total": 1, "passed": 0, "failed": 1},
        "tests": [{
            "name": "inv1", "kind": "invariant", "verdict": "fail",
            "expected": "pass", "from": "r1", "to": "r2",
            "meta": {"type": "bgp_session_up", "peer": "10.0.0.2"},
        }],
    }
    st = _format_test_summary(constructed)
    check("structured failure detail unavailable" in st,
          "formatter emits absence indicator for invariant with no observed_state")
    # committed core-failing exhibits the absent-half DATA condition
    d = _load("core-builtin-bgp", "failing")
    failed = [t for t in (d.get("tests") or [])
              if isinstance(t, dict) and t.get("verdict") == "fail"]
    check(len(failed) >= 1 and all(t.get("observed") == "blocked" for t in failed),
          "core-failing evidence: failed record observed==blocked (absent-half data)")
    check(all(not isinstance(t.get("observed_state"), dict) for t in failed),
          "core-failing evidence: no structured observed_state on the blocked record")


def test_replay_identity() -> None:
    print("[5] verdict-core replay-identity (core invariant to timing)")
    d = _load("udi-bgp-variant", "failing")
    core1 = _extract_verdict_core(d)
    pert = copy.deepcopy(d)
    s = pert.setdefault("summary", {})
    s["duration_ms"] = 999999
    s["started_at"] = 0.0
    s["finished_at"] = 1.0
    s["resolved_topology_mtime"] = 0.0
    pert["timing"] = {"x": 1}
    for t in pert.get("tests") or []:
        if isinstance(t, dict):
            t["duration_ms"] = 123456
    core2 = _extract_verdict_core(pert)
    check(json.dumps(core1, sort_keys=True) == json.dumps(core2, sort_keys=True),
          "verdict core byte-identical under timing perturbation")
    check(core1.get("result") == "fail", "extracted core retains authoritative result")
    check(json.dumps(_extract_verdict_core(core1), sort_keys=True)
          == json.dumps(core1, sort_keys=True),
          "extractor idempotent")


def test_no_ai_privileged_path() -> None:
    print("[6] Doctrine 1.12: no AI-privileged path in engine verdict surface")
    src = ENGINE.read_text(encoding="utf-8")
    m = _AI_TOKEN_RE.search(src)
    check(m is None,
          f"src/cassian_engine.py has no AI-origin branch token (found: {m.group(0) if m else 'none'})")


def test_lab_free() -> None:
    print("[7] lab-free: harness contains no lab-deploy / subprocess-spawn calls")
    self_src = Path(__file__).read_text(encoding="utf-8")
    # Needles are assembled by concatenation so this scanner does not match its
    # own pattern list; the literal call-forms must not appear verbatim in source.
    needles = [
        "subprocess" + ".run(",
        "subprocess" + ".Popen(",
        "os" + ".system(",
        "clab" + " deploy",
        "containerlab" + " deploy",
        "cassian" + " test ",
    ]
    found = [n for n in needles if n in self_src]
    check(not found, f"no deploy/spawn call patterns in harness (found: {found})")


def main() -> int:
    print("=== ai_change_reference_case_proof (lab-free) ===")
    for fn in (
        test_positive_evidence,
        test_negative_evidence,
        test_present_half,
        test_absent_half,
        test_replay_identity,
        test_no_ai_privileged_path,
        test_lab_free,
    ):
        fn()
    print()
    if _failures:
        print(f"RESULT: FAIL ({len(_failures)} check(s) failed)")
        for m in _failures:
            print(f"  - {m}")
        return 1
    print("RESULT: PASS (all checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
