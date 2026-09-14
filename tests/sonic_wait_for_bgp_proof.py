#!/usr/bin/env python3
"""tests/sonic_wait_for_bgp_proof.py -- 4.5-c WI-3 Unit B.

Req-IDs: REQ-45C-10 (the scenario `wait_for_bgp` action works for sonic-vm
                     nodes under the same scenario schema)
         REQ-45C-30 (no new action name; the scenario schema is unchanged)

Founder rulings applied, none re-opened here:
  LD-45C-R2  R1 -- the engine-side provider dispatch this leg observes.
  LD-45C-R12 R1/R2/R3 -- fixtures: a new converging pair for :463; the
      existing non-converging pair reused for :464 on a SHAPE condition.
  LD-45C-R13 R1/R2/R3 -- this file, subcommand-dispatched; argvs imported,
      never restated. R3 is satisfied VACUOUSLY: no leg here sends an argv to
      a guest (LD-45C-R15 R3), so LD-45C-R13 D-2's harness-argv question is
      untouched, not resolved.
  LD-45C-R14 -- CI wiring: three steps, each downing its own lab.
  LD-45C-R15 R1/R4 -- :463's non-vacuity is LEG A (lab-free branch proof)
      PLUS the live (VM) pass. Neither alone discharges it.
  LD-45C-R16 R1/R3/R4 -- :464 asserts on TWO surfaces: the scenario step
      RECORD for verdict and shape, and the step's CAPTURED OUTPUT for the
      13-grade per-neighbour evidence, which lives only in the run's output
      (`.github/workflows/cassian.yml`, the REQ-45C-29 step's own comment).
  Founder ruling, session 13 -- both fixtures declare the `wait_for_bgp`
      scenario step. Neither did when LD-45C-R12 was ratified; the legs below
      cannot run without it, and no CLI route supplies a scenario from
      outside the topology (`--scenario` takes `scenarios[*].id`).

Snapshot mapping (handover 6.7.2 mapping discipline):
  * `src/cassian_engine.py` is read as SOURCE by LEG A and LEG B. It is never
    imported -- `run_scenario` is closure-bound inside `cmd_test`.
  * `src/cassian_model.py` is IMPORTED LIVE by LEG A, because the branch
    condition is EVALUATED against the real registry rather than asserted
    from the code's shape (F-45C-C3-4: classification adopted from a
    grouping rather than read from the declarations is assert-from-structure).

LEGS
  Lab-free, run on every invocation:
    LEG A -- REQ-45C-10 branch selection (LD-45C-R15 R1/R4).
    LEG B -- REQ-45C-30 scenario-schema regression (15.2 :465).
  argv-driven, (VM):
    req10    <results.json>            -- 15.2 :463 positive
    req10neg <results.json> <capture>  -- 15.2 :464 negative, two surfaces
    schema                             -- lab-free legs only, no lab

COVERAGE LIMITS (PBE-P2-8) -- stated rather than implied:

  * NO SONiC TIMEOUT RECORD HAS EVER BEEN PRODUCED (`BL-P2-4.5c-81`, OPEN).
    Every record shape this file was written against was measured on FRR, in
    containers, in WSL2, from throwaway /tmp probes. The SONiC failure path
    is EXPECTED to carry `"error": "2"` because `cassian_nos_sonic._fail`
    writes five 13-grade lines to `sys.stderr` and then raises
    `SystemExit(2)`, and the scenario handler records `str(e)`. THAT IS AN
    INFERENCE FROM SOURCE, NOT AN OBSERVATION. Accordingly `_leg_req10neg`
    asserts NO exact `error` value (LD-45C-R16 R3); it PRINTS the observed
    value as evidence so the first real SONiC timeout record is captured
    rather than assumed. Converting that print into an assertion without a
    measurement is the defect this block exists to prevent.
  * `duration_ms` as a timeout discriminator rests on ONE observation --
    10,875 ms against a 10 s bound, once, on one FRR topology. The floor
    asserted below is self-relative (it reads `meta.timeout_s` out of the
    record), so it does not depend on that number; but nothing here
    establishes a bound.
  * LEG A proves branch SELECTION, not branch EXECUTION. That the condition
    evaluates False for `sonic-vm` shows which branch WOULD be taken; that
    the engine reaches that code at all is what the (VM) legs supply. The
    two are jointly necessary and neither is claimed sufficient
    (LD-45C-R15 8).
  * LEG A's residual structural surface: locating WHICH `if` is the dispatch
    is structural even though evaluating it is not (LD-45C-R15 D-1). The
    mitigation is the occurrence-count assertion below (Rule 19): if the
    engine ever grows a second `wait_for_bgp` dispatch, this leg REDs rather
    than picking one.
  * LEG B is a source-level enumeration of the action keys `run_scenario`
    dispatches on. It proves no NEW action name entered that surface. It
    does NOT prove the scenario schema is unchanged in any other respect,
    and it does not read the JSON schema of a step's payload.
  * The (VM) legs cannot be sandbox-proven: the authoring environment has no
    `ai-netsim`. They first execute on the runner.
"""
import io
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from cassian_model import (  # noqa: E402
    NOS_PROVIDERS,
    nos_wait_for_bgp_rejection,
)

_checks = []
_blocked = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


def blocked(name, reason):
    _blocked.append((name, reason))


def _engine_src():
    return io.open(os.path.join(_ROOT, "src", "cassian_engine.py"),
                   encoding="utf-8").read()


# --- LEG A (REQ-45C-10; LD-45C-R15 R1/R4): branch selection -------------------
# The dispatch is LOCATED structurally and then EVALUATED. Locating is the
# residual structural surface (LD-45C-R15 D-1); evaluating is what keeps this
# from being the assert-from-structure defect F-45C-C3-4 records.

_SCEN_DISPATCH_ANCHOR = 'nodes_by_name.get(node)'

_src = _engine_src()
_src_lines = _src.splitlines()

_anchor_idx = [i for i, ln in enumerate(_src_lines) if _SCEN_DISPATCH_ANCHOR in ln]
check("REQ-45C-10 LEG A: exactly ONE scenario wait_for_bgp dispatch in the engine",
      len(_anchor_idx) == 1,
      "Rule 19 -- a substitution is asserted by COUNT, not presence; found %d "
      "occurrence(s) of %r. A second dispatch means this leg is picking one."
      % (len(_anchor_idx), _SCEN_DISPATCH_ANCHOR))

_cond_txt = ""
if len(_anchor_idx) == 1:
    _i = _anchor_idx[0]
    # The branch is the first `if ...:` at or after the anchor. Bounded scan so
    # a refactor that separates them fails this leg rather than reaching past
    # the dispatch into unrelated code.
    _cond_line = None
    for _j in range(_i, min(_i + 8, len(_src_lines))):
        _m = re.match(r"\s*if (.+):\s*$", _src_lines[_j])
        if _m:
            _cond_line = _j
            _cond_txt = _m.group(1)
            break
    check("REQ-45C-10 LEG A: the dispatch branch condition was located",
          bool(_cond_txt),
          "engine line %s: %s" % ((_cond_line + 1) if _cond_line else "n/a",
                                  _cond_txt or "NOT FOUND within 8 lines of the anchor"))

if _cond_txt:
    def _takes_inline(ntype):
        """Evaluate the SHIPPED condition against the LIVE registry."""
        return bool(eval(_cond_txt, {"__builtins__": {}},  # noqa: S307
                         {"_ntype": ntype, "_prov": NOS_PROVIDERS.get(ntype)}))

    _UNREGISTERED = "definitely-not-a-registered-nos"

    check("REQ-45C-10 LEG A: `frr` takes the INLINE wait (NG-9: FRR keeps it)",
          _takes_inline("frr") is True,
          "condition: %s" % _cond_txt)
    check("REQ-45C-10 LEG A: `sonic-vm` takes the PROVIDER branch",
          _takes_inline("sonic-vm") is False,
          "this is the property REQ-45C-10 requires; evaluated, not read off "
          "the code's shape")
    check("REQ-45C-10 LEG A NON-VACUITY: an UNREGISTERED type never reaches a "
          "provider", _takes_inline(_UNREGISTERED) is True,
          "deny-by-default: %r resolves to no provider, so dispatch keeps it on "
          "the inline path" % _UNREGISTERED)
    check("REQ-45C-10 LEG A NON-VACUITY: the registry actually discriminates",
          _takes_inline("frr") != _takes_inline("sonic-vm"),
          "if these agreed, every check above would pass vacuously")

    # The validate-time gate is the reason the dispatch divergence at
    # LD-45C-R11 9 is safe: an unregistered type is rejected before it can
    # reach the inline vtysh path.
    check("REQ-45C-10 LEG A: validate ADMITS `sonic-vm` for wait_for_bgp",
          nos_wait_for_bgp_rejection("sonic-vm") is None,
          "cassian_model.nos_wait_for_bgp_rejection")
    check("REQ-45C-10 LEG A: validate REJECTS an unregistered type",
          isinstance(nos_wait_for_bgp_rejection(_UNREGISTERED), str),
          "reason: %s" % (nos_wait_for_bgp_rejection(_UNREGISTERED) or "")[:120])
    check("REQ-45C-10 LEG A: validate REJECTS the empty type",
          isinstance(nos_wait_for_bgp_rejection(""), str),
          "the caller passes '' for a missing type/kind (LD-45C-R11 R2)")


# --- LEG B (REQ-45C-30; 15.2 :465): scenario-schema regression ----------------
# "No new action name." Enumerated from `run_scenario`'s own dispatch, not
# recalled: the set is extracted from the shipped source and compared against
# the frozen pre-4.5-c set.

_EXPECTED_ACTION_KEYS = frozenset({
    "fault", "pcap_start", "pcap_stop", "run", "wait", "wait_for",
    "wait_for_bgp",
})

_rs_start = next((i for i, ln in enumerate(_src_lines)
                  if ln.startswith("    def run_scenario(")), None)
_rs_end = None
if _rs_start is not None:
    _rs_end = next((j for j in range(_rs_start + 1, len(_src_lines))
                    if _src_lines[j].startswith("    def ")), len(_src_lines))

check("REQ-45C-30 LEG B: run_scenario located in the shipped engine",
      _rs_start is not None, "engine line %s" % ((_rs_start + 1) if _rs_start is not None else "NOT FOUND"))

if _rs_start is not None:
    _rs_body = "\n".join(_src_lines[_rs_start:_rs_end])
    _found_keys = frozenset(re.findall(r'if "([a-z_]+)" in step', _rs_body))
    check("REQ-45C-30 LEG B: no NEW scenario action name",
          _found_keys == _EXPECTED_ACTION_KEYS,
          "new: %s  missing: %s"
          % (sorted(_found_keys - _EXPECTED_ACTION_KEYS) or "none",
             sorted(_EXPECTED_ACTION_KEYS - _found_keys) or "none"))
    check("REQ-45C-30 LEG B NON-VACUITY: the enumeration is non-empty and "
          "carries wait_for_bgp", "wait_for_bgp" in _found_keys and len(_found_keys) >= 7,
          "%d action keys enumerated" % len(_found_keys))

# Both fixtures declare the action under its EXISTING name and the existing
# payload keys. `timeout` is optional (engine: `int(wf.get("timeout") or 30)`);
# `node` is required. A fixture introducing a new key would be a schema change
# REQ-45C-30 forbids.
_FIXTURE_KEYS = frozenset({"node", "timeout"})
for _fx in ("sonic-bgp-scenario-wait.yaml", "sonic-bgp-nonconverging.yaml"):
    _p = os.path.join(_ROOT, "topologies", _fx)
    _txt = io.open(_p, encoding="utf-8").read() if os.path.isfile(_p) else ""
    # Strip comments before searching: the fixture headers DISCUSS wait_for_bgp,
    # and a substring match on a comment read as a declaration is the session-12
    # defect this strip exists to prevent.
    _code = "\n".join(ln for ln in _txt.splitlines()
                      if not ln.lstrip().startswith("#"))
    check("REQ-45C-30 %s declares the wait_for_bgp action (code, not comment)"
          % _fx, "wait_for_bgp:" in _code,
          "comments stripped before matching")
    # Scoped to the scenarios block: a key found elsewhere in the fixture
    # (`remote_as` under `bgp.neighbors`, say) says nothing about the step's
    # payload, and a check that cannot tell them apart is not a check.
    _scen = _code.split("\nscenarios:", 1)[1] if "\nscenarios:" in _code else ""
    _step = _scen.split("wait_for_bgp:", 1)[1] if "wait_for_bgp:" in _scen else ""
    _keys = set(re.findall(r"^\s{8,}([a-z_]+):", _step, re.MULTILINE))
    check("REQ-45C-30 %s uses only existing wait_for_bgp payload keys" % _fx,
          bool(_keys) and _keys.issubset(_FIXTURE_KEYS),
          "step payload keys: %s (permitted: %s)"
          % (sorted(_keys) or "NONE FOUND", sorted(_FIXTURE_KEYS)))


# --- (VM) legs ----------------------------------------------------------------

def _wait_records(results_path):
    """Every wait_for_bgp step record in results.json, across all scenarios."""
    doc = json.loads(io.open(results_path, encoding="utf-8").read())
    out = []
    for scen in (doc.get("scenarios") or []):
        for step in (scen.get("steps") or []):
            if isinstance(step, dict) and step.get("type") == "wait_for_bgp":
                out.append(step)
    return doc, out


def _leg_req10(results_path):
    """15.2 :463 positive (VM). The scenario wait waits, and proceeds."""
    doc, recs = _wait_records(results_path)
    check("REQ-45C-10 (VM) the run produced at least one scenario",
          bool(doc.get("scenarios")),
          "an absent scenarios block is a claim about the run, not the wait")
    check("REQ-45C-10 (VM) exactly ONE wait_for_bgp step record",
          len(recs) == 1,
          "Rule 19: found %d; the fixture declares one step" % len(recs))
    if len(recs) != 1:
        return
    r = recs[0]
    check("REQ-45C-10 (VM) the step record carries type wait_for_bgp",
          r.get("type") == "wait_for_bgp", "type=%r" % r.get("type"))
    check("REQ-45C-10 (VM) verdict is pass -- the wait proceeded",
          r.get("verdict") == "pass",
          "verdict=%r error=%r" % (r.get("verdict"), r.get("error")))
    meta = r.get("meta") or {}
    check("REQ-45C-10 (VM) meta.timeout_s present",
          isinstance(meta.get("timeout_s"), int),
          "meta=%r" % (meta,))
    dur = r.get("duration_ms")
    check("REQ-45C-10 (VM) duration_ms present",
          isinstance(dur, int), "duration_ms=%r" % (dur,))
    if isinstance(dur, int) and isinstance(meta.get("timeout_s"), int):
        check("REQ-45C-10 (VM) NON-VACUITY: it PROCEEDED rather than timing out",
              dur < int(meta["timeout_s"]) * 1000,
              "duration_ms=%d against timeout_s=%d -- a pass at or above the "
              "bound would not be a wait that proceeded"
              % (dur, int(meta["timeout_s"])))


def _leg_req10neg(results_path, capture_path):
    """15.2 :464 negative (VM). TWO surfaces (LD-45C-R16 R1).

    Surface 1 -- the RECORD: verdict and shape.
    Surface 2 -- the CAPTURED OUTPUT: the 13-grade per-neighbour evidence,
    which lives only there.
    """
    # --- surface 1: the record
    _doc, recs = _wait_records(results_path)
    check("REQ-45C-10neg (VM) exactly ONE wait_for_bgp step record",
          len(recs) == 1, "Rule 19: found %d" % len(recs))
    if len(recs) == 1:
        r = recs[0]
        meta = r.get("meta") or {}
        check("REQ-45C-10neg (VM) the step record carries type wait_for_bgp",
              r.get("type") == "wait_for_bgp", "type=%r" % r.get("type"))
        check("REQ-45C-10neg (VM) verdict is fail",
              r.get("verdict") == "fail", "verdict=%r" % r.get("verdict"))
        check("REQ-45C-10neg (VM) meta.timeout_s present",
              isinstance(meta.get("timeout_s"), int), "meta=%r" % (meta,))
        dur = r.get("duration_ms")
        if isinstance(dur, int) and isinstance(meta.get("timeout_s"), int):
            check("REQ-45C-10neg (VM) duration_ms >= timeout_s*1000 -- it POLLED "
                  "to the bound rather than failing early",
                  dur >= int(meta["timeout_s"]) * 1000,
                  "duration_ms=%d timeout_s=%d (LD-45C-R16 R3: the floor is the "
                  "timeout discriminator)" % (dur, int(meta["timeout_s"])))
        else:
            check("REQ-45C-10neg (VM) duration_ms >= timeout_s*1000", False,
                  "duration_ms=%r timeout_s=%r" % (dur, meta.get("timeout_s")))
        # BL-P2-4.5c-81: NO ASSERTION on `error`'s value. Printed as evidence so
        # the first SONiC timeout record is captured, not assumed. `"2"` is
        # INFERRED from cassian_nos_sonic._fail; it has never been observed.
        print("EVIDENCE (BL-P2-4.5c-81, not asserted): scenario record error=%r"
              % (recs[0].get("error"),))

    # --- surface 2: the captured output (mirrors _leg_req29)
    text = io.open(capture_path, encoding="utf-8", errors="replace").read()
    marker = "per-neighbour state at timeout"
    check("REQ-45C-10neg (VM) the capture carries the 13-grade per-neighbour "
          "text", marker in text,
          "cassian_nos_sonic._fail's detail argument; searched %s" % capture_path)
    check("REQ-45C-10neg (VM) the capture is non-empty",
          bool(text.strip()),
          "an empty capture is a claim about the capture, not the run")
    if marker in text:
        seg = text.split(marker, 1)[1].splitlines()[0]
        check("REQ-45C-10neg (VM) the timeout text names at least one peer "
              "state", ":" in seg, "segment: %s" % seg.strip()[:160])


# --- Dispatch -----------------------------------------------------------------
_vm_args = sys.argv[1:]
if not _vm_args or _vm_args[0] == "schema":
    blocked("REQ-45C-10 (VM) :463 converging sonic pair -> scenario wait "
            "proceeds",
            "no (VM) argv supplied; run: req10 <results.json>")
    blocked("REQ-45C-10 (VM) :464 non-converging -> deterministic timeout "
            "inside the scenario record",
            "no (VM) argv supplied; run: req10neg <results.json> <capture>")
elif _vm_args[0] == "req10" and len(_vm_args) == 2:
    _leg_req10(_vm_args[1])
elif _vm_args[0] == "req10neg" and len(_vm_args) == 3:
    _leg_req10neg(_vm_args[1], _vm_args[2])
else:
    sys.exit("usage: sonic_wait_for_bgp_proof.py "
             "[req10 <results.json> | req10neg <results.json> <capture> | "
             "schema]  (no argv = lab-free legs only)")


# --- Report -------------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
for _bn, _br in _blocked:
    print("BLOCKED %s  [%s]" % (_bn, _br))
print("=" * 60)
print("RESULT: %s -- %d checks, %d BLOCKED (WI-3 scenario wait_for_bgp%s)"
      % ("PASS" if not _failed else "FAIL", len(_checks), len(_blocked),
         "" if (_vm_args and _vm_args[0] != "schema") else ", lab-free legs"))
if _blocked:
    print("NOTE: %d (VM) leg(s) BLOCKED. A BLOCKED leg is not a pass; the "
          "closure report carries it as a condition (PBE-P2-8)." % len(_blocked))
sys.exit(1 if _failed else 0)
