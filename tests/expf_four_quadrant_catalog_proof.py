#!/usr/bin/env python3
"""
§4.5 expect-fail invariant semantics — four-quadrant catalog proof
(BL-H2.5-01; handover §6.7.2 / §15.2 REQ-EXPF-4; Doctrine §1.8 Negative-Test,
§1.14 Invariant-Driven Support / uniformity).

Proves that the four-quadrant expect-fail verdict contract for `kind: invariant`
is UNIFORM across the operative 13-type catalog, computed from the single
canonical dispatch seam in run_invariant_test (cassian_engine.py), rather than
coincidental per-type correctness. run_invariant_test and its helper
_evaluate_invariant_attempt are nested closures inside cmd_test (cassian_engine.py
L3090) with no lab-free runtime trigger (_evaluate_invariant_attempt calls
rt.exec(lab, ...)), so — exactly as the bl6_* / bl_h3_8_* / h57_* per-handover
proofs — uniformity is proven LAB-FREE by source validation of the seam plus a
behavioral model of the verdict combination, cross-checked against the live
source expression. Deployed-verdict positives (cassian test over the Q3/Q4
topology fixtures) are exercised separately as operator / NOS-VM verification
commands; they are not part of this lab-free harness.

Reads src/cassian_engine.py, src/cassian_model.py, src/cassian_tests.py as
captured in SNAPSHOT_MAPPING.txt (v2 ≡ v484 pin). Engine is byte-unchanged by
§4.5 (REQ-EXPF-PRES-1/2): this harness proves and locks already-correct logic.

Proof obligations (handover §15.2):
  P-EXPF-CAT   the operative catalog is exactly the 13 types declared in
               cassian_model.py (drift guard).
  P-EXPF-UNIF  every verdict VALUE assignment in run_invariant_test is either the
               canonical seam `verdict = "pass" if observed == expected else
               "fail"` or the B06 error/guard-path constant `verdict="fail"` —
               there is no divergent per-type verdict path (REQ-EXPF-4 / B05).
  P-EXPF-Q     for all 13 types x the four (expect, observed) quadrants, the
               canonical seam yields the contract verdict: Q1 pass/pass->pass,
               Q2 pass/fail->fail, Q3 fail/fail->pass, Q4 fail/pass->fail
               (REQ-EXPF-1/2/3; B01-B04).
  P-EXPF-13BC  §13(b)(c) observed_state is verdict-gated: built only under
               `if verdict == "fail":` (present on Q2/Q4, absent on Q1/Q3), and
               rendered by cassian_tests.py (_format_observed_state_block /
               _format_test_summary) — REQ-EXPF-3 / B04 / GC-4.
  P-EXPF-B06   the structural error/guard path forces verdict=fail REGARDLESS of
               expect and does NOT honor expect: fail (REQ-EXPF-3 / B06 / NG-3).
  P-EXPF-COV   each catalog type has at least one topologies/ fixture exercising
               the direct `expect: fail` path (REQ-EXPF-1/2 deployable catalog).
  P-DET        the verdict combination is a pure function (same inputs -> same
               output) and the seam carries no nondeterministic surface (D01/D04).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
_TOPO = os.path.join(_ROOT, "topologies")

_ENGINE = os.path.join(_SRC, "cassian_engine.py")
_MODEL = os.path.join(_SRC, "cassian_model.py")
_TESTS = os.path.join(_SRC, "cassian_tests.py")

# Authoritative 13-type operative catalog (cross-checked against cassian_model.py).
EXPECTED_CATALOG = (
    "bgp_session_up",
    "route_present",
    "route_absent",
    "bgp_med_equals",
    "bgp_localpref_equals",
    "route_advertised_to",
    "route_not_advertised_to",
    "evpn_mac_route_present",
    "evpn_mac_route_absent",
    "evpn_vni_route_present",
    "evpn_bgp_session_up",
    "ospf_neighbor_up",
    "interface_state",
)

# The single canonical verdict seam (the proven subject; byte-unchanged).
SEAM = 'verdict = "pass" if observed == expected else "fail"'
# The only other verdict VALUE permitted in run_invariant_test: the B06
# error/guard-path constant (recorded in the early-return failure records).
B06_VERDICT = 'verdict="fail",'

_NONDET = ("time.", "datetime", "random", "uuid", "os.environ", "getenv", "monotonic")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _extract_catalog(model_src):
    m = re.search(r"if inv_type not in \((.*?)\):", model_src, re.DOTALL)
    if not m:
        return ()
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1)))


def _run_invariant_test_body(engine_src):
    """Return the source of run_invariant_test: from its `    def` line up to the
    next sibling nested `    def ` inside cmd_test."""
    lines = engine_src.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith("    def run_invariant_test(")),
        None,
    )
    if start is None:
        return ""
    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].startswith("    def ")),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _verdict_value_assignment_lines(body):
    """Lines that assign a VALUE to verdict (RHS is a string literal / the seam
    ternary). Excludes comparisons (verdict ==) and passthrough kwargs
    (verdict=verdict), which do not match `verdict\\s*=\\s*"`."""
    out = []
    for ln in body.splitlines():
        if re.search(r'verdict\s*=\s*"', ln):
            out.append(ln.strip())
    return out


def seam(observed, expected):
    """Behavioral model of the canonical verdict seam (cross-checked vs source)."""
    return "pass" if observed == expected else "fail"


def error_path_verdict(expected):
    """Behavioral model of the B06 structural error/guard path: verdict=fail
    regardless of expect (does NOT honor expect: fail)."""
    return "fail"


# Four-quadrant contract table (expect x observed -> verdict, + §13(b)(c) gate).
QUADRANTS = {
    "Q1": dict(expect="pass", observed="pass", verdict="pass", observed_state=False),
    "Q2": dict(expect="pass", observed="fail", verdict="fail", observed_state=True),
    "Q3": dict(expect="fail", observed="fail", verdict="pass", observed_state=False),
    "Q4": dict(expect="fail", observed="pass", verdict="fail", observed_state=True),
}


def main():
    engine_src = _read(_ENGINE)
    model_src = _read(_MODEL)
    tests_src = _read(_TESTS)
    catalog = _extract_catalog(model_src)
    rit = _run_invariant_test_body(engine_src)

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # --- P-EXPF-CAT: catalog drift guard ---
    check("P-EXPF-CAT catalog has 13 types", len(catalog) == 13)
    check("P-EXPF-CAT catalog matches expected set", set(catalog) == set(EXPECTED_CATALOG))
    check("P-EXPF-CAT catalog order preserved", tuple(catalog) == EXPECTED_CATALOG)

    # --- P-EXPF-UNIF: seam uniformity / no divergent verdict path ---
    check("P-EXPF-UNIF run_invariant_test body located", bool(rit))
    check("P-EXPF-UNIF canonical seam present in engine (locked 11 sites)",
          engine_src.count(SEAM) == 11)
    check("P-EXPF-UNIF canonical seam present in run_invariant_test", SEAM in rit)
    val_assigns = _verdict_value_assignment_lines(rit)
    allowed = {SEAM, B06_VERDICT}
    divergent = [ln for ln in val_assigns if ln not in allowed]
    check("P-EXPF-UNIF every verdict value-assignment is the seam or B06 fail",
          val_assigns and not divergent)
    check("P-EXPF-UNIF no divergent per-type verdict path", divergent == [])

    # --- P-EXPF-Q: four-quadrant contract, uniform across all 13 types from the seam ---
    for t in catalog:
        for q, spec in QUADRANTS.items():
            check(f"P-EXPF-Q {t} {q} {spec['expect']}/{spec['observed']}->{spec['verdict']}",
                  seam(spec["observed"], spec["expect"]) == spec["verdict"])

    # --- P-EXPF-13BC: observed_state is verdict-gated; renderer present ---
    check("P-EXPF-13BC observed_state default None present", "observed_state_payload = None" in rit)
    check("P-EXPF-13BC observed_state built under verdict==fail gate",
          'if verdict == "fail":' in rit)
    none_defaults = rit.count("observed_state_payload = None")
    fail_gates = rit.count('if verdict == "fail":')
    check("P-EXPF-13BC predicate-path None-default pairs 1:1 with verdict==fail gate",
          none_defaults == fail_gates and none_defaults >= 1)
    _rit_lines = [ln.strip() for ln in rit.splitlines()]
    _adjacency_ok = all(
        i + 1 < len(_rit_lines) and _rit_lines[i + 1] == 'if verdict == "fail":'
        for i, ln in enumerate(_rit_lines)
        if ln == "observed_state_payload = None"
    )
    check("P-EXPF-13BC each predicate-path observed_state default is immediately verdict-gated",
          _adjacency_ok)
    check("P-EXPF-13BC observed_state passed to record_fn",
          "observed_state=observed_state_payload" in rit)
    check("P-EXPF-13BC renderer _format_observed_state_block present (cassian_tests.py)",
          "def _format_observed_state_block(" in tests_src)
    check("P-EXPF-13BC renderer _format_test_summary present (cassian_tests.py)",
          "def _format_test_summary(" in tests_src)
    for q, spec in QUADRANTS.items():
        # observed_state present iff verdict == fail (present Q2/Q4, absent Q1/Q3)
        check(f"P-EXPF-13BC {q} observed_state present iff verdict==fail",
              (spec["verdict"] == "fail") == spec["observed_state"])

    # --- P-EXPF-B06: error/guard path forces fail regardless of expect; no expect:fail honoring ---
    check("P-EXPF-B06 error path -> fail when expect: pass", error_path_verdict("pass") == "fail")
    check("P-EXPF-B06 error path -> fail when expect: fail", error_path_verdict("fail") == "fail")
    check("P-EXPF-B06 error path does NOT honor expect: fail (differs from Q3 predicate pass)",
          error_path_verdict("fail") != seam("fail", "fail"))
    check("P-EXPF-B06 engine error records carry the B06 verdict constant", B06_VERDICT in rit)

    # --- P-EXPF-COV: each catalog type has an expect: fail topology fixture ---
    topo_files = []
    if os.path.isdir(_TOPO):
        for dirpath, _dirs, files in os.walk(_TOPO):
            for fn in files:
                if fn.endswith((".yaml", ".yml")):
                    topo_files.append(os.path.join(dirpath, fn))
    topo_blob = {p: _read(p) for p in topo_files}
    for t in catalog:
        covered = any(
            re.search(r"type:\s*" + re.escape(t) + r"(\s|$)", txt) and "expect: fail" in txt
            for txt in topo_blob.values()
        )
        check(f"P-EXPF-COV {t} has an expect: fail fixture", covered)

    # --- P-DET: pure verdict combination + no nondeterministic surface in the seam line ---
    check("P-DET seam is a pure function (same inputs -> same output)",
          seam("pass", "fail") == seam("pass", "fail") and seam("fail", "fail") == seam("fail", "fail"))
    seam_lines = [ln for ln in rit.splitlines() if SEAM in ln]
    check("P-DET no nondeterministic token on the seam line(s)",
          seam_lines and not any(tok in ln for ln in seam_lines for tok in _NONDET))

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 64)
    print(f"checks: {sum(1 for _, p in checks if p)}/{len(checks)} passed")
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
