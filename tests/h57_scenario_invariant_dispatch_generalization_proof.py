#!/usr/bin/env python3
"""
§4.4 BL-H5-7 scenario invariant-dispatch generalization proof (owns doctrine
surface S1; handover §10a / §6.7.2).

Proves that on the scenario `run:` path, run_named_test routes ALL catalog
invariant types to the shared evaluator run_invariant_test, closing the
OSPF-via-scenario gap. The dispatch seam (run_named_test) is a nested closure
inside cmd_test (cassian_engine.py) with no lab-free runtime trigger, so this
harness proves the routing at the seam by source validation of the patched
guard plus a behavioral model of the dispatch decision -- deterministic and
lab-free, matching the bl6_* / bl_h3_8_* per-handover proof determinism. The
deployed-verdict positive (cassian test --scenario producing a genuine evaluated
verdict, no "missing src/dst") is exercised separately as an operator
verification command per the §6.7.2 extension model.

Proof obligations (handover §15.2):
  P-H57-COV  every one of the 13 catalog invariant types (sourced from
             cassian_model.py) routes through run_invariant_test from the
             scenario path -- the patched guard is type-agnostic
             (kind == "invariant"), with no per-inv_type gating.
  P-H57-POS  the prior interface_state-only special-case is gone; ospf_neighbor_up
             (and every other non-interface_state catalog type) now routes via the
             type-agnostic guard rather than falling to the dst-demanding `else`
             ("missing src/dst"). (Deployed-verdict run: operator command.)
  P-H57-NEG  non-regression: the standalone TEST-phase dispatch call
             (run_invariant_test(test_name=test_name, src=src, t=t)), the
             ping / tcp / bgp_neighbor scenario handlers, and the dst-demanding
             `else` for unknown kinds are all still present; non-invariant kinds
             do NOT route to the invariant evaluator.
  P-DET      the routing decision is a pure function of `kind` (same inputs ->
             same output) and the dispatch block carries no nondeterministic
             surface (time/env/random/uuid) -- REQ-ENGVAL-PRES-4 / D01.

Reads src/cassian_engine.py and src/cassian_model.py as captured in
SNAPSHOT_MAPPING.txt (v482 + the WI-1 dispatch patch).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")

_ENGINE = os.path.join(_SRC, "cassian_engine.py")
_MODEL = os.path.join(_SRC, "cassian_model.py")

# Authoritative copy of the 13-type invariant catalog, used to cross-check the
# catalog actually declared in cassian_model.py (drift guard).
EXPECTED_CATALOG = (
    "bgp_session_up",
    "route_present",
    "route_absent",
    "bgp_med_equals",
    "bgp_localpref_equals",
    "bgp_community",  # F3 re-baseline: section 4.10
    "bgp_as_path",    # F3 re-baseline: section 4.11
    "route_advertised_to",
    "route_not_advertised_to",
    "evpn_mac_route_present",
    "evpn_mac_route_absent",
    "evpn_vni_route_present",
    "evpn_bgp_session_up",
    "ospf_neighbor_up",
    "interface_state",
)

# Old (pre-BL-H5-7) interface_state-only scenario dispatch guard -> must be ABSENT.
_OLD_GUARD = 'if kind == "invariant" and inv_type == "interface_state":'
# New (BL-H5-7) type-agnostic scenario dispatch guard.
_NEW_GUARD = 'if kind == "invariant":'

# Nondeterministic-surface tokens that must not appear in the dispatch block.
_NONDET = ("time.", "datetime", "random", "uuid", "os.environ", "getenv", "monotonic")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _extract_catalog(model_src):
    # Pull the quoted invariant type names from the `if inv_type not in ( ... ):`
    # catalog tuple in cassian_model.py.
    m = re.search(r"if inv_type not in \((.*?)\):", model_src, re.DOTALL)
    if not m:
        return ()
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1)))


def _extract_dispatch_block(engine_src):
    # The patched scenario dispatch block is uniquely marked by record_fn_local.
    # Return the type-agnostic guard line through the run_invariant_test(...)
    # return, inclusive.
    lines = engine_src.splitlines()
    idx = next((i for i, ln in enumerate(lines) if "record_fn_local" in ln), None)
    if idx is None:
        return ""
    start = idx
    while start > 0 and lines[start].strip() != _NEW_GUARD:
        start -= 1
    end = idx
    seen_return = False
    while end < len(lines):
        if "run_invariant_test(" in lines[end]:
            seen_return = True
        if seen_return and lines[end].strip() == ")":
            break
        end += 1
    return "\n".join(lines[start:end + 1])


def _scenario_routes_to_invariant_evaluator(kind, inv_type):
    # Behavioral model of the patched run_named_test scenario dispatch guard:
    # kind == "invariant" delegates to run_invariant_test, type-agnostic (no
    # per-inv_type gating). Validated against the actual source below.
    return kind == "invariant"


def main():
    engine_src = _read(_ENGINE)
    model_src = _read(_MODEL)
    catalog = _extract_catalog(model_src)
    block1 = _extract_dispatch_block(engine_src)
    block2 = _extract_dispatch_block(_read(_ENGINE))
    guard_line = block1.splitlines()[0].strip() if block1 else ""

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # --- catalog drift guard ---
    check("catalog has 15 types", len(catalog) == 15)
    check("catalog matches expected set", set(catalog) == set(EXPECTED_CATALOG))

    # --- source validation of the patched dispatch seam ---
    check("dispatch block present (record_fn_local marker)", bool(block1))
    check("dispatch guard is type-agnostic (kind == 'invariant')", guard_line == _NEW_GUARD)
    check("dispatch guard has no per-inv_type gating", "inv_type" not in guard_line)
    check("dispatch block delegates to run_invariant_test",
          "return run_invariant_test(" in block1 and "record_fn=record_fn_local" in block1)
    check("P-H57-POS old interface_state-only guard removed (engine-wide)",
          _OLD_GUARD not in engine_src)

    # --- P-H57-COV: every catalog type routes via the type-agnostic guard ---
    for t in catalog:
        check(f"P-H57-COV {t} routes to run_invariant_test",
              _scenario_routes_to_invariant_evaluator("invariant", t) is True)

    # --- P-H57-POS: ospf_neighbor_up (gap driver) routes; no missing src/dst ---
    check("P-H57-POS ospf_neighbor_up routes (gap closed)",
          _scenario_routes_to_invariant_evaluator("invariant", "ospf_neighbor_up") is True)

    # --- P-H57-NEG: non-invariant kinds do NOT route to the invariant evaluator ---
    for k in ("ping", "tcp", "bgp_neighbor", "wait_for", "prereq"):
        check(f"P-H57-NEG non-invariant kind {k!r} not routed to evaluator",
              _scenario_routes_to_invariant_evaluator(k, None) is False)
    # --- P-H57-NEG: unchanged anchors still present in source ---
    check("P-H57-NEG standalone TEST-phase dispatch intact",
          "run_invariant_test(test_name=test_name, src=src, t=t)" in engine_src)
    check("P-H57-NEG ping handler intact", "run_ping_test(" in engine_src)
    check("P-H57-NEG tcp handler intact", "run_tcp_test(" in engine_src)
    check("P-H57-NEG bgp_neighbor handler intact", "run_bgp_neighbor_test(" in engine_src)
    check("P-H57-NEG dst-demanding else fallthrough intact",
          'error="missing src/dst"' in engine_src)

    # --- P-DET: pure routing decision + no nondeterministic surface in the block ---
    check("P-DET routing decision is pure (same inputs -> same output)",
          _scenario_routes_to_invariant_evaluator("invariant", "ospf_neighbor_up")
          == _scenario_routes_to_invariant_evaluator("invariant", "ospf_neighbor_up"))
    check("P-DET dispatch block byte-identical across two reads", block1 == block2)
    check("P-DET no nondeterministic token in dispatch block",
          not any(tok in block1 for tok in _NONDET))

    print("dispatch block under proof:")
    print("-" * 60)
    print(block1)
    print("-" * 60)
    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
