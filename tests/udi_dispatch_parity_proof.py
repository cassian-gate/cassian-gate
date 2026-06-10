#!/usr/bin/env python3
"""
§4.7 User-Defined Invariants (`exec`) -- dispatch parity proof
(handover §15 / REQ-UDI-DISPATCH-1/2/3; A5).

Source-validation proof (the h57_* pattern): `cassian test` dispatch executes
only against a deployed lab, so this proves the dispatch WIRING by inspecting
the engine source rather than running it. It asserts that `exec` is accepted and
routed to the DISTINCT `run_exec_test` evaluator at BOTH dispatch sites (the
standalone TEST loop and the scenario `run_named_test`), with the same
`record_fn` contract as the invariant path, and that the BL-H5-7
invariant-dispatch guard is byte-intact (invariant kinds still route to
`run_invariant_test`, never to `run_exec_test`). BL-H5-7 itself is independently
re-proved by h57_scenario_invariant_dispatch_generalization_proof.py.

Proof obligations:
  D1-STD     standalone accept-gate admits `exec` (DISPATCH-1).
  D1-SITES   exactly two `exec` dispatch guards (standalone + scenario) (DISPATCH-1).
  D2-DEF     run_exec_test defined exactly once.
  D2-STD     standalone `exec` routes to run_exec_test (DISPATCH-2).
  D2-SCN     scenario `exec` routes to run_exec_test with record_fn_local (DISPATCH-2).
  D2-DISTINCT run_exec_test never calls run_invariant_test; run_invariant_test is
             invoked only from the two invariant paths (no exec bleed) (DISPATCH-2).
  D2-BLH57   invariant guards intact: standalone + scenario still route to
             run_invariant_test (DISPATCH-2; cross-ref h57).
  D3-PARITY  scenario `exec` mirrors the scenario invariant record_fn contract
             (record_fn_local on scenario_ctx) -> identical record/meta path (DISPATCH-3).
  D2-REC     run_exec_test records via record_fn (parity record surface).
  D-DET      run_exec_test carries no nondeterministic surface.

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
_ENG = os.path.join(_SRC, "cassian_engine.py")


def _read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def _func(text, name):
    """Slice a `def name(...)` body (handles nested defs) up to the next def at <= its indent."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.lstrip().startswith(f"def {name}(")), None)
    if start is None:
        return ""
    base = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        l = lines[i]
        if l.strip() and (len(l) - len(l.lstrip())) <= base and l.lstrip().startswith("def "):
            end = i
            break
    return "\n".join(lines[start:end])


def main():
    s = _read(_ENG)
    fexec = _func(s, "run_exec_test")
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # D1: acceptance at both sites
    check("D1-STD standalone accept-gate admits exec",
          s.count('if kind not in ("ping", "tcp", "bgp_neighbor", "route_prefix", "invariant", "exec"):') == 1)
    check("D1-SITES exactly two exec dispatch guards (standalone + scenario)",
          s.count('if kind == "exec":') == 2)

    # D2: distinct evaluator + routing at both sites
    check("D2-DEF run_exec_test defined exactly once",
          s.count("def run_exec_test(") == 1)
    check("D2-STD standalone exec routes to run_exec_test",
          s.count("verdict = run_exec_test(test_name=test_name, src=src, t=t)") == 1)
    check("D2-SCN scenario exec routes to run_exec_test with record_fn_local",
          s.count("return run_exec_test(\n                test_name=ref, src=src, t=t, record_fn=record_fn_local") == 1)
    check("D2-DISTINCT run_exec_test never calls run_invariant_test",
          bool(fexec) and "run_invariant_test(" not in fexec)
    check("D2-DISTINCT run_invariant_test invoked only from invariant paths (1 def + 2 calls)",
          s.count("run_invariant_test(") == 3)
    check("D2-DISTINCT run_exec_test invoked only at the two dispatch sites (1 def + 2 calls)",
          s.count("run_exec_test(") == 3)

    # D2-BLH57: invariant guards byte-intact
    check("D2-BLH57 standalone invariant routes to run_invariant_test",
          s.count("verdict = run_invariant_test(test_name=test_name, src=src, t=t)") == 1)
    check("D2-BLH57 scenario invariant routes to run_invariant_test",
          s.count("return run_invariant_test(\n                test_name=ref, src=src, t=t, record_fn=record_fn_local") == 1)

    # D3-PARITY: scenario exec mirrors scenario invariant record_fn contract
    check("D3-PARITY scenario exec + invariant share record_fn_local contract (2 sites)",
          s.count("record_fn_local = (") == 2)

    # D2-REC + D-DET on the evaluator shell
    check("D2-REC run_exec_test records via record_fn", "record_fn(" in fexec)
    # WI-3: real evaluator uses time.time() for duration_ms (replay-normalized,
    # exactly as the invariant evaluator). Guard only UNEXPECTED nondeterminism;
    # record replay-stability is proven by udi_replay_determinism_proof.py.
    _nd = ("random.", "uuid", "datetime", "os.environ", "getenv")
    check("D-DET run_exec_test has no unexpected nondeterministic surface",
          bool(fexec) and not any(tok in fexec for tok in _nd))

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
