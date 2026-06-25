#!/usr/bin/env python3
"""
§4.11 bgp_as_path -- catalog coherence proof (P15; REQ-BGPASPATH-COVERAGE-1;
handover §15.2 / §6.7.2). Lab-free, source-anchored, drift-guarded, loud-fail.

Method: lab-free source-validation (loud-fail) -- MS Amendment A1 (was PBE-1b-4;
PBE-1b-4 is PROVISIONAL and its byte-unchanged-engine precondition does not hold
for the scoped engine, so only the lab-free source-validation technique applies).

The operative invariant catalog's authoritative pair is the gate-tuple
(Site A, cassian_model.py `if inv_type not in (...)`) and its operator-facing
unsupported-type error string (Site B, the `(supported: ...)` enumeration).
Both must enumerate the identical catalog including `bgp_as_path`. The
pack-subset (Site C, `supported_pack_invariant_types`) is an INTENTIONAL SUBSET
and is explicitly NOT part of the A<=>B coherence assertion; the harness instead
guards that `bgp_as_path` was not accidentally added to Site C (subset, not
equality, per the bgp_community/bgp_med_equals omission precedent).

This harness reads the source directly (no deployed lab) and fails loudly on any
divergence/omission. A drift-guard self-test confirms the comparison is not a
no-op.

Proof obligations:
  P15-A     Site A (gate-tuple) includes bgp_as_path.
  P15-B     Site B (error string) includes bgp_as_path.
  P15-AB    Site A and Site B enumerate the identical catalog (set + order).
  P15-C     Site C (pack-subset) intentionally EXCLUDES bgp_as_path (subset of A).
  P15-LOUD  drift-guard self-test: a synthetic A/B divergence is detected.

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
_MODEL = os.path.join(_SRC, "cassian_model.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _site_a_gate_tuple(model_src):
    # Site A: the `if inv_type not in (<tuple>):` membership gate.
    m = re.search(r"if inv_type not in \((.*?)\):", model_src, re.DOTALL)
    if not m:
        return ()
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1)))


def _site_b_error_string(model_src):
    # Site B: the `(supported: ...)` enumeration in the unsupported-type die().
    m = re.search(r"invariant\.type unsupported.*?\(supported:\s*(.*?)\)\"",
                  model_src, re.DOTALL)
    if not m:
        return ()
    return tuple(re.findall(r"[a-z][a-z_]{2,}", m.group(1)))


def _site_c_pack_subset(model_src):
    # Site C: the intentionally-narrow pack-subset set (excluded from A<=>B).
    m = re.search(r"supported_pack_invariant_types\s*=\s*\{(.*?)\}",
                  model_src, re.DOTALL)
    if not m:
        return ()
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1)))


def _coherent(a, b):
    """A<=>B coherence: identical ordered catalog. Loud-fail model -> False on
    any divergence (set or order)."""
    return tuple(a) == tuple(b)


def main():
    model_src = _read(_MODEL)
    site_a = _site_a_gate_tuple(model_src)
    site_b = _site_b_error_string(model_src)
    site_c = _site_c_pack_subset(model_src)

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    check("P15-A Site A gate-tuple includes bgp_as_path", "bgp_as_path" in site_a)
    check("P15-B Site B error string includes bgp_as_path", "bgp_as_path" in site_b)
    check("P15-AB Site A <=> Site B identical catalog (set)", set(site_a) == set(site_b))
    check("P15-AB Site A <=> Site B identical catalog (order)", tuple(site_a) == tuple(site_b))
    check("P15-AB coherence helper agrees", _coherent(site_a, site_b))
    check("P15-C Site C (pack-subset) excludes bgp_as_path", "bgp_as_path" not in site_c)
    check("P15-C Site C is an intentional subset of Site A",
          set(site_c) <= set(site_a) and 0 < len(site_c) < len(site_a))

    # P15-LOUD: drift-guard self-test -- the comparison must FLAG a synthetic
    # divergence (proves the harness is not a no-op; loud-fail model holds).
    synth_a = tuple(site_a)
    synth_b = tuple(t for t in site_b if t != "bgp_as_path")  # B drops the new type
    check("P15-LOUD synthetic A/B divergence is detected (loud-fail)",
          not _coherent(synth_a, synth_b))

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print(f"Site A ({len(site_a)}): {', '.join(site_a)}")
    print(f"Site B ({len(site_b)}): {', '.join(site_b)}")
    print(f"Site C ({len(site_c)}): {', '.join(site_c)}  [intentional subset; excluded from A<=>B]")
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
