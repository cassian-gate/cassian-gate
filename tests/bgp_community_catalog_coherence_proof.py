#!/usr/bin/env python3
"""
§4.10 bgp_community -- catalog coherence proof (P16; REQ-BGPCOM-COVERAGE-1;
handover §15.2 / §6.7.2). Lab-free, source-anchored, drift-guarded, loud-fail
(PBE-1b-4 proof-method).

The operative invariant catalog's authoritative pair is the gate-tuple
(Site A, cassian_model.py `if inv_type not in (...)`) and its operator-facing
unsupported-type error string (Site B, the `(supported: ...)` enumeration).
Both must enumerate the identical catalog including `bgp_community`. The
pack-subset (Site C, `supported_pack_invariant_types`) and the run_named_test
pre-check (Site D) are INTENTIONAL SUBSETS and are explicitly NOT part of the
A<=>B coherence assertion; the harness instead guards that `bgp_community` was
not accidentally added to Site C.

This harness reads the source directly (no deployed lab) and fails loudly on
any divergence/omission. A drift-guard self-test confirms the comparison is not
a no-op.

Proof obligations:
  P16-A     Site A (gate-tuple) includes bgp_community.
  P16-B     Site B (error string) includes bgp_community.
  P16-AB    Site A and Site B enumerate the identical catalog (set + order).
  P16-C     Site C (pack-subset) intentionally EXCLUDES bgp_community (subset of A).
  P16-LOUD  drift-guard self-test: a synthetic A/B divergence is detected.

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

    check("P16-A Site A gate-tuple includes bgp_community", "bgp_community" in site_a)
    check("P16-B Site B error string includes bgp_community", "bgp_community" in site_b)
    check("P16-AB Site A <=> Site B identical catalog (set)", set(site_a) == set(site_b))
    check("P16-AB Site A <=> Site B identical catalog (order)", tuple(site_a) == tuple(site_b))
    check("P16-AB coherence helper agrees", _coherent(site_a, site_b))
    check("P16-C Site C (pack-subset) excludes bgp_community", "bgp_community" not in site_c)
    check("P16-C Site C is an intentional subset of Site A",
          set(site_c) <= set(site_a) and 0 < len(site_c) < len(site_a))

    # P16-LOUD: drift-guard self-test -- the comparison must FLAG a synthetic
    # divergence (proves the harness is not a no-op; loud-fail model holds).
    synth_a = tuple(site_a)
    synth_b = tuple(t for t in site_b if t != "bgp_community")  # B drops the new type
    check("P16-LOUD synthetic A/B divergence is detected (loud-fail)",
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
