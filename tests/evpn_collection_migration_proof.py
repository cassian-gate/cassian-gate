#!/usr/bin/env python3
"""§4.5-c WI-7 — EVPN collection migration proof (REQ-45C-14).

Discharges the four §15.2 rows for REQ-45C-14 under the LD-45C-1 ruled shape
and the founder rulings of 2026-08-20:

  row 1  differential on the FRR EVPN topologies, pre/post migration --
         zero verdict deltas, and the supplementary Observation's evidence
         carrying `cmd` / excerpt / `returncode`
  row 2  AST count of `rt.exec` call sites inside `run_invariant_test`
         (baseline exactly 1, target ZERO)
  row 3  no-widening: `Observation`, `ObservationRequest` and the `collect`
         signature unchanged; no composite / multi-payload return
  row 4  misuse path: non-zero supplementary rc -> rc-gated record + exit
         CORE-side; the provider raises no control-flow exit

MODES
  (default)              lab-free legs only (rows 2, 3, 4 + baseline
                         self-consistency). Safe in any pre/post sweep.
  --artifacts <dir>      additionally run row 1 against captured
                         results.json files. In this mode a MISSING or
                         UNREADABLE artifact is a HARD FAIL, never a skip --
                         a silent skip would make the CI leg vacuous.

WHAT IS DETERMINISTIC, AND WHAT IS NOT  (Addendum rev 2, Rule 9)
  Measured on `ai-netsim` at 724eb7b: the EVPN route set contains the two
  DECLARED host MACs (00:11:22:33:44:55, 00:11:22:33:44:66) plus
  container-generated MACs that differ per lab instance -- observed
  56:92:d2:5f:3f:ab / 9a:53:ab:67:86:f7 in one lab and
  aa:c1:ab:bd:1f:74 / aa:c1:ab:f9:c7:97 in another. Route lists and route
  COUNTS are therefore NOT comparable across instances. This proof asserts
  only instance-invariant properties: verdicts, declared-MAC membership,
  route_type typing, and the int/str pairing. It never compares raw route
  lists or counts.

COVERAGE LIMITS  (PBE-P2-8)
  1. `topologies/evpn_mac_route_present_expect_fail.yaml` is NOT in the
     corpus. Its q4 case is declared first and fails, leaving q3
     `not_executed`; it therefore contributes no coverage of the migrated
     path and is not counted as if it did.
  2. `evpn_vni_route_present` does not route to the supplementary leg -- the
     migrated block gates on evpn_mac_route_present / _absent only. VNI-route
     text collection is uncovered here and is not claimed.
  3. The non-vacuity witness is the string-typed `route_type` entry. That
     typing is a PRE-EXISTING defect (JSON leg emits int at
     cassian_nos_frr.py:1154; text leg emits str at :1259; the dedup key at
     cassian_engine.py:6654 includes route_type so they do not collapse),
     recorded and routed to §4.5-e by founder ruling. WHOEVER NORMALISES THAT
     TYPING INVALIDATES THIS WITNESS AND MUST REPLACE IT IN THE SAME CHANGE.
  4. Row 1 proves the migrated path executed and produced no verdict delta.
     It does not prove FRR's response to the command string beyond what the
     corpus exercises.

Reports only; writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import argparse
import ast
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(REPO, "src", "cassian_engine.py")
FRR = os.path.join(REPO, "src", "cassian_nos_frr.py")
TYPES = os.path.join(REPO, "src", "cassian_nos_types.py")

DECLARED_MACS = ("00:11:22:33:44:55", "00:11:22:33:44:66")

# PRE-side baseline, captured on ai-netsim at 724eb7b (pre-migration), clean
# tree, authoritative invocation (topology path -> GATE). Provenance: the
# §4.5-c Chat-3 session-5 pre-side capture, /tmp/wi7-preside/.
# `reaches` = whether the declared test drives the migrated block, derived
# from the block's own gate: `not present and inv_type in
# ("evpn_mac_route_present", "evpn_mac_route_absent")`.
BASELINE = {
    "evpn-mac-route-present": {
        "topology": "topologies/evpn_mac_route_present.yaml",
        "tests": {
            "leaf2_sees_host1_mac_route": {
                "expected": "pass", "observed": "pass", "verdict": "pass",
                "reaches": False,
            },
        },
    },
    "evpn-mac-route-absent-expected-present": {
        "topology": "topologies/evpn_mac_route_absent_expected_present.yaml",
        "tests": {
            "leaf2_sees_absent_mac_route": {
                "expected": "pass", "observed": "fail", "verdict": "fail",
                "reaches": True,
            },
        },
    },
    "evpn-mac-route-absent-expect-fail": {
        "topology": "topologies/evpn_mac_route_absent_expect_fail.yaml",
        "tests": {
            "q3_evpn_mac_route_absent_host1_mac_present_expect_fail": {
                "expected": "fail", "observed": "fail", "verdict": "pass",
                "reaches": False,
            },
            "q4_evpn_mac_route_absent_absent_mac_holds_but_expect_fail": {
                "expected": "fail", "observed": "pass", "verdict": "fail",
                "reaches": True,
            },
        },
    },
}

RESULTS = []


def check(label, ok, detail=""):
    RESULTS.append((label, bool(ok), detail))
    print("%-6s %s%s" % ("PASS" if ok else "FAIL", label,
                         ("  -- " + detail) if detail else ""))
    return bool(ok)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _fn(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


# ------------------------------------------------------------------ row 2 --
def row2_exec_count():
    print("\n--- row 2: rt.exec inside run_invariant_test (target ZERO) ---")
    tree = ast.parse(_read(ENGINE))
    fn = _fn(tree, "run_invariant_test")
    if fn is None:
        return check("R2-FOUND run_invariant_test present", False)
    check("R2-FOUND run_invariant_test present", True,
          "span %d-%d" % (fn.lineno, fn.end_lineno))
    sites = [n.lineno for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "exec"]
    check("R2-ZERO no *.exec call site inside run_invariant_test",
          not sites, "sites=%s" % sites)
    seam = [n for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_nos_collect"]
    check("R2-SEAM supplementary collection dispatches via _nos_collect",
          len(seam) >= 1, "call sites=%d" % len(seam))


# ------------------------------------------------------------------ row 3 --
def row3_no_widening():
    print("\n--- row 3: no contract widening ---")
    types_src = _read(TYPES)
    tree = ast.parse(types_src)

    for cls in ("Observation", "ObservationRequest"):
        node = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.ClassDef) and n.name == cls), None)
        if node is None:
            check("R3-CONTRACT %s present" % cls, False)
            continue
        fields = sorted(
            t.target.id for t in node.body
            if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)
        )
        expect = {
            "Observation": ["data", "evidence", "kind"],
            "ObservationRequest": ["kind", "params"],
        }[cls]
        check("R3-CONTRACT %s fields unchanged" % cls,
              fields == expect, "fields=%s expected=%s" % (fields, expect))

    frr_tree = ast.parse(_read(FRR))
    collect = _fn(frr_tree, "collect")
    if collect is None:
        check("R3-SIG collect present in provider", False)
    else:
        args = [a.arg for a in collect.args.args]
        check("R3-SIG collect signature unchanged",
              args == ["rt", "lab", "node", "req"], "args=%s" % args)
        ret = collect.returns
        ret_name = getattr(ret, "id", None) or getattr(ret, "attr", None)
        check("R3-SIG collect returns a bare Observation",
              ret_name == "Observation", "returns=%r" % ret_name)

    leg = _fn(frr_tree, "_collect_evpn_routes_text")
    if leg is None:
        check("R3-LEG supplementary leg present", False)
        return
    check("R3-LEG supplementary leg present", True)
    returns = [n for n in ast.walk(leg) if isinstance(n, ast.Return)]
    single = all(
        isinstance(r.value, ast.Call)
        and getattr(r.value.func, "id", None) == "Observation"
        for r in returns if r.value is not None
    )
    check("R3-NOCOMPOSITE leg returns a single Observation, never a tuple",
          single and len(returns) >= 1, "returns=%d" % len(returns))
    ev = None
    for r in returns:
        if r.value is None or not isinstance(r.value, ast.Call):
            continue
        for kw in r.value.keywords:
            if kw.arg == "evidence" and isinstance(kw.value, ast.Dict):
                ev = sorted(k.value for k in kw.value.keys
                            if isinstance(k, ast.Constant))
    check("R3-EVIDENCE supplementary evidence carries cmd/excerpt/returncode",
          ev == ["cmd", "excerpt", "returncode"], "keys=%s" % ev)


# ------------------------------------------------------------------ row 4 --
def row4_misuse_path():
    print("\n--- row 4: misuse path is CORE-side ---")
    frr_src = _read(FRR)
    frr_tree = ast.parse(frr_src)
    leg = _fn(frr_tree, "_collect_evpn_routes_text")
    if leg is None:
        check("R4-LEG supplementary leg present", False)
        return
    raises = [n for n in ast.walk(leg)
              if isinstance(n, ast.Raise)
              or (isinstance(n, ast.Call)
                  and getattr(n.func, "id", None) == "SystemExit")]
    check("R4-PROVIDER provider raises no control-flow exit",
          not raises, "raise/SystemExit nodes=%d" % len(raises))

    eng_tree = ast.parse(_read(ENGINE))
    fn = _fn(eng_tree, "run_invariant_test")
    seg = ast.get_source_segment(_read(ENGINE), fn) or ""
    check("R4-CORE core reads the supplementary returncode",
          'evidence.get("returncode")' in seg)
    check("R4-CORE core gates on rc not in (0, None)",
          "rc_text not in (0, None)" in seg)
    check("R4-CORE core exits 2 on the misuse path",
          "raise SystemExit(2)" in seg)
    check("R4-CORE core handles NosCapabilityUnsupported explicitly",
          "except NosCapabilityUnsupported" in seg)
    check("R4-NOEXCERPT excerpt is never promoted into a record "
          "(founder ruling 2026-08-20)",
          '"excerpt"' not in seg)


# ------------------------------------------------------------------ row 1 --
def _routes_of(test):
    ev = test.get("evidence") or {}
    r = ev.get("routes")
    return r if isinstance(r, list) else []


def _typed(routes, want_str):
    out = []
    for rec in routes:
        rt = rec.get("route_type")
        if isinstance(rt, str) == want_str:
            out.append(rec)
    return out


def row1_differential(artdir):
    print("\n--- row 1: pre/post differential on the FRR EVPN corpus ---")
    for lab, spec in sorted(BASELINE.items()):
        path = os.path.join(artdir, "%s.results.json" % lab)
        if not os.path.exists(path):
            check("R1-ARTIFACT %s present" % lab, False,
                  "missing %s -- HARD FAIL, not a skip" % path)
            continue
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception as exc:
            check("R1-ARTIFACT %s readable" % lab, False, repr(exc))
            continue
        check("R1-ARTIFACT %s present and readable" % lab, True)

        got = {t.get("name"): t for t in (doc.get("tests") or [])}
        for name, base in sorted(spec["tests"].items()):
            t = got.get(name)
            if t is None:
                check("R1-ROW %s :: %s present" % (lab, name), False)
                continue

            same = (str(t.get("expected")) == base["expected"]
                    and str(t.get("observed")) == base["observed"]
                    and str(t.get("verdict")) == base["verdict"])
            check("R1-VERDICT %s :: %s zero delta" % (lab, name), same,
                  "post=(%s,%s,%s) pre=(%s,%s,%s)" % (
                      t.get("expected"), t.get("observed"), t.get("verdict"),
                      base["expected"], base["observed"], base["verdict"]))

            routes = _routes_of(t)
            macs = {str(r.get("mac") or "").lower() for r in routes}
            check("R1-DECLARED %s :: %s carries both declared MACs"
                  % (lab, name),
                  all(m in macs for m in DECLARED_MACS),
                  "declared present=%s" % sorted(m for m in DECLARED_MACS
                                                 if m in macs))

            str_typed = _typed(routes, True)
            if base["reaches"]:
                check("R1-NONVACUITY %s :: %s supplementary TEXT leg executed"
                      % (lab, name),
                      len(str_typed) > 0,
                      "string-typed route_type entries=%d" % len(str_typed))
                str_macs = {str(r.get("mac") or "").lower() for r in str_typed}
                int_macs = {str(r.get("mac") or "").lower()
                            for r in _typed(routes, False)}
                check("R1-PAIRED %s :: %s every text MAC also appears "
                      "int-typed" % (lab, name),
                      str_macs and str_macs.issubset(int_macs),
                      "text=%d int=%d unpaired=%s"
                      % (len(str_macs), len(int_macs),
                         sorted(str_macs - int_macs)))
            else:
                check("R1-NONVACUITY %s :: %s TEXT leg correctly NOT reached"
                      % (lab, name),
                      len(str_typed) == 0,
                      "string-typed entries=%d (expected 0)" % len(str_typed))

            obs = t.get("observed_state")
            populated = isinstance(obs, dict) and len(obs) > 0
            check("R1-13C %s :: %s observed_state populated iff verdict==fail"
                  % (lab, name),
                  populated == (base["verdict"] == "fail"),
                  "populated=%s verdict=%s" % (populated, base["verdict"]))

            ev = t.get("evidence") or {}
            check("R1-NOEXCERPT %s :: %s no excerpt in the record"
                  % (lab, name),
                  "excerpt" not in ev, "evidence keys=%s" % sorted(ev.keys()))


def baseline_self_check():
    print("\n--- baseline self-consistency ---")
    reaching = [(l, n) for l, s in BASELINE.items()
                for n, b in s["tests"].items() if b["reaches"]]
    check("BL-REACH corpus contains at least two reaching rows",
          len(reaching) >= 2, "reaching=%s" % sorted(reaching))
    check("BL-CONTROL corpus contains at least one non-reaching control",
          any(not b["reaches"] for s in BASELINE.values()
              for b in s["tests"].values()))
    for lab, spec in BASELINE.items():
        topo = os.path.join(REPO, spec["topology"])
        check("BL-TOPO %s fixture present" % lab, os.path.exists(topo),
              spec["topology"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default=None,
                    help="directory of <lab>.results.json captured post-migration")
    args = ap.parse_args()

    print("§4.5-c WI-7 — EVPN collection migration proof (REQ-45C-14)")
    print("mode: %s" % ("lab-free + differential" if args.artifacts
                        else "lab-free only"))

    row2_exec_count()
    row3_no_widening()
    row4_misuse_path()
    baseline_self_check()
    if args.artifacts:
        row1_differential(args.artifacts)
    else:
        print("\n--- row 1: NOT RUN (no --artifacts) ---")
        print("       row 1 is discharged only by the CI leg that passes")
        print("       --artifacts. This invocation does not discharge it.")

    failed = [r for r in RESULTS if not r[1]]
    print("\n%s" % ("=" * 62))
    print("checks: %d   PASS: %d   FAIL: %d"
          % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
    if failed:
        print("FAILED:")
        for label, _, detail in failed:
            print("  - %s%s" % (label, ("  -- " + detail) if detail else ""))
        return 1
    print("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
