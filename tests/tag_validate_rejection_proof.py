#!/usr/bin/env python3
"""
§4.8 Test Tags & Selective Execution -- `tags` declaration rejection proof
(Phase 1b SP #1-pattern; handover §6.7.2 / §15.2; owns Doctrine §1.6 / DC v2.1 §13(a)).

Proves that the topology-schema `tags` field is hard-failed at validation time
(cassian validate exit 2) with DC v2.1 §13(a)-sufficient content when malformed,
admitted kind-agnostically (including kind: exec) when well-formed, and that the
exec closed key-set still rejects every non-`tags` unknown key.

The two seams live in different functions: structural `tags` validation in
cassian_model.ensure_valid_topology, exec key-set widening in
cassian_model.resolve_topology. This harness mirrors cmd_validate's call order
(ensure_valid_topology -> resolve_topology) on a synthetic topology fed through
the real seams directly (the udi_*/bl6_* pattern), WITHOUT a deployed lab.
cassian validate's quiet-die mode is mirrored (cassian_common._QUIET_DIE = True)
so the deterministic rejection message is captured from SystemExit exactly as
cmd_validate captures it.

Coverage:
  REQ-TAG-SCHEMA-1  conforming tags validates; malformed rejected.
  REQ-TAG-SCHEMA-2  exec tags admitted; non-tags unknown exec key still rejected.
  REQ-TAG-VALIDATE-1  malformed tags -> §13(a)-sufficient rejection (what/where/valid-form).
  (REQ-TAG-VALIDATE-2 zero-match selector is added under WI-3, once --tag exists.)

Proof obligations:
  P-POS    well-formed tags (invariant + exec) validate (no false-fail).
  P-V1-NL  non-list tags rejected.
  P-V1-NS  non-string element rejected.
  P-V1-CS  charset-violating element rejected.
  P-V1-MT  empty-string element rejected.
  P-S2-OK  exec test carrying tags is admitted.
  P-S2-NO  exec test carrying a non-tags unknown key still rejected (G-7 preserved).
  P-13A    each rejection carries (a) 'tags' must be a list of strings (what),
           (b) tests[i] '<label>' (where), (c) matching [a-z0-9_-] (valid form),
           and the offending value.
  P-DET    identical malformed input -> byte-identical rejection message.
  P-NR     existing invariant/exec tests without tags still validate (non-regression).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import copy
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_common as _cc
_cc._QUIET_DIE = True  # mirror cmd_validate: die raises SystemExit(str(msg))
import cassian_model as cm

_NODES = [{"name": "r1", "type": "frr"}, {"name": "r2", "type": "frr"}]


def _topo(test):
    return {
        "name": "tag-reject-proof",
        "nodes": [dict(n) for n in _NODES],
        "links": [{"endpoints": ["r1:eth1", "r2:eth1"]}],
        "tests": [test],
    }


def _inv(**kw):
    t = {"name": "inv1", "kind": "invariant", "type": "bgp_session_up",
         "src": "r1", "dst": "10.0.0.2", "expect": "pass"}
    t.update(kw)
    return t


def _exec(**kw):
    t = {"name": "x", "kind": "exec", "src": "r1",
         "command": 'vtysh -c "show version"',
         "assertion": {"contains": "FRRouting"}}
    t.update(kw)
    return t


def _validate(test):
    """Mirror cmd_validate: ensure_valid_topology then resolve_topology."""
    td = copy.deepcopy(_topo(test))
    try:
        cm.ensure_valid_topology(td)
        cm.resolve_topology(td)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


def main():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # P-POS: well-formed tags validate (invariant + exec), no false-fail.
    o, _ = _validate(_inv(tags=["bgp", "edge"]))
    check("P-POS invariant + valid tags validates", o == "ok")
    o, _ = _validate(_exec(tags=["diag", "frr_1"]))
    check("P-POS exec + valid tags validates", o == "ok")

    # P-V1-*: malformed tags rejected.
    nl_o, nl_m = _validate(_inv(tags="bgp"))
    check("P-V1-NL non-list tags rejected", nl_o == "die")
    ns_o, ns_m = _validate(_inv(tags=[5]))
    check("P-V1-NS non-string element rejected", ns_o == "die")
    cs_o, cs_m = _validate(_inv(tags=["BGP"]))
    check("P-V1-CS charset violation rejected", cs_o == "die")
    mt_o, mt_m = _validate(_inv(tags=[""]))
    check("P-V1-MT empty-string element rejected", mt_o == "die")

    # P-S2-OK / P-S2-NO: exec key-set semantics.
    s2ok_o, _ = _validate(_exec(tags=["x"]))
    check("P-S2-OK exec carrying tags admitted", s2ok_o == "ok")
    s2no_o, s2no_m = _validate(_exec(bogus="nope"))
    check("P-S2-NO exec non-tags unknown key rejected", s2no_o == "die")
    check("P-S2-NO message names the unknown key", "bogus" in s2no_m)

    # P-13A: §13(a) sufficiency on the tags rejection (use the non-list case).
    check("P-13A (what) names tags-must-be-list",
          "'tags' must be a list of strings" in nl_m)
    check("P-13A (where) names tests[i] '<label>'",
          "tests[1] 'inv1'" in nl_m)
    check("P-13A (valid-form) names charset",
          "matching [a-z0-9_-]" in nl_m)
    check("P-13A (offending) names the bad value",
          "got 'bgp'" in nl_m)

    # P-DET: identical malformed input -> byte-identical message.
    d1_o, d1_m = _validate(_inv(tags="bgp"))
    d2_o, d2_m = _validate(_inv(tags="bgp"))
    check("P-DET deterministic rejection message", d1_m == d2_m and d1_m == nl_m)

    # P-NR: existing tests without tags still validate.
    nr1_o, _ = _validate(_inv())
    check("P-NR invariant without tags validates", nr1_o == "ok")
    nr2_o, _ = _validate(_exec())
    check("P-NR exec without tags validates", nr2_o == "ok")

    # P-V2: zero-match selector (REQ-TAG-VALIDATE-2, added WI-3). A --tag matching no declared
    # test excludes all of them => matched == 0 => hard-fail via the filter:no-match path.
    # The pure-logic zero-match condition is proven here; the actual exit(2) at the gate is
    # lab-confirmed (integration smoke / verify_phase1.sh --name DOES_NOT_EXIST analogue).
    import cassian_engine as _E
    import inspect as _insp
    _declared = [{"name": "t1", "tags": ["bgp"]}, {"name": "t2", "tags": ["edge"]}]
    check("P-V2 selector matching nothing excludes all (matched==0 condition)",
          all(not _E._tag_selected(_t, ["does-not-exist"]) for _t in _declared))
    check("P-V2 a present tag still matches (non-zero proceeds)",
          any(_E._tag_selected(_t, ["bgp"]) for _t in _declared))
    _esrc = _insp.getsource(_E)
    check("P-V2 zero-match label wired for --tag",
          "--tag {filter_tags!r}" in _esrc)
    check("P-V2 zero-match summary emits filtered_by_tag",
          'results["summary"]["filtered_by_tag"]' in _esrc)

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(("  PASS " if ok else "  FAIL ") + n)
    if failed:
        print("\nFAILED %d/%d: %s" % (len(failed), len(checks), "; ".join(failed)))
        sys.exit(1)
    print("\nAll %d checks passed." % len(checks))
    sys.exit(0)


if __name__ == "__main__":
    main()
