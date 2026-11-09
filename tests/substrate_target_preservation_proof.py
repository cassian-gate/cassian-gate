#!/usr/bin/env python3
"""tests/substrate_target_preservation_proof.py -- the W4 substrate/NOS target-preservation guard.

REQ-45a-17 (the W4 guard) + REQ-45a-18 (container-collapse identity assertions).
Founder ruling 2026-07-19 (adopting the §4.5-a Chat-3 R-1 recommendation).

WHAT THIS GUARD DOES
  Scans the migrated families -- cassian_engine.py, cassian_tests.py,
  cassian_runtime_container.py (addendum §2.4: the 25 substrate sites live only
  here) -- for a SUBSTRATE-vocabulary verb written as a bare `exec`/`sh` call
  (i.e. NOT a `substrate_*` call). A substrate operation spelled bare would, on a
  vm-runtime node, reach the GUEST instead of the WRAPPER -- the wrong entity
  (Finding 12). Any such site fails the proof (exit 1).

  INDEPENDENT SOURCES (addendum §8; PBE-P2-6 GOOD case). This guard derives its
  verdict from COMMAND TEXT (the literal argv/shell strings in the source);
  ROUTING derives from METHOD NAME (`substrate_*` vs bare) in the runtime
  classes. The two never share a source -- that independence is the guard's whole
  value. The denylist is a hand-committed literal, NEVER derived from the routing
  code.

THE DENYLIST -- committed literal, vocabulary-based, not semantic:
      tc qdisc, netem, tcpdump, ip -4 route show dev, ip -4 route replace
  These are the substrate verbs that are BOTH substrate-exclusive AND visible as
  static command text. (`tc` and `tcpdump` are also proven absent-or-shared on the
  guest by the addendum's EXPERIMENT rows: guest has no `tc`; guest HAS `tcpdump`.)

THE LIMIT -- documented here, not buried (REQ-45a-17). This guard is the
vocabulary LAYER of a layered defense, not a complete one. It does NOT catch:
  (1) `ip link set` -- DELIBERATELY EXCLUDED by ruling. It is shared with
      legitimate NOS interface provisioning (addendum §2.5 "provisioning content":
      cassian_runtime_container.py:1004-1019 FRR ifaces, :1089-1095 host), which
      is correctly written bare. No vocabulary predicate separates a substrate
      link fault from NOS provisioning; denylisting it would red the clean tree.
  (2) Runtime-ASSEMBLED commands -- a verb built into an f-string and passed as
      `sh -lc <var>` (the tcpdump CAPTURE at cassian_engine.py:9946/:9960 -> :9975,
      cassian_tests.py:2519) is not a static constant at the call node; the scan
      sees `sh -lc` but not the verb. (The `command -v tcpdump` PRECHECK, a static
      constant, IS covered.)
  Both residuals are SILENT hazards on a vm node -- the guest HAS `ip link` and
  `tcpdump` (addendum §2.5: "SONiC has tcpdump ... SILENT (worse: false
  reassurance)"). They are defended NOT here but by:
    - the WI-3 P-ROUTE dispatch asserts in
      tests/vm_runtime_validate_rejection_proof.py (substrate op -> bare argv into
      the wrapper; NOS op -> ssh argv into the guest), and
    - the container-collapse identity assertions below (REQ-45a-18).
  A green result here means "no substrate-EXCLUSIVE verb is spelled bare in the
  migrated families." It does NOT, on its own, mean the whole split is preserved.
  Read it together with the two guards named above.

Run:  PYTHONPATH=src python3 tests/substrate_target_preservation_proof.py
Exit: 0 = clean; 1 = a denylisted verb found bare, or an identity divergence.

Provenance: founder ruling 2026-07-19 (R-1); addendum §4.4 / §8 / §2.4 / §2.5;
scope REQ-45a-17/-18. House form per tests/tag_preservation_proof.py.
"""
import ast
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# The migrated families (addendum §2.4).
# Extended under MS condition C-1 (F-MS-1, §4.5-b closure): cassian_runtime_vm.py
# added to the defended set. Its 2 substrate_* sites (L364/L383) use
# call-expression receivers and were invisible to the pre-correction census
# regex; they sit on a module §4.5-b modified (REQ-45b-12), so REQ-45b-P1's
# zero-touch claim over them was previously undefended by BOTH instruments.
MIGRATED_FAMILIES = ("cassian_engine.py", "cassian_tests.py",
                     "cassian_runtime_container.py", "cassian_runtime_vm.py")

# --- committed literal denylist (see module docstring for the ruling + the LIMIT) ---
# Vocabulary-based, not semantic. Never auto-derived from the routing classes.
SUBSTRATE_VERB_DENYLIST = (
    "tc qdisc",
    "netem",
    "tcpdump",
    "ip -4 route show dev",
    "ip -4 route replace",
)
# EXCLUDED by ruling (documented in the module docstring, not buried): "ip link set"
# -- shared with NOS provisioning; covered by the P-ROUTE asserts + identity, not here.


def _denylist_hits(text):
    """Return the denylist verbs present in `text` as whole tokens/phrases."""
    low = text.lower()
    return [v for v in SUBSTRATE_VERB_DENYLIST
            if re.search(r'(?<![\w-])' + re.escape(v) + r'(?![\w-])', low)]


def _scan_source(src_text):
    """Yield (lineno, command_text) for every BARE `.exec(`/`.sh(` call in
    `src_text` -- NOT `.substrate_exec`/`.substrate_sh` (those route to the
    substrate by name and are exempt). command_text = all string CONSTANTS
    anywhere in the call, space-joined (the static argv / shell text). Runtime-
    assembled f-strings are not constants and are not seen (see the LIMIT)."""
    tree = ast.parse(src_text)
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("exec", "sh")):
            strs = [c.value for c in ast.walk(n)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            yield (n.lineno, " ".join(strs))


def _hits_in_source(src_text):
    """(lineno, [verbs], text) for each bare exec/sh call carrying a denylist verb.
    One code path shared by the file scan AND the controls -- so the controls prove
    the exact detector the tree is judged by."""
    out = []
    for lineno, text in _scan_source(src_text):
        hits = _denylist_hits(text)
        if hits:
            out.append((lineno, hits, text))
    return out


checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def main():
    # ---- positive controls: the detector MUST fire on a bare denylisted verb ----
    # Always-on red-case demonstration (REQ-45a-17), run through the SAME scanner
    # the tree is judged by. If these fail the detector is dead and every green
    # below is meaningless.
    check("positive control: detector fires on a bare 'tc qdisc' (red-case capability)",
          any("tc qdisc" in h for _, h, _ in
              _hits_in_source('rt.exec(lab, node, ["tc", "qdisc", "replace", "dev", iface])')))
    check("positive control: detector fires on a bare 'tcpdump' precheck",
          any("tcpdump" in h for _, h, _ in
              _hits_in_source('rt.exec(lab, node, ["sh", "-lc", "command -v tcpdump >/dev/null"])')))

    # ---- negative controls: the documented LIMIT + routing-by-name, as assertions ----
    check("limit control: 'ip link set' is NOT flagged (deliberate exclusion -- NOS collision)",
          _hits_in_source('rt.exec(lab, node, ["ip", "link", "set", iface, "up"])') == [])
    check("limit control: a NOS 'show ip route' is NOT flagged",
          _hits_in_source('rt.exec(lab, node, ["vtysh", "-c", "show ip route"])') == [])
    check("routing control: the same verb via substrate_exec is EXEMPT (routing by method name)",
          _hits_in_source('rt.substrate_exec(lab, node, ["tc", "qdisc", "replace"])') == [])

    # ---- the guard: no substrate-exclusive verb spelled bare in the migrated families ----
    violations = []
    for fam in MIGRATED_FAMILIES:
        path = os.path.join(_SRC, fam)
        for lineno, hits, text in _hits_in_source(open(path, encoding="utf-8").read()):
            violations.append((fam, lineno, hits, text[:70]))
    for fam, lineno, hits, snippet in violations:
        check(f"VIOLATION {fam}:{lineno} bare exec/sh carries {hits} -- must be substrate_*: {snippet!r}",
              False)
    check("no denylisted substrate verb is spelled bare in the migrated families",
          not violations)

    # ---- REQ-45a-18: container-collapse identity assertions (verbatim) ----
    # identity proof, not behavioural sample; fails at the moment of any future divergence.
    from cassian_runtime_container import ContainerRuntime
    assert ContainerRuntime.substrate_exec is ContainerRuntime.exec
    assert ContainerRuntime.substrate_copy_from is ContainerRuntime.copy_from_node
    check("REQ-45a-18: ContainerRuntime.substrate_exec is ContainerRuntime.exec",
          ContainerRuntime.substrate_exec is ContainerRuntime.exec)
    check("REQ-45a-18: ContainerRuntime.substrate_copy_from is ContainerRuntime.copy_from_node",
          ContainerRuntime.substrate_copy_from is ContainerRuntime.copy_from_node)

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
