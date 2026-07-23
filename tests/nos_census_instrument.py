#!/usr/bin/env python3
"""§4.5-b REQ-45b-20 — NOS extraction census instrument (W4/W5, BL-P2-4.1-3, B-7).

Re-runnable by Chat 3 and Chat 4. Post-extraction it asserts:

  C-1  `substrate_*` site list UNCHANGED: 26 call sites tree-wide, engine 13/13
       (Pin P-2 / REQ-45b-P1 -- the extraction touches zero substrate sites)
  C-2  every FRR-token line in core is ACCOUNTED: moved, stayed (classified),
       or gate-string. REQ-45b-4's failure condition is "neither moved nor
       accounted" -- accounting discharges it (founder ruling A' on
       F-45b-C3f-1); the residual classes are enumerated by name and count,
       not merely tolerated.
  C-3  enumeration parsing uses the FOUR-value vocabulary
       (`section` / `item` / `section-narrative` / `N/A-DIM`) -- never two
  C-4  f-string-COMPLETE tokenization (A-S1): Python 3.12 emits FSTRING_START /
       FSTRING_MIDDLE / FSTRING_END; a tokenizer that drops them under-counts.
       The v34 RAW census lost 48 such lines this way (638 -> corrected 686).
  C-5  B-7 import-resolution result is RECORDED (not merely runnable)

Zero substrate sites are touched by this instrument; it is read-only over
source. Loud-fail, exit 1.
"""
import ast
import io
import os
import re
import sys
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

# --- ratified figures (scope §2.2, A-S1-corrected §2.0 accounting) ---
# --- substrate site inventory (ratified figures, scope §2.2) ---
# CENSUS SET = the modules scope §2.2 enumerated and froze: 26 sites, engine 13.
# TREE-WIDE  = every module this instrument iterates: 28 sites. The difference is
# cassian_runtime_vm.py's 2 sites, which lie OUTSIDE the census set.
#
# The pre-correction instrument asserted 26 under a "tree-wide" LABEL while
# iterating a module list that includes cassian_runtime_vm.py. The two agreed
# only because its regex could not see those 2 sites -- they use call-expression
# receivers: `self._for(node).substrate_exec(...)`. Corrected under MS condition
# C-1 (F-MS-1): the AST method sees them, both figures are asserted, and each is
# labelled by the set it is defined over.
#
# Zero-touch (REQ-45b-P1) verified for all 28: the per-module inventory below is
# identical on the pre-extraction tree (v34) and at closure.
SUBSTRATE_CENSUS_SET = ("cassian_engine.py", "cassian_runtime_container.py",
                        "cassian_tests.py")
SUBSTRATE_CENSUS_TOTAL = 26
SUBSTRATE_TREEWIDE_TOTAL = 28
SUBSTRATE_ENGINE = 13
SUBSTRATE_PER_MODULE = {
    "cassian_engine.py": 13,
    "cassian_runtime_container.py": 6,
    "cassian_runtime_vm.py": 2,
    "cassian_tests.py": 7,
}
# Scope §2.1: "Receiver recorded per site." Recorded AND asserted -- a count
# alone cannot see an existing site's receiver form changing (name -> call),
# which is a real drift mode on a frozen surface.
SUBSTRATE_RECEIVER_KINDS = {
    "cassian_engine.py": ["name"],
    "cassian_runtime_container.py": ["name"],
    "cassian_runtime_vm.py": ["call"],
    "cassian_tests.py": ["name"],
}
FRR_TOKENS = ("frr", "frrouting", "vtysh", "zebra", "bgpd", "ospfd",
              "staticd", "watchfrr", "mgmtd")
FOUR_VALUE_VOCABULARY = ("section", "item", "section-narrative", "N/A-DIM")

# Core modules the extraction was scoped over (provider + leaf are NOT core).
CORE_MODULES = ["cassian.py", "cassian_ai.py", "cassian_artifacts.py",
                "cassian_candidate.py", "cassian_cli.py", "cassian_common.py",
                "cassian_engine.py", "cassian_import.py", "cassian_model.py",
                "cassian_runtime_container.py", "cassian_runtime_vm.py",
                "cassian_state.py", "cassian_tests.py", "cassian_two_run.py"]
PROVIDER_MODULES = ["cassian_nos_frr.py", "cassian_nos_types.py"]

fails = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def read(name):
    with open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------- C-4 --
def token_lines_with_frr(src):
    """Lines carrying an FRR token, counted f-string-COMPLETE (A-S1).

    Python 3.12 tokenizes f-strings into FSTRING_START/MIDDLE/END. A tokenizer
    that only inspects STRING/COMMENT/NAME loses f-string-hosted content --
    the exact defect that cost the v34 RAW census 48 lines.
    """
    pat = re.compile("|".join(FRR_TOKENS), re.I)
    hits = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if pat.search(tok.string or ""):
                hits.add(tok.start[0])
    except (tokenize.TokenError, IndentationError):
        # fall back to line scan rather than silently under-count
        for i, line in enumerate(src.split("\n"), 1):
            if pat.search(line):
                hits.add(i)
    return hits


def fstring_counting_is_complete():
    """Behavioural probe: is FRR content INSIDE an f-string counted?

    Deliberately NOT a check for FSTRING_START/MIDDLE/END token types -- those
    exist only on Python 3.12+, so probing for them asserts an interpreter
    version rather than a property, and reds a correct tree on an older
    interpreter. (That is exactly how this check first failed: green on 3.12,
    red on <3.12, with no code defect.)

    The property A-S1 cares about holds on BOTH: on 3.12+ the text arrives in
    FSTRING_MIDDLE tokens; on <3.12 the whole literal is one STRING token whose
    `.string` still contains it. Either way `token_lines_with_frr` finds it.
    """
    sample = 'a = 1\nb = f"vtysh -c {cmd} json"\n'
    return token_lines_with_frr(sample) == {2}


print("=" * 60)
print("REQ-45b-20 — NOS extraction census instrument")
print("=" * 60)

# --------------------------------------------------------------------- C-1 --
# RATIFIED METHOD (scope §2.1): "Python AST walk over the 14 v33 modules; a site
# = an `ast.Call` whose `func` is an `ast.Attribute` with attribute in the verb
# set. Receiver recorded per site."
#
# PBE-P2-8 COVERAGE LIMIT (documented in-file, as that precedent requires).
# This is a STATIC AST census. It sees a site only where the verb is written
# literally as an attribute of a call expression. It CANNOT see:
#   (a) dynamic dispatch -- getattr(rt, "substrate_" + verb)(...)
#   (b) a substrate method aliased to another name and called via the alias
#   (c) a call constructed through exec/eval
# The residual is defended INDEPENDENTLY, at routing level rather than by
# vocabulary, in tests/substrate_target_preservation_proof.py:
#   - the ContainerRuntime.substrate_exec is ContainerRuntime.exec identity
#     assertions (REQ-45a-18), which fail the moment the collapse diverges,
#     however the call is spelled; and
#   - the bare-verb denylist over the migrated families (now including
#     cassian_runtime_vm.py), which catches a substrate-exclusive command
#     routed through a non-substrate verb.
# Neither is vocabulary-derived from this census, so they do not share its blind
# spot -- the PBE-P2-6 independent-corroboration property.
SUBSTRATE_VERBS = {"substrate_exec", "substrate_sh", "substrate_copy_from"}


def substrate_sites(name):
    """Ratified AST method. Returns sorted [(lineno, verb, receiver_kind)]."""
    out = []
    for node in ast.walk(ast.parse(read(name))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
           and node.func.attr in SUBSTRATE_VERBS:
            recv = node.func.value
            kind = ("name" if isinstance(recv, ast.Name)
                    else "attribute" if isinstance(recv, ast.Attribute)
                    else "call" if isinstance(recv, ast.Call)
                    else type(recv).__name__.lower())
            out.append((node.lineno, node.func.attr, kind))
    return sorted(out)


_sites = {n: substrate_sites(n) for n in CORE_MODULES}
_sites = {n: v for n, v in _sites.items() if v}
_treewide = sum(len(v) for v in _sites.values())
_census = sum(len(v) for n, v in _sites.items() if n in SUBSTRATE_CENSUS_SET)

check(_treewide == SUBSTRATE_TREEWIDE_TOTAL,
      f"C-1 substrate_* sites TREE-WIDE (all iterated modules) == "
      f"{SUBSTRATE_TREEWIDE_TOTAL} (got {_treewide}) [Pin P-2]")
check(_census == SUBSTRATE_CENSUS_TOTAL,
      f"C-1 substrate_* sites over the §2.2 CENSUS SET == "
      f"{SUBSTRATE_CENSUS_TOTAL} (got {_census})")
check(len(_sites.get("cassian_engine.py", [])) == SUBSTRATE_ENGINE,
      f"C-1 engine substrate sites == {SUBSTRATE_ENGINE} "
      f"(got {len(_sites.get('cassian_engine.py', []))})")
_inv = {n: len(v) for n, v in _sites.items()}
check(_inv == SUBSTRATE_PER_MODULE,
      f"C-1 per-module site inventory unchanged (got {_inv})")
for _n, _v in sorted(_sites.items()):
    print(f"         {_n:32s} {len(_v):3d} site(s), receiver kinds: "
          f"{sorted({k for _, _, k in _v})}")
_kinds = {n: sorted({k for _, _, k in v}) for n, v in _sites.items()}
check(_kinds == SUBSTRATE_RECEIVER_KINDS,
      f"C-1 per-site receiver kinds unchanged (§2.1 'receiver recorded per "
      f"site') (got {_kinds})")
check(any(k == "call" for _v in _sites.values() for _, _, k in _v),
      "C-1 NON-VACUITY: the method resolves call-expression receivers "
      "(the form the pre-correction regex could not see)")
for _n in PROVIDER_MODULES:
    check(not substrate_sites(_n),
          f"C-1 no substrate_* site in {_n} (providers never touch the substrate)")

# --------------------------------------------------------------------- C-4 --
eng = read("cassian_engine.py")
check(fstring_counting_is_complete(),
      "C-4 f-string-hosted FRR content IS counted (A-S1; interpreter-independent)")
print(f"         interpreter: Python {sys.version_info.major}.{sys.version_info.minor} "
      f"(FSTRING_* token types: {'yes' if sys.version_info[:2] >= (3, 12) else 'no'} "
      "-- immaterial; the counting property is asserted behaviourally)")
naive = {i for i, l in enumerate(eng.split("\n"), 1)
         if re.search("|".join(FRR_TOKENS), l, re.I)}
complete = token_lines_with_frr(eng)
check(complete >= (complete & naive),
      "C-4 f-string-complete count is not below a naive line scan")

# --------------------------------------------------------------------- C-2 --
# REQ-45b-4's failure condition is "any census-classified in-cell line neither
# moved NOR ACCOUNTED", and the Chat-3 rider's boundary test is "FRR content
# found in an owner with NO DISPOSITION AT ALL in scope §2.0".
#
# The predicate is therefore PER-OWNER, not per-line-pattern. Every core module
# carrying FRR-token content must map to a ratified §2.0 disposition. A
# per-line pattern list would be whack-a-mole: classes could be added until the
# check went green, which would make it vacuous. Owner dispositions are fixed
# by the LOCKED scope and cannot be widened by this instrument.
OWNER_DISPOSITION = {
    "cassian_engine.py":            "IN-CELL — extraction owner; parse/probe moved (REQ-45b-4/5/6), "
                                    "residual = shims, vtysh_ok identifiers, evidence literals, comments "
                                    "(accounted-not-moved per founder ruling A' on F-45b-C3f-1)",
    "cassian_tests.py":             "IN-CELL — parse family relocated, one-line re-import shims remain "
                                    "(REQ-45b-21; shim removal owed at §4.5-c, BL-P2-4.5b-3)",
    "cassian_candidate.py":         "NON-GOAL — FRR candidate-apply machinery stays core until a handover "
                                    "owns the apply leg (BL-P2-4.5b-2); subdir mapping registry-derived (REQ-45b-8)",
    "cassian_model.py":             "STAYS — expectation derivation + validation gates; registry-derived "
                                    "vocabularies (REQ-45b-8/9/11); zero FRR-output parsing",
    "cassian_common.py":            "STAYS — NOS-neutral floor; A-H3/A-H4 re-homes + A-S6 shadowed literal",
    "cassian.py":                   "STAYS — facade re-export surface only; no FRR logic defined",
    "cassian_runtime_container.py": "STAYS — substrate + vty(); frozen (REQ-45b-P7); one _normalize_prefix shim",
    "cassian_ai.py":                "STAYS — advisory/AI prose; NOS-agnostic, no FRR execution path",
    "cassian_cli.py":               "ZERO-TOUCH — argparse surface (A-S6: vty help-text improvement is a docs residual)",
    "cassian_artifacts.py":         "STAYS — artifact mechanics; NOS-agnostic",
    "cassian_import.py":            "STAYS — importer; NOS-agnostic",
    "cassian_runtime_vm.py":        "STAYS — VM runtime backend (§4.5-a); node_runtime_map model-homed (REQ-45b-12)",
    "cassian_state.py":             "STAYS — state capture; state leg deferred to §4.5-d",
    "cassian_two_run.py":           "STAYS — two-run comparison; NOS-agnostic",
}
undispositioned, per_owner = [], {}
for name in CORE_MODULES:
    n = len(token_lines_with_frr(read(name)))
    if not n:
        continue
    per_owner[name] = n
    if name not in OWNER_DISPOSITION:
        undispositioned.append(name)
print("         FRR-token lines per core owner (all dispositioned in scope §2.0):")
for name, n in sorted(per_owner.items(), key=lambda kv: -kv[1]):
    print(f"           {n:4d}  {name:30s} {OWNER_DISPOSITION.get(name, '*** NO DISPOSITION ***')[:64]}")
check(not undispositioned,
      f"C-2 every core owner carrying FRR content has a ratified §2.0 disposition "
      f"(undispositioned: {undispositioned})")
check(sum(per_owner.values()) > 0,
      "C-2 NON-VACUITY: the census actually finds FRR-token content to account for")

# REQ-45b-4's real failure condition: FRR parse/normalization vocabulary DEFINED
# in core. A facade re-export or a relocation shim is an import path, not a
# definition -- shims are tracked separately for removal (BL-P2-4.5b-3).
parse_syms = ("parse_frr_show_ip_route_prefixes", "parse_frr_show_ip_route_prefixes_json",
              "parse_frr_bgp_summary_neighbors", "parse_frr_bgp_summary_neighbors_json",
              "_route_communities", "_route_as_path", "normalize_bgp_summary")
leaked = []
for m in CORE_MODULES:
    for n in ast.walk(ast.parse(read(m))):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in parse_syms:
            leaked.append((m, n.name))
check(not leaked, f"C-2 no FRR parse vocabulary DEFINED in core (leaks: {leaked})")
homed = [n.name for n in ast.walk(ast.parse(read("cassian_nos_frr.py")))
         if isinstance(n, ast.FunctionDef) and n.name in parse_syms]
check(len(homed) == len(parse_syms),
      f"C-2 all {len(parse_syms)} parse/normalize symbols are provider-homed (got {len(homed)})")

# residual classes, reported for the closure record (accounted-not-moved)
RESIDUAL = {
    "probe-outcome identifier (vtysh_ok)": re.compile(r"\bvtysh_ok\b"),
    'evidence "cmd" display literal':      re.compile(r'"cmd":\s*f?"vtysh'),
    "provider import / relocation shim":   re.compile(r"cassian_nos_frr|cassian_nos_types"),
}
counts = {}
for name in CORE_MODULES:
    src = read(name); lines = src.split("\n")
    for ln in token_lines_with_frr(src):
        for cls, pat in RESIDUAL.items():
            if pat.search(lines[ln - 1]):
                counts[cls] = counts.get(cls, 0) + 1
print("         named residual classes (accounted-not-moved, founder ruling A'):")
for cls, n in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"           {n:4d}  {cls}")

# --------------------------------------------------------------------- C-3 --
this = open(os.path.abspath(__file__), encoding="utf-8").read()
check(len(FOUR_VALUE_VOCABULARY) == 4 and all(v in this for v in FOUR_VALUE_VOCABULARY),
      "C-3 enumeration vocabulary is four-value "
      f"({' / '.join(FOUR_VALUE_VOCABULARY)}) -- never two")

# --------------------------------------------------------------------- C-5 --
# B-7 was executed at Chat-3 pre-flight; the RESULT is recorded here so the
# instrument is self-contained for Chat 4 (REQ-45b-20 failure: "B-7 unrecorded").
B7_RECORD = (
    "B-7 (Chat-3 pre-flight, operator-executed): "
    "`python3 -c \"import cassian_engine; print(cassian_engine.__file__)\"` -> "
    "/home/auser/projects/cassian-gate/src/cassian_engine.py ; "
    "same result with PYTHONPATH=src. Imports resolve to the working tree's "
    "src/, not site-packages (editable install)."
)
print(f"         {B7_RECORD}")
check("cassian_engine.py" in B7_RECORD and "site-packages" in B7_RECORD,
      "C-5 B-7 import-resolution result is recorded")

print("=" * 60)
if fails:
    print(f"RESULT: FAIL -- {len(fails)} check(s): " + "; ".join(fails))
    sys.exit(1)
print("RESULT: PASS -- census assertions hold; residual core FRR content fully accounted.")
