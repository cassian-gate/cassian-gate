#!/usr/bin/env python3
"""Static name-resolution guard for the shipped src/*.py module set.

Doctrine 1.18 script-creation authority block ratified 2026-08-10 (condition
C2 of the undefined-name bounded remediation).  Authoritative path pinned to
this file by that ratification.

WHAT THIS OWNS
    Detection of names referenced but not bound in their resolving scope --
    the class-closure surface of the undefined-name bounded remediation.
    Doctrine 1.13 (fail-fast); DC v2.1 13-adjacent rejection-path integrity.

WHAT THIS DOES NOT OWN
    Reachability (per-site traces do), dynamic binding, and getattr
    indirection.  See COVERAGE LIMIT below (PBE-P2-8).

EXTENSION MODEL
    Append-only allowlist, each entry carrying a trace or Ledger anchor.
    The swept-path roster is asserted equal to the src/*.py glob, so new
    modules are covered by default (deny-by-default).  The probe set extends
    when a new scope shape enters the language (the PEP 709 precedent).
    This guard never self-edits its allowlist or baseline.

USAGE
    python3 tests/name_resolution_guard.py              # gate the tree
    python3 tests/name_resolution_guard.py --selftest   # prove non-vacuity

EXIT
    0  clean, or selftest passed
    1  a finding outside the allowlist, a roster mismatch, or selftest failure
"""

import builtins
import glob
import hashlib
import os
import sys
import symtable
import tempfile
import threading

# --------------------------------------------------------------------------
# (c) Module implicit dunders.  Omitting these produced a live false-positive
# class during authoring: the first sweep returned 12 findings instead of 9,
# flagging __file__ in three scopes (CF Note 1 5.1).
# --------------------------------------------------------------------------
IMPLICIT_DUNDERS = frozenset({
    "__file__", "__name__", "__doc__", "__spec__",
    "__package__", "__loader__", "__builtins__", "__debug__", "__path__",
})

BUILTINS = frozenset(dir(builtins))

# --------------------------------------------------------------------------
# (e) ALLOWLIST -- four entries, append-only, each anchored.
#
# Keyed on (module, scope-path, name): the finding unit this guard actually
# emits.  symtable exposes no per-symbol line number, so a line-keyed
# allowlist is not expressible in this guard's own output without bolting on
# a second parser -- and line anchors drift on every edit (the excised site
# moved 9280 -> 9284 during this instrument alone).  Amendment A2 re-anchored
# REQ-UNDEF-11's excision proof from lines to scope for the same reason.
# Line numbers below are commentary, valid at the instrument's merge commit.
# --------------------------------------------------------------------------
ALLOWLIST = {
    # EXCISED by founder ruling (CF Note 1 1/6, Row A). Intent undetermined:
    # no step counter in scope; siblings take it as a parameter. Repair would
    # alter results.json content (engages PBE-P2-7). Ledger Row A records the
    # intractability and the Doctrine 1.7 silent-evidence-loss severity.
    # REQ-UNDEF-11. Line at merge: cassian_engine.py:9284.
    ("src/cassian_engine.py", "top.cmd_test.run_scenario", "step_index"),

    # RECORD-UNREACHABLE, zero-caller trace (REQ-UNDEF-10). execute_scenario
    # occurs exactly twice repo-wide: its definition (cassian_tests.py:2361)
    # and an aggregation import (cassian.py:102). No __all__ re-export, no
    # dynamic dispatch. Function retained by founder sub-decision (CF Note 1
    # 1). Lines at merge: 2597 / 2700 / 2713.
    ("src/cassian_tests.py", "top.execute_scenario", "results"),
    ("src/cassian_tests.py", "top.execute_scenario", "scen_id"),
    ("src/cassian_tests.py", "top.execute_scenario", "events"),
}

# --------------------------------------------------------------------------
# (f) COVERAGE LIMIT (PBE-P2-8).  Documented, not an exemption mechanism.
#
# This guard is STATIC and binding-only.  It does NOT cover:
#   - reachability. A flagged name may sit on a path no input reaches; an
#     unflagged line may still crash. Per-site traces carry that burden.
#   - dynamic binding: globals()/locals() mutation, exec, setattr on the
#     module.
#   - star-imports, which fail in the OPPOSITE direction: `from x import *`
#     followed by a use of an imported name is reported as UNBOUND -- a
#     FALSE POSITIVE, i.e. CI red on legitimate code, not a missed defect.
#     Latent only: src/*.py contains no star-import today. Recorded at
#     MS-F-4 because a permanent standing surface must state the true
#     failure direction.
#   - getattr indirection.
#   - UnboundLocalError. A name assigned LATER in the same scope is bound as
#     far as symtable is concerned, so a read before that assignment is
#     invisible here. This is not hypothetical: the undefined-name instrument
#     surfaced exactly such a defect in cmd_test's blocked-path blocks
#     (F-UNDEF-11), repaired under the NG-6 amendment in carry-forward
#     note 3. This guard would have gone green on those lines.
#
# The residual is defended by the per-site traces and Ledger rows named in
# the allowlist above -- tracked debt, not acceptance.
# --------------------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")


# --------------------------------------------------------------------------
# PEP 709 CANONICALISATION -- MATCHING ONLY.
#
# Python 3.12 inlines comprehensions into the parent scope (PEP 709), so one
# source yields `top.f.listcomp` on 3.10/3.11 and `top.f` on 3.12 -- measured
# on 3.10.20 / 3.11.15 / 3.12.3. The allowlist key carries no interpreter
# component, so a comprehension-scoped exemption has NO key that matches on
# all three, and this gate -- a REQUIRED status check -- has no green state
# for it. The matcher canonicalises both sides before comparing.
#
# EMISSION IS UNTOUCHED. Findings are appended per scope table and printed
# with their RAW scope path, never de-duplicated (REQ-UNDEF-12(b)).
#
# genexpr is EXCLUDED, and the exclusion is load-bearing: generator
# expressions are NOT inlined by PEP 709 -- `top.f.genexpr` on all three
# interpreters, measured. Adding it here would strip a live scope label and
# silently collapse genexpr exemptions.
#
# LATENT RESIDUAL, measured clean at v43: a function, class or scope literally
# named listcomp/setcomp/dictcomp would have a genuine label stripped, so an
# exemption for one scope could cover another. AST walk over all 17 src
# modules and the tests tree: zero instances. Clean today, not impossible.
# --------------------------------------------------------------------------
INLINED = ("listcomp", "setcomp", "dictcomp")


def canon_scope(scope):
    """Drop PEP 709-inlined comprehension labels from a scope path."""
    return ".".join(p for p in scope.split(".") if p not in INLINED)


def canon_key(triple):
    """Canonical MATCHING key for a finding or an allowlist entry."""
    rel, scope, name = triple
    return (rel, canon_scope(scope), name)


def is_allowlisted(finding, allowlist):
    """Does any allowlist entry exempt this finding?"""
    return canon_key(finding) in {canon_key(e) for e in allowlist}


def matched_entries(findings, allowlist):
    """Allowlist entries that at least one finding matches."""
    seen = {canon_key(f) for f in findings}
    return {e for e in allowlist if canon_key(e) in seen}


def stale_entries(findings, allowlist):
    """Allowlist entries no finding matches -> the MS-R-2 red.

    EXTRACTED from main(), where it was inline as
    `stale = sorted(ALLOWLIST - covered)`. With no predicate to call, the
    selftest carried a replica of the expression instead -- which reported
    PROVEN with the mitigation deleted entirely. C-1 and C-2 were both
    repaired by extracting a pure predicate; this is that repair, applied
    late.
    """
    return sorted(set(allowlist) - matched_entries(findings, allowlist))


def module_bound(table):
    out = set()
    for sym in table.get_symbols():
        if (sym.is_assigned() or sym.is_parameter()
                or sym.is_imported() or sym.is_namespace()):
            out.add(sym.get_name())
    return out


def walk(table, path, mod_bound, rel, findings):
    """(b) Emit one finding per name-per-scope. NEVER de-duplicate.

    symtable labels every comprehension child table `listcomp`, so below
    Python 3.12 two distinct sub-scopes can share a scope path. Collapsing
    (module, scope, name) triples would report 10 where 11 exist and can
    mask a genuine site (CF Note 1 5.1).
    """
    for sym in table.get_symbols():
        name = sym.get_name()
        if not sym.is_referenced():
            continue
        if (sym.is_assigned() or sym.is_parameter()
                or sym.is_imported() or sym.is_namespace()):
            continue
        if sym.is_free():
            continue
        if name in mod_bound or name in BUILTINS or name in IMPLICIT_DUNDERS:
            continue
        findings.append((rel, path, name))
    for child in table.get_children():
        walk(child, path + "." + child.get_name(), mod_bound, rel, findings)


def sweep(paths, root):
    """(a) stdlib symtable only. DS-1: sorted paths, symtable child order."""
    findings = []
    for rel in paths:
        with open(os.path.join(root, rel), "r", encoding="utf-8") as fh:
            source = fh.read()
        table = symtable.symtable(source, rel, "exec")
        walk(table, "top", module_bound(table), rel, findings)
    return findings


def sweep_source(source, rel="<injected>"):
    findings = []
    table = symtable.symtable(source, rel, "exec")
    walk(table, "top", module_bound(table), rel, findings)
    return findings


def roster(root):
    """Swept-path roster, via os.listdir."""
    src = os.path.join(root, "src")
    return sorted(
        os.path.join("src", f) for f in os.listdir(src) if f.endswith(".py")
    )


def glob_roster(root):
    """Independent second enumeration of src/*.py, via glob.glob.

    Mechanically distinct from roster()'s os.listdir + endswith, so the
    two agreeing is evidence. Comparing roster() against itself -- which
    is what shipped -- cannot fail and asserts nothing (MS condition C-1).
    """
    # glob.escape: `src` is a PATH, but glob reads its argument as a
    # PATTERN. An unescaped metacharacter in the repository root makes
    # glob enumerate a different directory -- which, with a decoy at the
    # resolved path, makes both rosters agree for the wrong reason
    # (MS condition C-2a). It also reds a healthy tree when no decoy
    # exists. Escaping closes both directions.
    src = os.path.join(root, "src")
    return sorted(
        os.path.join("src", os.path.basename(p))
        for p in glob.glob(os.path.join(glob.escape(src), "*.py"))
    )


def allowlisted_modules():
    """Modules the allowlist names. Each MUST appear in the roster."""
    return sorted({rel for rel, _scope, _name in ALLOWLIST})


def nested_python(root):
    """Tree shapes the flat sweep cannot see -> (nested_py, revisits).

    The ratified method sweeps `src/*.py`, flat. Its claim that this makes
    new modules 'covered by default' holds ONLY while the tree is flat: a
    module at src/nos/x.py is invisible, and every gate here prints PASS
    while it is. This does not widen the sweep -- it refuses to certify a
    tree shape the method was never ratified for. Resolving a red here is
    a founder ruling, not a guard change.

    SYMLINKED DIRECTORIES ARE FOLLOWED. `os.walk` defaults to
    followlinks=False, so a symlinked src/nos -> /elsewhere holding .py
    was importable and invisible to BOTH the flat sweep and this tripwire
    -- the exact shape the tripwire exists to refuse.

    Following links needs CYCLE HANDLING, not a keyword. Measured on
    Linux, unguarded `os.walk(followlinks=True)`:

        src/nos -> src            terminates,     41 dirs (kernel ELOOP
                                  at 40 symlink traversals)
        two-hop a -> b -> a       terminates,     83 dirs
        4 dirs x 3 subdirs, each
        linking back to src       DID NOT FINISH: >500,000 dirs in 15s

    So the simple loop does not hang -- ELOOP stops it -- while a cycle
    combined with branching does. On a REQUIRED status check that is worse
    than the defect being fixed, so this walks with an explicit stack.

    Directories are identified by (st_dev, st_ino), never by path.

    Every directory is walked at most once, which makes the walk provably
    finite. A directory reached a SECOND time is REPORTED, not silently
    dropped -- as `src/<name>`, the second route to it.

    Reporting rather than pruning quietly is load-bearing, and an earlier
    draft of this function got it wrong. That draft reported only a
    directory that was its own ANCESTOR, which is traversal-order
    dependent: on `src/a` and `src/b` cross-linked, whichever is visited
    first makes the other an alias rather than an ancestor, and a tree
    with a real cycle and no .py in it went GREEN. Non-emptiness of the
    revisit list does not depend on order -- exactly one route to a
    directory is walked first and every other route is a revisit -- so
    that is the property this reports.

    A src/ tree reachable by more than one path is not the flat shape the
    ratified method sweeps: with src/nos -> src every top-level module is
    ALSO importable as nos.X, and there is no finite listing of what lies
    below src/ at all. Same posture as a nested module: red, and resolve
    by ruling.

    Unreadable directories are skipped, as `os.walk(onerror=None)` did.
    """
    src = os.path.join(root, "src")
    found = []
    revisits = []

    def ident(path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    top = ident(src)
    seen = set() if top is None else {top}
    stack = [src]

    while stack:
        here = stack.pop()
        try:
            names = sorted(os.listdir(here))
        except OSError:
            continue
        at_top = os.path.abspath(here) == os.path.abspath(src)
        for n in names:
            p = os.path.join(here, n)
            if os.path.isdir(p):
                i = ident(p)
                if i is None:
                    continue
                if i in seen:
                    revisits.append(os.path.relpath(p, root))
                    continue
                seen.add(i)
                stack.append(p)
            elif n.endswith(".py") and not at_top:
                found.append(os.path.relpath(p, root))

    return sorted(found), sorted(revisits)


def _bounded_call(fn, seconds):
    """Run fn() under a wall-clock bound -> (finished, result).

    A broken cycle guard turns a red into a HANG on a required status
    check. A leg that tested it by simply calling the walker would
    EXHIBIT that failure instead of reporting it -- CI would sit until the
    job timeout with no signal. The call therefore runs on a daemon
    thread: if it does not finish, the leg reds and the process can still
    exit. Stdlib only; no new dependency.
    """
    box = {}

    def run():
        box["result"] = fn()

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("result")


def roster_is_sufficient(paths):
    """Can this roster support a class-closure claim? -> (bool, reason)

    A guard that sweeps nothing declares the class closed on no evidence
    (MS condition C-2b). Non-emptiness alone is NOT enough: repackaging
    src/ into a subpackage would leave src/__init__.py and pass a bare
    check while sweeping nothing of substance. Every allowlisted module
    must be present, or the guard is looking at the wrong tree.
    """
    if not paths:
        return False, "roster is EMPTY -- nothing was swept"
    missing = [m for m in allowlisted_modules() if m not in paths]
    if missing:
        return False, "allowlisted module(s) absent from roster: %s" % missing
    return True, "ok"


def swept_set_agrees(swept, independent):
    """Pure predicate, so --selftest can prove it returns False.

    A check that cannot be shown to fail is not a check. The non-vacuity
    leg for this predicate is in selftest() -- its absence is why C-1's
    defect shipped.
    """
    return list(swept) == list(independent)


def allowlist_match_counts(findings, allowlist):
    """How many findings each allowlist ENTRY absorbs.

    Membership alone is not enough: ONE entry silently covering N findings
    exempts findings that carry no anchor of their own. Two same-named
    nested definitions in one scope produce identical triples on EVERY
    supported interpreter -- that exposure is not PEP-709-bound (MS-F-5).

    Counting uses the SAME canonical key the matcher uses. Counting raw
    while matching canonically measures the wrong thing: on 3.10/3.11 a
    name unbound BOTH inside a comprehension AND in the function body
    yields two findings, `top.f.listcomp` and `top.f` (measured). One
    entry keyed `top.f.listcomp` exempts BOTH under canonical matching,
    while a raw count sees one and stays green -- MS-F-5's exposure
    arriving through the fix for the PEP 709 divergence. Keys are the RAW
    entries, so the red prints each entry as the allowlist writes it.
    """
    index = {}
    for e in allowlist:
        index.setdefault(canon_key(e), []).append(e)
    counts = {}
    for f in findings:
        for e in index.get(canon_key(f), ()):
            counts[e] = counts.get(e, 0) + 1
    return counts


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def preamble(paths, root):
    """(d) Self-provenance, printed on every run."""
    print("=" * 70)
    print("name-resolution guard  (tests/name_resolution_guard.py)")
    print("interpreter : %s" % sys.version.split()[0])
    print("command     : %s" % " ".join(
        [os.path.basename(sys.argv[0])] + sys.argv[1:]))
    print("root        : %s" % root)
    print("=" * 70)
    print("SWEPT-PATH MANIFEST (declared, not implicit)")
    for p in paths:
        print("  %s" % p)
    print("swept files : %d" % len(paths))
    digest = hashlib.sha256()
    for p in paths:
        digest.update(sha256_file(os.path.join(root, p)).encode("ascii"))
    print("manifest-hash (sha256 over sorted per-file sha256): %s"
          % digest.hexdigest())


# --------------------------------------------------------------------------
# REQ-UNDEF-13 INJECTION SET.
#
# Authored against the SCOPE MODEL of the language -- module, function,
# comprehension sub-scope, class body, nested function, lambda -- not against
# this file's branches. Enumerating from one's own implementation is the
# F-MS-1 failure mode; it is the reason this section exists.
# --------------------------------------------------------------------------
INJECTIONS = [
    ("module level",
     "import os\n"
     "VALUE = os.sep\n"
     "OTHER = undefined_at_module_level\n",
     "undefined_at_module_level"),

    ("function local",
     "def f():\n"
     "    return undefined_in_function\n",
     "undefined_in_function"),

    ("comprehension sub-scope (PEP 709 boundary)",
     "def f():\n"
     "    return [x for x in range(3) if x == undefined_in_listcomp]\n",
     "undefined_in_listcomp"),

    ("class body",
     "class C:\n"
     "    attr = undefined_in_class_body\n",
     "undefined_in_class_body"),

    ("nested function",
     "def outer():\n"
     "    def inner():\n"
     "        return undefined_in_nested\n"
     "    return inner\n",
     "undefined_in_nested"),

    ("lambda",
     "g = lambda: undefined_in_lambda\n",
     "undefined_in_lambda"),
]

# Trap 1 -- ast.walk-style scope flattening. `shared` IS bound, but in a
# DIFFERENT function. A flattening walker sees it bound somewhere and misses
# the unbound reference; a scope-correct walk flags it.
TRAP_FLATTENING = (
    "def binder():\n"
    "    shared = 1\n"
    "    return shared\n"
    "\n"
    "def reader():\n"
    "    return shared\n"
)

# Trap 2 -- implicit globals must be excluded BEFORE module-level existence
# is consulted. Omitting the dunder set produced a live false-positive class
# during authoring (CF Note 1 5.1).
TRAP_DUNDERS = (
    "def f():\n"
    "    return (__file__, __name__, __doc__, __spec__, __package__,\n"
    "            __loader__, __debug__)\n"
)


def enumeration_legs():
    """Non-vacuity aimed at the ENUMERATION, not at the predicate.

    C-1's fix proved swept_set_agrees() returns False on a hand-built
    pair. That established nothing about whether the two enumerations can
    disagree on a real filesystem -- the gap the MS reviewer had to close
    by attacking it. These legs build actual trees.
    """
    out = []

    # E -- a dotfile: glob applies POSIX leading-dot semantics, listdir
    # does not. Live proof the two mechanisms are genuinely independent.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        open(os.path.join(src, "visible.py"), "w").close()
        open(os.path.join(src, ".hidden.py"), "w").close()
        r, g = roster(td), glob_roster(td)
        out.append(("enumerations DIVERGE on a dotfile",
                    "src/.hidden.py" in r
                    and "src/.hidden.py" not in g
                    and not swept_set_agrees(r, g)))

    # K -- metacharacter root plus a decoy holding a DIFFERENT basename.
    # Unescaped, glob reads the decoy and returns ['src/decoy.py'].
    # Escaped, it reads the real directory. This leg fails pre-C-2a.
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "root[p]")
        real = os.path.join(root, "src")
        decoy = os.path.join(td, "rootp", "src")
        os.makedirs(real)
        os.makedirs(decoy)
        open(os.path.join(real, "real.py"), "w").close()
        open(os.path.join(decoy, "decoy.py"), "w").close()
        r, g = roster(root), glob_roster(root)
        out.append(("metachar root globbed LITERALLY",
                    g == ["src/real.py"] and swept_set_agrees(r, g)))

    # L -- roster sufficiency rejects the empty tree AND the subpackage
    # shape that a bare non-empty check would wave through.
    empty_ok, _ = roster_is_sufficient([])
    stub_ok, _ = roster_is_sufficient(["src/__init__.py"])
    full_ok, _ = roster_is_sufficient(
        allowlisted_modules() + ["src/__init__.py"])
    out.append(("roster sufficiency rejects empty + stub",
                (not empty_ok) and (not stub_ok) and full_ok))

    return out


def matching_legs():
    """Non-vacuity aimed at the MATCHING, not the counter.

    C-1's leg tested a predicate and missed the enumeration. C-2's legs
    test the enumeration. This one tests how findings are matched against
    the allowlist: build a duplicate scope path, allowlist its triple, and
    confirm that plain membership reports CLEAN while the cardinality
    check catches it. Exercising the counter alone would repeat C-1.
    """
    dup_src = ("def f():\n"
               "    def h():\n"
               "        return zz\n"
               "    def h():\n"
               "        return zz\n"
               "    return h\n")
    dup = sweep_source(dup_src, "src/x.py")
    fake_allow = {("src/x.py", "top.f.h", "zz")}

    two_findings = len(dup) == 2 and len(set(dup)) == 1
    membership_says_clean = not [x for x in dup if x not in fake_allow]
    counts = allowlist_match_counts(dup, fake_allow)
    cardinality_catches = any(n > 1 for n in counts.values())

    return [("allowlist over-match CAUGHT (MS-F-5)",
             two_findings and membership_says_clean and cardinality_catches)]


def canon_legs():
    """Non-vacuity for the canonical matcher, on the running interpreter.

    Every leg calls the real matcher against findings a real sweep
    produced. No interpreter is hardcoded: each expectation is derived
    from what the sweep actually returns, so the same legs are meaningful
    on 3.10, 3.11 and 3.12 without a version branch.
    """
    out = []
    m = "src/x.py"

    # (i) a comprehension-scoped exemption greens on THIS interpreter --
    # the state that does not exist without canonicalisation.
    comp = sweep_source("def f():\n    return [zz for _ in range(3)]\n", m)
    entry = (m, "top.f.listcomp", "zz")
    out.append(("comprehension exemption GREEN here",
                len(comp) == 1
                and [f for f in comp if not is_allowlisted(f, {entry})] == []
                and stale_entries(comp, {entry}) == []))

    # (ii) a NON-comprehension mismatch must still red, in both directions:
    # the finding stays unexpected AND the entry goes stale.
    nest = sweep_source("def f():\n    def h():\n        return zz\n"
                        "    return h\n", m)
    mism = (m, "top.f", "zz")
    out.append(("non-comprehension mismatch still REDS",
                len(nest) == 1
                and [f for f in nest if not is_allowlisted(f, {mism})] == nest
                and stale_entries(nest, {mism}) == [mism]))

    # (iii) genexpr is NOT inlined by PEP 709, so it must NOT canonicalise
    # onto its parent. Excluding it from INLINED is what this leg guards.
    gen = sweep_source("def f():\n    return (zz for _ in range(3))\n", m)
    parent = (m, "top.f", "zz")
    out.append(("genexpr NOT canonicalised",
                [f[1] for f in gen] == ["top.f.genexpr"]
                and [f for f in gen if not is_allowlisted(f, {parent})] == gen))

    # (iv) one name unbound BOTH in a comprehension AND in the body: two
    # findings below 3.12, one on 3.12. The entry exempts EVERY finding, and
    # the count must see every one it exempts -- so the MS-F-5 red fires
    # exactly when there is more than one. A raw count sees fewer than it
    # exempts, and this leg fails.
    both = sweep_source("def f():\n    a = [zz for _ in range(3)]\n"
                        "    return a, zz\n", m)
    dual = (m, "top.f.listcomp", "zz")
    counts = allowlist_match_counts(both, {dual})
    out.append(("cardinality counts what matcher exempts",
                [f for f in both if not is_allowlisted(f, {dual})] == []
                and counts.get(dual, 0) == len(both)
                and (any(n > 1 for n in counts.values()) == (len(both) > 1))))

    return out


def symlink_descent_legs():
    """Non-vacuity for symlink descent and cycle handling (Finding 2).

    Every leg builds a REAL tree on a REAL filesystem and calls the real
    walker. The two cycle legs are bounded, so a regression reds here
    instead of hanging the gate.
    """
    out = []
    py = os.path.join("src", "nos", "buried.py")

    # (i) the defect: a symlinked subdir holding .py was invisible.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        away = os.path.join(td, "elsewhere")
        os.makedirs(away)
        open(os.path.join(away, "buried.py"), "w").close()
        os.symlink(away, os.path.join(src, "nos"))
        nested, revisits = nested_python(td)
        out.append(("symlinked subdir with .py CAUGHT",
                    nested == [py] and revisits == []))

    # (ii) the ruled vector: src/nos -> src. Bounded, and the second
    # route is reported rather than pruned into silence.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        open(os.path.join(src, "top.py"), "w").close()
        os.symlink(src, os.path.join(src, "nos"))
        done, res = _bounded_call(lambda: nested_python(td), 10)
        out.append(("cycle src/nos -> src TERMINATES and reds",
                    done and res is not None
                    and res[1] == [os.path.join("src", "nos")]
                    and res[0] == []))

    # (iii) the shape that actually explodes: a cycle plus branching.
    # Unguarded this exceeds 500,000 directories without finishing.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        for i in range(4):
            d = os.path.join(src, "d%d" % i)
            os.makedirs(d)
            for j in range(3):
                os.makedirs(os.path.join(d, "s%d" % j))
            os.symlink(src, os.path.join(d, "back"))
        done, res = _bounded_call(lambda: nested_python(td), 10)
        out.append(("cycle WITH branching TERMINATES",
                    done and res is not None and len(res[1]) == 4
                    and res[0] == []))

    # (iv) two links to one real directory: must terminate, must report
    # the .py exactly once, and must report the extra routes.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        real = os.path.join(src, "nos")
        os.makedirs(real)
        open(os.path.join(real, "buried.py"), "w").close()
        os.symlink(real, os.path.join(src, "aliasA"))
        os.symlink(real, os.path.join(src, "aliasB"))
        done, res = _bounded_call(lambda: nested_python(td), 10)
        out.append(("aliased dir: .py once, extra routes reported",
                    done and res is not None
                    and len(res[0]) == 1
                    and res[0][0].endswith("buried.py")
                    and len(res[1]) == 2))

    # (v) a cross-linked cycle with NO .py anywhere. The ancestor-only
    # draft went green here; this is the leg that caught it.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(os.path.join(src, "a"))
        os.makedirs(os.path.join(src, "b"))
        os.symlink(os.path.join(src, "b"), os.path.join(src, "a", "tob"))
        os.symlink(os.path.join(src, "a"), os.path.join(src, "b", "toa"))
        done, res = _bounded_call(lambda: nested_python(td), 10)
        out.append(("cross-cycle with no .py still REDS",
                    done and res is not None and res[0] == []
                    and len(res[1]) > 0))

    # (vi) a plain flat tree must stay silent -- the leg that keeps the
    # five above from being satisfied by a function that always reds.
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        open(os.path.join(src, "cassian.py"), "w").close()
        os.makedirs(os.path.join(src, "cassian_gate.egg-info"))
        open(os.path.join(src, "cassian_gate.egg-info", "PKG-INFO"),
             "w").close()
        out.append(("flat tree with egg-info stays SILENT",
                    nested_python(td) == ([], [])))

    return out


def tree_shape_legs():
    """Non-vacuity for the two properties C-3 adds.

    The tripwire leg builds a REAL subpackage tree; the staleness leg
    exercises the matched/unmatched distinction the red now depends on.
    Testing the predicates in isolation would repeat C-1's mistake.
    """
    out = []

    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(os.path.join(src, "nos"))
        open(os.path.join(src, "top.py"), "w").close()
        flat_clean = nested_python(td) == ([], [])
        open(os.path.join(src, "nos", "buried.py"), "w").close()
        nested_caught = nested_python(td) == (
            [os.path.join("src", "nos", "buried.py")], [])
        out.append(("nested .py CAUGHT, flat tree clean (MS-R-1)",
                    flat_clean and nested_caught))

    # This leg was set algebra over three literals: it called no guard
    # function, read no guard state, and reported PROVEN with the staleness
    # mitigation deleted outright. It now calls the extracted predicate
    # against findings a real sweep produced.
    live = sweep_source("def f():\n    return zz\n", "src/x.py")
    live_entry = live[0]
    ghost = ("src/x.py", "top.gone", "zz")

    matched_is_clean = stale_entries(live, {live_entry}) == []
    planted_is_caught = stale_entries(live, {live_entry, ghost}) == [ghost]
    no_finding_at_all = stale_entries([], {ghost}) == [ghost]

    out.append(("stale entry CAUGHT by extracted predicate",
                len(live) == 1 and matched_is_clean
                and planted_is_caught and no_finding_at_all))

    return out


def selftest():
    print("=" * 70)
    print("name-resolution guard -- SELFTEST (REQ-UNDEF-13 non-vacuity)")
    print("interpreter : %s" % sys.version.split()[0])
    print("=" * 70)
    ok = True

    for label, source, expect in INJECTIONS:
        names = {f[2] for f in sweep_source(source)}
        hit = expect in names
        ok = ok and hit
        print("  %-45s %s" % (label, "DETECTED" if hit else "MISSED"))

    names = {f[2] for f in sweep_source(TRAP_FLATTENING)}
    hit = "shared" in names
    ok = ok and hit
    print("  %-45s %s" % ("trap: scope flattening",
                          "DETECTED" if hit else "MISSED"))

    same = ["src/a.py", "src/b.py"]
    diff = ["src/a.py"]
    can_fail = (swept_set_agrees(same, list(same))
                and not swept_set_agrees(same, diff))
    ok = ok and can_fail
    print("  %-45s %s" % ("swept-set assertion can FAIL (C-1)",
                          "PROVEN" if can_fail else "VACUOUS"))

    for label, hit in enumeration_legs():
        ok = ok and hit
        print("  %-45s %s" % (label, "PROVEN" if hit else "FAILED"))

    for label, hit in matching_legs():
        ok = ok and hit
        print("  %-45s %s" % (label, "PROVEN" if hit else "FAILED"))

    for label, hit in canon_legs():
        ok = ok and hit
        print("  %-45s %s" % (label, "PROVEN" if hit else "FAILED"))

    for label, hit in symlink_descent_legs():
        ok = ok and hit
        print("  %-45s %s" % (label, "PROVEN" if hit else "FAILED"))

    for label, hit in tree_shape_legs():
        ok = ok and hit
        print("  %-45s %s" % (label, "PROVEN" if hit else "FAILED"))

    names = {f[2] for f in sweep_source(TRAP_DUNDERS)}
    clean = not names
    ok = ok and clean
    print("  %-45s %s" % ("trap: implicit globals not false-positived",
                          "CLEAN" if clean else "FALSE POSITIVE %s" % sorted(names)))

    print("=" * 70)
    print("SELFTEST: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()

    paths = roster(ROOT)
    preamble(paths, ROOT)

    nested, revisits = nested_python(ROOT)
    if nested or revisits:
        print("\nFAIL: the tree below src/ is not the flat shape the "
              "ratified method sweeps.")
        for p in nested:
            print("  %s  -- .py below src/ top level (MS-R-1)" % p)
        for p in revisits:
            print("  %s  -- second route to a directory already walked "
                  "(symlink alias or cycle)" % p)
        print("The ratified method sweeps `src/*.py`, flat. Nested files are")
        print("INVISIBLE to it, and a cyclic tree has no finite listing of")
        print("what lies below src/ at all -- with src/nos -> src every")
        print("top-level module is also importable as nos.X. Every check")
        print("below would print PASS while either holds. Resolve by founder")
        print("ruling -- widening the sweep amends the ratified method and is")
        print("not this guard's to do.")
        return 1
    print("flat-tree precondition (no .py below src/ top level, no "
          "second route into it): PASS")

    sufficient, why = roster_is_sufficient(paths)
    if not sufficient:
        print("\nFAIL: %s" % why)
        print("A guard that sweeps nothing, or that cannot see the modules")
        print("its own allowlist names, asserts nothing (MS condition C-2b).")
        return 1
    print("roster sufficiency (non-empty; all allowlisted modules present): "
          "PASS")

    independent = glob_roster(ROOT)
    if not swept_set_agrees(paths, independent):
        print("\nFAIL: swept roster != independent src/*.py enumeration "
              "(deny-by-default breach)")
        print("  swept (os.listdir) : %s" % paths)
        print("  independent (glob) : %s" % independent)
        return 1
    print("swept-set assertion (os.listdir roster == glob.glob roster): "
          "PASS -- %d files, two independent enumerations" % len(paths))

    findings = sweep(paths, ROOT)

    print("\nFINDINGS (per scope table; NOT de-duplicated)")
    if not findings:
        print("  (none)")
    for rel, scope, name in findings:
        state = ("allowlisted"
                 if is_allowlisted((rel, scope, name), ALLOWLIST)
                 else "UNEXPECTED")
        print("  %-12s %s: %s: %s" % (state, rel, scope, name))

    unexpected = [f for f in findings if not is_allowlisted(f, ALLOWLIST)]
    covered = matched_entries(findings, ALLOWLIST)
    stale = stale_entries(findings, ALLOWLIST)

    counts = allowlist_match_counts(findings, ALLOWLIST)
    over = sorted(t for t, n in counts.items() if n > 1)
    if over:
        print("\nFAIL: an allowlist entry absorbed more than one finding "
              "(MS-F-5).")
        for rel, scope, name in over:
            print("  %s: %s: %s  -- matched %d findings"
                  % (rel, scope, name, counts[(rel, scope, name)]))
        print("Each entry carries ONE trace or Ledger anchor. Absorbing a")
        print("second finding would exempt an UN-ANCHORED one. Two distinct")
        print("scopes can share a path -- same-named nested defs on any")
        print("interpreter, comprehension labels below 3.12. Resolve by")
        print("ruling, not by widening the allowlist.")
        return 1
    print("allowlist cardinality (no entry matches >1 finding): PASS")

    print("\nfindings    : %d" % len(findings))
    print("allowlisted : %d of %d entries matched" % (len(covered), len(ALLOWLIST)))
    print("unexpected  : %d" % len(unexpected))

    if stale:
        print("\nNOTE: allowlist entries with no matching finding:")
        for rel, scope, name in stale:
            print("  %s: %s: %s" % (rel, scope, name))
        print("FAIL: an allowlisted exemption matched nothing (MS-R-2 "
              "mitigation).")
        print("An entry outlives the site it was granted for. Left standing,")
        print("it silently exempts the NEXT unbound name that resolves to the")
        print("same (module, scope, name) -- the allowlist key carries no site")
        print("component and symtable exposes none. Remove the entry by ruling.")
        print("If an entry goes quiet only on one interpreter (PEP 709 scope")
        print("labelling), that is itself a ruling moment, not a pass.")
        return 1

    if unexpected:
        print("\nFAIL: %d finding(s) outside the allowlist." % len(unexpected))
        return 1

    print("\nPASS: no unbound name outside the four anchored allowlist entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
