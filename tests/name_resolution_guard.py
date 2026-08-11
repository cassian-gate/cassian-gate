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
        state = "allowlisted" if (rel, scope, name) in ALLOWLIST else "UNEXPECTED"
        print("  %-12s %s: %s: %s" % (state, rel, scope, name))

    unexpected = [f for f in findings if f not in ALLOWLIST]
    covered = {f for f in findings if f in ALLOWLIST}
    stale = sorted(ALLOWLIST - covered)

    print("\nfindings    : %d" % len(findings))
    print("allowlisted : %d of %d entries matched" % (len(covered), len(ALLOWLIST)))
    print("unexpected  : %d" % len(unexpected))

    if stale:
        print("\nNOTE: allowlist entries with no matching finding:")
        for rel, scope, name in stale:
            print("  %s: %s: %s" % (rel, scope, name))
        print("Not a failure -- an entry may go quiet on an interpreter whose")
        print("scope labelling differs (PEP 709). Remove only with a ruling.")

    if unexpected:
        print("\nFAIL: %d finding(s) outside the allowlist." % len(unexpected))
        return 1

    print("\nPASS: no unbound name outside the four anchored allowlist entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
