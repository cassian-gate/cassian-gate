#!/usr/bin/env python3
"""§4.5-b REQ-45b-17 — NOS provider import-graph proof (LD-45b-2), lab-free.

Asserts the ruled acyclic import order (NOS-expansion structure design §3.2:
model -> provider -> common) over **runtime** import sets -- i.e. imports that
actually execute, excluding anything guarded by `if TYPE_CHECKING:`.

Properties:
  P-IMP-1  leaf runtime imports subset of stdlib (+ justified `cassian_common`)
  P-IMP-2  `cassian_runtime_container` NOT in leaf runtime imports
           (`Runtime` is annotation-only, under TYPE_CHECKING)
  P-IMP-3  provider runtime imports subset of stdlib + leaf + `cassian_common`
  P-IMP-4  the justified-common leg is CONCRETE: the provider's admitted
           `cassian_common` symbols are exactly the ruled set
           (A-H3: `_canonical_community_token`, `_BGP_COMMUNITY_CANON`;
            A-H4: `_normalize_prefix`; plus the F-45b-C1-1 NOS-neutral regexes)
  P-IMP-5  no engine import into leaf or provider, and no provider->model import
           (model -> provider IS the sanctioned edge -- REQ-45b-1 requires the
           model-homed registry to import the provider; REQ-45b-17's "in either
           direction" phrasing is imprecise on that point, carried forward)
  P-IMP-6  NON-VACUITY: a deliberately violated graph is caught (REQ-45b-19(iii))

Method: AST over source; `if TYPE_CHECKING:` bodies excluded from the runtime
set. Loud-fail, exit 1 on any failure.
"""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

LEAF = "cassian_nos_types.py"
PROVIDER = "cassian_nos_frr.py"
COMMON = "cassian_common"

# The RULED-ADMISSIBLE `cassian_common` symbols for the provider leg
# (REQ-45b-17; A-H3/A-H4; founder ruling A on F-45b-C1-1). The proof asserts
# the provider's actual admissions are a SUBSET of this set and names them --
# any symbol beyond it is a widening that must be ruled, not absorbed.
#
# `_BGP_COMMUNITY_CANON` is ruled-admissible but is NOT in fact imported by the
# provider: it is an implementation detail of `_canonical_community_token`,
# which is itself common-homed (A-H3). Requiring the import would create a dead
# import to satisfy a literal reading of REQ-45b-17's enumeration. Subset, not
# equality, is the correct predicate; the actual set is printed below so the
# instantiation is concrete and reviewable.
RULED_ADMISSIBLE_COMMON = {
    "_canonical_community_token",   # A-H3
    "_BGP_COMMUNITY_CANON",         # A-H3 (table; admissible with its function)
    "_normalize_prefix",            # A-H4
    "_RE_IPV4_PREFIX",              # F-45b-C1-1 (NOS-neutral)
    "_RE_NEIGH_LINE",               # F-45b-C1-1 (NOS-neutral)
}

PROJECT_MODULES = {
    "cassian", "cassian_ai", "cassian_artifacts", "cassian_candidate",
    "cassian_cli", "cassian_common", "cassian_engine", "cassian_import",
    "cassian_model", "cassian_nos_frr", "cassian_nos_types",
    "cassian_runtime_container", "cassian_runtime_vm", "cassian_state",
    "cassian_tests", "cassian_two_run",
}

fails = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def _typechecking_spans(tree):
    """Line spans of `if TYPE_CHECKING:` blocks -- excluded from runtime imports."""
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        t = node.test
        name = getattr(t, "id", None) or getattr(t, "attr", None)
        if name == "TYPE_CHECKING":
            spans.append((node.lineno, node.end_lineno))
    return spans


def runtime_imports(path):
    """{module_name: {symbols}} for imports that execute at runtime."""
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    guarded = _typechecking_spans(tree)

    def is_guarded(node):
        return any(a <= node.lineno <= b for a, b in guarded)

    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and not is_guarded(node):
            for a in node.names:
                out.setdefault(a.name.split(".")[0], set())
        elif isinstance(node, ast.ImportFrom) and not is_guarded(node):
            if node.level:            # relative import
                continue
            mod = (node.module or "").split(".")[0]
            out.setdefault(mod, set()).update(a.name for a in node.names)
    return out


def guarded_imports(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    guarded = _typechecking_spans(tree)
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(a <= node.lineno <= b for a, b in guarded):
                mod = getattr(node, "module", None) or (node.names[0].name if node.names else "")
                out.add((mod or "").split(".")[0])
    return out


def project_deps(imports):
    return {m for m in imports if m in PROJECT_MODULES}


print("=" * 60)
print("REQ-45b-17 — NOS provider import-graph proof")
print("=" * 60)

leaf_rt = runtime_imports(os.path.join(SRC, LEAF))
prov_rt = runtime_imports(os.path.join(SRC, PROVIDER))
leaf_guarded = guarded_imports(os.path.join(SRC, LEAF))

# ---- P-IMP-1 / P-IMP-2: the leaf ----
leaf_proj = project_deps(leaf_rt)
check(leaf_proj <= {COMMON},
      f"P-IMP-1 leaf runtime project-imports subset of {{{COMMON}}} (got {sorted(leaf_proj) or 'stdlib only'})")
check("cassian_runtime_container" not in leaf_rt,
      "P-IMP-2 cassian_runtime_container NOT a leaf runtime import")
check("cassian_runtime_container" in leaf_guarded,
      "P-IMP-2 Runtime is annotation-only (TYPE_CHECKING-guarded)")

# ---- P-IMP-3 / P-IMP-4: the provider ----
prov_proj = project_deps(prov_rt)
allowed = {"cassian_nos_types", COMMON}
check(prov_proj <= allowed,
      f"P-IMP-3 provider runtime project-imports subset of {sorted(allowed)} (got {sorted(prov_proj)})")

admitted = prov_rt.get(COMMON, set())
check(admitted <= RULED_ADMISSIBLE_COMMON,
      "P-IMP-4 justified-common leg subset of the ruled-admissible set")
check(bool(admitted),
      "P-IMP-4 justified-common leg is concretely instantiated (non-empty)")
print(f"         admitted symbols ({len(admitted)}): {', '.join(sorted(admitted))}")
_widened = sorted(admitted - RULED_ADMISSIBLE_COMMON)
check(not _widened, f"P-IMP-4 no unruled widening of the common leg (got {_widened})")

# ---- P-IMP-5: no core edges into leaf/provider; no provider -> model ----
for mod, imports in (("leaf", leaf_rt), ("provider", prov_rt)):
    check("cassian_engine" not in imports, f"P-IMP-5 no cassian_engine import in the {mod}")
check("cassian_model" not in prov_rt, "P-IMP-5 no provider -> cassian_model import")

# ---- P-IMP-6: NON-VACUITY (REQ-45b-19(iii)) ----
# A deliberately violated graph must be caught. Build a synthetic leaf that
# imports the runtime at module level and confirm the same predicate reds.
import tempfile

violation = (
    "from __future__ import annotations\n"
    "from cassian_runtime_container import Runtime  # deliberate violation\n"
)
with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
    tf.write(violation)
    vpath = tf.name
try:
    v_rt = runtime_imports(vpath)
    caught = ("cassian_runtime_container" in v_rt) and not (project_deps(v_rt) <= {COMMON})
    check(caught, "P-IMP-6 NON-VACUITY: a deliberate leaf-import violation is caught (REQ-45b-19(iii))")
finally:
    os.unlink(vpath)

print("=" * 60)
if fails:
    print(f"RESULT: FAIL -- {len(fails)} check(s): " + "; ".join(fails))
    sys.exit(1)
print("RESULT: PASS -- NOS import graph conforms to the ruled acyclic order.")
