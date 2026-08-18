#!/usr/bin/env python3
"""tests/sonic_leaf_import_proof.py — §4.5-c WI-1 import-floor proof.

Extends the `nos_leaf_import_proof` pattern to the SONiC provider (handover §7
P7: "the new provider module import-reached from the registry"). A sibling
rather than an edit: `nos_leaf_import_proof.py` pins `PROVIDER =
"cassian_nos_frr.py"` at :34 and is FRR-scoped; §14.4 admits new `tests/sonic_*`.

Asserts the ruled acyclic import order (design §3.2: model -> provider ->
common/leaf) holds for `src/cassian_nos_sonic.py`:
  * no runtime import of engine, model, or runtime_container
  * registry-reachable: cassian_model imports it and dispatches on node_type
  * the contract is complete (validate_provider) and the legs the ratified
    design assigns to SONiC are WIRED, not placeholders (NG-9)

Coverage limit (PBE-P2-8): this proof covers `cassian_nos_sonic.py` only. It is
not a generic sweep over NOS_PROVIDERS; a third provider needs its own sibling
or a generalized proof. Recorded so a later reader does not assume coverage
this file does not give.
"""
import ast
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

PROVIDER = "cassian_nos_sonic.py"
FORBIDDEN = {"cassian_engine", "cassian_model", "cassian_runtime_container",
             "cassian_tests", "cassian_cli", "cassian_artifacts",
             "cassian_import", "cassian_state", "cassian_two_run",
             "cassian_candidate", "cassian_ai"}

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


def _runtime_imports(path):
    """Module-level imports, excluding those guarded by TYPE_CHECKING."""
    src = io.open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    guarded = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            named = (isinstance(t, ast.Name) and t.id == "TYPE_CHECKING") or (
                isinstance(t, ast.Attribute) and t.attr == "TYPE_CHECKING")
            if named:
                guarded.append((node.lineno, node.end_lineno))
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(a <= node.lineno <= b for a, b in guarded):
                continue
            if isinstance(node, ast.Import):
                out.update(a.name.split(".")[0] for a in node.names)
            elif node.module:
                out.add(node.module.split(".")[0])
    return out


_ppath = os.path.join(_SRC, PROVIDER)
check("provider module exists at src/ top level (note 4 §1)", os.path.isfile(_ppath))

_rt = _runtime_imports(_ppath)
_violations = sorted(_rt & FORBIDDEN)
check("P-SIMP-1 no runtime import of core/engine/model/runtime from the provider",
      not _violations, "violations: %s" % (_violations or "none"))

check("P-SIMP-2 import floor is stdlib + the types leaf",
      _rt <= {"__future__", "json", "re", "shlex", "sys", "typing",
              "cassian_nos_types", "cassian_common"},
      "runtime imports: %s" % sorted(_rt))

# NON-VACUITY: the detector must be able to see a forbidden import.
_synthetic = _rt | {"cassian_engine"}
check("P-SIMP-1 NON-VACUITY: detector fires on a synthetic forbidden import",
      bool(_synthetic & FORBIDDEN),
      "proves the check discriminates rather than always passing")

# --- registry reachability --------------------------------------------------
import cassian_model as M  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import is_deferred, validate_provider  # noqa: E402

check("P-SIMP-3 provider is registered in NOS_PROVIDERS",
      M.NOS_PROVIDERS.get("sonic-vm") is S.SONIC_PROVIDER)
check("P-SIMP-3 registry key equals provider.node_type",
      S.SONIC_PROVIDER.node_type == "sonic-vm")
check("P-SIMP-3 default_image is registry-derived",
      M.nos_default_image("sonic-vm") == S.SONIC_DEFAULT_IMAGE,
      S.SONIC_DEFAULT_IMAGE)

_complete = True
try:
    validate_provider(S.SONIC_PROVIDER)
except Exception as _e:  # noqa: BLE001
    _complete = False
    _detail = str(_e)[:120]
check("P-SIMP-4 contract completeness (validate_provider)", _complete)

# --- NG-9: design-assigned legs are WIRED, not placeholders -----------------
for _leg in ("gen_node_config", "provision"):
    check("NG-9 %s is wired (design :240 assigns it to SONiC)" % _leg,
          not is_deferred(getattr(S.SONIC_PROVIDER, _leg)))

# --- NG-9: FRR's placeholders are untouched --------------------------------
import cassian_nos_frr as F  # noqa: E402
for _leg in ("gen_node_config", "provision", "nos_ready", "convergence_wait"):
    check("NG-9 FRR's %s placeholder is untouched" % _leg,
          is_deferred(getattr(F.FRR_PROVIDER, _leg)),
          "FRR deferral is provider-scoped, not contract-scoped (HALT-1)")

# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-1 SONiC provider import floor)"
      % ("PASS" if not _failed else "FAIL", len(_checks)))
sys.exit(1 if _failed else 0)
