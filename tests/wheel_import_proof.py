#!/usr/bin/env python3
"""tests/wheel_import_proof.py -- 4.5-c WI-11 packaging.

Req-IDs: REQ-45C-18 (py-modules covers every rostered RUNTIME module)
         REQ-45C-40 (five-step clean-wheel proof + roster equivalence assertion)
         REQ-45C-41 (P-45C-STR: no vendored or linked tree under src/)

Snapshot mapping (handover 6.7.2 mapping discipline): this proof consumes no
`src/` module directly. It reads `pyproject.toml` and
`tests/preservation_manifest.py` -> `MODULE_ROSTER`, and exercises the built
wheel out-of-tree. Session snapshot v48 == branch
`feature/4_5c-sonic-base-lifecycle`.

FOUNDER RULING 2026-08-18 (bounded-scope amendment naming REQ-45C-18 and
REQ-45C-40). `py-modules` carries the five runtime modules
`cassian_import`, `cassian_nos_types`, `cassian_nos_frr`, `cassian_nos_sonic`,
`cassian_runtime_vm`, and EXCLUDES `__init__`. Grounds of record: `src/__init__.py`
is a 0-byte source-tree marker, imported by nothing, never entering
`sys.modules` -- not a runtime module within REQ-45C-18's operative term.
Packaging it would install a bare `__init__.py` at the site-packages root, which
silently clobbers and is clobbered by any other distribution doing the same
(measured: pip emits no warning).

The exclusion is a RATCHET, not a hole. Leg A asserts equality modulo an
exclusion set that is hard-coded to exactly {"__init__"}, so widening it
requires editing this file; and asserts `src/__init__.py` stays 0 bytes and
unimported, so the day it gains content this proof REDs and the exclusion must
be re-argued. REQ-45C-40's intent is preserved exactly: the next module is not
`__init__`, so it lands in the equality check and cannot re-open the gap.

COVERAGE LIMITS (PBE-P2-8):
  * Legs A and B are hermetic. Legs 1-5 build and install, so they need network
    for build isolation and for the one declared dependency. They FAIL rather
    than skip when that is unavailable -- a clean-wheel proof that cannot build
    has not passed.
  * The wheel is built with build isolation ON, which honours
    `requires = ["setuptools>=69"]`. Building with `--no-build-isolation`
    against setuptools < 69 fails on `project.license` being a PEP 639 string.
    That is a stale local toolchain, not a repo defect -- recorded so it is not
    misdiagnosed.
  * Step 5 proves `validate` runs with the repo off `sys.path`. It does not
    prove every subcommand does; `validate` is the Req's named minimum.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXCLUDED_FROM_PACKAGING = frozenset({"__init__"})

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


def _run(argv, cwd=None, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)


# --- LEG A (REQ-45C-18): roster <-> py-modules equivalence, ratcheted ---------
_roster_src = io.open(os.path.join(_ROOT, "tests", "preservation_manifest.py"),
                      encoding="utf-8").read()
ROSTER = set(re.findall(r'"src/([A-Za-z_0-9]+)\.py"', _roster_src))

_pyproject = io.open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8").read()
_block = _pyproject.split("py-modules = [")[1].split("]")[0]
PY_MODULES = set(re.findall(r'"([A-Za-z_0-9]+)"', _block))

check("REQ-45C-18 roster parsed non-trivially", len(ROSTER) >= 17,
      "%d rostered modules" % len(ROSTER))
check("REQ-45C-18 py-modules parsed non-trivially", len(PY_MODULES) >= 17,
      "%d packaged modules" % len(PY_MODULES))

_expected = ROSTER - EXCLUDED_FROM_PACKAGING
check("REQ-45C-18 every rostered RUNTIME module is packaged",
      not (_expected - PY_MODULES),
      "missing: %s" % (sorted(_expected - PY_MODULES) or "none"))
check("REQ-45C-18 nothing is packaged that is not rostered",
      not (PY_MODULES - ROSTER),
      "extra: %s" % (sorted(PY_MODULES - ROSTER) or "none"))
check("REQ-45C-40 equivalence holds modulo the ruled exclusion",
      PY_MODULES == _expected,
      "roster %d - excluded %d == py-modules %d"
      % (len(ROSTER), len(EXCLUDED_FROM_PACKAGING), len(PY_MODULES)))

# --- LEG A ratchet: the exclusion cannot grow, and cannot become load-bearing -
check("REQ-45C-40 RATCHET: the exclusion set is exactly {'__init__'}",
      EXCLUDED_FROM_PACKAGING == frozenset({"__init__"}),
      "widening this requires editing the proof, which surfaces in review")
_init = os.path.join(_ROOT, "src", "__init__.py")
_size = os.path.getsize(_init) if os.path.isfile(_init) else -1
check("REQ-45C-40 RATCHET: src/__init__.py is still a 0-byte marker",
      _size == 0,
      "%d bytes -- if non-zero it may be a runtime module; the founder ruling's "
      "grounds no longer hold and the exclusion must be re-argued" % _size)
_importers = []
for _f in sorted(os.listdir(os.path.join(_ROOT, "src"))):
    if not _f.endswith(".py") or _f == "__init__.py":
        continue
    _t = io.open(os.path.join(_ROOT, "src", _f), encoding="utf-8").read()
    if re.search(r"^\s*(import __init__|from __init__ import)", _t, re.M):
        _importers.append(_f)
check("REQ-45C-40 RATCHET: no src module imports __init__",
      not _importers, "importers: %s" % (_importers or "none"))

# --- LEG B (REQ-45C-41): P-45C-STR, no vendored or linked tree under src/ ----
_nested = _run(["find", "src", "-mindepth", "2", "-name", "*.py"], cwd=_ROOT)
_links = _run(["find", "src", "-maxdepth", "1", "-type", "l"], cwd=_ROOT)
_n_nested = len([x for x in _nested.stdout.split("\n") if x.strip()])
_n_links = len([x for x in _links.stdout.split("\n") if x.strip()])
check("REQ-45C-41 find src -mindepth 2 -name '*.py' is 0", _n_nested == 0,
      "%d" % _n_nested)
check("REQ-45C-41 find src -maxdepth 1 -type l is 0", _n_links == 0,
      "%d" % _n_links)
_flat = _run(["find", "src", "-maxdepth", "1", "-name", "*.py"], cwd=_ROOT)
check("REQ-45C-41 NON-VACUITY: the find invocation reaches src/",
      len([x for x in _flat.stdout.split("\n") if x.strip()]) >= 17,
      "%d top-level .py -- proves a zero above is measured, not a broken find"
      % len([x for x in _flat.stdout.split("\n") if x.strip()]))

# --- LEGS 1-5 (REQ-45C-40): the five-step clean-wheel run --------------------
_tmp = tempfile.mkdtemp(prefix="cassian-wheel-proof-")
try:
    _dist = os.path.join(_tmp, "dist")
    _venv = os.path.join(_tmp, "venv")
    _work = os.path.join(_tmp, "work")
    os.makedirs(_work)

    # STEP 1 -- build the wheel in isolation
    # "in isolation" is enforced, not assumed. Two stale-artifact hazards were
    # MEASURED here and both silently served a wheel that did not match
    # pyproject.toml: (1) pip's wheel cache keys on name+version, so an earlier
    # build is reused -- hence --no-cache-dir; (2) a stale src/*.egg-info in the
    # working tree is reused by setuptools -- hence the build runs against a
    # copy with build artifacts stripped, never against the live tree.
    _src = os.path.join(_tmp, "src-copy")
    shutil.copytree(_ROOT, _src, ignore=shutil.ignore_patterns(
        ".git", "labs", "build", "dist", "*.egg-info", "__pycache__", ".venv"))
    _b = _run([sys.executable, "-m", "pip", "wheel", "--no-deps",
               "--no-cache-dir", "--wheel-dir", _dist, "."], cwd=_src)
    _whls = [f for f in os.listdir(_dist)] if os.path.isdir(_dist) else []
    check("REQ-45C-40 step 1: wheel builds in isolation", bool(_whls),
          (_whls or _b.stderr.strip().split("\n")[-1:] or [""])[0])

    if _whls:
        _whl = os.path.join(_dist, _whls[0])
        _in_whl = {os.path.basename(n)[:-3] for n in zipfile.ZipFile(_whl).namelist()
                   if n.endswith(".py") and "/" not in n}
        check("REQ-45C-40 wheel contents equal py-modules exactly",
              _in_whl == PY_MODULES,
              "wheel-only: %s  config-only: %s"
              % (sorted(_in_whl - PY_MODULES) or "none",
                 sorted(PY_MODULES - _in_whl) or "none"))
        check("REQ-45C-18 NON-VACUITY: the wheel carries the SONiC provider",
              "cassian_nos_sonic" in _in_whl,
              "the module this handover added is actually shipped")

        # STEP 2 -- clean environment
        _v = _run([sys.executable, "-m", "venv", _venv])
        _py = os.path.join(_venv, "bin", "python")
        _pip = os.path.join(_venv, "bin", "pip")
        _cli = os.path.join(_venv, "bin", "cassian")
        check("REQ-45C-40 step 2: clean venv created", os.path.isfile(_py),
              _v.stderr.strip()[-120:])

        if os.path.isfile(_py):
            _run([_pip, "install", "--quiet", "--no-deps", _whl])
            _run([_pip, "install", "--quiet", "PyYAML"])

            # STEP 3 -- import the entry point, out of tree
            _i = _run([_py, "-c",
                       "import cassian, cassian_nos_sonic, cassian_nos_frr, "
                       "cassian_nos_types, cassian_runtime_vm, cassian_import; "
                       "print(cassian_nos_sonic.__file__)"], cwd=_work)
            check("REQ-45C-40 step 3: entry point and all five added modules "
                  "import from the installed wheel", _i.returncode == 0,
                  (_i.stderr.strip().split("\n")[-1] if _i.returncode else
                   _i.stdout.strip()))
            check("REQ-45C-40 NON-VACUITY: resolution is source-independent",
                  _i.returncode == 0 and _ROOT not in _i.stdout,
                  "the repo tree is not on the clean env's sys.path")

            # STEP 4 -- cassian --help
            _h = _run([_cli, "--help"], cwd=_work)
            check("REQ-45C-40 step 4: cassian --help succeeds", _h.returncode == 0,
                  (_h.stderr.strip().split("\n")[-1] if _h.returncode else "rc=0"))

            # STEP 5 -- a source-independent validate
            _fx = os.path.join(_ROOT, "topologies", "sonic-base-lifecycle.yaml")
            if os.path.isfile(_fx):
                shutil.copy(_fx, _work)
            _val = _run([_cli, "validate", "sonic-base-lifecycle.yaml"], cwd=_work)
            check("REQ-45C-40 step 5: source-independent validate succeeds",
                  _val.returncode == 0,
                  (_val.stderr.strip().split("\n")[-1] if _val.returncode
                   else "VALIDATE PASS out of tree"))
finally:
    shutil.rmtree(_tmp, ignore_errors=True)

# --- Report ------------------------------------------------------------------
_fails = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%s %s%s" % ("PASS" if _ok else "FAIL", _n, ("  [%s]" % _d) if _d else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-11 packaging / clean wheel)"
      % ("PASS" if not _fails else "FAIL", len(_checks)))
if _fails:
    sys.exit("wheel_import_proof FAILED (%d check(s))." % len(_fails))
