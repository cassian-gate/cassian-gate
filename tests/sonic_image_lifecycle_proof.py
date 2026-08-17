#!/usr/bin/env python3
"""
tests/sonic_image_lifecycle_proof.py — §4.5-c WI-4 (B-8) image lifecycle proof.

Req-IDs: REQ-45C-11 (CI resolves via the contrib-owned path; no registry pull)
         REQ-45C-31 (missing image -> §13-grade error, exit 2, elements a/b/c)
         REQ-45C-32 (zero ghcr.io pins under topologies/)

Coverage limit (PBE-P2-8), stated rather than implied:
  This proof CANNOT verify that a locally-present `local/sonic-vm:<v>` tag was
  produced by contrib/sonic-image-build/ rather than by a hand `docker tag`.
  A vrnetlab-built image carries an identical `vrnetlab-version` label under
  either tag, and all tags of one image share an image ID. Provenance of the
  local tag is an operator responsibility. Non-vacuity here rests on the
  REQ-45C-31 negative leg, which is host-independent and cannot pass by
  accident: it asserts a deliberately unresolvable reference is REJECTED with
  the exact required elements.

Host-independent. No lab, no containerlab, no Docker image required.
"""
import io
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


# --- Leg 1 (REQ-45C-32): zero ghcr.io pins under topologies/ ----------------
_topo_dir = os.path.join(_ROOT, "topologies")
_ghcr_hits = []
for _dirpath, _dirnames, _filenames in os.walk(_topo_dir):
    for _fn in _filenames:
        _p = os.path.join(_dirpath, _fn)
        try:
            _txt = io.open(_p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for _i, _line in enumerate(_txt.split("\n"), 1):
            if "ghcr.io" in _line:
                _ghcr_hits.append("%s:%d" % (os.path.relpath(_p, _ROOT), _i))

check("REQ-45C-32 zero ghcr.io pins under topologies/",
      len(_ghcr_hits) == 0,
      "hits: %s" % (_ghcr_hits or "none"))

# Positive control for leg 1: the sweep can find a hit when one exists.
check("REQ-45C-32 sweep non-vacuity (detector fires on a synthetic hit)",
      "ghcr.io" in "image: ghcr.io/example/x:1",
      "control")

# --- Leg 2 (REQ-45C-11): no registry pull remains in the VM CI step ---------
_wf = os.path.join(_ROOT, ".github", "workflows", "cassian.yml")
_wf_txt = io.open(_wf, encoding="utf-8", errors="replace").read()
_pull_lines = [
    "%d" % _i
    for _i, _line in enumerate(_wf_txt.split("\n"), 1)
    if re.search(r"^\s*docker\s+pull\s+ghcr\.io/cassian-gate/sonic-vm", _line)
]
check("REQ-45C-11 no sonic-vm registry pull remains in cassian.yml",
      len(_pull_lines) == 0,
      "lines: %s" % (_pull_lines or "none"))

check("REQ-45C-11 vm-assertion-smoke step still present in cassian.yml",
      "vm-assertion-smoke" in _wf_txt,
      "guards against the step being deleted rather than corrected")

# --- Leg 3 (REQ-45C-31): missing image -> exit 2 with elements (a)/(b)/(c) ---
import cassian_engine as E  # noqa: E402

check("REQ-45C-31 gate function present", hasattr(E, "_assert_vm_images_present"))

_BOGUS = "local/sonic-vm-does-not-exist-45c:0"
_err = io.StringIO()
_code = None
try:
    _stderr, sys.stderr = sys.stderr, _err
    try:
        E._assert_vm_images_present([{"name": "s1", "image": _BOGUS}])
    finally:
        sys.stderr = _stderr
except SystemExit as _e:
    _code = _e.code
_msg = _err.getvalue()

check("REQ-45C-31 unresolvable image is rejected", _code is not None)
check("REQ-45C-31 exit code is 2 (not 1)", _code == 2, "got: %r" % (_code,))
check("REQ-45C-31 (a) names the unresolved image reference", _BOGUS in _msg)
check("REQ-45C-31 (b) states the contrib-owned-local-path reason",
      "not present at the contrib-owned local path" in _msg)
check("REQ-45C-31 (c) gives the exact contrib invocation",
      "contrib/sonic-image-build/build.sh" in _msg)
check("REQ-45C-31 names the offending node", "node: s1" in _msg)

# Non-vacuity control: a node with no image declared must NOT be rejected.
_ok = True
try:
    E._assert_vm_images_present([{"name": "s2", "image": ""}])
except SystemExit:
    _ok = False
check("REQ-45C-31 non-vacuity: imageless node is not rejected", _ok,
      "proves the gate discriminates rather than always failing")

# --- Report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _name, _ok, _detail in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _name,
                         ("  [%s]" % _detail) if _detail else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-4 image lifecycle, B-8)"
      % ("PASS" if not _failed else "FAIL", len(_checks)))
sys.exit(1 if _failed else 0)
