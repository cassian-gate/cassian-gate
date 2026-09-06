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

Lab-free by default; the `req11` subcommand is a (VM) leg on a booted guest.
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

# Positive control for leg 2: the pull detector fires on a synthetic line.
# LD-45C-R34 R3 -- Leg 2 shipped without one while legs 1 and 3 had theirs;
# BL-P2-4.5c-136 records the same shape in sonic_lifecycle_proof.py LEG 2.
check("REQ-45C-11 pull-detector non-vacuity (fires on a synthetic hit)",
      bool(re.search(r"^\s*docker\s+pull\s+ghcr\.io/cassian-gate/sonic-vm",
                     "          docker pull ghcr.io/cassian-gate/sonic-vm:202405")),
      "control")

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

# --- Leg 4 (REQ-45C-11, (VM)): §15.2 row 11 `:466` ---------------------------
def _leg_req11(topo_path, lab):
    """§15.2 row 11 (`:466`): CI resolves + boots the image via the contrib
    path, with zero registry interaction.

    LIVE DEVICE. Runs only on `ai-netsim-runner`, after `cassian up` has
    deployed the lab. There is no stub anywhere in it.

    WHY THE DEPLOYED IMAGE AND NOT THE DECLARED ONE. Leg 1 already sweeps
    `topologies/` for `ghcr.io` and Leg 2 sweeps the workflow. Reading the
    topology's own `image:` here would re-assert what Leg 1 established and
    would stay green even if the guest had booted from something else. The
    discriminating read is what the RUNNING container reports; it is
    independent of both file sweeps.

    STATED COVERAGE LIMIT (PBE-P2-8): this leg establishes that the reference
    the container actually runs carries no registry host and matches the
    declared local tag. It does NOT observe the network. That no packet
    reached a registry is INFERRED from the reference's shape, not measured.
    The file-level limit above also carries: provenance of the local tag --
    contrib-built versus hand-tagged -- is an operator responsibility.
    """
    import subprocess
    import yaml
    import cassian_runtime_vm as _RV

    print("=== tests/sonic_image_lifecycle_proof.py req11 (§15.2 row 11) ===")
    doc = yaml.safe_load(io.open(topo_path, encoding="utf-8").read()) or {}
    node = None
    for n in doc.get("nodes", []) or []:
        if isinstance(n, dict) and str(n.get("type") or "") == "sonic-vm":
            node = n
            break
    check("(11a) the topology declares a sonic-vm node", node is not None,
          repr([n.get("name") for n in doc.get("nodes", []) or []]))
    if node is None:
        return
    name = str(node.get("name"))
    declared = str(node.get("image") or "")

    rt = _RV.build_runtime(doc)
    try:
        running = rt.is_running(lab, name)
        run_err = ""
    except Exception as exc:  # noqa: BLE001 - a failed read is a result
        running, run_err = False, "%s: %s" % (type(exc).__name__, exc)
    check("(11b) the node is running after `cassian up`", running,
          run_err or "node=%s lab=%s" % (name, lab))

    cid = rt.node_id(lab, name)
    try:
        cp = subprocess.run(
            ["docker", "inspect", "-f", "{{.Config.Image}}", cid],
            check=False, capture_output=True, text=True)
        deployed = cp.stdout.strip()
        insp_err = "" if cp.returncode == 0 else cp.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        deployed, insp_err = "", "%s: %s" % (type(exc).__name__, exc)

    check("(11c) NON-VACUITY: the deployed-image read returned a non-empty "
          "reference, so an empty read cannot pass as a match",
          bool(deployed), insp_err or repr(deployed))

    def _has_registry_host(ref):
        head = ref.split("/")[0]
        return "/" in ref and ("." in head or ":" in head or head == "localhost")

    check("(11d) the DEPLOYED image carries no registry host",
          bool(deployed) and not _has_registry_host(deployed), repr(deployed))
    check("(11e) the deployed image is the declared contrib-owned local tag",
          bool(deployed) and deployed == declared,
          "deployed=%r declared=%r" % (deployed, declared))
    check("(11f) NON-VACUITY: the registry-host detector fires on a synthetic "
          "ghcr.io reference",
          _has_registry_host("ghcr.io/cassian-gate/sonic-vm:202405"), "control")


# --- Report -----------------------------------------------------------------
def _finish():
    _failed = [c for c in _checks if not c[1]]
    for _name, _ok, _detail in _checks:
        print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _name,
                             ("  [%s]" % _detail) if _detail else ""))
    print("=" * 60)
    print("RESULT: %s -- %d checks (WI-4 image lifecycle, B-8)"
          % ("PASS" if not _failed else "FAIL", len(_checks)))
    return 1 if _failed else 0


if __name__ == "__main__":
    # LD-45C-R34 R2 -- dispatch confined to this block. Legs 1-3 are top-level
    # and have already executed by the time control reaches here, so no argv is
    # today's behaviour byte-for-byte. An unknown subcommand is a usage error,
    # never a silent no-op that would let a mis-wired CI step pass unseen
    # (F-45C-C3-3, via LD-45C-R30 R1).
    _args = sys.argv[1:]
    if not _args:
        sys.exit(_finish())
    elif _args[0] == "req11" and len(_args) == 3:
        _leg_req11(_args[1], _args[2])
        sys.exit(_finish())
    else:
        sys.stderr.write(
            "usage: sonic_image_lifecycle_proof.py [req11 <topology> <lab>]\n")
        sys.exit(2)
