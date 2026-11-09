#!/usr/bin/env python3
"""SONiC ospf_neighbor_up UNSUPPORTED proof (REQ-45D-17; D-047.VAL; OSPF governance anchor).

OSPF on SONiC is not supported in this release (D-047.VAL refined IMPL to
UNSUP-with-clear-error at §4.5 core; IMPL deferred to §4.12). An
``ospf_neighbor_up`` invariant whose ``src`` resolves to a ``sonic-vm`` node is
therefore refused at validate with a deterministic UNSUPPORTED message, exit 2,
the same bytes on every run (handover §6.6 template, B08, §15.2 and §18 rows
-17). SONiC's capability table does not declare the kind, so exec-time
collection is refused by deny-by-default as well.

Proof obligations:
  P-OSU-CLI    ``cassian validate topologies/sonic-ospf-unsup.yaml`` run twice as
               a subprocess: exit 2 both times, stdout empty, and stderr EQUAL to
               the pinned bytes both times (equality, not containment).
  P-OSU-SEAM   the same fixture through the real seams in cmd_validate's call
               order (``ensure_valid_topology`` -> ``resolve_topology``) under the
               quiet-die mode: the recorded error message EQUALS the pinned
               message body, so the CLI bytes come from the REQ-45D-17 site.
  P-OSU-ELEM   the message names the invariant, the type, the node and its type,
               says "not supported in this release", and points to
               ``docs/cli-reference-v1.md``; that file exists and carries
               ``ospf_neighbor_up`` (REQ-45D-18's declaration, founder ruling
               S27-R6), so the pointer does not dangle.
  P-OSU-FRR    FRR OSPF is untouched: ``topologies/ospf_neighbor_up.yaml``
               validates (exit 0), and the fixture with ``src`` moved to its frr
               node validates in-process -- the refusal depends on the src type.
  P-OSU-OTHER  every other non-frr src keeps the pre-existing frr-only message
               BYTE-IDENTICAL (measured at cassian-gate@75133da): an ``nft-fw``
               src is the vehicle. The new check is narrow by construction.
  P-OSU-CAP    SONiC's capability table does not declare ``ospf_neighbor_up``
               (absent key; ``capability_for`` is not IMPL); FRR's declares it
               IMPL.
  P-OSU-NV     non-vacuity, each counter-example taken from REQ-45D-17's failure
               conditions and each shown to be caught: (1) "the declaration passes
               validate" -- a source mutant without the UNSUPPORTED branch, run
               through the CLI, is caught by P-OSU-CLI's comparison; (2) "the
               message bytes vary between runs" -- a mutant whose message carries
               a per-process value is caught by the two-run equality; (3) "the
               capability table declares ospf_neighbor_up" -- an in-memory
               declaration is caught by P-OSU-CAP's predicate. Each mutation is
               asserted by occurrence count before it is applied (Rule 19), so a
               mutant that fails to build fails loudly instead of passing.

Coverage limits, stated in-file (PBE-P2-8):
  - Lab-free. Proves the VALIDATE-time refusal and the capability declaration;
    no SONiC guest is contacted and nothing about guest OSPF is claimed.
  - The exec-time backstop (``_nos_collect`` refusing an undeclared kind) is
    proved by tests/sonic_observation_kinds_proof.py (K-DISPATCH); here only
    the declaration it reads is asserted.
  - P-OSU-OTHER uses one non-frr, non-sonic type (``nft-fw``); it shows the new
    check does not reach that type, not that no future type is reached.

Exit 0 on all-pass; exit 1 otherwise.
"""
import contextlib
import copy
import io
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import cassian_common as C  # noqa: E402
import cassian_model as M  # noqa: E402
import cassian_nos_frr as F  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import CAP_IMPL, capability_for, impl  # noqa: E402

FIXTURE = os.path.join("topologies", "sonic-ospf-unsup.yaml")
FRR_FIXTURE = os.path.join("topologies", "ospf_neighbor_up.yaml")
REFERENCE = os.path.join(ROOT, "docs", "cli-reference-v1.md")

# The pinned bytes (handover §6.6 template, plus the corrective line the item-5
# message carries; founder-visible at session 27 and not objected to).
EXPECTED_MSG = (
    "Topology invalid: invariant ospf-on-sonic: type ospf_neighbor_up is unsupported "
    "on node s1 (type sonic-vm) — OSPF on SONiC is not supported in this release; "
    "see docs/cli-reference-v1.md\n"
    "Valid: point src at a node of type frr, or remove this invariant."
)
EXPECTED_STDERR = "ERROR: " + EXPECTED_MSG + "\n"

# The frr-only message for any other non-frr src, as it read before this change
# (measured on cassian-gate@75133da with this exact declaration).
OTHER_MSG = (
    "tests[1] (ospf-on-nft): invariant 'ospf_neighbor_up' references src 'f1' of "
    "type 'nft-fw'; this invariant requires src to be a node of type 'frr'"
)

checks = []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


def validate_cli(src_dir=SRC, topology=FIXTURE):
    """Run `cassian validate` as a subprocess; return (rc, stdout, stderr)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir
    env["PYTHONUNBUFFERED"] = "1"
    r = subprocess.run([sys.executable, os.path.join(src_dir, "cassian.py"), "validate", topology],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr


def cli_leg(runs):
    """P-OSU-CLI's predicate over two runs: exit 2, no stdout, pinned stderr, equal bytes."""
    (rc1, out1, err1), (rc2, out2, err2) = runs
    return (rc1 == 2 and rc2 == 2 and out1 == "" and out2 == ""
            and err1 == EXPECTED_STDERR and err2 == EXPECTED_STDERR and err1 == err2)


def validate_inproc(topo):
    """Mirror cmd_validate in-process under quiet-die; return ("ok"|"die", message)."""
    td = copy.deepcopy(topo)
    prev = getattr(C, "_QUIET_DIE", False)
    C._QUIET_DIE = True
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            M.ensure_valid_topology(td)
            M.resolve_topology(td)
        return ("ok", "")
    except SystemExit:
        return ("die", C.LAST_ERROR_MSG or "")
    finally:
        C._QUIET_DIE = prev


def cap_leg(provider):
    """P-OSU-CAP's predicate on a provider: the kind is neither declared nor IMPL."""
    return ("ospf_neighbor_up" not in provider.capabilities
            and capability_for(provider, "ospf_neighbor_up").state != CAP_IMPL)


with open(os.path.join(ROOT, FIXTURE), encoding="utf-8") as fh:
    TOPO = yaml.safe_load(fh)

# ---- P-OSU-CLI -------------------------------------------------------------
runs = [validate_cli(), validate_cli()]
for n, (rc, out, err) in enumerate(runs, 1):
    check("P-OSU-CLI run %d exits 2" % n, rc == 2, "rc=%s" % rc)
    check("P-OSU-CLI run %d prints nothing on stdout" % n, out == "", repr(out[:80]))
    check("P-OSU-CLI run %d stderr equals the pinned bytes" % n, err == EXPECTED_STDERR, repr(err[:160]))
check("P-OSU-CLI stderr bytes identical across the two runs", runs[0][2] == runs[1][2])
check("P-OSU-CLI composite predicate holds on the shipped tree", cli_leg(runs))

# ---- P-OSU-SEAM ------------------------------------------------------------
_o, _m = validate_inproc(TOPO)
check("P-OSU-SEAM fixture is refused in-process", _o == "die")
check("P-OSU-SEAM recorded message equals the pinned message body", _m == EXPECTED_MSG, repr(_m[:160]))

# ---- P-OSU-ELEM ------------------------------------------------------------
for label, token in (("invariant name", "invariant ospf-on-sonic:"),
                     ("type", "type ospf_neighbor_up is unsupported"),
                     ("node and its type", "on node s1 (type sonic-vm)"),
                     ("release statement", "not supported in this release"),
                     ("reference pointer", "see docs/cli-reference-v1.md"),
                     ("corrective action", "Valid: point src at a node of type frr")):
    check("P-OSU-ELEM message carries the %s" % label, token in EXPECTED_MSG and token in _m)
with open(REFERENCE, encoding="utf-8") as fh:
    _ref = fh.read()
check("P-OSU-ELEM pointer target exists and mentions ospf_neighbor_up", "ospf_neighbor_up" in _ref)

# ---- P-OSU-FRR -------------------------------------------------------------
_frc, _fout, _ferr = validate_cli(topology=FRR_FIXTURE)
check("P-OSU-FRR topologies/ospf_neighbor_up.yaml validates (exit 0)", _frc == 0, "rc=%s %s" % (_frc, _ferr[:120]))
_frr = copy.deepcopy(TOPO)
_frr["tests"][0]["src"] = "r1"
_frr["tests"][0]["neighbor"] = "192.0.2.31"
_o, _m2 = validate_inproc(_frr)
check("P-OSU-FRR the fixture with src on its frr node validates", _o == "ok", _m2[:160])

# ---- P-OSU-OTHER -----------------------------------------------------------
_oth = {
    "name": "osu-other",
    "nodes": [{"name": "r1", "type": "frr", "router_id": "192.0.2.41"},
              {"name": "f1", "type": "nft-fw"}],
    "links": [{"endpoints": ["r1:eth1", "f1:eth1"]}],
    "tests": [{"name": "ospf-on-nft", "kind": "invariant", "type": "ospf_neighbor_up",
               "src": "f1", "neighbor": "192.0.2.41"}],
}
_o, _m3 = validate_inproc(_oth)
check("P-OSU-OTHER nft-fw src is refused", _o == "die")
check("P-OSU-OTHER nft-fw src keeps the frr-only message byte-identical", _m3 == OTHER_MSG, repr(_m3[:160]))

# ---- P-OSU-CAP -------------------------------------------------------------
check("P-OSU-CAP SONiC capability table does not declare ospf_neighbor_up", cap_leg(S.SONIC_PROVIDER))
check("P-OSU-CAP FRR declares ospf_neighbor_up IMPL (FRR OSPF untouched)",
      capability_for(F.FRR_PROVIDER, "ospf_neighbor_up").state == CAP_IMPL)

# ---- P-OSU-NV --------------------------------------------------------------
UNSUP_ANCHOR = '                if _src_kind == "sonic-vm":\n'
MSG_ANCHOR = '"supported in this release; see docs/cli-reference-v1.md\\n"'


def mutant_runs(old, new, label):
    """Build a source mutant in a temp tree (count asserted first) and run the CLI twice."""
    with open(os.path.join(SRC, "cassian_model.py"), encoding="utf-8") as fh:
        text = fh.read()
    count = text.count(old)
    check("P-OSU-NV %s: mutation anchor occurs exactly once" % label, count == 1, "count=%d" % count)
    if count != 1:
        return None
    tmp = tempfile.mkdtemp(prefix="osu-nv-")
    try:
        msrc = os.path.join(tmp, "src")
        shutil.copytree(SRC, msrc, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        with open(os.path.join(msrc, "cassian_model.py"), "w", encoding="utf-8") as fh:
            fh.write(text.replace(old, new))
        return [validate_cli(src_dir=msrc), validate_cli(src_dir=msrc)]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_nv1 = mutant_runs(UNSUP_ANCHOR, '                if False:\n', "no UNSUPPORTED branch")
check("P-OSU-NV (1) a tree without the UNSUPPORTED branch is caught by P-OSU-CLI",
      _nv1 is not None and not cli_leg(_nv1)
      and "requires src to be a node of type 'frr'" in _nv1[0][2])
_nv2 = mutant_runs(MSG_ANCHOR,
                   'f"supported in this release; see docs/cli-reference-v1.md '
                   '({__import__(\'os\').getpid()})\\n"',
                   "per-process message")
check("P-OSU-NV (2) varying message bytes are caught by the two-run equality",
      _nv2 is not None and _nv2[0][2] != _nv2[1][2] and not cli_leg(_nv2))
_saved = dict(S.SONIC_PROVIDER.capabilities)
try:
    S.SONIC_PROVIDER.capabilities["ospf_neighbor_up"] = impl()
    _caught3 = not cap_leg(S.SONIC_PROVIDER)
finally:
    S.SONIC_PROVIDER.capabilities.clear()
    S.SONIC_PROVIDER.capabilities.update(_saved)
check("P-OSU-NV (3) an ospf_neighbor_up declaration on SONiC is caught by P-OSU-CAP", _caught3)
check("P-OSU-NV capability table restored after mutation", cap_leg(S.SONIC_PROVIDER)
      and dict(S.SONIC_PROVIDER.capabilities) == _saved)

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
