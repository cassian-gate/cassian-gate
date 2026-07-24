#!/usr/bin/env python3
"""§4.5-b REQ-45b-19 — NOS deny-by-default negative proof set, lab-free.

Every leg asserts that a VIOLATION is caught. A leg that passes on the
violation it exists to catch is a failure of the proof, not of the code.

Legs:
  (i)   an unregistered node type at a shipped provider seam fails loud with
        the §6.6 registry-UNSUP shape, exit 2; and a REGISTERED-but-non-capable
        type raises the distinguishable capability deny (B01 / B02)
  (ii)  `cassian vty` non-FRR UNSUP proven byte-exact against §6.6, PRE-dispatch
  (iii) a deliberate leaf-import violation is caught -- delegated to
        nos_leaf_import_proof.py's P-IMP-6, executed here so the leg is
        observable from this proof too
  (iv)  an unregistered new module reds the roster guards (LD-9 leg); asserted
        on the guards' own predicate against a synthetic on-disk set, so the
        mechanism is proven without mutating the tree

BOUNDED POSITIVE LEG (ruled). Leg (ii)'s positive half asserts only that the
gate DOES NOT FIRE for an FRR node -- i.e. execution reaches the dispatch line.
It does NOT assert that `vty` then succeeds. That is deliberate and bounded,
not an oversight: the downstream path is blocked by pre-existing defect
F-45b-E-1 (`vty` is called in `cassian_engine.cmd_vty` but is not imported into
`cassian_engine`; every invocation reaching dispatch raises NameError). That
defect is outside §4.5-b's §14.4 bounded touch set and is tracked as a Ledger
row routed to the undefined-name defect-class remediation. When that row
closes, this leg extends to assert end-to-end pass-through.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import yaml  # noqa: E402
import cassian_common as CM  # noqa: E402
CM._QUIET_DIE = True
import cassian_engine as E  # noqa: E402
import cassian_nos_frr as F  # noqa: E402
from cassian_nos_types import ObservationRequest  # noqa: E402
from preservation_manifest import MODULE_ROSTER  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)


class _Unreachable:
    def exec(self, *a, **k):
        raise AssertionError("provider must not be reached on a denied dispatch")


print("=" * 60)
print("REQ-45b-19 — NOS deny-by-default negative proof set")
print("=" * 60)

# ---------------------------------------------------------------- leg (i) ---
SEAM = "cmd_test invariant collection"
EXPECTED_REGISTRY_UNSUP = (
    "ERROR: unsupported node type 'sonic' at cmd_test invariant collection: "
    "no NOS provider is registered for it.\n"
    "Supported: frr, nft-fw.\n"
    "Next:\n"
    "  Extension route: add src/cassian_nos_<token>.py and register it in NOS_PROVIDERS\n"
    "  (see the NOS expansion structure design)."
)

got = None
try:
    E._nos_collect(_Unreachable(), "L", "s1", "sonic",
                   ObservationRequest(kind="bgp_session_up"), SEAM)
except SystemExit as ex:
    got = str(ex.code)
check(got == EXPECTED_REGISTRY_UNSUP,
      "(i) unregistered type -> byte-exact §6.6 registry UNSUP")
check(got is not None, "(i) unregistered type exits (does not fall through)")

denied = None
try:
    E._nos_collect(_Unreachable(), "L", "fw1", "nft-fw",
                   ObservationRequest(kind="bgp_session_up"), SEAM)
except E.NosCapabilityUnsupported as ex:
    denied = ex
check(denied is not None,
      "(i) registered-but-non-capable type raises NosCapabilityUnsupported (B02)")
if denied is not None:
    check(denied.ntype == "nft-fw" and denied.kind == "bgp_session_up",
          "(i) capability deny names the offending (node-type, kind) pair")

# every shipped collect kind must be declared by the FRR provider
undeclared = sorted(k for k in F._COLLECT_HANDLERS if k not in F._FRR_CAPABILITIES)
check(not undeclared,
      f"(i) every shipped collect kind is capability-declared (undeclared: {undeclared})")

# ---------------------------------------------------------------- leg (ii) --
labdir = os.path.join(str(E.LABS_DIR), "clab-nosdenyproof")
os.makedirs(labdir, exist_ok=True)
with open(os.path.join(labdir, "topology.resolved.yaml"), "w", encoding="utf-8") as fh:
    yaml.safe_dump({"name": "nosdenyproof",
                    "nodes": [{"name": "fw1", "type": "nft-fw"},
                              {"name": "r1", "type": "frr"}]}, fh)

EXPECTED_VTY_UNSUP = (
    "ERROR: 'cassian vty' is an FRR vtysh shortcut; node 'fw1' is type 'nft-fw', not 'frr'.\n"
    "Supported: frr nodes only.\n"
    "Next:\n"
    '  Run: cassian exec nosdenyproof fw1 "show bgp summary"   (NOS-agnostic, allow-listed)'
)
try:
    vgot = None
    try:
        E.cmd_vty(argparse.Namespace(lab="nosdenyproof", node="fw1",
                                     command="show bgp summary"))
    except SystemExit as ex:
        vgot = str(ex.code)
    check(vgot == EXPECTED_VTY_UNSUP, "(ii) vty non-FRR -> byte-exact §6.6 UNSUP, exit 2")

    # PRE-dispatch: the gate must fire before vty() is reached.
    src_txt = open(os.path.join(SRC, "cassian_engine.py"), encoding="utf-8").read()
    gate_at = src_txt.find("'cassian vty' is an FRR vtysh shortcut")
    disp_at = src_txt.find("cp = vty(rt, lab, node, command)")
    check(0 < gate_at < disp_at, "(ii) gate is PRE-dispatch in cmd_vty source order")

    # BOUNDED positive leg -- see module docstring (F-45b-E-1).
    fired = False
    try:
        E.cmd_vty(argparse.Namespace(lab="nosdenyproof", node="r1",
                                     command="show bgp summary"))
    except SystemExit as ex:
        fired = "FRR vtysh shortcut" in str(ex.code)
    except NameError:
        fired = False   # reached dispatch; blocked by F-45b-E-1 (bounded, tracked)
    except Exception:
        fired = False
    check(not fired,
          "(ii) BOUNDED positive leg: gate does NOT fire for an FRR node "
          "(end-to-end pass-through unassertable -- F-45b-E-1, tracked)")
finally:
    shutil.rmtree(labdir, ignore_errors=True)

# --------------------------------------------------------------- leg (iii) --
r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "nos_leaf_import_proof.py")],
                   capture_output=True, text=True,
                   env=dict(os.environ, PYTHONPATH=SRC))
check(r.returncode == 0, "(iii) import-graph proof passes on the shipped graph")
check("P-IMP-6 NON-VACUITY" in r.stdout and "PASS  P-IMP-6" in r.stdout,
      "(iii) import-graph proof's deliberate-violation leg is present and green")

# ---------------------------------------------------------------- leg (iv) --
# The roster guards compute `added = on_disk - MODULE_ROSTER`. Prove the
# predicate reds for an unregistered module, without mutating the tree.
on_disk = {f"src/{n}" for n in os.listdir(SRC) if n.endswith(".py")}
check(not (on_disk - MODULE_ROSTER) and not (MODULE_ROSTER - on_disk),
      "(iv) shipped tree: on-disk src set == MODULE_ROSTER (currently green)")
synthetic = on_disk | {"src/cassian_nos_sonic.py"}
check(bool(synthetic - MODULE_ROSTER),
      "(iv) NON-VACUITY: an unregistered new module reds the roster predicate (LD-9)")
check(len(MODULE_ROSTER) == 17, f"(iv) roster denominator is 17 (got {len(MODULE_ROSTER)})")

print("=" * 60)
if fails:
    print(f"RESULT: FAIL -- {len(fails)} check(s): " + "; ".join(fails))
    sys.exit(1)
print("RESULT: PASS -- deny-by-default holds at every shipped seam; "
      "every negative leg catches its violation.")
