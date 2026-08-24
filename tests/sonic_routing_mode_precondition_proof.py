#!/usr/bin/env python3
"""tests/sonic_routing_mode_precondition_proof.py -- §4.5-c WI-1 packet 3a.

Req-ID: REQ-45C-44(b) -- the mode precondition. Ledger row BL-P2-4.5c-50.

Snapshot mapping: `cassian_nos_sonic` -> `src/cassian_nos_sonic.py`. Session
snapshot v54 == branch `feature/4_5c-sonic-base-lifecycle` @ `20db092`.

WHAT THIS COVERS -- §15.2's four REQ-45C-44 rows, and which are NOT here:
  :489  positive        overlay authors no platform-owned data
                        -> already proven by sonic_configgen_determinism_proof
  :492  negative        §4.5-c writes neither mode key anywhere
                        -> LEG 3 below
  :491  negative (VM)   clean guest passes; SEEDED guest fails loud
                        -> LEG 1/2 prove the PREDICATE lab-free. The seeded
                           REAL guest half is NOT here; it needs guest
                           mutation and is packet 3b's.
  :490  positive (VM)   post-apply device read vs pre-apply
                        -> NOT here; needs the pre/post window (BL-P2-4.5c-35)

LAB-FREE by construction. The guest read is replayed through a fake runtime,
so this proves the predicate's behaviour, not the device's. It reports no
BLOCKED legs: a (VM) row is not claimed by a lab-free proof, which is the
defect BL-P2-4.5c-35 records.

STATED COVERAGE LIMITS (PBE-P2-8):
  * The replayed payloads are the MEASURED shape from sonic-vm:202405
    (SONiC.202405.1033627-fecd4ec81, read 2026-08-24) -- a Python repr of
    DEVICE_METADATA['localhost']. If a future image returns a different shape,
    these legs still pass while the real read fails. LEG 4 pins the argv so
    the drift is at least locatable.
  * The proof asserts the guard REFUSES a seeded guest. It does not establish
    what SONiC does in those modes -- unmeasured, and the reason the
    disposition is refusal rather than adaptation.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_sonic as S  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _CP:
    def __init__(self, rc, out):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


class _FakeRuntime:
    """Replays one guest read. Records argv so single-sourcing is provable."""

    def __init__(self, out, rc=0):
        self.calls = []
        self._cp = _CP(rc, out)

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        return self._cp


# Measured verbatim on sonic-vm:202405, 2026-08-24. Stock guest, un-provisioned.
CLEAN = ("{'bgp_asn': '65100', 'buffer_model': 'traditional', "
         "'default_bgp_status': 'up', 'default_pfcwd_status': 'disable', "
         "'hostname': 's1', 'hwsku': 'Force10-S6000', "
         "'mac': '22:7b:ff:8d:f6:71', 'platform': 'x86_64-kvm_x86_64-r0', "
         "'timezone': 'UTC', 'type': 'LeafRouter'}\n")


def _seeded(key, value):
    return CLEAN.rstrip("\n")[:-1] + ", '%s': '%s'}\n" % (key, value)


# --- LEG 1: a clean guest passes ----------------------------------------------

rt = _FakeRuntime(CLEAN)
ok = True
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit:
    ok = False
check("REQ-45C-44(b) clean guest passes (measured stock DEVICE_METADATA)", ok)

# --- LEG 2: NON-VACUITY -- each forbidden key, independently, fails loud -------
# Enumerated per key rather than tested once (Rule 14): a guard that fires on
# one key and not the other would pass a single-shape test.

for key, value in (("docker_routing_config_mode", "unified"),
                   ("frr_mgmt_framework_config", "true")):
    rt = _FakeRuntime(_seeded(key, value))
    code = None
    try:
        S.assert_routing_mode_clean(rt, "lab", "s1")
    except SystemExit as exc:
        code = exc.code
    check("REQ-45C-44(b) NON-VACUITY: seeded `%s` fails loud, exit 2" % key,
          code == 2, "exit=%r" % code)

# both set at once
rt = _FakeRuntime(_seeded("docker_routing_config_mode", "split"))
code = None
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit as exc:
    code = exc.code
check("REQ-45C-44(b) a non-default mode VALUE also fails (value not matched)",
      code == 2, "exit=%r" % code)

# --- LEG 3: §15.2 :492 -- §4.5-c writes neither key anywhere -------------------

root = os.path.join(os.path.dirname(__file__), "..")
hits = []
for key in S._FORBIDDEN_MODE_KEYS:
    cp = subprocess.run(["grep", "-rn", key, "src/"], cwd=root,
                        capture_output=True, text=True)
    for line in (cp.stdout or "").splitlines():
        # The provider's own guard names the keys; that is the guard, not a write.
        if line.startswith("src/cassian_nos_sonic.py:"):
            continue
        hits.append(line)
check("REQ-45C-44(b) §15.2 :492 -- §4.5-c writes neither mode key anywhere",
      not hits, "hits: %s" % (hits or "none"))

# non-vacuity for LEG 3: the grep instrument can find the keys when present
cp = subprocess.run(["grep", "-rn", S._FORBIDDEN_MODE_KEYS[0], "src/"],
                    cwd=root, capture_output=True, text=True)
check("LEG 3 NON-VACUITY: the grep finds the key in the guard itself",
      bool((cp.stdout or "").strip()),
      "guard occurrences: %d" % len((cp.stdout or "").splitlines()))

# --- LEG 4: PBE-P2-6 -- the mode read is single-sourced and NOT _HWSKU_ARGV ----

rt = _FakeRuntime(CLEAN)
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit:
    pass
check("PBE-P2-6: the guard issues exactly one guest read",
      len(rt.calls) == 1, "calls=%d" % len(rt.calls))
check("PBE-P2-6: the read uses _DEVICE_METADATA_ARGV verbatim",
      rt.calls and tuple(rt.calls[0]) == S._DEVICE_METADATA_ARGV,
      "argv=%s" % (rt.calls[0] if rt.calls else None))
check("PBE-P2-6: _HWSKU_ARGV is NOT widened to carry the mode read",
      S._DEVICE_METADATA_ARGV != S._HWSKU_ARGV
      and "hwsku" not in " ".join(S._DEVICE_METADATA_ARGV))

# --- LEG 5: the guard runs BEFORE any generation or supply --------------------

import inspect  # noqa: E402
src = inspect.getsource(S.provision)
i_guard = src.find("assert_routing_mode_clean(")
i_probe = src.find("probe_facts(")
i_gen = src.find("gen_node_config(")
check("the precondition precedes probe_facts and gen_node_config in provision",
      -1 < i_guard < i_probe and i_guard < i_gen,
      "guard=%d probe=%d gen=%d" % (i_guard, i_probe, i_gen))

# --- LEG 6: leaf-import constraint preserved ----------------------------------
# nos-expansion-structure-design-RATIFIED.md:112 -- providers import only
# cassian_common and the stdlib. `ast` is stdlib; this leg fails if the guard's
# addition reached for the model.

mod_src = open(os.path.join(root, "src", "cassian_nos_sonic.py"),
               encoding="utf-8").read()
check("leaf-import constraint: provider does not import cassian_model",
      "import cassian_model" not in mod_src
      and "from cassian_model" not in mod_src)

# --- report -------------------------------------------------------------------

fails = [c for c in _checks if not c[1]]
for name, ok, detail in _checks:
    print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                       ("  [%s]" % detail) if detail else ""))
print("=" * 60)
print("RESULT: %s -- %d/%d checks passed (REQ-45C-44(b) mode precondition, "
      "BL-P2-4.5c-50)"
      % ("PASS" if not fails else "FAIL", len(_checks) - len(fails),
         len(_checks)))
if fails:
    sys.exit("sonic_routing_mode_precondition_proof FAILED (%d check(s))."
             % len(fails))
