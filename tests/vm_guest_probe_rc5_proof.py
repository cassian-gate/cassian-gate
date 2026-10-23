#!/usr/bin/env python3
"""VM guest-probe rc=5 transient proof (BL-P2-4.5c-32; founder rulings R1 and D-i, 2026-09-24).

The vrnetlab launcher sets the guest password over the serial console at every
boot, so the guest's sshd can answer before the credentials exist and a probe
can return sshpass rc=5 immediately before the first success. Under D-i,
``classify_guest_probe_rc`` treats rc=5 as transient (returns None) and the
readiness loop keeps polling. If the LAST result observed at the existing
guest-ready deadline is rc=5, ``guest_probe_deadline_error`` returns the
existing auth-failure message, byte-identical, including
``_VM_CRED_PROVENANCE``.

The loop under test is the SHIPPED
``cassian_runtime_container.verify_sonic_vm_ready``, driven with a faked
transport and a faked clock. Nothing in src/ is replaced except by the
non-vacuity mutant below, which is restored and re-checked.

Proof obligations (session-6 rulings note §2):
  P-RC5-READY     transport 255, then 5, then 0 reaches ready, in exactly
                  three probes.
  P-RC5-DEADLINE  a transport answering 5 until the deadline ends on the
                  auth-failure text, byte-identical to the pre-change text
                  (frozen below from 470d834), and not before the deadline.
  P-RC5-CLASS     classes keyed on the last result are preserved: rc=6 still
                  fails on the first probe with its unchanged text; a last
                  result of 255 at the deadline is class (a) and of 1 is class
                  (c), both byte-identical to their pre-change text; rc=5 then
                  255 up to the deadline is (a), not (b).
  P-RC5-NV        non-vacuity: with the pre-D-i classifier (rc=5 fatal)
                  restored, P-RC5-READY's scenario dies on probe 2, so the
                  harness detects it; the shipped classifier is restored and
                  re-checked afterwards.
  The ``_ec_b`` construct of vm_runtime_validate_rejection_proof.py asserts
  D-i at the function level; this file asserts it through the loop.

Coverage limits, stated in-file (PBE-P2-8):
  - Lab-free. No guest is contacted; the transport and the clock are fakes.
    Whether a real boot's rc=5 falls inside the readiness window is
    OBSERVATIONAL only: CI cannot place a probe in the boot window on demand
    (session-6 rulings note §2, UNCOVERED in advance).
  - Leg 1 (the substrate/QEMU wait) is satisfied trivially by the fake and is
    not under test here.
  - The trade-off D-i accepts is recorded, not asserted away: genuinely wrong
    credentials are reported at the existing deadline, not at the first rc=5.

Exit 0 on all-pass; exit 1 on any failure.
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, _SRC)

import cassian_common as C  # noqa: E402
import cassian_runtime_container as RC  # noqa: E402
import cassian_runtime_vm as V  # noqa: E402

checks = []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


# Pre-change texts, frozen from the tree at 470d834 (node "s1", deadline 300 s).
PRE_AUTH_FAIL = 's1: VM guest not reachable over SSH: authentication failed (sshpass rc=5). The launcher sets the guest password at every boot over the serial console (default: admin). Valid: an image built via contrib/sonic-image-build/ (launcher defaults), or an image whose launcher credentials match the built-in constants (ghcr.io/cassian-gate/sonic-vm:202405 does). See docs/vm-runtime-capabilities.md.'
PRE_HOST_KEY = 's1: VM guest not reachable over SSH: host key unknown (sshpass rc=6). This cannot occur under the pinned transport options (StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null), so the transport is misconfigured. Valid: an unmodified vm-runtime transport. See docs/vm-runtime-capabilities.md.'
PRE_UNREACHABLE = "s1: VM guest not reachable over SSH: connection failed (ssh rc=255) for 300s. The wrapper is running and QEMU is up, but nothing is answering on the guest's forwarded SSH port (port 22 on the node's management address, host-forwarded by qemu). Valid: a booted guest whose SSH service is listening. See docs/vm-runtime-capabilities.md."
PRE_TIMEOUT_RC1 = 's1: VM guest not ready within 300s: the SSH transport answered but the guest did not return rc=0 to a trivial command (last rc=1). Valid: a booted guest that executes commands. See docs/vm-runtime-capabilities.md.'


class _CP:
    def __init__(self, rc):
        self.returncode = rc
        self.stdout = ""
        self.stderr = ""


class _FakeRuntime:
    """Leg 1 sees a running wrapper with QEMU; leg 2 replays `seq`, repeating
    its last element once exhausted."""

    def __init__(self, seq):
        self.seq = list(seq)
        self.probes = 0

    def is_running(self, lab, node):
        return True

    def substrate_exec(self, lab, node, argv, check=False, capture_output=False):
        return _CP(0)

    def exec(self, lab, node, argv, check=False, capture_output=True):
        i = min(self.probes, len(self.seq) - 1)
        self.probes += 1
        return _CP(self.seq[i])


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s


def drive(seq):
    """Run the shipped loop; return (outcome, message, probes, elapsed)."""
    rt = _FakeRuntime(seq)
    clock = _FakeClock()
    start = clock.now
    saved_time, saved_quiet = RC.time, C._QUIET_DIE
    RC.time = clock  # the loop reads time.time() / time.sleep() through this name
    C._QUIET_DIE = True  # die() raises SystemExit(<message>) instead of printing
    try:
        RC.verify_sonic_vm_ready(rt, "lab", "s1")
        return ("ready", None, rt.probes, clock.now - start)
    except SystemExit as e:
        return ("died", str(e.code), rt.probes, clock.now - start)
    finally:
        RC.time, C._QUIET_DIE = saved_time, saved_quiet


T = V.VM_GUEST_READY_TIMEOUT_S

# ---------------------------------------------------------------- P-RC5-READY
o, m, n, el = drive([255, 5, 0])
check("P-RC5-READY 255, 5, 0 reaches ready", o == "ready", m or "")
check("P-RC5-READY exactly three probes", n == 3, "probes=%d" % n)

# ---------------------------------------------------------------- P-RC5-DEADLINE
o, m, n, el = drive([5])
check("P-RC5-DEADLINE rc=5 until the deadline exits", o == "died")
check("P-RC5-DEADLINE text is the pre-change auth-failure text, byte-identical", m == PRE_AUTH_FAIL)
check("P-RC5-DEADLINE not before the deadline", el >= T, "elapsed=%.0fs deadline=%.0fs" % (el, T))
check("P-RC5-DEADLINE polled more than once", n > 1, "probes=%d" % n)
check("P-RC5-DEADLINE classifier returns None for rc=5",
      V.classify_guest_probe_rc("s1", V.VM_SSHPASS_RC_AUTH_FAIL) is None)
check("P-RC5-DEADLINE (b) text carries no deadline value",
      V.guest_probe_deadline_error("s1", V.VM_SSHPASS_RC_AUTH_FAIL, 60) == PRE_AUTH_FAIL)

# ---------------------------------------------------------------- P-RC5-CLASS
o, m, n, el = drive([6])
check("P-RC5-CLASS rc=6 still fails on the first probe", o == "died" and n == 1, "probes=%d" % n)
check("P-RC5-CLASS rc=6 text unchanged", m == PRE_HOST_KEY)
o, m, n, el = drive([255])
check("P-RC5-CLASS last result 255 at the deadline is (a), text unchanged", o == "died" and m == PRE_UNREACHABLE)
o, m, n, el = drive([1])
check("P-RC5-CLASS last result 1 at the deadline is (c), text unchanged", o == "died" and m == PRE_TIMEOUT_RC1)
o, m, n, el = drive([5, 255])
check("P-RC5-CLASS rc=5 then 255 to the deadline is (a), not (b)", o == "died" and m == PRE_UNREACHABLE)

# ---------------------------------------------------------------- P-RC5-NV
_shipped = V.classify_guest_probe_rc


def _pre_d_i(node, rc):
    if rc == V.VM_SSHPASS_RC_AUTH_FAIL:
        return PRE_AUTH_FAIL.replace("s1: ", node + ": ", 1)
    return _shipped(node, rc)


V.classify_guest_probe_rc = _pre_d_i
try:
    o_nv, m_nv, n_nv, _ = drive([255, 5, 0])
finally:
    V.classify_guest_probe_rc = _shipped
check("P-RC5-NV harness detects rc=5-fatal (the ready scenario dies on probe 2)",
      o_nv == "died" and n_nv == 2 and m_nv == PRE_AUTH_FAIL, "outcome=%s probes=%d" % (o_nv, n_nv))
o, m, n, el = drive([255, 5, 0])
check("P-RC5-NV shipped classifier restored after mutation",
      o == "ready" and V.classify_guest_probe_rc is _shipped)

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
