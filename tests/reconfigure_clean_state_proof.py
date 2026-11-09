#!/usr/bin/env python3
"""tests/reconfigure_clean_state_proof.py -- 4.5-c: --reconfigure destroys unconditionally.

Doctrine surface: 1.9 Clean-State Gate Doctrine ("Authoritative gate execution is
clean-state ... destroy or disregard prior execution state as required to preserve
gate authority ... not optional, advisory, or best-effort") and 1.4 Deterministic
Execution Doctrine, whose non-reliance list names "silent conditional behavior".

Founder ruling 2026-08-18. The destroy under `--reconfigure` was gated on
`LABS_DIR/<lab>.clab.yaml` existing. That file is WORKSPACE state; the containers
it must remove are DAEMON state. CI wipes `labs/` every run (.gitignore + the
actions/checkout default `clean: true`), so the gate skipped teardown and the
deploy met containers a previous run had left running -- observed in CI run
32042686577 attempt 1, where the whole step ran in 140 ms with no destroy between
VALIDATE PASS and "containers [...] already exist".

The authoritative gate reaches this code: `cassian_engine.py` calls
`cmd_up(Namespace(..., reconfigure=True, _from_gate=True))`.

Snapshot mapping (handover 6.7.2 mapping discipline): consumes `cassian_engine`
-> `src/cassian_engine.py`. Session snapshot v48 == branch
`feature/4_5c-sonic-base-lifecycle`.

COVERAGE LIMITS (PBE-P2-8), stated rather than implied:
  * Lab-free. `_run_containerlab` and `run` are replaced by recorders, so this
    proves WHICH commands cmd_up issues and in WHAT ORDER. It does not prove
    containerlab's own behaviour when asked to destroy an absent lab -- that
    needs a host and is OPEN here. `check=False` is preserved on the destroy, so
    a non-zero exit remains tolerated by design.
  * Asserts the destroy is ISSUED before the deploy. It does not assert the
    daemon reached a clean state, which is not observable without a runtime.
  * Exercises the FRR path. A vm-runtime topology would additionally trip the
    image-presence gate, which is REQ-45C-31's surface, not this one.
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_engine as E  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


TOPO = """name: reconfigure-clean-state-probe

nodes:
  - name: r1
    type: frr
    router_id: 192.0.2.31
  - name: r2
    type: frr
    router_id: 192.0.2.32

links:
  - endpoints: ["r1:eth1", "r2:eth1"]
    ipv4: ["198.51.100.4/31", "198.51.100.5/31"]
"""


class _Stop(Exception):
    """Sentinel: halt cmd_up at the deploy so nothing past it runs."""


class _CP:
    returncode = 0
    stdout = b""
    stderr = b""


def _drive(clab_present: bool):
    """Run cmd_up(--reconfigure) with recorders in place. Returns the call log."""
    calls = []

    def rec_containerlab(argv, check=True, **kw):
        calls.append(list(argv))
        if "deploy" in argv:
            raise _Stop()
        return _CP()

    def rec_run(argv, check=True, **kw):
        calls.append(list(argv))
        return _CP()

    orig_cl, orig_run, orig_labs = E._run_containerlab, E.run, E.LABS_DIR
    tmp = tempfile.mkdtemp(prefix="cassian-reconfig-probe-")
    try:
        topo_path = os.path.join(tmp, "probe.yaml")
        io.open(topo_path, "w", encoding="utf-8").write(TOPO)

        from pathlib import Path
        labs = Path(tmp) / "labs"
        labs.mkdir(parents=True, exist_ok=True)
        E.LABS_DIR = labs
        import cassian_artifacts as A
        orig_a_labs = A.LABS_DIR
        A.LABS_DIR = labs
        import cassian_runtime_container as RC
        orig_rc_labs = RC.LABS_DIR
        RC.LABS_DIR = labs

        if clab_present:
            (labs / "reconfigure-clean-state-probe.clab.yaml").write_text(
                "name: reconfigure-clean-state-probe\n", encoding="utf-8")

        import cassian_common as CC
        orig_quiet = CC.QUIET_RUN
        CC.QUIET_RUN = True  # suppress the "Wrote:" path lines; this is a probe

        E._run_containerlab, E.run = rec_containerlab, rec_run
        import argparse
        try:
            E.cmd_up(argparse.Namespace(topology=topo_path, reconfigure=True,
                                        _from_gate=False))
        except _Stop:
            pass
        finally:
            A.LABS_DIR, RC.LABS_DIR = orig_a_labs, orig_rc_labs
            CC.QUIET_RUN = orig_quiet
    finally:
        E._run_containerlab, E.run, E.LABS_DIR = orig_cl, orig_run, orig_labs
    return calls


def _verbs(calls):
    return [c[2] if len(c) > 2 and c[1] == "containerlab" else c[1]
            for c in calls if len(c) > 1]


# --- LEG 1: the file is ABSENT -- the case CI always hits --------------------
absent = _drive(clab_present=False)
v_absent = _verbs(absent)
check("1.9 destroy is ISSUED when the .clab.yaml is absent",
      "destroy" in v_absent, "verbs: %s" % v_absent)
check("1.9 destroy precedes deploy",
      "destroy" in v_absent and "deploy" in v_absent
      and v_absent.index("destroy") < v_absent.index("deploy"),
      "order: %s" % v_absent)
check("1.4 no silent conditional: reconfigure always tears down",
      v_absent.count("destroy") == 1,
      "exactly one destroy issued, not zero and not repeated")

# --- LEG 2: the file is PRESENT -- the pre-existing behaviour is preserved ---
present = _drive(clab_present=True)
v_present = _verbs(present)
check("regression: destroy still issued when the .clab.yaml is present",
      "destroy" in v_present, "verbs: %s" % v_present)
check("regression: both paths issue the same command sequence",
      v_absent == v_present,
      "absent=%s present=%s" % (v_absent, v_present))

# --- LEG 3: the cleanup rm is still issued, and still after the destroy ------
rm_calls = [c for c in absent if len(c) > 1 and c[1] == "rm"]
check("cleanup rm -rf is still issued", len(rm_calls) == 1,
      "%d rm call(s)" % len(rm_calls))
check("rm -rf follows the destroy (artifact ordering preserved)",
      "destroy" in v_absent and "rm" in v_absent
      and v_absent.index("destroy") < v_absent.index("rm"),
      "order: %s" % v_absent)

# --- LEG 4 NON-VACUITY: the recorder observes the real code path -------------
check("NON-VACUITY: the recorder captured a deploy attempt",
      "deploy" in v_absent,
      "proves cmd_up ran through to the deploy, so the absence of a destroy "
      "would have been visible")
check("NON-VACUITY: every recorded call is sudo-prefixed as shipped",
      all(c and c[0] == "sudo" for c in absent),
      "recorded: %d call(s)" % len(absent))

# --- Report ------------------------------------------------------------------
_fails = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%s %s%s" % ("PASS" if _ok else "FAIL", _n, ("  [%s]" % _d) if _d else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (--reconfigure clean-state, Doctrine 1.9/1.4)"
      % ("PASS" if not _fails else "FAIL", len(_checks)))
if _fails:
    sys.exit("reconfigure_clean_state_proof FAILED (%d check(s))." % len(_fails))
