#!/usr/bin/env python3
"""BL-P2-4.5c-29 part (b) -- SONIC_PROVIDER.nos_ready and its guarded dispatch.

Lab-free. `nos_ready` is the NOS-readiness leg the ratified design assigns to
SONiC (design :228, :240) and which RG-45C-P7 / NG-9 require wired before
closure. It is SINGLE-SHOT by founder ruling (2026-08-20): transport is already
established by the runtime-layer gate part (a) added, and this provider's
import floor admits neither `time` nor `cassian_runtime_vm`
(sonic_leaf_import_proof P-SIMP-2).

RATCHET, not a gap-closing assertion (R-C3-16): measured across four cold boots
of local/sonic-vm:202405 (2026-08-20), CONFIG_DB answered at the FIRST
reachable sample every time. The leg exists to fail loudly if that ordering
ceases to hold.

COVERAGE LIMIT (PBE-P2-8): this proves (i) the predicate's pass/fail behaviour
against a fake runtime, (ii) that the engine dispatches it before `provision`,
and (iii) that a provider whose `nos_ready` is still deferred is SKIPPED rather
than invoked. It does NOT prove anything about a real guest, and it does NOT
prove that swss/syncd/bgp are serving -- measured, those arrive up to ~90s
after CONFIG_DB answers.

NOTE ON THE GUARD CONTROL (Finding 10): a control built on a real FRR or nft-fw
provider would be VACUOUS -- both have `provision` deferred, so the existing
skip at the top of the loop already excludes them before `nos_ready` is
reached. The guard is forward-looking, and only a provider with `provision`
WIRED and `nos_ready` DEFERRED exercises it. Leg (3) constructs exactly that.
"""
import ast
import io
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, _SRC)

import cassian_engine as E  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import NosProvider, deferred_leg  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _CP:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = "Debian GNU/Linux 12 \\n \\l\n"


class _FakeRuntime:
    """Replays one guest read. Records the argv so single-sourcing is provable."""

    def __init__(self, rc=0, out="Force10-S6000\n"):
        self.calls = []
        self._cp = _CP(rc, out)

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        return self._cp


# --- leg 1: the predicate ------------------------------------------------------

_rt_ok = _FakeRuntime(rc=0, out="Force10-S6000\n")
_raised = None
try:
    S.nos_ready(_rt_ok, "lab", "s1")
except SystemExit as exc:  # pragma: no cover - failure path
    _raised = exc
check("(1) ready guest: nos_ready returns without raising", _raised is None,
      "raised: %r" % (_raised,))
check("(1) it issues exactly one guest read", len(_rt_ok.calls) == 1,
      "calls: %r" % (_rt_ok.calls,))
check("(1) PBE-P2-6: the read is the single-sourced _HWSKU_ARGV",
      _rt_ok.calls == [list(S._HWSKU_ARGV)],
      "argv: %r" % (_rt_ok.calls,))
check("(1) probe_facts consumes the SAME source (no parallel literal)",
      "_HWSKU_ARGV" in io.open(os.path.join(_SRC, "cassian_nos_sonic.py"),
                               encoding="utf-8").read()
      .split("def probe_facts")[1][:400])

# --- leg 2: the ratchet (control seen to fail) --------------------------------
# Each of these MUST raise. If any stopped raising, the leg would be vacuous.

for _label, _rt_bad in (
    ("non-zero rc", _FakeRuntime(rc=1, out="")),
    ("rc 0 but empty stdout", _FakeRuntime(rc=0, out="")),
    ("rc 0 but whitespace-only stdout", _FakeRuntime(rc=0, out="   \n")),
):
    _code = None
    try:
        S.nos_ready(_rt_bad, "lab", "s1")
    except SystemExit as exc:
        _code = exc.code
    check("(2) RATCHET fails loud, exit 2 -- %s" % _label, _code == 2,
          "exit code: %r" % (_code,))

# --- leg 3: guarded dispatch, on a SYNTHETIC provider --------------------------

def _provider(node_type, nos_ready_leg, log):
    def _provision(rt, lab, node, node_d, topo):
        log.append("provision")
        return None

    return NosProvider(
        node_type=node_type,
        default_image=None,
        runtime_requirement=None,  # keeps part (a)'s vm gate out of this leg
        capabilities={},
        gen_node_config=deferred_leg("gen_node_config", "proof fake"),
        provision=_provision,
        nos_ready=nos_ready_leg,
        convergence_wait=deferred_leg("convergence_wait", "proof fake"),
        collect=deferred_leg("collect", "proof fake"),
        candidate=None,
        status_bgp_summary=None,
        status_routes=None,
        collect_targets=(),
        doctor_checks=deferred_leg("doctor_checks", "proof fake"),
        exec_command_rule=deferred_leg("exec_command_rule", "proof fake"),
        state_profiles={},
        state_argv_allow=deferred_leg("state_argv_allow", "proof fake"),
    )


def _dispatch(wire_nos_ready):
    """Both legs must append to the SAME log, or ordering cannot be observed."""
    log = []
    if wire_nos_ready:
        def _leg(rt, lab, node):
            log.append("nos_ready")
    else:
        _leg = deferred_leg("nos_ready", "proof fake -- deferred")
    node_type = "proof-fake-nos"
    real_registry = E.NOS_PROVIDERS
    try:
        E.NOS_PROVIDERS = {node_type: _provider(node_type, _leg, log)}
        E._provision_nos_providers(
            _FakeRuntime(), "proof-lab",
            {"nodes": [{"name": "n1", "type": node_type}]})
    finally:
        E.NOS_PROVIDERS = real_registry
    return log


_log_wired = _dispatch(True)
check("(3) a WIRED nos_ready is dispatched before provision",
      _log_wired == ["nos_ready", "provision"],
      "dispatch log: %r" % (_log_wired,))

_log_deferred = _dispatch(False)
check("(3) NON-VACUITY: a DEFERRED nos_ready is SKIPPED, not invoked "
      "(deferred_leg would SystemExit(2) if reached)",
      _log_deferred == ["provision"],
      "dispatch log: %r" % (_log_deferred,))

check("(3) the two legs differ, so the marker guard is load-bearing",
      _log_wired != _log_deferred,
      "wired=%r deferred=%r" % (_log_wired, _log_deferred))

# --- leg 4: the binding is real, not a placeholder -----------------------------

check("(4) SONIC_PROVIDER.nos_ready is wired, not deferred",
      getattr(S.SONIC_PROVIDER.nos_ready, "cassian_deferred_leg", None) is None,
      "marker: %r" % (getattr(S.SONIC_PROVIDER.nos_ready,
                              "cassian_deferred_leg", None),))
check("(4) it is the module's own nos_ready",
      S.SONIC_PROVIDER.nos_ready is S.nos_ready)

_engine_src = io.open(os.path.join(_SRC, "cassian_engine.py"),
                      encoding="utf-8").read()
_fn = next((n for n in ast.walk(ast.parse(_engine_src))
            if isinstance(n, ast.FunctionDef)
            and n.name == "_provision_nos_providers"), None)
_nr = _pv = None
if _fn is not None:
    for _n in ast.walk(_fn):
        if isinstance(_n, ast.Call):
            _f = _n.func
            _nm = _f.attr if isinstance(_f, ast.Attribute) else (
                _f.id if isinstance(_f, ast.Name) else None)
            if _nm == "nos_ready" and _nr is None:
                _nr = _n.lineno
            if _nm == "provision" and _pv is None:
                _pv = _n.lineno
check("(4) nos_ready dispatch precedes provision in source order",
      _nr is not None and _pv is not None and _nr < _pv,
      "nos_ready at :%s, provision at :%s" % (_nr, _pv))

# --- report -------------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n,
                         ("  [%s]" % _d) if _d else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d check(s) (BL-P2-4.5c-29 part (b) nos_ready)"
          % len(_failed))
    sys.exit(1)
print("RESULT: PASS -- %d checks (BL-P2-4.5c-29 part (b) nos_ready)"
      % len(_checks))
