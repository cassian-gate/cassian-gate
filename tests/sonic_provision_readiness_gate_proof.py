#!/usr/bin/env python3
"""BL-P2-4.5c-29 part (a) -- VM-runtime reachability gate before `provision`.

Lab-free. `cmd_up` reaches `_provision_nos_providers` with no node-readiness
gate anywhere on its path (`verify_lab_ready` has a single call site, in
`cmd_test`), so `provision` dispatched into a SONiC guest whose SSH transport
was not yet up and `probe_facts` received rc 255. The gate added here runs
`verify_sonic_vm_ready` for provider nodes declaring `runtime_requirement ==
"vm"` before their `provision` leg is called.

AUTHORITY LEG: behavioural. Doctrine 1.7 -- validation authority is
behaviour-driven, not configuration-driven. A structural check would pass on a
gate that is written but never reached, which is the exact defect class this
packet repairs (RG-45C-P7 retired the earlier negative-grep form for the same
reason: it "would have passed vacuously while testing nothing about the
boundary").

COVERAGE LIMIT (PBE-P2-8): this proves dispatch ORDERING INSIDE
`_provision_nos_providers` -- that a vm-runtime provider node is gated on
reachability before `provision`, and that a non-vm provider node is not. It
does NOT prove that `cmd_up` reaches `_provision_nos_providers`, and it does
NOT prove that any other lifecycle phase is gated. `cmd_up` still has no
reachability gate for host, nft-fw or frr nodes; `verify_lab_ready` cannot
serve as one because `verify_host_ready` and `verify_frr_ready` require
provisioning `cmd_up` has not yet performed. That residual is a routed backlog
row, not a claim of this proof.
"""
import ast
import io
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, _SRC)

import cassian_engine as E  # noqa: E402
from cassian_nos_types import NosProvider, deferred_leg  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


# --- harness -----------------------------------------------------------------

class _FakeRuntime:
    """Inert. The gate and the provision leg are what record; rt is a token."""


def _make_provider(node_type, runtime_requirement, log):
    """A provider whose `provision` is WIRED (so the LD-H2 deferred-leg skip in
    `_provision_nos_providers` does not short-circuit before the gate) and which
    records its own dispatch."""

    def _provision(rt, lab, node, node_d, topo):
        log.append("provision")
        return None  # nothing applied -> core's artifact write is skipped

    return NosProvider(
        node_type=node_type,
        default_image=None,
        runtime_requirement=runtime_requirement,
        capabilities={},
        gen_node_config=deferred_leg("gen_node_config", "proof fake"),
        provision=_provision,
        nos_ready=deferred_leg("nos_ready", "proof fake"),
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


def _run(runtime_requirement):
    """Run the real `_provision_nos_providers` against one fake provider node.

    Returns the ordered dispatch log. `verify_sonic_vm_ready` is replaced for
    the duration so the gate records instead of reaching a runtime; the engine
    module state is restored in `finally` (house pattern, cf.
    h54_doctor_ip_j_probe_proof).
    """
    log = []
    node_type = "proof-fake-nos"
    provider = _make_provider(node_type, runtime_requirement, log)

    real_verify = E.verify_sonic_vm_ready
    real_registry = E.NOS_PROVIDERS

    def _fake_verify(rt, lab, node):
        log.append("ready")

    try:
        E.verify_sonic_vm_ready = _fake_verify
        E.NOS_PROVIDERS = {node_type: provider}
        topo = {"nodes": [{"name": "n1", "type": node_type}]}
        E._provision_nos_providers(_FakeRuntime(), "proof-lab", topo)
    finally:
        E.verify_sonic_vm_ready = real_verify
        E.NOS_PROVIDERS = real_registry

    return log


# --- leg 1: behavioural authority --------------------------------------------

_vm_log = _run("vm")
check(
    "(1) vm-runtime provider node is gated on reachability BEFORE provision",
    _vm_log == ["ready", "provision"],
    "dispatch log: %r" % (_vm_log,),
)

# --- leg 2: behavioural non-vacuity (the control) ----------------------------
# If the gate were unconditional, this would read ["ready", "provision"] too.
# Deleting the gate statement from the engine makes leg 1 read ["provision"].

_non_vm_log = _run(None)
check(
    "(2) NON-VACUITY: non-vm provider node is NOT gated (gate is conditional)",
    _non_vm_log == ["provision"],
    "dispatch log: %r" % (_non_vm_log,),
)

check(
    "(2) NON-VACUITY: the two legs differ, so the gate is load-bearing",
    _vm_log != _non_vm_log,
    "vm=%r non-vm=%r" % (_vm_log, _non_vm_log),
)

# --- leg 3: AST diagnostic ----------------------------------------------------
# Names the line on regression, where leg 1 reports only the symptom.

_engine_src = io.open(os.path.join(_SRC, "cassian_engine.py"),
                      encoding="utf-8").read()
_fn = next(
    (n for n in ast.walk(ast.parse(_engine_src))
     if isinstance(n, ast.FunctionDef) and n.name == "_provision_nos_providers"),
    None,
)
check("(3) _provision_nos_providers is present in the engine", _fn is not None)

_gate_line = None
_prov_line = None
if _fn is not None:
    for _n in ast.walk(_fn):
        if isinstance(_n, ast.Call):
            _f = _n.func
            _nm = _f.id if isinstance(_f, ast.Name) else (
                _f.attr if isinstance(_f, ast.Attribute) else None)
            if _nm == "verify_sonic_vm_ready" and _gate_line is None:
                _gate_line = _n.lineno
            if _nm == "provision" and _prov_line is None:
                _prov_line = _n.lineno

check(
    "(3) gate call precedes the provision dispatch in source order",
    _gate_line is not None and _prov_line is not None
    and _gate_line < _prov_line,
    "gate at :%s, provision at :%s" % (_gate_line, _prov_line),
)

check(
    "(3) engine imports verify_sonic_vm_ready from the runtime layer",
    "verify_sonic_vm_ready" in _engine_src.split("\n")[95],
    "importer line :96",
)

# --- report -------------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n,
                         ("  [%s]" % _d) if _d else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d check(s) (BL-P2-4.5c-29 part (a) readiness gate)"
          % len(_failed))
    sys.exit(1)
print("RESULT: PASS -- %d checks (BL-P2-4.5c-29 part (a) readiness gate)"
      % len(_checks))
