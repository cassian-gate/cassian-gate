from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

from cassian_common import die
from cassian_runtime_container import ContainerRuntime, Runtime

# LD-45a-2 (RULED 2026-07-16), AMENDED (SP #1 inline, founder-ruled 2026-07-17):
# vrnetlab-image credentials, carried as module constants. NOT a topology/schema key
# (REQ-45a-P6; DC v2.1 §10 -- the runtime axis must not add model surface).
#
# The LD sourced these from the launcher's CONSTANTS (--username default, PASSWORD
# constant) -- read, not run. Runtime evidence falsifies the password: launch.py
# OVERWRITES it over the serial console at every boot ('passwd -q admin' -> 'admin',
# observed on ghcr.io/cassian-gate/sonic-vm:202405 across two labs; the guest logs
# 'BAD PASSWORD: shorter than 8 characters' and accepts it). Confirmed by a green
# login returning 'SONiC Software Version: SONiC.202405.1033627-fecd4ec81'.
VM_SSH_USERNAME = "admin"
VM_SSH_PASSWORD = "admin"

# D02/D05: pinned transport timings; explicit constants, no wall-clock content.
VM_SSH_CONNECT_TIMEOUT_S = 10

# D04: locale pin on every remote command so guest output shape is deterministic.
_VM_LOCALE_PIN = "LC_ALL=C "


def _vm_ssh_argv(host: str, remote_cmd: str) -> list[str]:
    """
    B02: the wrapper-chain transport, composed exactly.

    Run INSIDE the vrnetlab wrapper (via ContainerRuntime.exec), sshpass+ssh to the
    node's management address -- the wrapper's own clab name, i.e. rt.node_id() --
    which qemu host-forwards to the guest NOS (d9850b4 R-O2: only TCP 22 is
    hostfwd'd; the listener is 0.0.0.0:22 inside the wrapper).

    AMENDED (SP #1 inline, founder-ruled 2026-07-17): B02/§5 specified
    'admin@localhost'. Runtime evidence: from inside the wrapper, localhost:22 times
    out during banner exchange, while admin@clab-<lab>-<node> returns rc=0 and real
    SONiC output -- same guest, same qemu listener, only the source address differs.
    §5's claim that the ruled route was the "same route as the shipped up-path hint"
    is now true rather than aspirational: the hint is engine:1395,
    f"  ssh admin@{rt.node_id(lab_name, _vm_node)}" -- this is that route.

    D03: UserKnownHostsFile=/dev/null + StrictHostKeyChecking=no -- zero persisted
    state accrues in the wrapper across runs.
    """
    return [
        "sshpass",
        "-p",
        VM_SSH_PASSWORD,
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=" + str(VM_SSH_CONNECT_TIMEOUT_S),
        VM_SSH_USERNAME + "@" + host,
        remote_cmd,
    ]


# --- guest-probe rc classification (B07; §13-grade) -----------------------
# sshpass(1) exit codes: 5 = invalid/incorrect password; 6 = host public key
# unknown. ssh returns 255 on connection failure (refused / timed out /
# unreachable); sshpass passes ssh's status through unchanged.
VM_SSHPASS_RC_AUTH_FAIL = 5
VM_SSHPASS_RC_HOST_KEY = 6
VM_SSH_RC_CONNECT_FAIL = 255

# D01/D05: guest boot variance is absorbed entirely by this deadline. Explicit
# pinned constants; no wall-clock content reaches output.
# LD-R3 (ruled 2026-07-18): 300 is an implementation ESTIMATE, never validated
# against a CI cold start (pull + boot + poll); launch.py reports ~25s local
# boot. Kept per the ruling; first CI cold-start timing cited at §4.5-a closure.
VM_GUEST_READY_TIMEOUT_S = 300
VM_GUEST_READY_INTERVAL_S = 5.0

# LD-45a-2 (as amended): the auth-fail leg names the credentials' real provenance --
# the launcher's boot-time bootstrap, not a build-time property of the image.
_VM_CRED_PROVENANCE = (
    "The launcher sets the guest password at every boot over the serial "
    "console (default: admin). Valid: an image built via "
    "contrib/sonic-image-build/ (launcher defaults), or an image whose "
    "launcher credentials match the built-in constants "
    "(ghcr.io/cassian-gate/sonic-vm:202405 does). "
    "See docs/vm-runtime-capabilities.md."
)


def classify_guest_probe_rc(node: str, rc: int) -> str | None:
    """
    B07: map a guest-probe transport result to a §13-grade fatal error, or return
    None when the result is transient and the caller should keep polling.

    Fatal immediately:
      (b) auth-fail -- sshpass rc=5. Polling cannot cure wrong credentials, and
                       waiting out the deadline would misreport the class as (c).
      (a)-class     -- sshpass rc=6 (host key). Should not occur under the pinned
                       ssh options; mapped defensively with a transport note.
    Transient (None):
      ssh rc=255 (connect failure) and any other rc -- the guest may still be
      booting; the deadline owns the final classification.
    """
    if rc == VM_SSHPASS_RC_AUTH_FAIL:
        return (
            f"{node}: VM guest not reachable over SSH: authentication failed "
            f"(sshpass rc=5). {_VM_CRED_PROVENANCE}"
        )
    if rc == VM_SSHPASS_RC_HOST_KEY:
        return (
            f"{node}: VM guest not reachable over SSH: host key unknown "
            f"(sshpass rc=6). This cannot occur under the pinned transport options "
            f"(StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null), so the "
            f"transport is misconfigured. Valid: an unmodified vm-runtime "
            f"transport. See docs/vm-runtime-capabilities.md."
        )
    return None


def guest_probe_deadline_error(node: str, rc: int | None, timeout_s: float) -> str:
    """
    B07 deadline classification:
      (a) unreachable -- the last observed result was a connect failure (rc=255):
                         nothing is answering on the guest's forwarded SSH port.
      (c) timeout     -- the transport answered but the guest never returned rc=0.
    """
    if rc == VM_SSH_RC_CONNECT_FAIL:
        return (
            f"{node}: VM guest not reachable over SSH: connection failed "
            f"(ssh rc=255) for {timeout_s:.0f}s. The wrapper is running and QEMU is "
            f"up, but nothing is answering on the guest's forwarded SSH port "
            f"(port 22 on the node's management address, host-forwarded by qemu). "
            f"Valid: a booted guest whose SSH service is listening. "
            f"See docs/vm-runtime-capabilities.md."
        )
    return (
        f"{node}: VM guest not ready within {timeout_s:.0f}s: the SSH transport "
        f"answered but the guest did not return rc=0 to a trivial command "
        f"(last rc={rc}). Valid: a booted guest that executes commands. "
        f"See docs/vm-runtime-capabilities.md."
    )


class VmRuntime(Runtime):
    """
    Execution backend for vm-runtime nodes (REQ-45a-1a/-1b).

    DC v2.1 §10 / cassian_model.py:881 -- this changes WHERE commands execute, never
    what the model authorizes, validates, or renders.

    exec/sh reach the GUEST over the wrapper-chain transport. Every lifecycle surface
    delegates to the wrapped ContainerRuntime, i.e. it describes the WRAPPER (Pin B,
    B04) -- unchanged wrapper-level semantics.
    """

    def __init__(self, wrapped: ContainerRuntime | None = None) -> None:
        self._wrapped = wrapped if wrapped is not None else ContainerRuntime()

    # --- transport (guest) -------------------------------------------------

    def exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        # B03: the remote command is a single ssh argument, quoting preserved via
        # shlex (no shell-injection-prone interpolation), locale-pinned (D04).
        remote_cmd = _VM_LOCALE_PIN + shlex.join(cmd)
        # B02: interactive=False ALWAYS -- the chain never opens a tty.
        # D08: the wrapped ContainerRuntime.exec is reused literally, so the
        # subprocess.CompletedProcess contract is identical and the guest's
        # rc/stdout/stderr pass through unrewritten (REQ-45a-1a).
        return self._wrapped.exec(
            lab,
            node,
            _vm_ssh_argv(self._wrapped.node_id(lab, node), remote_cmd),
            check=check,
            capture_output=capture_output,
            interactive=False,
            timeout_s=timeout_s,
        )

    # --- lifecycle (wrapper; delegated -- Pin B / B04) ----------------------

    def node_id(self, lab: str, node: str) -> str:
        return self._wrapped.node_id(lab, node)

    def is_running(self, lab: str, node: str) -> bool:
        return self._wrapped.is_running(lab, node)

    def is_running_id(self, node_id: str) -> bool:
        return self._wrapped.is_running_id(node_id)

    def exists_id(self, node_id: str) -> bool:
        return self._wrapped.exists_id(node_id)

    def restart_node(self, lab: str, node: str) -> subprocess.CompletedProcess:
        return self._wrapped.restart_node(lab, node)

    def container_id(self, lab: str, node: str) -> str:
        return self._wrapped.container_id(lab, node)

    # --- substrate (wrapper; explicit name -- addendum 1744bbb §3.5) --------

    def substrate_exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        # The substrate is the vrnetlab launcher container the wrapped
        # ContainerRuntime already reaches -- exactly what the readiness
        # bypass hand-built before the seam existed (REQ-45a-4a).
        return self._wrapped.exec(
            lab,
            node,
            cmd,
            check=check,
            capture_output=capture_output,
            interactive=interactive,
            timeout_s=timeout_s,
        )

    def substrate_copy_from(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        # Substrate-side files (e.g. the pcap tcpdump wrote in the wrapper's
        # netns): the launcher IS the right entity -- delegate to the wrapped
        # ContainerRuntime (REQ-45a-8; pcap retrieval restored).
        return self._wrapped.copy_from_node(lab, node, src_path, dst_path, check=check)

    # --- explicit-unsupported (deny-by-default -- REQ-45a-8 / B10) ---------

    def copy_to_node(self, lab: str, node: str, src: Path, dst: str) -> subprocess.CompletedProcess:
        _die_copy_unsupported("copy_to_node", node)
        raise RuntimeError("unreachable")

    def copy_from_node(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        _die_copy_unsupported("copy_from_node", node)
        raise RuntimeError("unreachable")


def _die_copy_unsupported(op: str, node: str) -> None:
    """
    REQ-45a-8 / B10: §13-grade explicit-UNSUP. Names the operation, the node, the
    valid surface, and the deferral home. Shape mirrors the shipped exec-into gate
    message (offending value -> "Valid:" clause -> DC §10 citation).
    """
    die(
        "runtime." + op + ": node " + repr(node) + " has resolved runtime 'vm'; "
        "copying files to or from the guest NOS of a vm-runtime node is NOT "
        "SUPPORTED in this release. Bare copy_* means the NOS (addendum §4.1), "
        "and guest file transfer is not built. Valid: give the operation a node "
        "whose resolved runtime is 'container'; for substrate-side files (the "
        "vrnetlab launcher container, e.g. pcaps) use substrate_copy_from. "
        "Guest file transfer for vm-runtime nodes is deferred to Phase 2 §4.5-f "
        "(DC v2.1 §10, 'Model vs runtime backend')."
    )


class NodeDispatchingRuntime(Runtime):
    """
    Per-node dispatch facade (REQ-45a-2 / B01).

    Holds the node -> resolved-runtime map from the resolved topology. Container
    nodes pass through to ContainerRuntime untouched (REQ-45a-P1); vm nodes route
    to VmRuntime. Dispatch keys SOLELY on the resolved `runtime` value and never on
    node.type (D07; P4 Arista-clean).

    Lifecycle/identity surfaces are wrapper-level for BOTH classes (B04), so they
    delegate to ContainerRuntime unconditionally -- including the *_id surfaces,
    which carry no node name to dispatch on.
    """

    def __init__(self, node_runtimes: dict[str, str]) -> None:
        self._container = ContainerRuntime()
        self._vm = VmRuntime(self._container)
        self._node_runtimes = dict(node_runtimes)

    def _for(self, node: str) -> Runtime:
        if self._node_runtimes.get(node) == "vm":
            return self._vm
        return self._container

    def exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        return self._for(node).exec(
            lab,
            node,
            cmd,
            check=check,
            capture_output=capture_output,
            interactive=interactive,
            timeout_s=timeout_s,
        )

    def copy_to_node(self, lab: str, node: str, src: Path, dst: str) -> subprocess.CompletedProcess:
        return self._for(node).copy_to_node(lab, node, src, dst)

    def copy_from_node(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        return self._for(node).copy_from_node(lab, node, src_path, dst_path, check=check)

    def substrate_exec(
        self,
        lab: str,
        node: str,
        cmd: list[str],
        *,
        check: bool = False,
        capture_output: bool = True,
        interactive: bool = False,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess:
        return self._for(node).substrate_exec(
            lab,
            node,
            cmd,
            check=check,
            capture_output=capture_output,
            interactive=interactive,
            timeout_s=timeout_s,
        )

    def substrate_copy_from(
        self,
        lab: str,
        node: str,
        src_path: str,
        dst_path: str,
        *,
        check: bool = True,
    ):
        return self._for(node).substrate_copy_from(lab, node, src_path, dst_path, check=check)

    def node_id(self, lab: str, node: str) -> str:
        return self._container.node_id(lab, node)

    def is_running(self, lab: str, node: str) -> bool:
        return self._container.is_running(lab, node)

    def is_running_id(self, node_id: str) -> bool:
        return self._container.is_running_id(node_id)

    def exists_id(self, node_id: str) -> bool:
        return self._container.exists_id(node_id)

    def restart_node(self, lab: str, node: str) -> subprocess.CompletedProcess:
        return self._container.restart_node(lab, node)

    def container_id(self, lab: str, node: str) -> str:
        return self._container.container_id(lab, node)


def node_runtime_map(topo: dict[str, Any] | None) -> dict[str, str]:
    """
    Derive {node_name: resolved_runtime} from a resolved topology.

    Same shape as the model's exec-into gate derivation (cassian_model.py:2874-2878)
    and reads the same resolved field; no normalization helper is introduced and no
    model semantics are keyed on transport (PBE-1b-9 inert; DC v2.1 §10).
    """
    out: dict[str, str] = {}
    if not isinstance(topo, dict):
        return out
    for n in (topo.get("nodes") or []):
        if not isinstance(n, dict):
            continue
        name = str(n.get("name") or "").strip()
        if not name:
            continue
        out[name] = str(n.get("runtime") or "").strip().lower()
    return out


def build_runtime(topo: dict[str, Any] | None = None) -> Runtime:
    """
    B01: return the dispatching runtime iff any resolved node has runtime == "vm";
    otherwise ContainerRuntime (including topo=None) -- bare-call-site semantics
    preserved (REQ-45a-2).
    """
    node_runtimes = node_runtime_map(topo)
    if "vm" not in node_runtimes.values():
        return ContainerRuntime()
    return NodeDispatchingRuntime(node_runtimes)
