"""NOS provider types leaf (Phase 2 §4.5-b, REQ-45b-2; LD-45b-2).

Shared provider-contract types for the NOS provider structure (NOS-expansion
structure design §3.3/§3.4). This leaf is the bottom of the ruled acyclic
import order (design §3.2: model -> provider -> common/leaf):

  - Runtime import floor: STDLIB ONLY (LD-45b-2). `cassian_common` may be
    admitted only if a concrete shared value is needed -- none is (the leaf
    carries types and the deferred-leg mechanics, no values).
  - `Runtime` and `Path` appear in annotations only, imported under
    TYPE_CHECKING with `from __future__ import annotations` -- there is NO
    runtime import of `cassian_runtime_container` (REQ-45b-2 floor).

Authority split (design §5): providers own NOS content; core owns invariants,
predicate evaluation, verdicts, rendering, and artifacts. Nothing defined here
carries verdict authority -- an `Observation` is evidence-bearing input to
core predicate evaluation, never a pass/fail decision.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:  # annotation-only imports (REQ-45b-2: no runtime import)
    from pathlib import Path

    from cassian_runtime_container import Runtime


# -------------------------
# Capability disposition (design §3.4 -- deny-by-default)
# -------------------------

CAP_IMPL = "IMPL"
CAP_VERIFY = "VERIFY"
CAP_UNSUP = "UNSUP"


@dataclass(frozen=True)
class CapabilityDisposition:
    """One capability token's disposition: IMPL, VERIFY, or UNSUP(message).

    Deny-by-default (Doctrine 4.1 / DC §2): an absent token is UNSUP with a
    generated message -- nothing is implicitly supported. Enforced, not
    documentary: dispatch sites check the declaration before dispatching.
    """

    state: str  # CAP_IMPL | CAP_VERIFY | CAP_UNSUP
    message: str | None = None


def impl() -> CapabilityDisposition:
    return CapabilityDisposition(CAP_IMPL)


def verify() -> CapabilityDisposition:
    return CapabilityDisposition(CAP_VERIFY)


def unsup(message: str) -> CapabilityDisposition:
    return CapabilityDisposition(CAP_UNSUP, message)


def capability_for(provider: "NosProvider", token: str) -> CapabilityDisposition:
    """Deny-by-default capability resolution (design §3.4).

    Returns the declared disposition, or a deterministic generated UNSUP for
    any undeclared token. Never returns implicit support; never raises.
    """
    declared = provider.capabilities.get(token)
    if declared is not None:
        return declared
    return CapabilityDisposition(
        CAP_UNSUP,
        f"capability '{token}' is not declared by NOS provider "
        f"'{provider.node_type}' (deny-by-default)",
    )


# -------------------------
# Observation seam types (design §3.3 -- core-owned, NOS-neutral)
# -------------------------


@dataclass(frozen=True)
class ObservationRequest:
    """A bounded, named observation request (Doctrine §1.14).

    `kind` names the invariant/test kind whose observation is requested
    (e.g. "bgp_session_up", "route_present", "bgp_neighbor"); `params`
    carries kind-typed parameters (prefixes, peer addresses, VNIs, ...).
    NEVER show-command strings -- NOS command vocabulary is provider-side
    content and must not cross this seam inbound (scope §8 P3).
    """

    kind: str
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    """A provider-collected, core-normalized observation. Never a verdict.

    `data` uses NOS-neutral vocabulary per (kind, node-type) normalization --
    no NOS vocabulary in field names, no raw NOS JSON pass-through as
    contract. `evidence` carries the raw command + output excerpt and
    diagnostics for §13(c)/DC §7 evidence surfaces. Predicates evaluate
    `data`; renderers show `evidence` (design §3.3).
    """

    kind: str
    data: Any
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StatusObservation:
    """One operational status probe's captured output (status/collect legs).

    Carries the probe outcome verbatim so core rendering stays byte-identical
    through the extraction (REQ-45b-P2): `returncode`, `stdout`, `stderr` as
    captured; `evidence` carries the command and any diagnostics.
    """

    returncode: int
    stdout: str
    stderr: str
    data: Mapping[str, Any] = field(default_factory=dict)
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CollectTarget:
    """One artifact `cassian collect` gathers for a node type.

    `artifact_name` is the artifact file name core writes; `run` produces the
    content probe result. Artifact mechanics (paths, writing, recording) stay
    core (REQ-45b-6: no artifact-mechanics move to the provider).
    """

    artifact_name: str
    run: Callable[["Runtime", str, str], StatusObservation]


@dataclass(frozen=True)
class StateProfile:
    """State-capture profile shape (phased: concrete fields land with the
    state leg at §4.5-d alongside `state_argv_allow`; carried here so the
    provider contract is complete at REQ-45b-2)."""

    name: str
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CandidateSpec:
    """Candidate-config surface declaration for one NOS (design §3.3).

    `subdir` is the candidate directory name for this NOS (the explicit
    subdir<->node-type mapping of REQ-45b-8 -- vocabularies mapped, never
    silently unified). `validate`/`apply` are the candidate workflow legs;
    the FRR apply machinery is a NON-GOAL here (BL-P2-4.5b-2) and those legs
    carry phased-instantiation placeholders until a handover owns them.
    """

    subdir: str
    extensions: tuple[str, ...]
    validate: Callable[["Path", dict], None]
    apply: Callable[["Runtime", str, str, "Path"], dict]


# -------------------------
# The provider contract (design §3.3 -- implement-ready)
# -------------------------


@dataclass(frozen=True)
class NosProvider:
    """One NOS's content behind the provider contract (design §3.3).

    Field order and semantics follow the ratified contract. All fields are
    required at construction (dataclass no-defaults => the import-time
    completeness check is intrinsic: an incomplete provider fails at import,
    B10). A phased-instantiation placeholder counts as present; wiring
    status is tracked per leg (LD-H2)."""

    # ---- identity / lifecycle ----
    node_type: str
    default_image: str | None
    runtime_requirement: str | None
    capabilities: Mapping[str, CapabilityDisposition]

    # `gen_node_config` carries a third argument and `provision` returns the
    # mapping it applied, beyond ratified design `:144`/`:147`. Founder ruling
    # (§4.5-c Chat 3, orchestration shape): SONiC's generated overlay depends
    # on device facts that exist only after boot, so `provision` probes,
    # generates THROUGH this leg, supplies, and returns what it applied; core
    # serializes that return value via `write_json_canonical` (PBE-P2-7,
    # REQ-45C-20/-42). Providers still author no artifact.
    #
    # Generation stays a PURE function of its arguments -- observed facts are
    # passed in, never fetched here -- so REQ-45C-20's determinism property is
    # checkable without a runtime. The facts mapping is OPAQUE to core: core
    # passes it through and never interprets it, keeping NOS vocabulary out of
    # the contract (design `:244` (i)).
    #
    # Design `:147`'s `cfg_artifacts` parameter was never implemented in any
    # shipped version (the fifth argument has always been `topo`, preceded by
    # `node_d`); it is amended forward, not restored.
    gen_node_config: Callable[[dict, dict, "Mapping[str, Any] | None"], "dict[str, Any] | None"]
    provision: Callable[["Runtime", str, str, dict, dict], "dict[str, Any] | None"]
    nos_ready: Callable[["Runtime", str, str], None]
    convergence_wait: Callable[["Runtime", str, str, int], None]

    # ---- validation ----
    collect: Callable[["Runtime", str, str, ObservationRequest], Observation]

    # ---- change workflow ----
    candidate: "CandidateSpec | None"

    # ---- operational ----
    # `status_bgp_summary` carries a defaulted `want_raw` beyond design §3.3's
    # (rt, lab, node) signature: the raw-text variant is a caller-varying probe
    # and the unextended form cannot reproduce the shipped per-mode probe
    # sequence (founder ruling on F-45b-C4-1). `status_routes` is unchanged --
    # it derives its raw text from data the leg already returns.
    status_bgp_summary: "Callable[[Runtime, str, str, bool], StatusObservation] | None"
    status_routes: "Callable[[Runtime, str, str], StatusObservation] | None"
    collect_targets: tuple[CollectTarget, ...]
    doctor_checks: Callable[[], "list[tuple[str, bool, str]]"]

    # ---- bounded per-type rules contributed into existing single decision
    # sites (the decision sites themselves do not move or fragment;
    # `_exec_command_allowed` stays inline this handover, REQ-45b-10) ----
    exec_command_rule: Callable[[str], "tuple[bool, str]"]
    state_profiles: Mapping[str, StateProfile]
    state_argv_allow: Callable[[str, "list[str]"], "tuple[bool, str]"]


# -------------------------
# Phased-instantiation placeholder mechanics (§17 LD-H2)
# -------------------------


def deferred_leg(leg: str, owning_handover: str) -> Callable[..., Any]:
    """Return the loud deferred-leg callable for an unwired contract leg.

    LD-H2: (1) unwired legs carry this placeholder and fail loud, §13-grade,
    if ever reached -- never a silent no-op; (2) a decision site switches to
    provider-dispatch only in the handover that lands that leg; (3) presence
    (not wiring) satisfies the completeness check; (4) wiring status is
    tracked per leg via the attributes below for later censuses.
    """

    def _deferred(*_args: Any, **_kwargs: Any) -> Any:
        sys.stderr.write(
            f"ERROR: NOS provider leg '{leg}' is not wired in this build "
            f"(phased instantiation; lands at {owning_handover}).\n"
            "Next:\n"
            "  Reaching this placeholder is a defect; report it with the "
            "command that produced it.\n"
        )
        raise SystemExit(2)

    _deferred.cassian_deferred_leg = leg  # type: ignore[attr-defined]
    _deferred.cassian_owning_handover = owning_handover  # type: ignore[attr-defined]
    return _deferred


def is_deferred(fn: Any) -> bool:
    """True if `fn` is an LD-H2 phased-instantiation placeholder."""
    return callable(fn) and hasattr(fn, "cassian_deferred_leg")


def validate_provider(p: NosProvider) -> None:
    """Import-time completeness check (B10): every contract field present
    and shape-sane; placeholder counts as present. Fails loud at import.

    Does NOT verify legs are wired -- wiring status is tracked per leg
    (LD-H2 point 3/4)."""
    problems: list[str] = []
    if not p.node_type or not isinstance(p.node_type, str):
        problems.append("node_type must be a non-empty str")
    if not isinstance(p.capabilities, Mapping):
        problems.append("capabilities must be a Mapping")
    for cap_leg in ("gen_node_config", "provision", "nos_ready",
                    "convergence_wait", "collect", "doctor_checks",
                    "exec_command_rule", "state_argv_allow"):
        if not callable(getattr(p, cap_leg)):
            problems.append(f"{cap_leg} must be callable")
    for opt_leg in ("status_bgp_summary", "status_routes"):
        v = getattr(p, opt_leg)
        if v is not None and not callable(v):
            problems.append(f"{opt_leg} must be callable or None")
    if p.candidate is not None and not isinstance(p.candidate, CandidateSpec):
        problems.append("candidate must be a CandidateSpec or None")
    if not isinstance(p.collect_targets, tuple):
        problems.append("collect_targets must be a tuple")
    if not isinstance(p.state_profiles, Mapping):
        problems.append("state_profiles must be a Mapping")
    if problems:
        sys.stderr.write(
            "ERROR: NOS provider contract incomplete for "
            f"'{getattr(p, 'node_type', '<unknown>')}': "
            + "; ".join(problems)
            + "\nNext:\n  Fix the provider definition; every §3.3 contract "
            "field must be present (a phased-instantiation placeholder "
            "counts as present).\n"
        )
        raise SystemExit(2)
