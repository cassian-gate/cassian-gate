"""FRR NOS provider (Phase 2 §4.5-b, REQ-45b-3; design §3.3).

Carries FRR's NOS content behind the provider contract: identity, capability
declarations, the candidate-surface declaration, and -- as the §4.5-b
extraction lands -- the collection seam (`collect`), the status legs, and the
`cassian collect` target set. Core owns invariants, predicate evaluation,
verdicts, rendering, and artifacts (design §5); this module never decides
pass/fail.

Import floor (REQ-45b-3/-17): stdlib + the types leaf, plus `cassian_common`
for the ruled shared helpers only (A-H3/A-H4: `_canonical_community_token`,
`_BGP_COMMUNITY_CANON`, `_normalize_prefix` -- admitted when the extraction
wires them). Never engine, model, or runtime_container.

Unshipped legs (REQ-45b-3 deferral list) carry the LD-H2 phased-instantiation
placeholder: present (completeness check passes), loud §13-grade if reached,
never a silent no-op. Wiring status per leg:

  gen_node_config    -> deferred (config-generation leg; §4.5-d/-f)
  provision          -> deferred (provisioning leg; §4.5-d/-f)
  nos_ready          -> deferred (readiness leg; §4.5-d/-f)
  convergence_wait   -> deferred (convergence leg; §4.5-d/-f)
  exec_command_rule  -> deferred (§4.5-d; LD-45b-6 / BL-P2-4.5b-1 -- the
                        decision site `_exec_command_allowed` stays inline
                        this handover and NEVER consults this field,
                        REQ-45b-10)
  state_profiles     -> empty (state leg; §4.5-d)
  state_argv_allow   -> deferred (state leg; §4.5-d)
  doctor_checks      -> deferred (per-NOS doctor leg; post-§4.5-b sub-handover,
                        unassigned -- cmd_doctor's image literal derives from
                        `default_image`, not from this leg, REQ-45b-11-ext)
  candidate.validate -> deferred (candidate-apply leg; BL-P2-4.5b-2)
  candidate.apply    -> deferred (candidate-apply leg; BL-P2-4.5b-2 -- the
                        FRR apply machinery stays in cassian_candidate)

Capability note: `interface_state` is deliberately NOT declared here -- its
collection is NOS-agnostic (Linux `ip -j link show` primitives) and stays
core; deny-by-default makes any accidental provider dispatch for it fail
loud. Token vocabulary below = the observation-seam kinds + operational
legs shipped by §4.5-b; alignment with the full §6-checklist token map
matures with the SONiC provider (§4.5-c onward).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cassian_nos_types import (
    CandidateSpec,
    CapabilityDisposition,
    NosProvider,
    deferred_leg,
    impl,
)

if TYPE_CHECKING:  # annotation-only; no runtime import (REQ-45b-17)
    pass


FRR_NODE_TYPE = "frr"

# REQ-45b-11 single source: the model's effective-image default for frr
# derives from this value (one source, two readers with cmd_doctor per
# REQ-45b-11-ext). Value unchanged through the extraction (P2).
FRR_DEFAULT_IMAGE = "frrouting/frr:latest"


# Capability declarations (design §3.4): the (kind, node-type) pairs FRR
# supports through the §4.5-b seams. Deny-by-default -- an absent token is
# UNSUP with a generated message; dispatch sites check before dispatching.
_FRR_CAPABILITIES: dict[str, CapabilityDisposition] = {
    # observation seam -- invariant kinds (model-validated vocabulary)
    "bgp_session_up": impl(),
    "route_present": impl(),
    "route_absent": impl(),
    "bgp_med_equals": impl(),
    "bgp_localpref_equals": impl(),
    "bgp_community": impl(),
    "bgp_as_path": impl(),
    "route_advertised_to": impl(),
    "route_not_advertised_to": impl(),
    "evpn_mac_route_present": impl(),
    "evpn_mac_route_absent": impl(),
    "evpn_vni_route_present": impl(),
    "evpn_bgp_session_up": impl(),
    "ospf_neighbor_up": impl(),
    # observation seam -- test/step kinds routed through the same seam
    "bgp_neighbor": impl(),
    "route_prefix": impl(),
    # operational legs shipped by §4.5-b
    "status_bgp_summary": impl(),
    "status_routes": impl(),
    "collect_bgp_summary": impl(),
    "candidate": impl(),
}


FRR_PROVIDER = NosProvider(
    node_type=FRR_NODE_TYPE,
    default_image=FRR_DEFAULT_IMAGE,
    runtime_requirement=None,
    capabilities=_FRR_CAPABILITIES,
    # -- lifecycle legs: deferred (REQ-45b-3 deferral list) --
    gen_node_config=deferred_leg("gen_node_config", "§4.5-d/-f"),
    provision=deferred_leg("provision", "§4.5-d/-f"),
    nos_ready=deferred_leg("nos_ready", "§4.5-d/-f"),
    convergence_wait=deferred_leg("convergence_wait", "§4.5-d/-f"),
    # -- validation seam: wired by this handover's extraction WI --
    collect=deferred_leg("collect", "§4.5-b (this handover's extraction WI)"),
    # -- change workflow: subdir/extensions ship (REQ-45b-8 derivation
    #    source); validate/apply legs are BL-P2-4.5b-2 NON-GOALs here --
    candidate=CandidateSpec(
        subdir="frr",
        extensions=(".conf",),
        validate=deferred_leg("candidate.validate", "BL-P2-4.5b-2 destination"),
        apply=deferred_leg("candidate.apply", "BL-P2-4.5b-2 destination"),
    ),
    # -- operational legs: wired by this handover's status/collect WIs --
    status_bgp_summary=deferred_leg(
        "status_bgp_summary", "§4.5-b (this handover's status WI)"
    ),
    status_routes=deferred_leg(
        "status_routes", "§4.5-b (this handover's status WI)"
    ),
    collect_targets=(),  # filled by this handover's collect WI (B04)
    doctor_checks=deferred_leg("doctor_checks", "post-§4.5-b (unassigned)"),
    # -- bounded per-type rules: deferred; decision sites stay inline --
    exec_command_rule=deferred_leg("exec_command_rule", "§4.5-d (LD-45b-6)"),
    state_profiles={},
    state_argv_allow=deferred_leg("state_argv_allow", "§4.5-d"),
)
