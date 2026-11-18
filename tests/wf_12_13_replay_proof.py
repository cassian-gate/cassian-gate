#!/usr/bin/env python3
"""wf_12_13_replay_proof.py — §4.12 WI-3 fold (BL-1b3-1) PO-B3-fold.

A committed, CI-safe, LAB-FREE WF-12/13 byte-identity replay regression. Replaces
the §4.3 PO-2 leg that ran through `verify_phase1.sh` (a lab deploy) and so was not
reproducible from committed artifacts (BL-§4.3-V1 / Finding B). TM-CI-1 preserved.

  REQ-WF-12  cassian `test` TEST-path render is byte-identical on replay.
  REQ-WF-13  existing declared-tests `wait_for` types (ping/tcp/route_prefix) render
             byte-identical; the legacy block is drift-guarded against a committed golden.
  TM-CI-1    the regression is lab-free; `verify_phase1.sh` is reintroduced nowhere;
             this proof is itself wired into the public CI gate.
  REQ-45E-15 (§4.5-e, ER-5, BL-P2-4.5c-64) the lockstep is two-directional: every
             listed proof appears in the gate, and every `python tests/<name>_proof.py`
             invocation in the gate is named in this file's lists.

Method (PBE-1b-8): render the real cassian_tests surfaces over committed synthetic
fixtures, twice, and assert byte-identity; non-vacuity guards against a trivial
constant. No container, no `cassian up/test/down`, no `verify_phase1.sh`.

Run:  PYTHONPATH=src python3 tests/wf_12_13_replay_proof.py
"""
import copy
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import cassian_tests as ct  # noqa: E402

checks: list[tuple[str, bool]] = []


def check(name: str, ok: object) -> None:
    checks.append((name, bool(ok)))


# ----- lab-free TEST-path render harness (same approach as the WI-1 b6 proof) -----
def _render_summary(results: dict, lab: str = "wf12demo") -> str:
    tmp = pathlib.Path(tempfile.mkdtemp()) / f"clab-{lab}"
    tmp.mkdir(parents=True, exist_ok=True)
    orig = ct.lab_dir
    try:
        ct.lab_dir = lambda _l: tmp
        return ct.write_test_summary_artifact(lab, results).read_text(encoding="utf-8")
    finally:
        ct.lab_dir = orig


# ===== Committed fixtures =====
# WF-13: declared-tests scenario path exercising the legacy ping/tcp/route_prefix block.
SCEN = {
    "scenarios": [
        {"id": "s1", "verdict": "pass", "steps": [
            {"type": "run", "ref": "t_core"},
            {"type": "wait_for", "wait_for": {"type": "ping", "from": "h1", "to": "h2", "expect": "ok"}},
            {"type": "wait_for", "wait_for": {"type": "tcp", "from": "h1", "to_ip": "10.0.0.2", "expect": "open"}},
            {"type": "wait_for", "wait_for": {"type": "route_prefix", "from": "r1", "to": "10.0.0.0/24", "expect": "present"}},
            {"type": "fault", "action": "link_down", "target": "r1-r2"},
        ]},
        {"id": "s2", "verdict": "pass", "steps": [
            {"type": "wait_for", "wait_for": {"type": "ping", "from": "h2", "to": "h1", "expect": "ok"}},
        ]},
    ]
}
# WF-12: TEST-path summary fixture.
TEST = {"result": "pass", "topology": {"name": "wf12demo"},
        "tests": [{"name": "t1", "verdict": "pass"}, {"name": "t2", "verdict": "pass"}],
        "scenarios": [{"id": "s1", "verdict": "pass"}]}

# ----- REQ-WF-13: declared-tests render replay byte-identity -----
r1 = ct._render_scenarios_summary(copy.deepcopy(SCEN))
r2 = ct._render_scenarios_summary(copy.deepcopy(SCEN))
check("REQ-WF-13 scenarios render is byte-identical on replay", r1 == r2)

# ----- REQ-WF-13: legacy ping/tcp/route_prefix lines drift-guarded (committed golden) -----
GOLDEN_LINES = [
    "    [1] run test=t_core",
    "    [2] wait_for ping h1->h2 expect=ok",
    "    [3] wait_for tcp h1->10.0.0.2 expect=open",
    "    [4] wait_for route_prefix r1->10.0.0.0/24 expect=present",
    "    [5] fault link_down r1-r2",
]
_r1_lines = r1.splitlines()
for gl in GOLDEN_LINES:
    check(f"REQ-WF-13 golden line preserved: {gl.strip()}", gl in _r1_lines)
check("REQ-WF-13 scenario headers rendered", "scenario s1: PASS" in r1 and "scenario s2: PASS" in r1)

# ----- REQ-WF-12: TEST-path summary render replay byte-identity -----
t1 = _render_summary(copy.deepcopy(TEST))
t2 = _render_summary(copy.deepcopy(TEST))
check("REQ-WF-12 TEST-path summary is byte-identical on replay", t1 == t2)

# ----- Non-vacuity: distinct input -> distinct render (not a trivial constant) -----
SCEN_ALT = copy.deepcopy(SCEN)
SCEN_ALT["scenarios"][0]["steps"][1]["wait_for"]["to"] = "h9"  # ping target h2 -> h9
check("NV WF-13 distinct scenario input -> distinct render",
      ct._render_scenarios_summary(SCEN_ALT) != r1)
TEST_ALT = copy.deepcopy(TEST)
TEST_ALT["tests"] = [TEST_ALT["tests"][0]]  # 2 declared tests -> 1; changes "Tests executed: N"
check("NV WF-12 distinct test input -> distinct render", _render_summary(TEST_ALT) != t1)

# ----- TM-CI-1: lab-free CI posture preserved + this regression is CI-wired -----
gate = (ROOT / ".github" / "workflows" / "cassian.yml").read_text(encoding="utf-8")
# REQ-45E-15: every name this file lists, gathered as each loop checks it, so the
# reverse direction below compares the gate against the declared list (never a
# list derived from the workflow).
LISTED: list[str] = []
check("TM-CI-1 verify_phase1.sh reintroduced nowhere in cassian.yml",
      "verify_phase1.sh" not in gate)
check("TM-CI-1 scripts/verify_phase1.sh absent from the repo",
      not (ROOT / "scripts" / "verify_phase1.sh").exists())
check("fold is CI-wired: wf_12_13_replay_proof.py present in the gate",
      "wf_12_13_replay_proof.py" in gate)
LISTED.append("wf_12_13_replay_proof.py")

# §4.5-b (REQ-45b-18 / §14.4 conditional entry): the three NOS provider-structure
# proofs are gate-wired in lockstep with the cassian.yml step that runs them.
for _p in ("nos_leaf_import_proof.py", "nos_deny_by_default_proof.py",
           "nos_census_instrument.py"):
    check(f"§4.5-b proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)

# §4.5-c (§14.4 conditional lockstep; Ledger BL-P2-4.5c-11): the four lab-free
# SONiC base-lifecycle proofs are gate-wired in lockstep with the cassian.yml
# step that runs them. A proof that never gates enforces nothing.
# Coverage limit (PBE-P2-8), stated rather than implied: this is a substring test
# over cassian.yml. It proves each proof is NAMED in the gate. It does NOT prove
# the step executes, that the runner reaches it, or that the proof passes.
for _p in ("sonic_leaf_import_proof.py", "sonic_configgen_determinism_proof.py",
           "sonic_provision_supply_proof.py", "sonic_image_lifecycle_proof.py",
           "sonic_lifecycle_proof.py", "sonic_status_probe_sequence_proof.py",
           "wheel_import_proof.py", "reconfigure_clean_state_proof.py",
           "sonic_provision_readiness_gate_proof.py",
           "sonic_nos_ready_proof.py",
           "evpn_collection_migration_proof.py",
           "cmd_evidence_derivation_differential_proof.py",
           "sonic_unsupported_capability_disposition_proof.py",
           "sonic_endpoint_recognition_proof.py",
           "sonic_routing_mode_precondition_proof.py",
           # §4.5-c WI-3 packet 4b-iii: CI-wired by the (VM) steps.
           "sonic_precheck_proof.py",
           # §4.5-c WI-3 packet 5b: the scenario wait_for_bgp legs
           # (REQ-45C-10/-30), CI-wired by the (VM) steps.
           # LD-45C-R14 R4, §14.4 conditional lockstep.
           "sonic_wait_for_bgp_proof.py",
           # §4.5-c WI-1 packet 2 C2: the preconfigured-mode proof. Created in
           # packet 1 and left unwired (BL-P2-4.5c-109); LD-45C-R27 R1 assigns
           # the wiring to packet 2 and R2 requires this lockstep entry as its
           # price. Three cassian.yml steps run it -- the lab-free harness, the
           # row-4 mode4 arm and the row-26 req26 arm (LD-45C-R30 R2) -- and
           # this substring test proves only that the NAME appears, per the
           # coverage limit stated above.
           "sonic_preconfigured_proof.py"):
    check(f"§4.5-c proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)

# §4.5-d (REQ-45D-27; founder ruling (B), 2026-09-24): §4.5-d's hosted proofs
# are gate-wired in lockstep with the cassian.yml steps that run them, in a
# section loop of their own beside §4.5-b's and §4.5-c's, so each check names
# the section that owns the proof. Coverage limit (PBE-P2-8), as stated for
# §4.5-c above: this substring test proves each proof is NAMED in the gate; it
# does NOT prove the step executes, that the runner reaches it, or that the
# proof passes.
for _p in ("sonic_exec_allowlist_proof.py",   # H1-a2-ii, REQ-45D-5
           "vm_guest_probe_rc5_proof.py",    # S7, BL-P2-4.5c-32 (R1/D-i)
           "sonic_observation_kinds_proof.py",  # H1-b1 script 1, REQ-45D-1/-8/-9/-10/-15/-16
           "sonic_observed_state_render_proof.py",  # H1-b1 script 2, REQ-45D-21 (ruling (i))
           "exec_rule_parity_proof.py",       # H1-a2-ii, REQ-45D-6/-7
           "route_prefix_seam_parity_proof.py",  # H1-b3 script 1b, REQ-45D-2 (ruling Q-B)
           "evpn_precheck_mac_poll_proof.py",  # S24-R5, BL-P2-4.5c-53 (S25-R4)
           "evpn_rr_next_hop_self_proof.py",  # S26-R8/R9, BL-P2-4.5c-219 (S25-R5)
           "sonic_ospf_unsupported_proof.py",  # S27-R4, REQ-45D-17
           "wf_added_steps_if_key_proof.py",  # S27-R4, REQ-45D-28
           "sonic_status_collect_proof.py",  # S27-R4, REQ-45D-19/-20 (lab-free legs)
           "sonic_bgp_session_live_proof.py",  # S29-R1, row 15, REQ-45D-1/-8/-16/-19 (VM)
           "sonic_rib_collection_live_proof.py",  # S29-R6, row 8, REQ-45D-2/-11/-12 (VM)
           "frr_nos_ready_proof.py",  # S31-R10 to S31-R19, S30-R5 readiness packet
           "results_tamper_check_bundle_proof.py",  # S32-R3, BL-P2-4.5c-230 (tamper seal)
           "frr_address_step_window_proof.py",  # S33-R4, BL-P2-4.5c-233 (address-step window)
           "sonic_ping_through_proof.py",  # S34-R1 to S34-R4, row 10, REQ-45D-3/-4/-26 (VM)
           "sonic_exec_live_proof.py",  # S35-R1 to S35-R6, row 9, REQ-45D-5 (VM)
           # S36-R1 to S36-R3, row 11, REQ-45D-19/-20 (VM): the (VM) step's invocation;
           # the file name alone is already named, by its lab-free step, above
           "sonic_status_collect_proof.py live topologies/sonic-status-collect.yaml",
           "sonic_within_boot_reprovision_proof.py",  # S37-R1 to S37-R3, row 13, REQ-45D-30 (VM)
           "sonic_init_cfg_layering_proof.py",  # S37-R4, row 12, REQ-45D-29 (VM)
           "sonic_grey_failure_proof.py"):  # S37-R5, S37-R6, S37-R14, row 14, REQ-45D-22 (VM)
    check(f"§4.5-d proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)

# Stage-1 gap item (d)(2) (handover WI-9, Am-1; founder rulings of 2026-10-27): the item's
# hosted proofs are gate-wired in lockstep with the cassian.yml steps that run them, in a
# section loop of their own. HS-7 is entered with WI-13 (ruling D4); WI-9 adds HS-1 to HS-6.
# Coverage limit (PBE-P2-8), as stated for §4.5-c above: this substring test proves each
# proof is NAMED in the gate; it does NOT prove the step executes, that the runner reaches
# it, or that the proof passes. Since §4.5-e it is also two-directional (REQ-45E-15,
# BL-P2-4.5c-64): the reverse check below reds a gate step that runs a proof no list names.
for _p in ("probe_unusable_verdict_proof.py",  # HS-7, WI-13, PO-30 (ruling D4)
           "unusable_read_sweep_proof.py",  # HS-8, WI-15 script 2, PO-32 (S1D2-S18-R1)
           "checks_catalogue_drift_proof.py",  # HS-1, WI-9 step A (REQ-S1D2-15, -29)
           "checks_catalogue_coherence_proof.py",  # HS-2, WI-9 step B
           "checks_param_conformance_proof.py",  # HS-3, WI-9 step A
           "checks_command_surface_proof.py",  # HS-4, WI-9 step B
           "checks_readonly_ai_free_proof.py",  # HS-5, WI-9 step B
           "cli_surface_preservation_proof.py"):  # HS-6, WI-9 step B
    check(f"(d)(2) proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)

# §4.5-e (REQ-45E-15; ER-5; BL-P2-4.5c-64, discharged by this change): the lockstep is
# two-directional. The proofs the gate ran before §4.5-b's loop existed are entered here,
# by the section whose step runs them, so every invocation is named. Coverage limit
# (PBE-P2-8): the reverse direction matches `python tests/<name>_proof.py` (and
# `python3`) as written in the gate; a proof run through an interpreter variable (the
# (d)(2) matrix step's `"$py" tests/...`) or a script not named `*_proof.py` is outside
# its pattern, and is covered only by the existing direction where a list names it.
for _s, _p in (
        ("§4.1", "bl6_observed_state_absence_render_proof.py"),
        ("§4.3", "bl_h3_8_scenarios_summary_existing_type_render_proof.py"),
        ("§4.4", "h53_resolve_interface_existence_proof.py"),
        ("§4.4", "h57_scenario_invariant_dispatch_generalization_proof.py"),
        ("§4.7", "udi_validate_rejection_proof.py"),
        ("§4.7", "udi_guardrail_uniformity_proof.py"),
        ("§4.7", "udi_dispatch_parity_proof.py"),
        ("§4.7", "udi_assertion_eval_proof.py"),
        ("§4.7", "udi_four_quadrant_proof.py"),
        ("§4.7", "udi_replay_determinism_proof.py"),
        ("§4.7", "udi_render_boundary_proof.py"),
        ("§4.7", "udi_blast_radius_coverage_proof.py"),
        ("§4.7", "udi_preservation_proof.py"),
        ("§4.8", "tag_validate_rejection_proof.py"),
        ("§4.8", "tag_selector_proof.py"),
        ("§4.8", "tag_nonexec_schema_proof.py"),
        ("§4.8", "tag_authority_parity_proof.py"),
        ("§4.8", "tag_schema_invariance_proof.py"),
        ("§4.8", "tag_replay_determinism_proof.py"),
        ("§4.8", "tag_nonexec_render_boundary_proof.py"),
        ("§4.8", "tag_preservation_proof.py"),
        ("§4.9", "ai_change_reference_case_proof.py"),
        ("§4.10", "bgp_community_validate_rejection_proof.py"),
        ("§4.10", "bgp_community_catalog_coherence_proof.py"),
        ("§4.10", "bgp_community_set_gen_proof.py"),
        ("§4.10", "bgp_community_eval_match_proof.py"),
        ("§4.10", "bgp_community_four_quadrant_proof.py"),
        ("§4.10", "bgp_community_authority_parity_proof.py"),
        ("§4.10", "bgp_community_replay_determinism_proof.py"),
        ("§4.10", "bgp_community_render_boundary_proof.py"),
        ("§4.10", "bgp_community_preservation_proof.py"),
        ("§4.10", "expf_four_quadrant_catalog_proof.py"),
        ("§4.11", "bgp_as_path_validate_rejection_proof.py"),
        ("§4.11", "bgp_as_path_catalog_coherence_proof.py"),
        ("§4.11", "bgp_as_path_eval_match_proof.py"),
        ("§4.11", "bgp_as_path_four_quadrant_proof.py"),
        ("§4.11", "bgp_as_path_authority_parity_proof.py"),
        ("§4.11", "bgp_as_path_replay_determinism_proof.py"),
        ("§4.11", "bgp_as_path_render_boundary_proof.py"),
        ("§4.11", "bgp_as_path_preservation_proof.py"),
        ("§4.12", "b6_pass_scope_render_proof.py"),
        ("§4.12", "b6_13bc_seam_preservation_proof.py"),
        ("§4.12", "h54_doctor_ip_j_probe_proof.py"),
        ("§4.13", "audit_evidence_schema_format_proof.py"),
        ("§4.13", "audit_tamper_check_replay_proof.py"),
        ("§4.13", "audit_release_version_determinism_proof.py"),
        ("§4.13", "audit_baseline_diff_determinism_proof.py"),
        ("§4.13", "audit_intent_input_sufficiency_proof.py"),
        ("§4.13", "audit_intent_verdict_invariance_proof.py"),
        ("§4.13", "audit_self_contained_interpretation_proof.py"),
        ("§4.13", "audit_unverifiable_render_boundary_proof.py"),
        ("§4.13", "audit_seam_preservation_proof.py"),
        ("§4.13", "audit_nonscoped_preservation_proof.py"),
        ("§4.14", "importer/importer_behavior_proof.py"),
        ("§4.14", "importer/backend_seam_proof.py"),
        ("§4.14", "importer/preservation_proof.py"),
        ("Phase 2 §4.4", "two_run_injected_difference_proof.py"),
        ("Phase 2 §4.4", "two_run_verdict_substitution_proof.py"),
        ("Phase 2 §4.4", "two_run_config_vs_behaviour_proof.py"),
        ("Phase 2 §4.4", "two_run_canonical_serialization_proof.py"),
        ("Phase 2 §4.4", "two_run_real_run_positive_proof.py"),
        ("R-O1", "vm_runtime_validate_rejection_proof.py")):
    check(f"{_s} proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)

# §4.5-e base: the proofs its own CI steps run (handover §6.7.4), one entry per step, entered
# with the step (REQ-45E-15).
for _p in ("wf_additions_only_proof.py",  # WI-3, REQ-45E-14, §6.7.4 row 2
           "substrate_target_preservation_proof.py",  # WI-3, REQ-45E-16, §6.7.4 row 3
           # WI-5, REQ-45E-29 to -36, §6.7.4 row 1: the EVPN-on-FRR family step (the row-4 hosted step
           # runs `cassian up`/`test`, no proof file)
           "evpn_authority_parity_proof.py",
           "evpn_catalog_coherence_proof.py",
           "evpn_eval_match_proof.py",
           "evpn_four_quadrant_proof.py",
           "evpn_render_boundary_proof.py",
           "evpn_replay_determinism_proof.py",
           "evpn_validate_rejection_proof.py",
           "evpn_gen_proof.py"):
    check(f"§4.5-e proof is CI-wired: {_p} present in the gate", _p in gate)
    LISTED.append(_p)
# Non-vacuity (handover §15.2, negative-proof row 16): with the proof listed, an in-memory
# gate without its step turns the existing direction red.
_gate_nv16 = "".join(_l for _l in gate.splitlines(keepends=True)
                     if "substrate_target_preservation_proof" not in _l)
check("NV REQ-45E-16 a gate without the substrate step reds the listed proof's existing-direction check",
      "substrate_target_preservation_proof.py" in gate
      and "substrate_target_preservation_proof.py" not in _gate_nv16)

_INVOKED_RE = r"\bpython3? tests/([A-Za-z0-9_./-]+_proof\.py)\b"


def _unlisted(gate_text: str) -> list[str]:
    """REQ-45E-15, B13: the gate's `python tests/<name>_proof.py` invocations that no list names."""
    _named = {_n.split()[0] for _n in LISTED}
    return sorted({_m for _m in re.findall(_INVOKED_RE, gate_text) if _m not in _named})


_invoked = sorted(set(re.findall(_INVOKED_RE, gate)))
check("REQ-45E-15 reverse: every `python tests/<name>_proof.py` invocation in the gate is named in a list"
      + ("" if not _unlisted(gate) else " (unlisted: " + ", ".join(_unlisted(gate)) + ")"),
      not _unlisted(gate))
_names = {_n.split()[0] for _n in LISTED}
check(f"REQ-45E-15 reverse leg reached: {len(_invoked)} distinct invoked proofs, {len(_names)} listed names",
      len(_invoked) > 0 and len(_names) > 0)
# Non-vacuity (handover §15.2 row 15): an in-memory gate with one added step whose proof
# no list names turns the reverse check red.
_gate_nv = gate + "\n      - name: nv unlisted step\n        run: |\n          python tests/zz_nv_unlisted_step_proof.py\n"
check("NV REQ-45E-15 an in-memory gate step running an unlisted proof reds the reverse check",
      "zz_nv_unlisted_step_proof.py" in _unlisted(_gate_nv)
      and "zz_nv_unlisted_step_proof.py" not in _unlisted(gate))
_gate_nv3 = gate + "\n          python3 tests/zz_nv_unlisted_py3_proof.py\n"
check("NV REQ-45E-15 the same holds for a `python3` invocation",
      "zz_nv_unlisted_py3_proof.py" in _unlisted(_gate_nv3)
      and "zz_nv_unlisted_py3_proof.py" not in _unlisted(gate))

fails = [n for n, ok in checks if not ok]
print(f"PO-B3-fold (WF-12/13 replay): {len(checks) - len(fails)}/{len(checks)} checks passed.")
for n, ok in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
if fails:
    sys.exit(f"PO-B3-fold FAILED ({len(fails)} check(s)).")
print("PO-B3-fold OK.")
