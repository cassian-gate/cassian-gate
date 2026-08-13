"""Single registration locus for the src/*.py module roster (§4.3).

ROSTER ONLY: paths, no SHA-256 values. Per-module baseline SHAs, each proof's
baseline anchor, and each proof's SCOPED set stay per-proof (D-2). Registering a
new src/ module happens ONCE here; each enforcing guard still pins (baselines)
it -- register-once != baseline-once.

Guard property (DC v2.1 §14 item 8, "No silent mutation introduced", per the
ratified E-1 correction): the full-roster guards derive their enforced set as
MODULE_ROSTER - SCOPED - ALLOWED_NEW, so a rostered-enforced-but-unbaselined
module fails loud ("re-baseline required: <mod>") -- never silently skipped,
never auto-baselined. No baseline SHA is recomputed-to-match or self-healed
(v8 §15 hard floor). Membership integrity is intrinsic: the four full-roster
guards run a bidirectional disk == roster check (added AND removed).

Forward authoring principle (REQ-43-7 / F-2): a future need to freeze a
sub-module *segment* while the module legitimately evolves is authored as a NEW
seam proof at AST-function-segment granularity (cf. audit_seam_preservation_proof,
b6_13bc_seam_preservation_proof) -- NOT as a whole-module pin. The six
whole-module guards correctly remain whole-module; narrowing a frozen-module pin
would let drift through (a hard-floor violation). This manifest reduces roster-
MEMBERSHIP maintenance, not per-change SHA re-baseline on the whole-module guards.

Placement: deliberately NOT under src/ -- a roster of src/*.py must not be a
member of src/*.py (no self-reference). Data only: no __main__, no gate step; it
is imported by the guards, never invoked as a step in cassian.yml.
"""

MODULE_ROSTER = frozenset({
    "src/__init__.py",
    "src/cassian.py",
    "src/cassian_ai.py",
    "src/cassian_artifacts.py",
    "src/cassian_candidate.py",
    "src/cassian_cli.py",
    "src/cassian_common.py",
    "src/cassian_engine.py",
    "src/cassian_import.py",
    "src/cassian_model.py",
    # §4.5-b new modules (WI-B NOS provider structure); enforced (REQ-45b-13; LD-9).
    "src/cassian_nos_frr.py",
    "src/cassian_nos_types.py",
    "src/cassian_runtime_container.py",
    "src/cassian_runtime_vm.py",
    "src/cassian_state.py",
    "src/cassian_tests.py",
    "src/cassian_two_run.py",
})
