from __future__ import annotations

import argparse
from pathlib import Path

import cassian_common
from cassian_common import die

import cassian_engine
from cassian_engine import (
    _bind_workspace_labs_dir,
    _command_uses_workspace_labs,
    _invocation_reset_written_artifacts,
    _print_artifacts_footer_for_lab,
    cmd_gen,
    cmd_validate,
    cmd_doctor,
    cmd_preflight,
    cmd_adapt_terraform,
    cmd_adapt_ansible,
    cmd_up,
    cmd_replay,
    cmd_down,
    cmd_destroy,
    cmd_cleanup,
    cmd_exec,
    cmd_vty,
    cmd_status,
    cmd_collect,
    cmd_run,
    cmd_test,
)
from cassian_ai import cmd_ai_review

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cassian",
        description="Cassian Gate: deterministic network change validation gate",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Quick help:\n"
            "  cassian test <topology.yaml>              (authoritative gate)\n"
            "  cassian replay <artifact-dir> --gate      (authoritative replay)\n"
            "  cassian replay -h                         (replay options)\n"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # gen
    p_gen = sub.add_parser("gen", help="Generate containerlab file from topology")
    p_gen.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_gen.set_defaults(func=cmd_gen)

    # validate
    p_val = sub.add_parser("validate", help="Validate topology + scenarios (no lab, no containers)")
    p_val.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_val.add_argument("--json", action="store_true", help="Emit machine-readable JSON (CI-friendly)")
    p_val.set_defaults(func=cmd_validate)

    # validate-contrib
    p_vc = sub.add_parser("validate-contrib", help="Validate contrib content structurally (no lifecycle, no artifacts)")
    p_vc.add_argument("contrib_path", help="Explicit contrib path to validate")
    p_vc.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_vc.set_defaults(func=cmd_validate)

    # doctor (read-only environment readiness; no mutation)
    p_doc = sub.add_parser("doctor", help="Read-only environment readiness checks (no mutation)")
    p_doc.set_defaults(func=cmd_doctor)

    # preflight (advisory-only, declared-only, resolve-time)
    p_pre = sub.add_parser("preflight", help="Advisory static preflight (declared-only; no execution)")
    p_pre.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_pre.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    p_pre.add_argument("--out", default=None, help="Output path (default: artifacts/preflight/preflight.json)")
    p_pre.add_argument("--adapter", action="append", default=[], help="Path to an adapters.v1 JSON (repeatable; advisory-only)")
    p_pre.set_defaults(func=cmd_preflight)

    # adapt (read-only input adapters; advisory-only)
    p_adapt = sub.add_parser("adapt", help="Read-only input adapters (advisory-only)")
    sub_adapt = p_adapt.add_subparsers(dest="adapter", required=True)

    p_tf = sub_adapt.add_parser("terraform", help="Adapt Terraform plan JSON (terraform show -json)")
    p_tf.add_argument("--plan", required=True, help="Path to terraform plan JSON (terraform show -json)")
    p_tf.add_argument("--out", default=None, help="Output directory (default: artifacts/adapters/)")
    p_tf.add_argument("--strict", action="store_true", help="Fail (exit 1) if parse_errors are present")
    p_tf.set_defaults(func=cmd_adapt_terraform)

    p_ans = sub_adapt.add_parser("ansible", help="Adapt rendered Ansible output directory (read-only)")
    p_ans.add_argument("--dir", required=True, help="Path to rendered Ansible output directory")
    p_ans.add_argument("--out", default=None, help="Output directory (default: artifacts/adapters/)")
    p_ans.add_argument("--strict", action="store_true", help="Fail (exit 1) if parse_errors are present")
    p_ans.set_defaults(func=cmd_adapt_ansible)

    # up
    p_up = sub.add_parser("up", help="Generate + deploy")
    p_up.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_up.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_up.set_defaults(func=cmd_up)

    # replay
    p_replay = sub.add_parser(
        "replay",
        help="Deterministically re-execute a prior run using its artifacts as authoritative inputs",
    )
    p_replay.add_argument(
        "artifacts",
        help="Artifact directory containing topology.resolved.yaml and results.json (authoritative inputs)",
    )
    p_replay.add_argument(
        "--gate",
        action="store_true",
        help="Run authoritative clean-state gate replay (generate→deploy→provision→test→collect→destroy).",
    )
    p_replay.add_argument(
        "--verify-results",
        action="store_true",
        help="(Opt-in) Verify replay results match the source verdict core (semantic equivalence). Mismatch exits 1. Default: off.",
    )
    p_replay.add_argument(
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    p_replay.set_defaults(func=cmd_replay)

    # down
    p_down = sub.add_parser("down", help="Destroy a deployed lab by name")
    p_down.add_argument("name", help="Lab name (topology 'name')")
    p_down.add_argument(
        "--strict",
        action="store_true",
        help="Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).",
    )
    p_down.set_defaults(func=cmd_down)

    # destroy (explicit ops; does not delete artifacts by default)
    p_destroy = sub.add_parser("destroy", help="Destroy a lab runtime; keep artifacts unless --purge-artifacts")
    p_destroy.add_argument("name", help="Lab name (topology 'name')")
    p_destroy.add_argument(
        "--strict",
        action="store_true",
        help="Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).",
    )
    p_destroy.add_argument(
        "--purge-artifacts",
        dest="purge_artifacts",
        action="store_true",
        help="Also delete labs/clab-<lab> artifacts after runtime teardown attempt.",
    )
    p_destroy.set_defaults(func=cmd_destroy)

    # cleanup
    p_cleanup = sub.add_parser(
        "cleanup",
        help="Safely clean up Cassian Gate-owned labs found under labs/ (dry-run unless --yes)",
    )
    p_cleanup.add_argument(
        "--all",
        action="store_true",
        help="Required. Only targets Cassian Gate labs with artifact dirs under labs/clab-* (never scans Docker).",
    )
    p_cleanup.add_argument(
        "--yes",
        action="store_true",
        help="Actually destroy labs listed in the plan (artifacts are NOT deleted).",
    )
    p_cleanup.set_defaults(func=cmd_cleanup)

    # exec
    p_exec = sub.add_parser("exec", help="Exec a command inside a node container; if no command, open bash")
    # Make positionals optional at parse-time so quiet-mode misuse is Cassian Gate-owned (no argparse dumps).
    p_exec.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_exec.add_argument("node", nargs="?", help="Node name (e.g. r1)")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command to run inside container")
    p_exec.set_defaults(func=cmd_exec)

    # collect
    p_collect = sub.add_parser("collect", help="Collect runtime artifacts for a lab")
    p_collect.add_argument("lab", help="Lab name (topology 'name')")
    p_collect.set_defaults(func=cmd_collect)

    # vty
    p_vty = sub.add_parser("vty", help="Run a vtysh command easily")
    # Make positionals optional at parse-time so quiet-mode misuse is Cassian Gate-owned (no argparse dumps).
    p_vty.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_vty.add_argument("node", nargs="?", help="Node name (e.g. r1)")
    p_vty.add_argument("command", nargs="?", help='vtysh command as one string, e.g. "show bgp summary"')
    p_vty.set_defaults(func=cmd_vty)

    # status
    p_status = sub.add_parser("status", help="Show lab status (containers + optional BGP summary)")
    # Make positional optional at parse-time so quiet-mode misuse is Cassian Gate-owned (no argparse dumps).
    p_status.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_status.add_argument("--bgp", action="store_true", help="Include 'show bgp summary' for FRR nodes")
    p_status.add_argument("--bgp-verbose", action="store_true", help="Print full 'show bgp summary' output")
    p_status.add_argument("--strict", action="store_true", help="Exit non-zero if any FRR peers are not Established")
    p_status.add_argument("--interfaces", action="store_true", help="Include 'ip -br a' output per node")
    p_status.add_argument("--summary", action="store_true", help="Print a one-line summary at the end")
    p_status.add_argument("--json", action="store_true", help="Emit machine-readable JSON (no command echo)")
    p_status.add_argument("--routes", action="store_true", help="Validate expected routes exist (read-only)")
    p_status.add_argument("--routes-verbose", action="store_true", help="Include raw 'show ip route' output (human mode)")
    p_status.set_defaults(func=cmd_status)

    # test
    p_test = sub.add_parser(
        "test",
        help="Run tests (lab-name mode) or run an authoritative clean-state gate (topology.yaml mode)",
    )
    p_test.add_argument(
        "lab",
        nargs="?",
        help="Lab name OR topology file path (.yaml/.yml). "
            "If a topology path is provided, runs an authoritative clean-state gate "
            "(up → test → down) using the topology name (or filename stem). "
            "Optional when using --two-run (then provide --two-run-topology).",
            )
    p_test.add_argument(
        "--two-run",
        action="store_true",
        help="Run the authoritative gate twice (baseline then change) and write an evidence-only diff bundle. "
             "Requires --two-run-topology and --candidate-config.",
    )
    p_test.add_argument(
        "--two-run-topology",
        dest="two_run_topology",
        help="Topology YAML filename under ./topologies or a full path (used only with --two-run).",
    )
    p_test.add_argument("--name", help="Run only the test with this name (e.g. tests[4] or a named test)")
    p_test.add_argument("--kind", choices=["ping", "tcp"], help="Run only tests of this kind")
    p_test.add_argument("--tag", action="append", dest="tag", metavar="TAG", help="Run only tests carrying this tag (repeatable; OR-union). Mutually exclusive with --scenario.")
    p_test.add_argument(
        "--keep-going",
        action="store_true",
        help="Run all tests even if one fails (still exits non-zero if any fail)",
    )
    p_test.add_argument(
        "--json",
        action="store_true",
        help="Print results.json to stdout in addition to writing the file",
    )
    p_test.add_argument(
        "--candidate-config",
        dest="candidate_config",
        help="Apply candidate operational configs from a directory before running tests (gate-only, atomic). "
"Directory contract: frr/<node>.conf and/or nft/<node>.nft|.ruleset",
    )
    # Support both forms:
    #   cassian --verbose test ...
    #   cassian test ... --verbose
    p_test.add_argument(
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    p_test.set_defaults(func=cmd_test)
    p_test.add_argument("--scenario", help="Run only this scenario id (scenarios[*].id). Note: skips declared tests")
    p_test.add_argument("--all-scenarios", action="store_true", help="Run all scenarios. Note: skips declared tests")
    # capture-config (supporting evidence only; exploration feature) - explicitly forbidden in gate-first test
    p_test.add_argument(
        "--capture-config",
        action="store_true",
        help="Exploration evidence only (writes labs/<lab>/artifacts/capture_config/**). "
             "Forbidden in cassian test; will exit 2 if used.",
    )
    p_test.add_argument("--scenario-verbose", action="store_true", help="Print each scenario step as it runs (human-only; does not change artifacts)",)
    p_test.add_argument(
    "--precheck-controlplane",
    action="store_true",
    help="Run global control-plane prechecks (e.g., BGP wait) before executing scenarios. "
         "Default: off when --scenario/--all-scenarios is used.",
    )
        # State capture (supporting evidence only; never gates)
    p_test.add_argument(
        "--state-capture",
        default="none",
        choices=["none", "pre", "post", "both"],
        help="supporting evidence capture timing (none|pre|post|both). Non-authoritative; never affects verdicts.",
    )
    p_test.add_argument(
        "--state-profile",
        action="append",
        default=[],
        help=(
            "enable supporting evidence capture profile (repeatable). "
            "No implicit default; required when --state-capture != none."
        ),
    )
    p_test.add_argument(
        "--list-scenarios",
        action="store_true",
        help=(
            "List scenarios without deploy/execute. "
            "If given a topology file, scenarios are shown from post-Resolve expansion. "
            "If given a lab name, requires existing lab artifacts under labs/clab-<lab>/."
        ),
    )
    # run
    p_run = sub.add_parser("run", help="Ephemeral workflow: up -> test -> collect -> down (CI-friendly)")
    p_run.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    # Support both forms:
    #   cassian --verbose run ...
    #   cassian run ... --verbose
    p_run.add_argument(
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    p_run.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_run.add_argument(
        "--keep",
        action="store_true",
        help="Do not destroy the lab at the end (useful for debugging failures).",
    )
    p_run.add_argument(
        "--destroy-always",
        action="store_true",
        help="Attempt to destroy the lab even if up/test/collect fails.",
    )
    p_run.add_argument(
        "--no-collect",
        action="store_true",
        help="Skip collect (faster, but no artifacts).",
    )
    p_run.add_argument(
        "--capture-config",
        action="store_true",
        help="Exploration evidence only: capture host+live configs after provision "
             "into labs/<lab>/artifacts/capture_config/** (never gates).",
    )
    p_run.add_argument("--no-test", action="store_true", help="Skip test phase (still may collect/capture-config).")
    p_run.add_argument("--scenario", help="Run one declared scenario by id.")
    p_run.add_argument("--all-scenarios", action="store_true", help="Run all declared scenarios.")
    p_run.set_defaults(func=cmd_run)

    # ai (group)
    p_ai = sub.add_parser("ai", help="Unified advisory-only AI interface (artifact-only)")
    p_ai.add_argument("--online", action="store_true", help="Request online-enriched advisory rendering (explicit opt-in only)")
    p_ai.add_argument("question", nargs="*", help="Natural language advisory question")
    p_ai.add_argument("--lab", help="Explicit lab name (context priority 2)")
    p_ai.add_argument("--artifacts", help="Explicit artifacts directory (context priority 1)")
    p_ai.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    p_ai.set_defaults(func=cmd_ai_review)

    args = parser.parse_args()

    old_quiet = cassian_common.QUIET_RUN
    cassian_common.QUIET_RUN = (not bool(getattr(args, "verbose", False)))

    footer_lab = ""
    footer_authority = ""
    try:
        # Deterministic per-invocation resets (presentation-only).
        cassian_engine._PRIV_NOTICE_PRINTED = False
        _invocation_reset_written_artifacts()

        cmd_name = str(getattr(args, "cmd", "") or "").strip()
        invocation_workspace = Path.cwd()
        if _command_uses_workspace_labs(cmd_name):
            _bind_workspace_labs_dir(invocation_workspace)

        # Footer (WI-1a): gate-mode-only artifact footer (cassian test <topology.yaml>)
        if str(getattr(args, "cmd", "") or "") == "test":
            if not bool(getattr(args, "two_run", False)) and not bool(getattr(args, "list_scenarios", False)):
                footer_lab = str(getattr(args, "lab", "") or "").strip()

                # Determine authority kind deterministically for artifact labeling.
                # Prefer the command handler's explicit report authority; otherwise infer from input shape.
                footer_authority = str(getattr(args, "_report_authority", "") or "").strip().lower()
                if not footer_authority:
                    raw = footer_lab.lower()
                    footer_authority = "gate" if raw.endswith((".yaml", ".yml")) else "lab"

                # WI-1 (Set 6): only gate mode must emit the stable Artifacts footer.
                if footer_authority != "gate":
                    footer_lab = ""
                    footer_authority = ""

        try:
            args.func(args)
        except SystemExit:
            raise
        except Exception as e:
            # Quiet mode must never leak raw Python exception class names or tracebacks.
            # Verbose mode preserves the current raw traceback behavior.
            if bool(getattr(args, "verbose", False)):
                raise
            msg = str(e).strip()
            if not msg:
                msg = "unexpected error"
            die(f"ERROR: {msg}", code=1)
    finally:
        # Restore global quiet flag deterministically (commands may override temporarily)
        cassian_common.QUIET_RUN = old_quiet

        if footer_lab:
            _print_artifacts_footer_for_lab(footer_lab, authority_kind=footer_authority)

if __name__ == "__main__":
    main()
