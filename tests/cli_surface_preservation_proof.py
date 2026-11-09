#!/usr/bin/env python3
"""HS-6 -- CLI surface preservation proof (Stage-1 gap item (d)(2), WI-7 script 3).

Proof obligation: PO-16, with its usage-error leg and the baseline proof against a 644fb20 worktree (handover
v9-rev3 section 15.1; Am-4 with R-1, Am-5). Requirement: REQ-S1D2-19. Acceptance checks: C-8 and C-25.
Founder rulings applied: LD-S1D2-3 (`checks` registered after `import`); section 6.1's root-parser delta, the only
permitted change to existing output; DC section 14 item 8 over the CLI surface; S1D2-S21-R2 (WI-7's third script).

PRESERVATION-PROOF HARNESS (section 3.1). The baseline below is 644fb20's help and usage bytes and exit codes,
captured once from a 644fb20 checkout and held in this file. It is not self-healing and is never recomputed: drift
is a failure signal. The only permitted delta is the fixed transform of section 6.1 (root_delta() below, three
parts), applied to the NEW output only, never to the baseline.

Baseline provenance: captured from cassian-gate@644fb2031a74cc7b658c28ba91e0b9d62377021f under python3.11 (3.11.18)
with COLUMNS=200, PYTHONDONTWRITEBYTECODE=1, from an empty temporary directory, by Chat 3 of (d)(2) session 22 on
2026-11-06; the same capture under python3.10 (3.10.20) and python3.12 (3.12.3) gave identical bytes, and python3.13
differs on `import --help`. Section 18 C-25 proves the baseline equal to 644fb20 on the WSL host:
`COLUMNS=200 python3.11 tests/cli_surface_preservation_proof.py --tree /tmp/cg644 --no-delta`.

Cases (37): the root (`--help`, no arguments, the invalid choice `zz-invalid`), `adapt --help`, `--help` for each
of the 20 leaves the 644fb20 parser registers, and, for each of the 13 of them whose required argument argparse
refuses when it is omitted, the leaf invoked with no arguments (a usage error, exit 2). Both lists were read from the
644fb20 parser. `ai` and `exec` also mark an argument required, but take it as `nargs="*"` and `nargs=REMAINDER`, so
argparse accepts them bare and their handlers answer instead; they are not usage errors and are not cases here.

Legs
  B   PO-16  for every case, `python3 -B <tree>/src/cassian.py <args>` with COLUMNS=200 from an empty temporary
             directory gives the baseline's exit code, stdout and stderr, byte for byte, after the root-delta
             transform is applied to the new output (unless --no-delta). Help outputs and usage errors are two legs.
  T   PO-16  the transform is exact: on the tree under test it changes the three root cases only, removing in
             each exactly the delta parts section 6.1 names (two choice sets and the `checks` help row in
             `--help`; one choice set in the no-arguments usage error; one choice set and one invalid-choice list
             entry in the invalid-choice error). Not run with --no-delta.
  N   MUTANTS a baseline entry altered in a temporary copy is reported by the comparator; the prototype delta (the
             root usage line, the choices line, one help row after `import`, the invalid-choice list), applied to
             the baseline's own root outputs, is fully removed by the transform and nothing else is; an
             unrelated extra help row survives the transform and is reported.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. Interpreter: the bytes are bound under the interpreter that runs this proof. At COLUMNS=200, over these cases
     at 644fb20, python3.10 (3.10.20), 3.11 (3.11.15, 3.11.18) and 3.12.3 give the baseline's bytes; on the WSL
     host this proof passes under 3.10.12 and 3.11.15. From 3.12.8 argparse prints the invalid-choice list without
     quotes (an argparse probe over 3.12.3 to 3.12.13; the full capture under 3.12.13 differs on that one case
     only), so the root invalid-choice error differs and the transform's invalid-choice part finds nothing to
     remove: this proof fails under 3.12.8 and later. python3.13 differs on `import --help`, and at COLUMNS=80 also
     on root `--help`, the invalid-choice error and the root no-arguments usage error. Run it under python3.11
     (C-8); CI step B's pinned 3.11 run is the binding one (C-26).
  2. The cases are the 37 above: an option's help text inside a leaf is covered by that leaf's `--help`; an
     argument value's own error message (other than a missing required argument) is not, nor is what the `ai` and
     `exec` handlers print when invoked bare.
  3. The transform matches the `{...,checks}` choice set, the `, 'checks'` invalid-choice entry and one line
     starting `    checks ` by text; it is applied to the new output only.

usage: python3.11 tests/cli_surface_preservation_proof.py [--tree PATH] [--no-delta]
       (from the repo root; writes nothing; --tree defaults to the repo this file is in)
"""
import argparse
import copy
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEAVES_644 = ("adapt ansible", "adapt terraform", "ai", "cleanup", "collect", "destroy", "doctor", "down", "exec",
              "gen", "import", "preflight", "replay", "run", "status", "test", "up", "validate", "validate-contrib",
              "vty")
REQUIRED_644 = ("adapt ansible", "adapt terraform", "collect", "destroy", "down", "gen", "import", "preflight",
                "replay", "run", "up", "validate", "validate-contrib")
ROOT_CASES = ("root --help", "root no-args", "root invalid choice")
HELP_CASES = [("root --help", ["--help"]), ("adapt --help", ["adapt", "--help"])]
HELP_CASES += [(f"{leaf} --help", leaf.split() + ["--help"]) for leaf in LEAVES_644]
USAGE_CASES = [("root no-args", []), ("root invalid choice", ["zz-invalid"])]
USAGE_CASES += [(f"{leaf} no-args", leaf.split()) for leaf in REQUIRED_644]

# Section 6.1's root-parser delta: what the transform removes from each root case, by part.
DELTA_EXPECTED = {"root --help": {"choice set": 2, "invalid-choice entry": 0, "help row": 1},
                  "root no-args": {"choice set": 1, "invalid-choice entry": 0, "help row": 0},
                  "root invalid choice": {"choice set": 1, "invalid-choice entry": 1, "help row": 0}}
CHOICE_SET = re.compile(r"\{([^{}\n]*),checks\}")
INVALID_ENTRY = ", 'checks')"
HELP_ROW = re.compile(r"(?m)^    checks {2,}[^\n]*\n")

# ---------------------------------------------------------------------------------------------------------------
# The 644fb20 baseline: case -> (exit code, stdout, stderr). Captured once; never recomputed.
# ---------------------------------------------------------------------------------------------------------------
BASELINE = {
    "root --help": (
        0,
        "usage: cassian [-h] [--verbose] {gen,validate,validate-contrib,doctor,preflight,adapt,up,replay,down,destroy,cleanup,exec,collect,vty,status,test,run,ai,import} ...\n"
        "\n"
        "Cassian Gate: deterministic network change validation gate\n"
        "\n"
        "positional arguments:\n"
        "  {gen,validate,validate-contrib,doctor,preflight,adapt,up,replay,down,destroy,cleanup,exec,collect,vty,status,test,run,ai,import}\n"
        "    gen                 Generate containerlab file from topology\n"
        "    validate            Validate topology + scenarios (no lab, no containers)\n"
        "    validate-contrib    Validate contrib content structurally (no lifecycle, no artifacts)\n"
        "    doctor              Read-only environment readiness checks (no mutation)\n"
        "    preflight           Advisory static preflight (declared-only; no execution)\n"
        "    adapt               Read-only input adapters (advisory-only)\n"
        "    up                  Generate + deploy\n"
        "    replay              Deterministically re-execute a prior run using its artifacts as authoritative inputs\n"
        "    down                Destroy a deployed lab by name\n"
        "    destroy             Destroy a lab runtime; keep artifacts unless --purge-artifacts\n"
        "    cleanup             Safely clean up Cassian Gate-owned labs found under labs/ (dry-run unless --yes)\n"
        "    exec                Exec a command inside a node container; if no command, open bash\n"
        "    collect             Collect runtime artifacts for a lab\n"
        "    vty                 Run a vtysh command easily\n"
        "    status              Show lab status (containers + optional BGP summary)\n"
        "    test                Run tests (lab-name mode) or run an authoritative clean-state gate (topology.yaml mode)\n"
        "    run                 Ephemeral workflow: up -> test -> collect -> down (CI-friendly)\n"
        "    ai                  Unified advisory-only AI interface (artifact-only)\n"
        "    import              Import brownfield sources into an authoritative (topology, starter_invariants) pair\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --verbose             Print full raw command trace + containerlab logs (debug). Default is quiet gate output.\n"
        "\n"
        "Quick help:\n"
        "  cassian test <topology.yaml>              (authoritative gate)\n"
        "  cassian replay <artifact-dir> --gate      (authoritative replay)\n"
        "  cassian replay -h                         (replay options)\n",
        "",
    ),
    "adapt --help": (
        0,
        "usage: cassian adapt [-h] {terraform,ansible} ...\n"
        "\n"
        "positional arguments:\n"
        "  {terraform,ansible}\n"
        "    terraform          Adapt Terraform plan JSON (terraform show -json)\n"
        "    ansible            Adapt rendered Ansible output directory (read-only)\n"
        "\n"
        "options:\n"
        "  -h, --help           show this help message and exit\n",
        "",
    ),
    "adapt ansible --help": (
        0,
        "usage: cassian adapt ansible [-h] --dir DIR [--out OUT] [--strict]\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n"
        "  --dir DIR   Path to rendered Ansible output directory\n"
        "  --out OUT   Output directory (default: artifacts/adapters/)\n"
        "  --strict    Fail (exit 1) if parse_errors are present\n",
        "",
    ),
    "adapt terraform --help": (
        0,
        "usage: cassian adapt terraform [-h] --plan PLAN [--out OUT] [--strict]\n"
        "\n"
        "options:\n"
        "  -h, --help   show this help message and exit\n"
        "  --plan PLAN  Path to terraform plan JSON (terraform show -json)\n"
        "  --out OUT    Output directory (default: artifacts/adapters/)\n"
        "  --strict     Fail (exit 1) if parse_errors are present\n",
        "",
    ),
    "ai --help": (
        0,
        "usage: cassian ai [-h] [--online] [--lab LAB] [--artifacts ARTIFACTS] [--format {json,text}] [question ...]\n"
        "\n"
        "positional arguments:\n"
        "  question              Natural language advisory question\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --online              Request online-enriched advisory rendering (explicit opt-in only)\n"
        "  --lab LAB             Explicit lab name (context priority 2)\n"
        "  --artifacts ARTIFACTS\n"
        "                        Explicit artifacts directory (context priority 1)\n"
        "  --format {json,text}  Output format\n",
        "",
    ),
    "cleanup --help": (
        0,
        "usage: cassian cleanup [-h] [--all] [--yes]\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n"
        "  --all       Required. Only targets Cassian Gate labs with artifact dirs under labs/clab-* (never scans Docker).\n"
        "  --yes       Actually destroy labs listed in the plan (artifacts are NOT deleted).\n",
        "",
    ),
    "collect --help": (
        0,
        "usage: cassian collect [-h] lab\n"
        "\n"
        "positional arguments:\n"
        "  lab         Lab name (topology 'name')\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        "",
    ),
    "destroy --help": (
        0,
        "usage: cassian destroy [-h] [--strict] [--purge-artifacts] name\n"
        "\n"
        "positional arguments:\n"
        "  name               Lab name (topology 'name')\n"
        "\n"
        "options:\n"
        "  -h, --help         show this help message and exit\n"
        "  --strict           Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).\n"
        "  --purge-artifacts  Also delete labs/clab-<lab> artifacts after runtime teardown attempt.\n",
        "",
    ),
    "doctor --help": (
        0,
        "usage: cassian doctor [-h]\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        "",
    ),
    "down --help": (
        0,
        "usage: cassian down [-h] [--strict] name\n"
        "\n"
        "positional arguments:\n"
        "  name        Lab name (topology 'name')\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n"
        "  --strict    Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).\n",
        "",
    ),
    "exec --help": (
        0,
        "usage: cassian exec [-h] [lab] [node] ...\n"
        "\n"
        "positional arguments:\n"
        "  lab         Lab name (topology 'name')\n"
        "  node        Node name (e.g. r1)\n"
        "  command     Command to run inside container\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        "",
    ),
    "gen --help": (
        0,
        "usage: cassian gen [-h] topology\n"
        "\n"
        "positional arguments:\n"
        "  topology    Topology YAML filename under ./topologies or a full path\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        "",
    ),
    "import --help": (
        0,
        "usage: cassian import [-h] -o OUT [--backend BACKEND] source\n"
        "\n"
        "positional arguments:\n"
        "  source             Brownfield source directory (e.g. a committed NetBox export + rendered configs)\n"
        "\n"
        "options:\n"
        "  -h, --help         show this help message and exit\n"
        "  -o OUT, --out OUT  Output directory for the emitted authoritative pair\n"
        "  --backend BACKEND  Importer backend (default: netbox)\n",
        "",
    ),
    "preflight --help": (
        0,
        "usage: cassian preflight [-h] [--format {json,text}] [--out OUT] [--adapter ADAPTER] topology\n"
        "\n"
        "positional arguments:\n"
        "  topology              Topology YAML filename under ./topologies or a full path\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --format {json,text}  Output format\n"
        "  --out OUT             Output path (default: artifacts/preflight/preflight.json)\n"
        "  --adapter ADAPTER     Path to an adapters.v1 JSON (repeatable; advisory-only)\n",
        "",
    ),
    "replay --help": (
        0,
        "usage: cassian replay [-h] [--gate] [--verify-results] [--verbose] artifacts\n"
        "\n"
        "positional arguments:\n"
        "  artifacts         Artifact directory containing topology.resolved.yaml and results.json (authoritative inputs)\n"
        "\n"
        "options:\n"
        "  -h, --help        show this help message and exit\n"
        "  --gate            Run authoritative clean-state gate replay (generate→deploy→provision→test→collect→destroy).\n"
        "  --verify-results  (Opt-in) Verify replay results match the source verdict core (semantic equivalence). Mismatch exits 1. Default: off.\n"
        "  --verbose         Print full raw command trace + containerlab logs (debug). Default is quiet gate output.\n",
        "",
    ),
    "run --help": (
        0,
        "usage: cassian run [-h] [--verbose] [--reconfigure] [--keep] [--destroy-always] [--no-collect] [--capture-config] [--no-test] [--scenario SCENARIO] [--all-scenarios] topology\n"
        "\n"
        "positional arguments:\n"
        "  topology             Topology YAML filename under ./topologies or a full path\n"
        "\n"
        "options:\n"
        "  -h, --help           show this help message and exit\n"
        "  --verbose            Print full raw command trace + containerlab logs (debug). Default is quiet gate output.\n"
        "  --reconfigure        Destroy the existing lab first, then redeploy (safe for generated bind-mount files).\n"
        "  --keep               Do not destroy the lab at the end (useful for debugging failures).\n"
        "  --destroy-always     Attempt to destroy the lab even if up/test/collect fails.\n"
        "  --no-collect         Skip collect (faster, but no artifacts).\n"
        "  --capture-config     Exploration evidence only: capture host+live configs after provision into labs/<lab>/artifacts/capture_config/** (never gates).\n"
        "  --no-test            Skip test phase (still may collect/capture-config).\n"
        "  --scenario SCENARIO  Run one declared scenario by id.\n"
        "  --all-scenarios      Run all declared scenarios.\n",
        "",
    ),
    "status --help": (
        0,
        "usage: cassian status [-h] [--bgp] [--bgp-verbose] [--strict] [--interfaces] [--summary] [--json] [--routes] [--routes-verbose] [lab]\n"
        "\n"
        "positional arguments:\n"
        "  lab               Lab name (topology 'name')\n"
        "\n"
        "options:\n"
        "  -h, --help        show this help message and exit\n"
        "  --bgp             Include 'show bgp summary' for FRR nodes\n"
        "  --bgp-verbose     Print full 'show bgp summary' output\n"
        "  --strict          Exit non-zero if any FRR peers are not Established\n"
        "  --interfaces      Include 'ip -br a' output per node\n"
        "  --summary         Print a one-line summary at the end\n"
        "  --json            Emit machine-readable JSON (no command echo)\n"
        "  --routes          Validate expected routes exist (read-only)\n"
        "  --routes-verbose  Include raw 'show ip route' output (human mode)\n",
        "",
    ),
    "test --help": (
        0,
        "usage: cassian test [-h] [--two-run] [--two-run-topology TWO_RUN_TOPOLOGY] [--name NAME] [--kind {ping,tcp}] [--tag TAG] [--keep-going] [--json] [--candidate-config CANDIDATE_CONFIG] [--verbose]\n"
        "                    [--scenario SCENARIO] [--all-scenarios] [--capture-config] [--scenario-verbose] [--precheck-controlplane] [--state-capture {none,pre,post,both}] [--state-profile STATE_PROFILE]\n"
        "                    [--list-scenarios]\n"
        "                    [lab]\n"
        "\n"
        "positional arguments:\n"
        "  lab                   Lab name OR topology file path (.yaml/.yml). If a topology path is provided, runs an authoritative clean-state gate (up → test → down) using the topology name (or filename\n"
        "                        stem). Optional when using --two-run (then provide --two-run-topology).\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --two-run             Run the authoritative gate twice (baseline then change) and write an evidence-only diff bundle. Requires --two-run-topology and --candidate-config.\n"
        "  --two-run-topology TWO_RUN_TOPOLOGY\n"
        "                        Topology YAML filename under ./topologies or a full path (used only with --two-run).\n"
        "  --name NAME           Run only the test with this name (e.g. tests[4] or a named test)\n"
        "  --kind {ping,tcp}     Run only tests of this kind\n"
        "  --tag TAG             Run only tests carrying this tag (repeatable; OR-union). Mutually exclusive with --scenario.\n"
        "  --keep-going          Run all tests even if one fails (still exits non-zero if any fail)\n"
        "  --json                Print results.json to stdout in addition to writing the file\n"
        "  --candidate-config CANDIDATE_CONFIG\n"
        "                        Apply candidate operational configs from a directory before running tests (gate-only, atomic). Directory contract: frr/<node>.conf and/or nft/<node>.nft|.ruleset\n"
        "  --verbose             Print full raw command trace + containerlab logs (debug). Default is quiet gate output.\n"
        "  --scenario SCENARIO   Run only this scenario id (scenarios[*].id). Note: skips declared tests\n"
        "  --all-scenarios       Run all scenarios. Note: skips declared tests\n"
        "  --capture-config      Exploration evidence only (writes labs/<lab>/artifacts/capture_config/**). Forbidden in cassian test; will exit 2 if used.\n"
        "  --scenario-verbose    Print each scenario step as it runs (human-only; does not change artifacts)\n"
        "  --precheck-controlplane\n"
        "                        Run global control-plane prechecks (e.g., BGP wait) before executing scenarios. Default: off when --scenario/--all-scenarios is used.\n"
        "  --state-capture {none,pre,post,both}\n"
        "                        supporting evidence capture timing (none|pre|post|both). Non-authoritative; never affects verdicts.\n"
        "  --state-profile STATE_PROFILE\n"
        "                        enable supporting evidence capture profile (repeatable). No implicit default; required when --state-capture != none.\n"
        "  --list-scenarios      List scenarios without deploy/execute. If given a topology file, scenarios are shown from post-Resolve expansion. If given a lab name, requires existing lab artifacts under\n"
        "                        labs/clab-<lab>/.\n",
        "",
    ),
    "up --help": (
        0,
        "usage: cassian up [-h] [--reconfigure] topology\n"
        "\n"
        "positional arguments:\n"
        "  topology       Topology YAML filename under ./topologies or a full path\n"
        "\n"
        "options:\n"
        "  -h, --help     show this help message and exit\n"
        "  --reconfigure  Destroy the existing lab first, then redeploy (safe for generated bind-mount files).\n",
        "",
    ),
    "validate --help": (
        0,
        "usage: cassian validate [-h] [--json] topology\n"
        "\n"
        "positional arguments:\n"
        "  topology    Topology YAML filename under ./topologies or a full path\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n"
        "  --json      Emit machine-readable JSON (CI-friendly)\n",
        "",
    ),
    "validate-contrib --help": (
        0,
        "usage: cassian validate-contrib [-h] [--json] contrib_path\n"
        "\n"
        "positional arguments:\n"
        "  contrib_path  Explicit contrib path to validate\n"
        "\n"
        "options:\n"
        "  -h, --help    show this help message and exit\n"
        "  --json        Emit machine-readable JSON\n",
        "",
    ),
    "vty --help": (
        0,
        "usage: cassian vty [-h] [lab] [node] [command]\n"
        "\n"
        "positional arguments:\n"
        "  lab         Lab name (topology 'name')\n"
        "  node        Node name (e.g. r1)\n"
        "  command     vtysh command as one string, e.g. \"show bgp summary\"\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        "",
    ),
    "root no-args": (
        2,
        "",
        "usage: cassian [-h] [--verbose] {gen,validate,validate-contrib,doctor,preflight,adapt,up,replay,down,destroy,cleanup,exec,collect,vty,status,test,run,ai,import} ...\n"
        "cassian: error: the following arguments are required: cmd\n",
    ),
    "root invalid choice": (
        2,
        "",
        "usage: cassian [-h] [--verbose] {gen,validate,validate-contrib,doctor,preflight,adapt,up,replay,down,destroy,cleanup,exec,collect,vty,status,test,run,ai,import} ...\n"
        "cassian: error: argument cmd: invalid choice: 'zz-invalid' (choose from 'gen', 'validate', 'validate-contrib', 'doctor', 'preflight', 'adapt', 'up', 'replay', 'down', 'destroy', 'cleanup', 'exec', 'collect', 'vty', 'status', 'test', 'run', 'ai', 'import')\n",
    ),
    "adapt ansible no-args": (
        2,
        "",
        "usage: cassian adapt ansible [-h] --dir DIR [--out OUT] [--strict]\n"
        "cassian adapt ansible: error: the following arguments are required: --dir\n",
    ),
    "adapt terraform no-args": (
        2,
        "",
        "usage: cassian adapt terraform [-h] --plan PLAN [--out OUT] [--strict]\n"
        "cassian adapt terraform: error: the following arguments are required: --plan\n",
    ),
    "collect no-args": (
        2,
        "",
        "usage: cassian collect [-h] lab\n"
        "cassian collect: error: the following arguments are required: lab\n",
    ),
    "destroy no-args": (
        2,
        "",
        "usage: cassian destroy [-h] [--strict] [--purge-artifacts] name\n"
        "cassian destroy: error: the following arguments are required: name\n",
    ),
    "down no-args": (
        2,
        "",
        "usage: cassian down [-h] [--strict] name\n"
        "cassian down: error: the following arguments are required: name\n",
    ),
    "gen no-args": (
        2,
        "",
        "usage: cassian gen [-h] topology\n"
        "cassian gen: error: the following arguments are required: topology\n",
    ),
    "import no-args": (
        2,
        "",
        "usage: cassian import [-h] -o OUT [--backend BACKEND] source\n"
        "cassian import: error: the following arguments are required: source, -o/--out\n",
    ),
    "preflight no-args": (
        2,
        "",
        "usage: cassian preflight [-h] [--format {json,text}] [--out OUT] [--adapter ADAPTER] topology\n"
        "cassian preflight: error: the following arguments are required: topology\n",
    ),
    "replay no-args": (
        2,
        "",
        "usage: cassian replay [-h] [--gate] [--verify-results] [--verbose] artifacts\n"
        "cassian replay: error: the following arguments are required: artifacts\n",
    ),
    "run no-args": (
        2,
        "",
        "usage: cassian run [-h] [--verbose] [--reconfigure] [--keep] [--destroy-always] [--no-collect] [--capture-config] [--no-test] [--scenario SCENARIO] [--all-scenarios] topology\n"
        "cassian run: error: the following arguments are required: topology\n",
    ),
    "up no-args": (
        2,
        "",
        "usage: cassian up [-h] [--reconfigure] topology\n"
        "cassian up: error: the following arguments are required: topology\n",
    ),
    "validate no-args": (
        2,
        "",
        "usage: cassian validate [-h] [--json] topology\n"
        "cassian validate: error: the following arguments are required: topology\n",
    ),
    "validate-contrib no-args": (
        2,
        "",
        "usage: cassian validate-contrib [-h] [--json] contrib_path\n"
        "cassian validate-contrib: error: the following arguments are required: contrib_path\n",
    ),
}

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


def root_delta(text):
    """Section 6.1's fixed transform, applied to new output only: (transformed text, counts by part)."""
    text, n_sets = CHOICE_SET.subn(r"{\1}", text)
    n_entries = text.count(INVALID_ENTRY)
    text = text.replace(INVALID_ENTRY, ")")
    text, n_rows = HELP_ROW.subn("", text)
    return text, {"choice set": n_sets, "invalid-choice entry": n_entries, "help row": n_rows}


def run_case(tree, argv):
    env = dict(os.environ, COLUMNS="200", PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([sys.executable, "-B", str(Path(tree) / "src" / "cassian.py"), *argv], cwd=td,
                           capture_output=True, timeout=300, env=env)
        left = os.listdir(td)
    return r.returncode, r.stdout.decode("utf-8"), r.stderr.decode("utf-8") + (f"(files left: {left})" if left else "")


def compare(results, baseline, delta):
    """Mismatches of results against the baseline, after the transform on the new side when delta is on."""
    bad, counts = [], {}
    for name, (rc, out, err) in results.items():
        if delta:
            out, c_out = root_delta(out)
            err, c_err = root_delta(err)
            counts[name] = {k: c_out[k] + c_err[k] for k in c_out}
        want = baseline.get(name)
        if want is None:
            bad.append(f"{name}: no baseline entry")
            continue
        for part, got, exp in (("exit code", rc, want[0]), ("stdout", out, want[1]), ("stderr", err, want[2])):
            if got != exp:
                where = ""
                if isinstance(got, str):
                    gl, el = got.splitlines(), exp.splitlines()
                    i = next((i for i, (a, b) in enumerate(zip(gl, el)) if a != b), min(len(gl), len(el)))
                    where = f" at line {i + 1}"
                bad.append(f"{name}: {part} differs{where}")
    return bad, counts


def main():
    ap = argparse.ArgumentParser(prog="cli_surface_preservation_proof")
    ap.add_argument("--tree", default=str(ROOT), help="the cassian-gate tree to test (default: this repo)")
    ap.add_argument("--no-delta", action="store_true", help="disable the root-delta transform (C-25, at 644fb20)")
    opts = ap.parse_args()
    delta = not opts.no_delta
    tree = Path(opts.tree).resolve()
    if not (tree / "src" / "cassian.py").is_file():
        print(f"RESULT: FAIL (no src/cassian.py under --tree {opts.tree})")
        sys.exit(1)
    print(f"mode: {'root-delta transform on the new output' if delta else '--no-delta (baseline proof)'}; "
          f"{len(HELP_CASES) + len(USAGE_CASES)} cases; COLUMNS=200", flush=True)

    results = {name: run_case(tree, argv) for name, argv in HELP_CASES + USAGE_CASES}
    for label, cases in (("help outputs (root, adapt, the 20 leaves)", HELP_CASES),
                         ("usage errors (root no-args, invalid choice, the 13 leaves argparse refuses bare)",
                          USAGE_CASES)):
        part = {name: results[name] for name, _argv in cases}
        bad, _counts = compare(part, BASELINE, delta)
        codes = sorted({rc for rc, _o, _e in part.values()})
        check(f"B PO-16 {label}: exit code, stdout and stderr equal 644fb20's baseline", not bad,
              "; ".join(bad[:3]) + (f" (+{len(bad) - 3} more)" if len(bad) > 3 else "") if bad
              else f"{len(cases)} cases, exit codes {codes}")

    if delta:
        _bad, counts = compare(results, BASELINE, True)
        wrong = [f"{n}: {c}" for n, c in counts.items()
                 if c != DELTA_EXPECTED.get(n, {"choice set": 0, "invalid-choice entry": 0, "help row": 0})]
        check("T PO-16 the transform removes exactly section 6.1's delta parts, in the three root cases only",
              not wrong, "; ".join(wrong[:3]) if wrong else
              "; ".join(f"{n}: {sum(DELTA_EXPECTED[n].values())} parts" for n in ROOT_CASES))

    # N: the comparator and the transform can fail.
    altered = copy.deepcopy(BASELINE)
    rc, out, err = altered["doctor --help"]
    altered["doctor --help"] = (rc, out.replace("doctor", "doctoR", 1), err)
    bad, _c = compare({"doctor --help": BASELINE["doctor --help"]}, altered, False)
    check("N PO-16 a baseline entry altered in a temporary copy is reported by the comparator",
          bad == ["doctor --help: stdout differs at line 1"], "; ".join(bad) or "comparator held")
    proto = {}
    for name in ROOT_CASES:
        rc, out, err = BASELINE[name]
        proto[name] = (rc, *(re.sub(r"\{([^{}\n]*,import)\}", r"{\1,checks}", t)
                             .replace("'import')", "'import', 'checks')") for t in (out, err)))
    rc, out, err = proto["root --help"]
    lines = out.split("\n")
    i = next(i for i, ln in enumerate(lines) if ln.startswith("    import "))
    lines.insert(i + 1, "    checks              Print the capability catalogue (prototype row)")
    proto["root --help"] = (rc, "\n".join(lines), err)
    bad, counts = compare(proto, BASELINE, True)
    exact = all(counts[n] == DELTA_EXPECTED[n] for n in ROOT_CASES)
    check("N PO-16 the prototype delta (usage line, choices line, help row after import, invalid-choice list) "
          "is fully removed by the transform", not bad and exact and proto["root --help"][1] != BASELINE["root --help"][1],
          "; ".join(bad) or ("; ".join(f"{n}: {counts[n]}" for n in ROOT_CASES)))
    rc, out, err = proto["root --help"]
    extra = (rc, out.replace("    checks ", "    zz-extra            an unrelated row\n    checks ", 1), err)
    bad, _c = compare({"root --help": extra}, BASELINE, True)
    check("N PO-16 an unrelated extra help row survives the transform and is reported",
          len(bad) == 1 and bad[0].startswith("root --help: stdout differs"), "; ".join(bad) or "transform removed it")

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
