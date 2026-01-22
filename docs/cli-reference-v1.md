---

# ai-netsim v1 CLI Reference

**Version:** v1 / v1.x
**Status:** STABLE
**Scope:** CLI surface (commands, flags, semantics)

This document lists supported CLI commands and their semantics in v1 / v1.x.

---

## 1) Core Commands

### `netsim gen <topology.yaml>`

**Purpose:** Generate containerlab artifacts from a topology.

* input: a topology YAML filename under `./topologies` or a full path
* output: generated lab artifacts under `labs/` (non-authoritative)

---

### `netsim validate <topology.yaml> [--json]`

**Purpose:** Validate topology + scenarios without deploying containers.

Flags:

* `--json`
  Emit machine-readable JSON output (CI-friendly).

---

### `netsim up <topology.yaml> [--reconfigure]`

**Purpose:** Generate and deploy a lab.

Flags:

* `--reconfigure`
  Destroy the existing lab first, then redeploy.

---

### `netsim down <name>`

**Purpose:** Destroy a deployed lab by name.

Arguments:

* `<name>` is the lab name (topology `name`).

---

### `netsim cleanup --all [--yes]`

**Purpose:** Safely clean up ai-netsim-owned labs found under `labs/`.

Flags:

* `--all` (required)
  Only targets ai-netsim labs that have artifact dirs under `labs/clab-*`.
  **Never scans Docker globally.**

* `--yes`
  Actually destroy labs listed in the plan.
  Artifacts are **not deleted**.

Default behavior:

* dry-run unless `--yes`

---

## 2) Exec and Inspection Helpers

### `netsim exec <lab> <node> [command...]`

**Purpose:** Execute a command inside a container.

Arguments:

* `<lab>`: lab name (topology `name`)
* `<node>`: node name (e.g., `r1`)
* `[command...]`: remainder arguments executed inside container

Behavior:

* if no command is provided, opens an interactive shell

---

### `netsim vty <lab> <node> "<vtysh command>"`

**Purpose:** Run a vtysh command on an FRR node.

Arguments:

* `<lab>`: lab name
* `<node>`: FRR node name
* `<vtysh command>`: one string, e.g. `"show bgp summary"`

---

### `netsim status <lab> [flags]`

**Purpose:** Show lab status (containers + optional FRR info).

Flags:

* `--bgp`
  Include `show bgp summary` for FRR nodes.

* `--bgp-verbose`
  Print full `show bgp summary` output.

* `--strict`
  Exit non-zero if any FRR peers are not `Established`.

* `--interfaces`
  Include `ip -br a` output per node.

* `--summary`
  Print a one-line summary at the end.

* `--json`
  Emit machine-readable JSON (no command echo).

* `--routes`
  Validate expected routes exist (read-only check).

* `--routes-verbose`
  Include raw `show ip route` output (human mode).

---

### `netsim collect <lab>`

**Purpose:** Collect runtime artifacts for a lab.

Arguments:

* `<lab>`: lab name

Notes:

* This is an operational helper. The authoritative artifacts remain `results.json` and `topology.resolved.yaml`.

---

## 3) Gate Command

### `netsim test <lab> [flags]`

**Purpose:** Run declared tests and scenarios for a lab.

**Authority:** This is the gate path (clean-state semantics are enforced by your operational workflow; the contract remains binding).

Arguments:

* `<lab>`: lab name (e.g. `three-frr-two-hosts-fw-routed`)

Test selection flags:

* `--name <test-name>`
  Run only the test with this name.

* `--kind ping|tcp`
  Run only tests of this kind.
  **Note:** this filter is limited to `ping|tcp` even though v1.x supports `bgp_neighbor` as an atomic test type.

* `--keep-going`
  Run all tests even if one fails (still exits non-zero if any fail).

Output flags:

* `--json`
  Print `results.json` to stdout in addition to writing the file.

Scenario flags:

* `--scenario <id>`
  Run only this scenario ID (`scenarios[*].id`).

* `--all-scenarios`
  Run all scenarios after steady-state tests.

* `--scenario-verbose`
  Print each scenario step as it runs (human-only; does not change artifacts).

Convergence control:

* `--precheck-controlplane`
  Run global control-plane prechecks (e.g., BGP wait) before executing scenarios.
  Default: off when `--scenario` / `--all-scenarios` is used.

Listing:

* `--list-scenarios`
  List scenarios from `labs/clab-<lab>/topology.resolved.yaml` (no deploy/execute).

---

## 4) One-shot Workflow (Non-authoritative)

### `netsim run <topology.yaml> [flags]`

**Purpose:** Ephemeral workflow: `up → test → collect → down`.

This is explicitly non-authoritative and primarily for exploration / convenience.

Flags:

* `--reconfigure`
  Destroy the existing lab first, then redeploy.

* `--keep`
  Do not destroy the lab at the end (useful for debugging failures).

* `--destroy-always`
  Attempt to destroy the lab even if up/test/collect fails.

* `--no-collect`
  Skip collect (faster, but no artifacts).

---

## 5) Assistive AI (Advisory Only)

### `netsim ai explain <target> [flags]`

**Purpose:** Explain a prior run using artifacts only.

Arguments:

* `<target>`: lab name or topology file (to resolve lab)

Common AI flags:

* `--bundle`
  Emit deterministic JSON bundle (no model) and exit 0.

* `--bundle-out <path>`
  Write bundle JSON to this path and exit 0.

* `--online`
  Attempt online model call (BYO key). Never gates; exit 0 on failure.

* `--model <name>`
  Override model name (else `AI_NETSIM_AI_MODEL`).

* `--format json|text`
  Output format (default: `json`, CI-safe).

Explain-only flags:

* `--strict-inputs`
  Usage error (exit 2) if required artifacts are missing.

* `--max-items <n>`
  Bound findings/suggestions deterministically (default: 50).

---

### `netsim ai review <topology.yaml> [flags]`

**Purpose:** Review topology tests/scenarios coverage (no execution).

Arguments:

* `<topology.yaml>`: topology file

Flags:

* same common AI flags as above
* `--max-items <n>` (default: 50)

---

### `netsim ai coach [flags]`

**Purpose:** Onboarding and guidance (no YAML generation).

Flags:

* same common AI flags as above

---

## 6) Exit Code Semantics

* `0`
  Success. For AI commands, `0` also covers “AI unavailable” cases.

* `2`
  Usage / input / artifact error (not a gate failure).

* non-zero (other)
  Hard execution failure (deploy/provision/runtime failure), or strict status failure.

---

**End of ai-netsim v1 CLI Reference**

---
