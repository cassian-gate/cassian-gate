---

# Cassian Gate v1 CLI Reference

**Version:** v1 / v1.x  
**Status:** STABLE  
**Scope:** CLI surface (commands, flags, semantics)

This document lists supported CLI commands and their semantics in v1 / v1.x.

---

## 1) Core Commands

### `cassian gen <topology.yaml>`

**Purpose:** Generate containerlab artifacts from a topology.

* input: a topology YAML filename under `./topologies` or a full path
* output: generated lab artifacts under `labs/` (non-authoritative)

---

### `cassian validate <topology.yaml> [--json]`

**Purpose:** Validate topology + scenarios without deploying containers.

Flags:

* `--json`  
  Emit machine-readable JSON output (CI-friendly).

---

### `cassian up <topology.yaml> [--reconfigure]`

**Purpose:** Generate and deploy a lab.

Flags:

* `--reconfigure`  
  Destroy the existing lab first, then redeploy.

---

### `cassian down <name>`

**Purpose:** Destroy a deployed lab by name.

Arguments:

* `<name>` is the lab name (topology `name`).

---

### `cassian cleanup --all [--yes]`

**Purpose:** Safely clean up Cassian Gate-owned labs found under `labs/`.

Flags:

* `--all` (required)  
  Only targets Cassian Gate labs that have artifact dirs under `labs/clab-*`.  
  **Never scans Docker globally.**

* `--yes`  
  Actually destroy labs listed in the plan.  
  Artifacts are **not deleted**.

Default behavior:

* dry-run unless `--yes`

---

## 2) Exec and Inspection Helpers

### `cassian exec <lab> <node> [command...]`

**Purpose:** Execute a command inside a container.

Arguments:

* `<lab>`: lab name (topology `name`)
* `<node>`: node name (e.g., `r1`)
* `[command...]`: remainder arguments executed inside container

Behavior:

* if no command is provided, opens an interactive shell

---

### `cassian vty <lab> <node> "<vtysh command>"`

**Purpose:** Run a vtysh command on an FRR node.

Arguments:

* `<lab>`: lab name
* `<node>`: FRR node name
* `<vtysh command>`: one string, e.g. `"show bgp summary"`

---

### `cassian status <lab> [flags]`

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

### `cassian collect <lab>`

**Purpose:** Collect runtime artifacts for a lab.

Arguments:

* `<lab>`: lab name

Notes:

* This is an operational helper. The authoritative artifacts remain `results.json` and `topology.resolved.yaml`.

---

## 3) Gate Command

### `cassian test <lab> [flags]`

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

State capture flags:

* `--state-capture {none, pre, post, both}`  
  When to run state-capture probes. `none` disables (default), `pre` runs probes before tests, `post` runs after, `both` runs at both points. Captures are written as non-authoritative supporting evidence and never change verdicts, exit codes, or authoritative artifacts.

* `--state-profile <name>` (repeatable)  
  Select which built-in state-capture profile(s) to run. Repeat the flag to run multiple profiles in one invocation. Required when `--state-capture` is not `none`. The built-in profiles are:

    * `frr-routing-basic` — IPv4 and IPv6 routing tables from FRR zebra (`show ip route json`, `show ipv6 route json`).
    * `frr-bgp-basic` — BGP control-plane state from FRR bgpd (summary, neighbors, IPv4-unicast prefixes).
    * `frr-ospf-basic` — OSPFv2 state from FRR ospfd (neighbors, interfaces, LSA database). Requires the topology to declare an `ospf:` block.
    * `frr-interfaces-basic` — interface admin/operational state on FRR nodes via Linux iproute2 `ip -j link show` and `ip -j addr show` (not vtysh). Pairs naturally with the `interface_state` invariant.
    * `frr-comprehensive` — aggregate of the four FRR profiles above (10 commands). OSPF commands included unconditionally; produce empty/non-fatal output on non-OSPF topologies.
    * `linux-net-basic` — basic interface, route, and neighbor state on Linux hosts (`ip addr`, `ip link`, `ip route`, `ip neigh`).
    * `linux-sockets-basic` — listening TCP/UDP sockets on Linux hosts (`ss -tulpn`).
    * `nft-ruleset-basic` — nftables ruleset on nft-fw firewall nodes (`nft list ruleset`).
    * `linux-forwarding-basic` — IP forwarding and rp_filter sysctls on nft-fw nodes (`net.ipv4.ip_forward`, `net.ipv4.conf.all.rp_filter`, `net.ipv4.conf.default.rp_filter`).

  Full per-profile descriptions live in `contrib/state-profiles/README.md`.

---

## 4) One-shot Workflow (Non-authoritative)

### `cassian run <topology.yaml> [flags]`

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

### `cassian ai`

**Purpose:** Optional advisory AI entrypoint.

Behavior:

* explicitly invoked by the operator
* advisory only
* non-authoritative
* never changes verdicts, exit codes, lifecycle execution, or authoritative artifacts

Notes:

* shipped AI behavior must be described only through the `cassian ai` entrypoint
* AI guidance remains outside the authority chain
* absence or unavailability of AI does not weaken deterministic engine behavior

---

## 6) Exit Code Semantics

* `0`  
  Success.

* `2`  
  Usage / input / artifact error (not a gate failure).

* non-zero (other)  
  Hard execution failure (deploy/provision/runtime failure), or strict status failure.

---

**End of Cassian Gate v1 CLI Reference**

---