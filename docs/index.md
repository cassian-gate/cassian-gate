# Cassian Gate

**Deterministic pre-production proof layer for network changes.**

[Get started :octicons-arrow-right-24:](quickstart.md){ .md-button .md-button--primary }
[Read the principles :octicons-arrow-right-24:](project-principles.md){ .md-button }

---

## What it is

Cassian Gate is an execution-backed validation gate for network changes. Engineers declare topology, tests, and scenarios; the gate runs them through a clean-state authoritative path and returns explicit PASS/FAIL outcomes backed by auditable artifacts. The posture is behavior-first, artifact-authoritative, CI-safe, and local-first.

## Where the authority line sits

Cassian Gate is not a general-purpose lab platform, not a chaos engine, not a controller, not a heuristic validator, not an AI decision system, and not a feature-parity NOS platform. AI surfaces remain advisory only — never authoritative. Exploratory workflows do not count as deployment authority.

For named, tool-by-tool disambiguation of the categories above and the blast-radius scale boundary, see [Scope and scale discipline](scope-discipline.md).

## Who it's for

Cassian Gate is built for network engineers who need proof before production, platform engineers who want a CI-safe gate around network changes, and teams that need machine-consumable artifacts instead of "probably safe" judgment. v2 ships the deterministic gate engine, FRR-based validation, named routing and policy invariants, scenario-based failure choreography, replay, blast radius, preflight, two-run comparison, candidate-config workflows, state capture, PCAP capture, and Terraform / Ansible adapters.

## Get started

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __Quickstart__

    ---

    Shortest path to an authoritative first PASS verdict from this repo.

    [:octicons-arrow-right-24: Get started](quickstart.md)

-   :material-book-open-variant:{ .lg .middle } __Topology Schema__

    ---

    Schema spec for topologies, invariants, scenarios, and state probes.

    [:octicons-arrow-right-24: Schema (v1.5)](topology-schema-v1.5.md)

-   :material-console-line:{ .lg .middle } __CLI Reference__

    ---

    Every `cassian` subcommand, its flags, and its exit codes.

    [:octicons-arrow-right-24: CLI Reference](cli-reference-v1.md)

-   :material-test-tube:{ .lg .middle } __Proof Kit__

    ---

    Sample topologies showing authoritative PASS and authoritative FAIL.

    [:octicons-arrow-right-24: Proof Kit](proof-kit.md)

-   :material-cog-outline:{ .lg .middle } __CI Integration__

    ---

    GitHub Actions and GitLab CI templates that gate merges on proof.

    [:octicons-arrow-right-24: CI Integration](ci/github-actions.md)

-   :material-scale-balance:{ .lg .middle } __Project principles__

    ---

    What Cassian Gate decides, and what it does not.

    [:octicons-arrow-right-24: Project principles](project-principles.md)

</div>
