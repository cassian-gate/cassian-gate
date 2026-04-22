# Cassian Gate

Deterministic pre-production proof layer for network changes.

## What it is

Cassian Gate is an execution-backed validation gate for network changes. It lets engineers declare topology, tests, and scenarios, run them through a clean-state authoritative path, and get explicit PASS/FAIL outcomes with auditable artifacts. It is behavior-first, artifact-authoritative, CI-safe, local-first, and any AI usage remains advisory only.

## What it is not

Cassian Gate is not a general-purpose lab platform, not a chaos engine, not a controller, not a heuristic validator, not an AI decision system, and not a feature-parity NOS platform. It also does not treat exploratory workflows as deployment authority.

## Who it's for

Cassian Gate is for network engineers who need proof before production, platform or infrastructure engineers who want a CI-safe gate around network changes, and teams that need explicit machine-consumable artifacts instead of “probably safe” judgment.

## Who it's not yet for

Cassian Gate is not yet for teams expecting broad multi-vendor parity, teams that want exploratory lab workflows to count as authoritative validation, or teams that need commercial NOS coverage before adoption.

## Install

Primary public install path for the v2 release surface:

```bash
pipx install cassian-gate
```

Alternative:

```bash
pip install cassian-gate
```

For current repo-based usage and setup details, start with [`docs/quickstart.md`](docs/quickstart.md).

## Quick start

```bash
cassian doctor
cassian test topologies/first-run-proof-minimal.yaml
```

That gives you the shortest path to an authoritative first PASS verdict from this repository surface.

## Proof Kit

* Passing first-run proof: [`topologies/first-run-proof-minimal.yaml`](topologies/first-run-proof-minimal.yaml) — shortest path to a first authoritative PASS verdict proving the declared TCP flow is allowed.
* Fail-catching first-run proof: [`topologies/first-run-proof-fail-catching.yaml`](topologies/first-run-proof-fail-catching.yaml) — shows Cassian Gate returning an authoritative FAIL when the declared TCP expectation is wrong.
* Copy-paste GitHub Actions template: [`contrib/ci/cassian-gate-ci.yml`](contrib/ci/cassian-gate-ci.yml) — ready-to-copy CI workflow that runs the proof gate and uploads `results.json` and `topology.resolved.yaml`.

## What's in v2

v2 includes the deterministic gate engine, FRR-based validation, named routing and policy invariants, scenario-based failure choreography, grey failures, replay, blast radius, preflight, two-run comparison, candidate-config workflows, state capture, PCAP capture, Terraform and Ansible adapters, and advisory AI surfaces that remain outside authority.

## Links

* Docs index: [`docs/README.md`](docs/README.md)
* Quickstart: [`docs/quickstart.md`](docs/quickstart.md)
* Operator cheatsheet: [`docs/cheatsheet.md`](docs/cheatsheet.md)
* First-run proof family: [`contrib/topologies/first-run-proof/README.md`](contrib/topologies/first-run-proof/README.md)

## Future direction

Post-v2 expansion deepens FRR first, then adds SONiC as the next open NOS and Arista as the first commercial NOS, without weakening deterministic gate authority.
