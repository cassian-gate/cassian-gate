# Project principles

This page states what Cassian Gate decides on your behalf, what it deliberately does not, and where to read further. It is the project's authority-boundary reference — the answer to give a CI gate review, a vendor questionnaire, or a security team asking what this tool will and will not commit to.

## What Cassian Gate decides

Cassian Gate is an execution-backed validation gate for network changes. Engineers declare topology, tests, and scenarios; the gate runs the declaration through a clean-state authoritative path — starting from a defined initial condition every time, executing the declared scenario, reaching explicit PASS/FAIL outcomes with auditable artifacts. The verdict is bound to the declared expectation and recorded in `results.json` — the project's verdict of record, which downstream automation can consume directly. The same inputs produce the same artifact; the gate is deterministic under its declared semantics. The posture is behavior-first, artifact-authoritative, CI-safe, and local-first: the gate evaluates what the network does under declared conditions, the artifact carries the verdict, and the same run produces the same artifact in CI and on a laptop.

## What Cassian Gate does not decide

Cassian Gate is not a general-purpose lab platform, not a chaos engine, not a controller, not a heuristic validator, not an AI decision system, and not a feature-parity NOS platform. The gate also does not treat exploratory workflows as deployment authority — running an interactive lab session to understand a problem has value, but it isn't deployment authority. Only a recorded, artifact-backed, declared-expectation PASS is.

AI usage in the gate is advisory only. Models may suggest, summarize, or annotate; they never decide a verdict, never write a result, and never sit on the authority path between declared intent and recorded outcome. A FAIL verdict cannot be promoted to PASS by a model, a summary, or any non-authoritative tool.

For CI gate reviews, vendor questionnaires, and security teams: this tool does not make routing decisions, does not make policy decisions, does not make deployment decisions, and does not promote heuristic or AI judgments to authoritative status.

## Where to read more

- [Quickstart](quickstart.md) — shortest path to a first authoritative PASS verdict from this repository.
- [Topology Schema Reference](topology-schema-v1.5.md) — declared shape of topologies, tests, scenarios, and invariants.
- [CLI Reference](cli-reference-v1.md) — every `cassian` subcommand and its exit codes.
- [CI Integration](ci/GITHUB_ACTIONS.md) — gate-on-merge templates for GitHub Actions and GitLab CI.
- [Project README](https://github.com/cassian-gate/cassian-gate/blob/main/README.md) — full v2 capability list and v2.0 ship status.
