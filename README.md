# Cassian Gate

Cassian Gate is a deterministic, evidence-first network change validation gate.

It is designed to let engineers validate intended network behavior before production changes are applied, using explicit topologies, tests, scenarios, and authoritative artifacts.

Cassian Gate is:

- deterministic in authoritative execution semantics
- artifact-authoritative for machine-consumable results
- CI-safe and gate-oriented
- local-first and engineer-friendly
- optionally AI-assisted in an advisory-only role

Cassian Gate is not:

- a general lab platform
- a chaos engine
- a heuristic validator
- an AI decision system
- a scripting engine for validation authority

## Start here

For the main documentation entry point, see:

- [`docs/README.md`](docs/README.md)

For a guided first pass, see:

- [`docs/quickstart.md`](docs/quickstart.md)

For command reference, see:

- [`docs/cheatsheet.md`](docs/cheatsheet.md)

## Current repo note

This cleanup pass is focused on the current repository surface.

Packaging and public install-path refinement may be completed in a later pass. Until then, treat the documentation in `docs/` as the authoritative operator-facing surface for current usage.

## Project purpose

Cassian Gate exists to replace guesswork with proof.

It validates behavior through explicit tests, scenarios, and authoritative artifacts so network changes can be checked before they reach production.
