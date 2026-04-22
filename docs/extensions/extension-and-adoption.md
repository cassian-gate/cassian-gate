# Extensions and Adoption

Cassian Gate is a deterministic network validation engine.

This document defines the approved extension surface foundation introduced by Extension Set 1.

## Purpose

The purpose of this extension surface is to make repository structure and contributor intent explicit without changing engine behavior.

Extensions in this repository add declarative content and ecosystem organization only.

They do not add execution authority.

## Core boundary

The Cassian Gate core remains the only authority for:

- lifecycle execution
- pass/fail verdicts
- exit codes
- replay behavior
- authoritative artifact semantics
- AI authority boundaries

Nothing under `contrib/` changes those core authority surfaces by existing in the repository.

## What extension surfaces are for

The approved extension surfaces are bounded repository locations for declarative contribution content such as:

- packs
- scenarios
- topologies
- state profiles
- future NOS bundle structure

These surfaces exist so contributors and maintainers can distinguish ecosystem content from core engine code.

## What extension surfaces are not

These surfaces are not:

- executable plugins
- runtime hooks
- lifecycle hooks
- dynamic imports
- auto-discovery inputs
- implicit support claims
- verdict logic
- exit code control
- artifact authority

Cassian Gate does not support a plugin system here.

## Set 1 boundary

Extension Set 1 introduces structure and public contract only.

It does not introduce:

- runtime scanning
- runtime loading
- runtime registration
- contrib validation commands
- contrib schema enforcement
- NOS runtime support
- candidate-config extensions
- CLI changes
- artifact schema changes

## Approved extension categories

The approved structural categories are:

- `contrib/packs/`
- `contrib/scenarios/`
- `contrib/topologies/`
- `contrib/state-profiles/`
- `contrib/nos/`

These categories are structural only in Set 1.

## Declarative content only

Content under approved extension surfaces must remain declarative.

Examples include:

- YAML
- documentation
- bounded examples
- future-facing structural placeholders

Declarative content does not gain execution authority by being present in the repository.

## No lifecycle mutation

Contrib content cannot modify:

- resolve
- generate
- deploy
- provision
- test
- collect
- destroy

The lifecycle remains fixed and core-owned.

## No verdict or exit-code mutation

Contrib content cannot modify:

- pass/fail ownership
- failure semantics
- misuse semantics
- exit code mapping

## No artifact-authority mutation

Contrib content cannot make itself authoritative over:

- `topology.resolved.yaml`
- `results.json`
- `results.summary.txt`

Generated artifacts and authoritative artifacts remain core-defined.

## AI boundary unchanged

Contrib content cannot change the AI boundary.

AI remains advisory-only and non-authoritative.

## `contrib/nos/` boundary

`contrib/nos/` is structural only in Set 1.

Its presence does not mean:

- NOS bundles are operational in v2
- runtime discovery exists
- readiness integration exists
- supported vendor onboarding exists
- declarative NOS bundle execution exists

Declarative NOS bundle support belongs to later post-v2 work.

## Adoption meaning

The extension surface should help contributors understand where future approved declarative content belongs.

It should also help maintainers review scope cleanly and reject accidental authority creep.

## Support claim boundary

Repository structure alone must never be interpreted as current runtime support.

Future direction described in documentation is not a claim that the engine already supports that behavior.

## Summary

Extension Set 1 creates a bounded, reviewable, non-executable extension surface foundation.

It strengthens contributor clarity and adoption readiness without changing deterministic execution behavior.
