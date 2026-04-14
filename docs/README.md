# Cassian Gate

Cassian Gate is a deterministic, artifact-authoritative network change-validation gate for engineers who want proof before production changes.

It validates declared network behavior through deterministic execution, authoritative artifacts, and explicit pass/fail outcomes before deployment.

Cassian Gate is **not**:
- a general-purpose network lab platform
- a controller
- a chaos engine
- a heuristic validator
- an AI decision system
- a feature-parity multi-NOS platform

Cassian Gate is for:
- network engineers validating planned changes before production
- platform and infrastructure engineers who need a CI-safe network gate
- teams that want deterministic artifacts and explicit authority boundaries

Cassian Gate is **not yet** for:
- teams looking for a broad network automation platform
- users expecting generic NOS feature parity across vendors
- users wanting exploratory labs or AI-driven decisions to act as deployment authority

**Status:** AUTHORITATIVE  
**Audience:** Network engineers, platform engineers, CI/CD operators  
**Scope:** Active Cassian Gate documentation surface in this repository

This directory contains the active documentation for **Cassian Gate**.

These documents explain:
- how Cassian Gate should be used
- which surfaces are authoritative
- which materials are supporting only
- where internal or historical documentation has been separated from the active docs surface

If documentation here conflicts with implementation at the level of authority, lifecycle meaning, or intended behavior, the documented contract and locked project doctrine govern.

---

## Start here

Recommended reading order:

1. `design-contract.md`  
   The authoritative behavioral contract.

2. `admin-guide-v1.md`  
   The operator mental model, authority boundaries, and correct usage.

3. `topology-schema-v1.md`  
   The topology input model and validation semantics.

4. `cli-reference-v1.md`  
   The command and flag reference.

5. `quickstart.md`  
   The fastest path to running the repo successfully.

6. `cheatsheet.md`  
   A broader operator reference with examples.

---

## Active documentation surface

### Core docs

- `design-contract.md`
- `admin-guide-v1.md`
- `topology-schema-v1.md`
- `cli-reference-v1.md`
- `quickstart.md`
- `cheatsheet.md`

### Supporting docs

- `input-adapters.md`
- `vm-runtime-capabilities.md`

### Extensions / adoption / examples

- `extensions/extension-and-adoption.md`
- `examples/first-run-proof-failure-narrative.md`
- `ci/GITHUB_ACTIONS.md`
- `ci/GITLAB_CI.md`

### AI docs (active surface)

- `ai/README.md`
- `ai/guardrails.md`
- `ai/cli-contract-ai.md`
- `ai/online_ai.md`

---

## Internal and historical material

The following areas are intentionally separated from the active docs surface:

- `docs/internal/`
- `docs/archive/`
- `docs/ai/internal/`

These locations may contain maintainer notes, internal planning, historical handovers, or working material. They are not the primary operator-facing documentation surface.

---

## Authority reminders

Cassian Gate documentation follows the locked project doctrine and design contract.

Key reminders:

- `cassian test` is the authoritative gate surface
- exploratory workflows do not become authoritative by convenience
- `results.json` is the authoritative verdict artifact
- `results.summary.txt` is explanatory only
- AI is advisory only and never decides pass/fail
- generated artifacts do not become authoritative inputs

---

## Repository reality note

The canonical product name is **Cassian Gate** and the canonical CLI name is **`cassian`**.

Active operator-facing documentation in this surface uses the canonical product and CLI naming consistently. Historical or internal material outside the active docs surface does not change product identity or authority boundaries.

---

## One-sentence summary

> **This documentation defines how Cassian Gate is operated, understood, and trusted.**
