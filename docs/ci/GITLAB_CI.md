# GitLab CI — Cassian Gate gate template

This document describes a GitLab CI pattern for running **Cassian Gate** as a
**deterministic, clean-state validation gate**.

It is a supporting CI guide. It does **not** replace deterministic execution,
authoritative artifacts, or the project design contract.

## What this pipeline is for

Use this pattern when you want a GitLab pipeline to:

- validate topology input before execution
- run the authoritative gate with `cassian test`
- preserve generated artifacts for audit and debugging
- avoid treating exploratory workflows as deployment authority

## What this pipeline is not

This pipeline is **not**:

- a broad CI automation framework
- a substitute for the Cassian Gate authority model
- a reason to treat `cassian run` as a gate
- a promise that every GitLab runner shape supports containerlab reliably

## Authority rules

Keep these boundaries explicit:

- authoritative gate execution runs through `cassian test <topology.yaml>`
- `cassian run` remains exploratory and non-authoritative
- `results.json` remains the authoritative verdict artifact
- `results.summary.txt` remains explanatory only
- `labs/` remains generated evidence only

## Runner requirements

A practical GitLab runner for current Cassian Gate usage typically needs:

- Linux host or runner
- Docker available to the runner
- `containerlab` installed ahead of time
- sufficient privileges for containerlab networking

A shell executor on a Linux host is often the simplest fit.

If you use another runner model, keep the required runtime privileges explicit and review them
carefully.

## Typical CI shape

A narrow, truthful pipeline usually looks like this:

1. install pinned Python dependencies
2. run repository verification or syntax checks as needed
3. validate the topology
4. run the authoritative gate with `cassian test`
5. upload generated artifacts for review

## Example local reproduction

From repo root:

```bash
python -m py_compile src/*.py
bash scripts/verify_phase1.sh

cassian validate topologies/three-frr-two-hosts-fw-routed.yaml
cassian test topologies/three-frr-two-hosts-fw-routed.yaml --scenario quick_all
```

This keeps CI aligned to the authoritative gate surface.

## Example artifact upload set

Typical artifact upload choices include:

- `labs/**/results.json`
- `labs/**/results.summary.txt`
- `labs/**/topology.resolved.yaml`
- `labs/**/artifacts/**`

If your storage policy allows it, you may also retain the broader `labs/**` directory on failure
for debugging.

## Important boundary

This page is supporting guidance only.

Deploy/no-deploy meaning still comes from:

- deterministic execution
- `cassian test`
- authoritative generated artifacts, especially `results.json`
