# GitHub Actions — Cassian Gate official gate template (OSS)

This repository includes an official GitHub Actions workflow that runs **Cassian Gate** as a
**deterministic, clean-state validation gate**.

## What this workflow does (stable contract)

The workflow:

1. Pins Python (3.11)
2. Installs Python dependencies deterministically
3. Runs a fast syntax sanity check:
   - `python -m py_compile src/*.py`
4. Runs the repository's authoritative verification oracle:
   - `bash scripts/verify_phase1.sh`
5. Runs a minimal project-level gate:
   - `./src/netsim.py up topologies/three-frr-two-hosts-fw-routed.yaml --reconfigure`
   - `./src/netsim.py test three-frr-two-hosts-fw-routed --scenario quick_all`
   - `./src/netsim.py down three-frr-two-hosts-fw-routed`
6. Uploads generated `labs/` artifacts for audit/debug.

### Authority rules (important)

- **Pass/fail is determined by Cassian Gate (`cassian test`) and/or the repo oracle script.**
- CI must not run `cassian run` as a gate.
- `labs/` is generated evidence only; authoritative inputs are `topologies/` and `src/`.

## Runner requirements (OSS-friendly)

**This workflow is intended for self-hosted runners.**

`containerlab` requires Docker privileges and Linux networking capabilities
(netns, veth, etc). GitHub-hosted runners may not support this reliably.

Your runner must provide:

- Linux host
- Docker engine available to the runner user
- `containerlab` installed **ahead of time** and **pinned** (do not install "latest" in CI)

The workflow fails fast with a clear error if `containerlab` is missing.

## Artifacts

On success, CI uploads a bounded evidence set:

- `labs/**/results.json`
- `labs/**/results.summary.txt`
- `labs/**/topology.resolved.yaml`
- `labs/**/artifacts/**` (supporting evidence only)

On failure, CI additionally uploads:

- `labs/**` (full evidence bundle)

## Reproducing locally

From repo root:

```bash
python -m py_compile src/*.py
bash scripts/verify_phase1.sh

./src/netsim.py up topologies/three-frr-two-hosts-fw-routed.yaml --reconfigure
./src/netsim.py test three-frr-two-hosts-fw-routed --scenario quick_all
./src/netsim.py down three-frr-two-hosts-fw-routed

