# GitLab CI — ai-netsim official gate template (OSS)

This repository includes an official GitLab CI pipeline that runs **ai-netsim** as a
**deterministic, clean-state validation gate**.

## What this pipeline does (stable contract)

The pipeline:

1. Pins Python (3.11)
2. Installs Python dependencies deterministically
3. Runs:
   - `python -m py_compile src/*.py`
4. Runs the repository's authoritative verification oracle:
   - `bash scripts/verify_phase1.sh`
5. Runs a minimal project-level gate:
   - `./src/netsim.py up topologies/three-frr-two-hosts-fw-routed.yaml --reconfigure`
   - `./src/netsim.py test three-frr-two-hosts-fw-routed --scenario quick_all`
   - `./src/netsim.py down three-frr-two-hosts-fw-routed`

### Authority rules (important)

- **Pass/fail is determined by ai-netsim (`netsim test`) and/or the repo oracle script.**
- CI must not run `netsim run` as a gate.
- `labs/` is generated evidence only; authoritative inputs are `topologies/` and `src/`.

## Runner requirements

**Recommended (OSS-friendly):** GitLab Runner **Shell executor** on a Linux host with:

- Docker engine available
- `containerlab` installed ahead of time and pinned
- Sufficient privileges for containerlab networking

If you use GitLab Runner Docker executor, it must be configured in a privileged way
(and typically with Docker socket access). This is org-specific and not mandated by ai-netsim.

The template fails fast if `containerlab` is missing.

## Artifacts

The pipeline uploads:

- `labs/**/results.json`
- `labs/**/results.summary.txt`
- `labs/**/topology.resolved.yaml`
- `labs/**/artifacts/**` (supporting evidence only)

You can choose to upload all of `labs/**` on failures if your storage policy allows it.

## Reproducing locally

From repo root:

```bash
python -m py_compile src/*.py
bash scripts/verify_phase1.sh

./src/netsim.py up topologies/three-frr-two-hosts-fw-routed.yaml --reconfigure
./src/netsim.py test three-frr-two-hosts-fw-routed --scenario quick_all
./src/netsim.py down three-frr-two-hosts-fw-routed

