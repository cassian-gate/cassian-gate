# Input Adapters (Read-Only) — Terraform Plan JSON + Rendered Ansible Output

This feature lets Cassian Gate ingest external change context (Terraform plan JSON, rendered Ansible output)
as non-authoritative, advisory-only metadata.

Adapters are designed to improve:

* change scope visibility (what appears to be changing)
* advisory preflight / AI context (what you might need to prove)

They never change:

* lifecycle phases
* test/scenario selection
* pass/fail verdicts
* exit codes of `cassian test`

Adapters are read-only, offline-first, deterministic parsers.

---

## Authority boundary (non-negotiable)

Adapters MUST NOT:

* select tests/scenarios automatically
* gate runs or affect CI verdicts
* mutate topology YAML
* apply configs or run terraform/ansible
* infer vendor semantics beyond the input text

All adapter outputs are explicitly labeled:

* `authority: advisory`
* `schema_version: adapters.v1`

---

## Commands

### Terraform plan JSON adapter

Input: JSON output from Terraform, e.g. `terraform show -json <planfile>`.

```bash
./src/netsim.py adapt terraform --plan /path/to/plan.json
```

Options:

* `--out <dir>` (default: `artifacts/adapters/`)
* `--strict` (exit 1 if parse_errors are present)

Output (canonical filename):

* `<out>/terraform.plan.adapter.json`

---

### Rendered Ansible output adapter

Input: a directory containing rendered outputs (template results), not live device state.

```bash
./src/netsim.py adapt ansible --dir /path/to/rendered_dir
```

Options:

* `--out <dir>` (default: `artifacts/adapters/`)
* `--strict` (exit 1 if parse_errors are present)

Output (canonical filename):

* `<out>/ansible.rendered.adapter.json`

Notes:

* File selection is allowlist-based (deterministic).
* Outputs may include `file_hash` (sha256) for traceability.

---

## Using adapters with preflight (advisory-only)

Adapters are never auto-discovered. You must pass them explicitly:

```bash
./src/netsim.py preflight topologies/three-frr-two-hosts-fw-routed.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --adapter artifacts/adapters/ansible.rendered.adapter.json \
  --format json
```

Rules:

* Missing/unreadable adapter path is a usage error for preflight (exit 1).
* Adapter `parse_errors` inside the JSON remain advisory; preflight still exits 0.

---

## Using adapters with AI review / explain (advisory-only)

Adapters are optional context only, explicitly passed:

```bash
./src/netsim.py ai review topologies/three-frr-two-hosts-fw-routed.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --bundle
```

```bash
./src/netsim.py ai explain three-frr-two-hosts-fw-routed \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --bundle
```

Rules:

* Missing/unreadable adapter path is an AI usage error (exit 2).
* Adapters never affect gate results; `cassian test` remains authoritative.

---

## CI pattern (recommended)

Run adapters and preflight as separate advisory steps before the authoritative gate:

```bash
# Produce adapter inputs (done by your pipeline — may require terraform/ansible there)
terraform show -json plan.out > plan.json

# Convert to normalized advisory context (Cassian Gate does not run terraform)
./src/netsim.py adapt terraform --plan plan.json

# Optional: preflight with adapter context
./src/netsim.py preflight topologies/<topology>.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --format json

# Authoritative gate (unchanged)
./src/netsim.py test <labname>
```

Important:

* Adapter parsing is offline-first (file-only).
* Adapters are not required to run the gate.
* The only authoritative inputs are `topologies/*.yaml` + `src/`.