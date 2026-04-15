# Input Adapters (Read-Only) — Terraform Plan JSON + Rendered Ansible Output

This feature lets Cassian Gate ingest external change context such as Terraform plan JSON and rendered Ansible output as non-authoritative, advisory-only metadata.

Adapters are designed to improve:

* change-scope visibility (what appears to be changing)
* advisory preflight context
* advisory AI context for human review

They do **not** change:

* lifecycle phases
* test or scenario selection
* pass/fail verdicts
* authoritative gate meaning
* exit semantics of `cassian test`

Adapters are read-only, offline-first, deterministic parsers.

---

## Authority boundary (non-negotiable)

Adapters must **not**:

* select tests or scenarios automatically
* gate runs or affect CI verdicts
* mutate topology YAML
* apply configs or run Terraform or Ansible
* infer vendor semantics beyond the provided input text

All adapter outputs are supporting context only.

They remain:

* advisory
* explicitly supplied
* outside the authoritative gate chain

---

## Commands

### Terraform plan JSON adapter

Input: JSON output from Terraform, for example `terraform show -json <planfile>`.

```bash
cassian adapt terraform --plan /path/to/plan.json
```

Options:

* `--out <dir>`
* `--strict`

Typical output filename:

* `terraform.plan.adapter.json`

---

### Rendered Ansible output adapter

Input: a directory containing rendered outputs such as template results, not live device state.

```bash
cassian adapt ansible --dir /path/to/rendered_dir
```

Options:

* `--out <dir>`
* `--strict`

Typical output filename:

* `ansible.rendered.adapter.json`

Notes:

* file selection is deterministic
* outputs may include file-level traceability metadata

---

## Using adapters with preflight (advisory-only)

Adapters are never auto-discovered. Pass them explicitly when you want preflight to include adapter context.

```bash
cassian preflight topologies/three-frr-two-hosts-fw-routed.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --adapter artifacts/adapters/ansible.rendered.adapter.json \
  --format json
```

Rules:

* unreadable or missing adapter paths are treated as preflight input errors
* adapter parse issues remain advisory context, not validation verdicts
* adapters do not make preflight authoritative

---

## Using adapters with AI (advisory-only)

Adapters can also be supplied as advisory context for artifact-based AI interpretation workflows.

Use the current `cassian ai` surface together with the relevant artifact or lab path, and include adapters only when you want extra change-context during explanation or review.

Examples of the current AI entrypoint:

```bash
cassian ai --artifacts <artifacts-dir> "what should I prove first"
```

```bash
cassian ai --lab <lab> "why did this fail"
```

Rules:

* adapters remain optional context only
* adapters never affect gate results
* `cassian test` remains the sole authoritative validation gate
* AI remains advisory-only whether adapters are present or not

---

## CI pattern (recommended)

Run adapters and preflight as separate advisory steps before the authoritative gate.

```bash
# Produce adapter inputs in your pipeline.
terraform show -json plan.out > plan.json

# Convert to normalized advisory context.
cassian adapt terraform --plan plan.json

# Optional: preflight with adapter context.
cassian preflight topologies/<topology>.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json \
  --format json

# Authoritative gate.
cassian test <topology.yaml>
```

Important:

* adapter parsing is file-based advisory context
* adapters are not required to run the gate
* the only authoritative inputs remain `topologies/*.yaml` and `src/*`
* release docs and adapter outputs do not become authoritative proof
