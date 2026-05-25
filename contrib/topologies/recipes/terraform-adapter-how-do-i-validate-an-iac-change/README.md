# How do I validate an IaC change?

This recipe directory contains three files: `README.md`,
`topology.yaml`, and `plan.json`. `topology.yaml` is the Cassian
Gate topology preflight runs against; `plan.json` is the byte-output
of `terraform show -json` from the synthetic Terraform module
documented under "Reproducing this plan" below.

## What this proves

This recipe answers a first-use question:

**How do I validate an IaC change against my network topology?**

The Cassian Gate Terraform adapter converts a `terraform show -json`
plan into a normalized advisory `adapters.v1` JSON. That adapter
output can then be passed to `cassian preflight --adapter
<adapter-output>`, which surfaces the IaC change context inside the
preflight findings.

Both the adapter output and the preflight output are advisory —
they are not gate verdicts. They give an engineer reading the
artifacts visibility into what an upcoming infrastructure change
would alter, alongside the declared topology's coverage gaps.

Authoritative pass/fail decisions still come from `cassian test`
against a declared topology and tests. This recipe demonstrates
only the advisory IaC-integration workflow.

## How to run it

Run from the repository root, with the environment already set up
per [`docs/quickstart.md`](../../../docs/quickstart.md) (also at
[docs.cassiangate.dev/quickstart](https://docs.cassiangate.dev/quickstart/)):

```bash
cassian adapt terraform \
  --plan contrib/topologies/recipes/terraform-adapter-how-do-i-validate-an-iac-change/plan.json

cassian preflight \
  contrib/topologies/recipes/terraform-adapter-how-do-i-validate-an-iac-change/topology.yaml \
  --adapter artifacts/adapters/terraform.plan.adapter.json
```

The first command (`cassian adapt terraform`) writes the adapter
output to `artifacts/adapters/terraform.plan.adapter.json` by
default. The second command (`cassian preflight`) reads that
adapter output and writes preflight findings to
`artifacts/preflight/preflight.json` by default.

## What to look for

After both commands complete, inspect:

- `artifacts/adapters/terraform.plan.adapter.json` — the adapter
  output. The `items[]` array lists the changes the Terraform plan
  declared (each with an `action` like `create`, an `address`, and
  resource metadata). The `summary` block reports `items_added`,
  `items_changed`, `items_removed`, and `items_total`. The
  `authority` field reads `advisory` — this output never affects a
  gate verdict.
- `artifacts/preflight/preflight.json` — the preflight output.
  Under the top-level `adapters` block, the consumed adapter input
  appears with its `summary`, `parse_errors_count`, and
  `parse_warnings_count`. This gives an engineer reading preflight
  findings the IaC change context alongside the topology's coverage
  gaps.

Both artifacts are advisory-authority. `cassian preflight` does not
produce a gate verdict; it produces advisory findings. The gate
verdict path remains `cassian test`.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)

## Reproducing this plan

The `plan.json` in this recipe directory is the byte-output of
`terraform show -json` against a synthetic minimal Terraform module.
The Terraform module source itself is not committed (no `.tf`
files, no `terraform.tfstate*`, no `.terraform/` directory, no
`.terraform.lock.hcl`) — it lives here as copy-pasteable text so an
operator can regenerate `plan.json` if needed.

To reproduce, run the following in a temporary work directory
**outside this recipe directory** so that `.tf` files,
`terraform.tfstate*`, `.terraform/`, and `.terraform.lock.hcl`
never enter the recipe's committed surface:

```bash
WORK_DIR=$(mktemp -d -t cassian-recipe-tf.XXXXXX)
cd "$WORK_DIR"

cat > main.tf <<'EOF'
terraform {
  required_version = ">= 1.4"
}

resource "terraform_data" "prefix_to_advertise" {
  input = {
    prefix      = "10.50.0.0/16"
    description = "tenant prefix planned for advertisement"
  }
}
EOF

terraform init -no-color
terraform plan -no-color -out=tfplan.binary
terraform show -json tfplan.binary > plan.json

# Copy the resulting plan.json into the recipe directory:
cp plan.json <repo-root>/contrib/topologies/recipes/terraform-adapter-how-do-i-validate-an-iac-change/plan.json

# Clean up the temp dir:
cd <repo-root>
rm -rf "$WORK_DIR"
```

The module uses `terraform_data` (built-in to Terraform 1.4+, no
external provider required) so it reproduces deterministically
without provider authentication. An operator can adapt the
synthetic module to mirror real-world Terraform changes (adding
resources, modifying inputs) and regenerate `plan.json` to
demonstrate Cassian Gate consuming different IaC change shapes.
