# What changed between baseline and change?

This recipe directory contains `README.md` only. The topologies it
demonstrates against are referenced in-place from `topologies/`
rather than copied here.

## What this proves

This recipe answers a first-use question:

**What changed between my baseline and my proposed change?**

`cassian test --two-run` runs Cassian Gate twice — once against a
baseline topology, once against a change topology with a candidate
operational-config directory applied — and writes a two-run bundle
that records both runs alongside an evidence-only diff summary.

The "change" is the combination of the change topology and the
candidate-config directory. The candidate-config directory contains
the device configs (FRR `.conf` files, and optionally nft rulesets)
that are applied to the live devices during the change run only.
Per-run `results.json` files carry each run's verdict at
`overall.verdict`; the diff summary in the bundle is advisory
evidence describing what differs between the two runs.

The recipe references three existing inputs:

- Baseline topology: [`topologies/rw-bgp-tenant30-baseline.yaml`](../../../topologies/rw-bgp-tenant30-baseline.yaml)
- Change topology: [`topologies/rw-bgp-tenant30-change.yaml`](../../../topologies/rw-bgp-tenant30-change.yaml)
- Candidate-config directory: [`tests/fixtures/rw-bgp-tenant30-change/`](../../../tests/fixtures/rw-bgp-tenant30-change) (the FRR configs applied on the change run)

These all live in the repository; the recipe does not copy or
modify them.

## How to run it

Run from the repository root, with the environment already set up
per [`docs/quickstart.md`](../../../docs/quickstart.md) (also at
[docs.cassiangate.dev/quickstart](https://docs.cassiangate.dev/quickstart/)):

```bash
cassian test \
  --two-run \
  --two-run-topology topologies/rw-bgp-tenant30-change.yaml \
  --candidate-config tests/fixtures/rw-bgp-tenant30-change/ \
  topologies/rw-bgp-tenant30-baseline.yaml
```

The positional argument is the baseline topology;
`--two-run-topology` supplies the change topology; and
`--candidate-config` supplies the directory of FRR (and optionally
nft) configs applied to the change run only. Cassian Gate runs
both topologies from clean state in sequence and assembles a
two-run bundle under `labs/`.

## What to look for

After the run completes, inspect the two-run bundle at
`labs/clab-<change-topology-name>/two_run/` (named after the
`--two-run-topology` topology — in this recipe,
`labs/clab-rw-bgp-tenant30-change/two_run/`):

- `two_run/baseline/results.json` — the baseline run's per-run
  results. The verdict lives at `overall.verdict`;
  `authority.verdict_source` reports `"tests"`.
- `two_run/change/results.json` — the change run's per-run results,
  same structure, plus a `candidate_apply` section recording the
  applied candidate-config directory and per-node apply outcome.
- `two_run/diff/summary.json` and `two_run/diff/summary.txt` — the
  evidence-only diff summary comparing the two runs. Advisory.
- Each run's full artifact tree under `two_run/<baseline|change>/artifacts/`
  including blast-radius, coverage, and per-node interface/route
  dumps.

Read each `results.json`'s `overall.verdict` first; that is where
the per-run verdict lives. Consult `diff/summary.{json,txt}` after
you have both verdicts in hand, when you want to understand
specifically what changed between the two runs.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)
