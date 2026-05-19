# What changed between baseline and change?

This recipe directory contains `README.md` only. The topologies it
demonstrates against are referenced in-place from `topologies/`
rather than copied here.

## What this proves

This recipe answers a first-use question:

**What changed between my baseline and my proposed change?**

`cassian test --two-run` is the comparison execution mode. It runs
Cassian Gate twice — once against a baseline topology, once against
a change topology — and produces an advisory `comparison.json`
artifact that records what differs between the two runs.

Each run produces its own authoritative `results.json` verdict from
its own clean-state gate execution. The `comparison.json` artifact
is advisory; it does not own a verdict on its own.

The recipe references the existing reference pair:

- Baseline: [`topologies/rw-bgp-tenant30-baseline.yaml`](../../../topologies/rw-bgp-tenant30-baseline.yaml)
- Change: [`topologies/rw-bgp-tenant30-change.yaml`](../../../topologies/rw-bgp-tenant30-change.yaml)

These topologies live in the repository's authoritative `topologies/`
directory; the recipe does not copy or modify them.

## How to run it

Run from the repository root, with the environment already set up
per [`docs/quickstart.md`](../../../docs/quickstart.md) (also at
[docs.cassiangate.dev/quickstart](https://docs.cassiangate.dev/quickstart/)):

```bash
cassian test \
  --two-run \
  --two-run-topology topologies/rw-bgp-tenant30-change.yaml \
  topologies/rw-bgp-tenant30-baseline.yaml
```

The positional argument is the baseline topology;
`--two-run-topology` supplies the change topology. Cassian Gate runs
both topologies from clean state in sequence.

## What to look for

After the run completes, inspect:

- `labs/clab-<base>/two_run/comparison.json` — the advisory
  comparison artifact for the run. It records the differences
  between the baseline run and the change run. Use this to
  understand what the change altered.
- Each run's `results.json`, written to its own lab directory under
  `labs/`. These are the authoritative per-run verdicts.

Read each `results.json` first; it owns the pass/fail verdict for
its run. Consult `comparison.json` after you have the authoritative
verdicts in hand, when you want to understand specifically what
changed between the two runs.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)
