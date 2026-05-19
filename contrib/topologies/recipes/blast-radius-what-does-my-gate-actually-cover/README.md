# What does my gate actually cover?

This recipe directory contains two files: `README.md` and
`topology.yaml`. The topology declares a routed nft-fw chain plus
a scenario that exercises only some of the available fault and
wait classes, producing a meaningful `coverage.summary` block in
`blast_radius.json`.

## What this proves

This recipe answers a first-use question:

**What does my gate actually cover, and what is it missing?**

Every `cassian test` run produces an advisory `blast_radius.json`
artifact during the Collect phase. The artifact reports which
fault classes, wait classes, and topology elements the declared
tests and scenarios actually exercised — and which ones were
available in the topology but untouched.

`blast_radius.json` is advisory. It does not affect the gate
verdict. The authoritative pass/fail decision still lives in
`results.json`. Blast radius lets an engineer see, after a
passing gate run, what proportion of the declared topology was
actually exercised.

The recipe topology is deliberately constructed to show this gap:
the scenario touches only one fault class (`interface_down` /
`interface_up` on `fw1:eth1`) and one wait class (`wait_for: ping`),
while the topology declares three links, two routed firewalls, and
supports many other fault classes (`link_down`, `packet_loss`,
`latency`, `bandwidth_cap`, `prefix_blackhole`) and wait classes
(`wait` elapsed-time, `wait_for: tcp`, etc.) that the scenario
never invokes. `coverage.summary` reflects this gap.

## How to run it

Run from the repository root, with the environment already set up
per [`docs/quickstart.md`](../../../docs/quickstart.md) (also at
[docs.cassiangate.dev/quickstart](https://docs.cassiangate.dev/quickstart/)):

```bash
cassian test contrib/topologies/recipes/blast-radius-what-does-my-gate-actually-cover/topology.yaml
```

The gate runs end-to-end (resolve → deploy → provision → test →
collect → destroy) and produces `blast_radius.json` as one of the
Collect-phase artifacts.

## What to look for

After the run completes, inspect:

- `labs/clab-blast-radius-recipe/artifacts/blast-radius/blast_radius.json` —
  the advisory blast-radius artifact. The `coverage.summary` block
  reports touched-vs-untouched entries for fault classes, wait
  classes, and topology elements. Use this to understand what the
  gate's declared tests and scenarios actually exercised.
- `labs/clab-blast-radius-recipe/results.json` — the authoritative
  gate verdict. This is the file that owns pass/fail;
  `blast_radius.json` does not influence it.
- `labs/clab-blast-radius-recipe/results.summary.txt` — the
  human-readable verdict summary.

The recipe topology declares a scenario that intentionally touches
only a slice of the available fault and wait surface. When you
inspect `coverage.summary`, the untouched entries are the recipe's
deliberate gaps, not bugs. Adapt the recipe for real validation by
either declaring tests and scenarios that exercise more of the
topology, or accepting that some surfaces are out of scope for the
particular gate run.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)
