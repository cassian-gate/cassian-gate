# What does my gate actually cover?

This recipe directory contains two files: `README.md` and
`topology.yaml`. The topology declares a routed nft-fw chain plus
a scenario that exercises only some of the available fault and
wait classes, producing meaningful coverage data in
`blast_radius.json`.

## What this proves

This recipe answers a first-use question:

**What does my gate actually cover, and what is it missing?**

Every `cassian test` run produces a `blast_radius.json` artifact
during the Collect phase. The artifact carries
`"authority": "supporting_evidence"` — a non-authoritative
supporting-evidence class, advisory with respect to the gate
verdict. It reports two views of what the declared tests and
scenarios exercised: `directly_covered` (the specific nodes and
links touched) and `potentially_affected` (graph-reachable
elements from the directly-covered scope, each annotated with a
`reason`). A `coverage_basis` array enumerates the specific test
entries and scenario steps that drove coverage, and a `counts`
block reports the numeric summary.

`blast_radius.json` does not affect the gate verdict. The
authoritative pass/fail decision is carried by `results.json`'s
`overall.verdict`; `results.json`'s `authority.verdict_source`
reports `"tests"`. Blast radius lets an engineer see, after a
passing gate run, what proportion of the declared topology the
run actually exercised.

The recipe topology is deliberately constructed to show coverage
gaps: the scenario touches only one fault class (`interface_down`
/ `interface_up` on `fw1:eth1`) and one wait class
(`wait_for: ping`), while the topology declares three links, two
routed firewalls, and supports many other fault classes
(`link_down`, `packet_loss`, `latency`, `bandwidth_cap`,
`prefix_blackhole`) and wait classes (`wait` elapsed-time,
`wait_for: tcp`, etc.) that the scenario never invokes. The
resulting `counts` report `directly_covered_nodes: 2` (h1 and
fw1) and `directly_covered_links: 0`, against
`potentially_affected_nodes: 2` (fw2 and h2) and
`potentially_affected_links: 3`.

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
  the supporting-evidence blast-radius artifact (advisory in
  effect; literal `"authority"` field reads `"supporting_evidence"`).
  Top-level fields include `directly_covered` (nodes/links the
  declared tests and scenarios touched), `potentially_affected`
  (graph-reachable from the directly-covered scope, each with a
  `reason` string explaining inclusion), `counts` (numeric
  summary), and `coverage_basis` (the specific test entries and
  scenario steps that drove coverage).
- `labs/clab-blast-radius-recipe/results.json` — the authoritative
  results artifact. The gate verdict is at `overall.verdict`;
  `authority.verdict_source` reports `"tests"`. The top-level
  `blast_radius` block summarises the same counts for convenience
  and carries `authority: supporting_evidence` for reference. The
  blast-radius artifact does not influence the verdict.
- `labs/clab-blast-radius-recipe/results.summary.txt` — the
  human-readable verdict summary.

The recipe topology declares a scenario that intentionally
touches only a slice of the available fault and wait surface.
When you compare `directly_covered` (what was exercised) against
`potentially_affected` (what the graph reaches) and against the
topology's full declared set of fault and wait classes, the gap
is the recipe's deliberate untouched surface, not bugs. Adapt
the recipe for real validation by either declaring tests and
scenarios that exercise more of the topology, or accepting that
some surfaces are out of scope for the particular gate run.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)
