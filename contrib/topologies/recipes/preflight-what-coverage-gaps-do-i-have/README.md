# What coverage gaps do I have?

This recipe directory contains two files: `README.md` and
`topology.yaml`. The topology declares a routed host-fw-host
shape with intentionally minimal test coverage and no scenarios
at all, so `cassian preflight` produces meaningful
coverage-gap findings.

## What this proves

This recipe answers a first-use question:

**What coverage gaps do I have in my declared topology?**

`cassian preflight <topology.yaml>` runs a declared-only static
analysis (no deploy, no runtime, no `cassian test` lifecycle).
It examines what the topology and its tests/scenarios declare,
identifies surface that is declared but never exercised by any
declared test or scenario, and writes an advisory artifact to
`artifacts/preflight/preflight.json`.

The preflight artifact carries `"authority": "advisory"`.
**Preflight findings do not affect the gate verdict.** The gate
verdict path remains `cassian test` → `results.json`. Preflight
is a static-analysis aid for engineers reviewing the declared
coverage of a topology before committing to a full gate run.

This is the static-coverage counterpart to the [blast-radius
recipe](../blast-radius-what-does-my-gate-actually-cover/),
which reports runtime-coverage observed during a `cassian test`
run. Blast radius answers "what did my run exercise?" Preflight
answers "what did I even declare to exercise?" Both are
advisory; neither owns the gate verdict.

The recipe topology declares deliberate coverage gaps: a second
host (`h2`), a second link (`h2 <-> fw1:eth2`), a TCP/443 allow
rule, fault-capable interfaces, and the entire scenario surface —
none of which the single declared test (h1 pinging fw1's
directly-connected interface) exercises, since no `scenarios:`
block is declared at all. `preflight.json` findings reflect these
declared-but-untouched surfaces.

## How to run it

Run from the repository root, with the environment already set up
per [`docs/quickstart.md`](../../../docs/quickstart.md) (also at
[docs.cassiangate.dev/quickstart](https://docs.cassiangate.dev/quickstart/)):

```bash
cassian preflight contrib/topologies/recipes/preflight-what-coverage-gaps-do-i-have/topology.yaml
```

The command exits 0 on success and writes findings to
`artifacts/preflight/preflight.json`. No lab is created; no
runtime is exercised.

## What to look for

After the run completes, inspect:

- `artifacts/preflight/preflight.json` — the advisory preflight
  artifact. The top-level `"authority"` field reads
  `"advisory"`. The `"findings"` array lists the
  declared-but-untouched surface in the topology. Use this to
  understand which parts of the declared topology your test set
  never exercises.

To confirm the verdict-independence boundary for yourself, run
the gate against the same topology:

```bash
cassian test contrib/topologies/recipes/preflight-what-coverage-gaps-do-i-have/topology.yaml
```

The gate verdict (PASS or FAIL) depends only on the declared
tests in `results.json`; the preflight findings do not influence
it. Preflight is a separate, advisory surface.

For artifact schemas and the full CLI flag reference:

- Operator cheatsheet — [`docs/cheatsheet.md`](../../../docs/cheatsheet.md)
  or [docs.cassiangate.dev/cheatsheet](https://docs.cassiangate.dev/cheatsheet/)
- CLI reference — [`docs/cli-reference-v1.md`](../../../docs/cli-reference-v1.md)
  or [docs.cassiangate.dev/cli-reference-v1](https://docs.cassiangate.dev/cli-reference-v1/)
