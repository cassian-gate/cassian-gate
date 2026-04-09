# Failover — Does validation fail when a link drops?

This is supporting Set 2 scenario content.

It is not the official first-run proof.
It is not the primary recipe bridge.
It exists to show one bounded deterministic failure-choreography example using the normal authoritative gate path only.

## User question answered

Does Cassian Gate catch the difference between a deterministic fault sequence that recovers correctly and one that does not?

## What this demonstrates

A very small directly connected reachability topology with a deliberate interface bounce scenario.

The scenario uses only currently supported behavior:

- `run`
- `fault.interface_down`
- `fault.interface_up`
- `wait_for`

No new scenario actions, waits, convergence behavior, or verdict logic are introduced.

## Fault sequence

1. Run a passing ping test from `h1` to directly connected `fw1`.
2. Bring down `fw1:eth1`.
3. Wait until that ping fails.
4. Bring `fw1:eth1` back up.
5. Wait until the ping passes again.
6. Run the same ping test again.

The failing variant keeps the same topology shape and the same choreography shape, but intentionally declares the final test expectation incorrectly so the scenario run ends in a validation failure rather than a syntax or runtime error.

## Files to inspect first

Inspect or copy one of these first:

- `passing/topology.yaml`
- `failing/topology.yaml`

## Exact commands

Passing variant:

    python src/netsim.py test contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/passing/topology.yaml
    echo "exit=$?"

Failing variant:

    python src/netsim.py test contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/failing/topology.yaml
    echo "exit=$?"

## Expected outcome difference

Passing variant:

- gate run succeeds
- scenario passes
- exit code uses existing success semantics

Failing variant:

- gate run executes normally
- scenario fails by validation outcome
- exit code uses existing validation-failure semantics

The failing variant is intentionally a validation failure.
It is not meant to fail because of invalid YAML, unsupported fields, or backend/runtime breakage.

## Support boundary

This is a bounded single-purpose fault-sequence example only.

It does not claim:

- broad failover coverage
- protocol completeness
- NOS certification
- general scenario completeness

## Supporting surfaces

Set 2 also includes reusable supporting content such as invariant packs and state profiles.
Those are secondary surfaces.
They do not replace the official first-run proof family, the recipe bridge, or this scenario example as the main failure-demonstrating artifact in this slice.