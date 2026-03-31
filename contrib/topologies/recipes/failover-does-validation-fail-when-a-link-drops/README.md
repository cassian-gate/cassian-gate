# Does validation fail when a link drops?

This recipe answers a first-use question:

**Does validation fail when a link drops?**

This recipe uses current deterministic scenario semantics only.
It is the next-step bridge after the official first-run proof.
It does not replace that first-run proof.

## What the passing variant proves

The passing variant proves that a declared scenario can validate an expected failed service check before and after an explicit link failure.

Run:

    python src/netsim.py test contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/passing/topology.yaml --all-scenarios

Expected result:

- PASS
- the pre-fault TCP check correctly fails
- the explicit link-down fault is applied
- the post-fault wait and post-fault test correctly observe failure

## What the failing variant shows

The failing variant shows a meaningful scenario validation failure:

- the same link is dropped
- the declared post-fault expectation incorrectly says the service check should pass

Run:

    python src/netsim.py test contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/failing/topology.yaml --all-scenarios

Expected result:

- FAIL (validation)
- the failure comes from the declared scenario expectation not matching observed behavior

## Which file to copy or edit first

Start from this file:

    contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/passing/topology.yaml

Copy it first, then change:

- endpoints
- fault target
- wait expectations
- scenario ID
- test names

## Support boundary

This recipe demonstrates one bounded fault-choreography validation question using existing scenario semantics only.

It does **not** introduce:

- new scenario actions
- new wait behavior
- hidden retries
- broad resiliency guarantees
- authority over verdicts or artifacts

Recipe docs are explanatory only.
Engine execution and generated artifacts remain authoritative.
