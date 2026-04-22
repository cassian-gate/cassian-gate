# Can host A reach host B?

This recipe answers a first-use question:

**Can host A reach host B?**

This recipe is the next-step bridge after the official first-run proof.
It is not the primary official first-run artifact.

## What the passing variant proves

The passing variant proves a bounded service-reachability check:
host A can reach host B on a declared allowed TCP port.

Run:

    cassian test contrib/topologies/recipes/reachability-can-host-a-reach-host-b/passing/topology.yaml

Expected result:

- normal authoritative gate execution
- PASS
- authoritative verdict remains in `results.json`

## What the failing variant shows

The failing variant shows the same validation question failing by validation outcome, not by YAML syntax or runtime misuse.

Here the topology still blocks the tested TCP port, while the declared test still expects reachability to pass.

Run:

    cassian test contrib/topologies/recipes/reachability-can-host-a-reach-host-b/failing/topology.yaml
    
Expected result:

- normal authoritative gate execution
- FAIL (validation)
- the failure comes from the declared proof not being satisfied

## Which file to copy or edit first

Start from this file:

    contrib/topologies/recipes/reachability-can-host-a-reach-host-b/passing/topology.yaml

Copy it to your own working topology and change:

- node names
- IP subnets
- service port
- firewall allow/deny settings
- test names and expectations

## Support boundary

This recipe demonstrates one bounded reachability task using current supported engine semantics only.

It does **not** claim:

- multi-hop routing proof
- broad protocol completeness
- product certification
- NOS certification
- authority over verdicts or artifacts

Recipe docs are explanatory only.
`results.json` remains the authoritative verdict artifact; generated artifacts do not become authoritative inputs.
