# Does this firewall block or allow a port?

This recipe answers a first-use question:

**Does this firewall block or allow a port?**

This recipe is the next-step bridge after the official first-run proof.
It is not the primary official first-run artifact.

## What the passing variant proves

The passing variant proves two bounded policy outcomes in one small example:

- TCP/8443 is allowed
- TCP/2222 is blocked

Run:

    python src/netsim.py test contrib/topologies/recipes/policy-does-this-firewall-block-or-allow-a-port/passing/topology.yaml

Expected result:

- PASS
- both the allowed-port proof and blocked-port proof match the declared expectations

## What the failing variant shows

The failing variant shows a meaningful validation failure:

- the topology still blocks TCP/2222
- the declared test incorrectly expects that blocked port to pass

Run:

    python src/netsim.py test contrib/topologies/recipes/policy-does-this-firewall-block-or-allow-a-port/failing/topology.yaml

Expected result:

- FAIL (validation)
- the failure is the declared proof being wrong for the actual policy

## Which file to copy or edit first

Start from this file:

    contrib/topologies/recipes/policy-does-this-firewall-block-or-allow-a-port/passing/topology.yaml

Copy it first, then change:

- allowed TCP port list
- test ports
- host names or addresses

## Support boundary

This recipe demonstrates a bounded firewall allow/deny validation question using current supported engine semantics only.

It does **not** claim:

- general firewall correctness
- broad service validation
- full policy certification
- authority over verdicts or artifacts

Recipe docs are explanatory only.
Engine execution and generated artifacts remain authoritative.
