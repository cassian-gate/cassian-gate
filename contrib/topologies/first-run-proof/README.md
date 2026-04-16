# First-Run Proof

This is the official first-run adoption proof family for Cassian Gate.

Failure-first path:

1. Run the failing variant first to see Cassian Gate catch a real validation problem.
2. Run the passing variant second to see the same proof succeed when the policy is correct.

What this example proves:

- Cassian Gate can run an authoritative gate through the normal `cassian test` path
- Cassian Gate can catch a real service-reachability failure caused by incorrect firewall policy
- the same bounded topology can produce a clean PASS when the policy is corrected

What the failure represents:

- a production-relevant policy mistake
- the service on TCP/8443 is expected to be reachable
- the firewall policy is wrong, so the declared proof fails

Official first-run commands:

    cassian test contrib/topologies/first-run-proof/failing/topology.yaml
    cassian test contrib/topologies/first-run-proof/passing/topology.yaml

Expected verdict difference:

- `failing/topology.yaml` -> FAIL (validation)
- `passing/topology.yaml` -> PASS

Where artifacts appear:

- `labs/clab-first-run-proof-failing/`
- `labs/clab-first-run-proof-passing/`

Authoritative artifacts are:

- `topology.resolved.yaml`
- `results.json`

Human-readable only:

- `results.summary.txt`

What to inspect or copy first:

- start with `contrib/topologies/first-run-proof/failing/topology.yaml`
- then compare it with `contrib/topologies/first-run-proof/passing/topology.yaml`

Support boundary:

- this example proves only this bounded open-source first-run case
- it does not claim broad protocol completeness
- it does not claim broad NOS support
- it does not imply certification beyond the demonstrated case
