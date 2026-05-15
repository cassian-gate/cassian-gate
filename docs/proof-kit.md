# Proof Kit / Examples

Walkable examples that show Cassian Gate producing authoritative PASS and authoritative FAIL outcomes against real declared topologies. Each entry pairs a passing variant (the gate confirms the declared proof is satisfied) with a failing variant (the gate catches a real validation problem on the same bounded topology).

## First-Run Proof

The official first-run adoption proof family. Failure-first path: run the failing variant first to see Cassian Gate catch a real validation problem, then run the passing variant to see the same proof succeed when the policy is correct.

- [Source: `contrib/topologies/first-run-proof/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/first-run-proof)

## Recipe — Can host A reach host B?

A bounded service-reachability check: host A reaches host B on a declared allowed TCP port. The next-step bridge after the first-run proof.

- [Source: `contrib/topologies/recipes/reachability-can-host-a-reach-host-b/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/reachability-can-host-a-reach-host-b)

## Recipe — Does this firewall block or allow a port?

Two bounded policy outcomes in one small example: TCP/8443 is allowed, TCP/2222 is blocked. The failing variant declares the wrong expectation for the actual policy.

- [Source: `contrib/topologies/recipes/policy-does-this-firewall-block-or-allow-a-port/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/policy-does-this-firewall-block-or-allow-a-port)

## Recipe — Does validation fail when a link drops?

A bounded deterministic failure-choreography example. A directly connected reachability topology with a deliberate interface bounce scenario, run only through the normal authoritative gate path.

- [Source: `contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/failover-does-validation-fail-when-a-link-drops)
