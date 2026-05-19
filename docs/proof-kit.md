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

## Recipe — What changed between baseline and change?

Uses `cassian test --two-run` to validate a proposed change against a known-good baseline. Two clean-state authoritative gate executions plus an advisory `comparison.json` artifact recording what differs between the runs.

- [Source: `contrib/topologies/recipes/two-run-what-changed-between-baseline-and-change/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/two-run-what-changed-between-baseline-and-change)

## Recipe — How do I validate an IaC change?

Uses `cassian adapt terraform` to convert a `terraform show -json` plan into an advisory `adapters.v1` JSON, then `cassian preflight --adapter <adapter-output>` to surface the IaC change context inside preflight findings. Both adapter output and preflight output are advisory and do not affect the gate verdict.

- [Source: `contrib/topologies/recipes/terraform-adapter-how-do-i-validate-an-iac-change/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/terraform-adapter-how-do-i-validate-an-iac-change)

## Recipe — What does my gate actually cover?

Demonstrates the advisory `blast_radius.json` artifact produced during `cassian test`'s Collect phase. The recipe topology declares a scenario that touches only some of the available fault and wait classes, producing a meaningful `coverage.summary` block; blast radius does not affect the gate verdict.

- [Source: `contrib/topologies/recipes/blast-radius-what-does-my-gate-actually-cover/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/blast-radius-what-does-my-gate-actually-cover)

## Recipe — What coverage gaps do I have?

Demonstrates `cassian preflight` producing the advisory `preflight.json` artifact via declared-only static analysis (no deploy, no runtime). The recipe topology declares deliberate coverage gaps so the findings are meaningful; preflight does not affect the gate verdict.

- [Source: `contrib/topologies/recipes/preflight-what-coverage-gaps-do-i-have/`](https://github.com/cassian-gate/cassian-gate/tree/main/contrib/topologies/recipes/preflight-what-coverage-gaps-do-i-have)
