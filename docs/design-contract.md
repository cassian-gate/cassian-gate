# ai-netsim Design Contract (Authoritative)

**Version:** v1.2
**Status:** LOCKED
**Scope:** Applies to v1 and all future versions unless explicitly amended

This document defines the **non-negotiable behavioral guarantees** of ai-netsim.

Its purpose is to ensure ai-netsim remains a:

* deterministic
* auditable
* replay-stable
* CI-safe network validation gate

even as features expand.

If any change conflicts with this contract, the change **must be redesigned, deferred, or gated behind an explicit opt-in mechanism** that preserves default behavior.

---

# 1) Repository structure & sources of truth

## Authoritative inputs

The following are the **only inputs allowed to influence validation outcomes**:

```
topologies/*.yaml
src/*
```

### topologies/

User-declared **network intent**, including:

* nodes
* links
* addressing
* tests
* scenarios
* expectations

### src/

Execution engine implementation:

* resolvers
* generators
* runtime adapters
* test semantics

**Contract rule**

Only changes to these locations may change validation results.

---

## Generated outputs (never authoritative)

Generated artifacts include:

```
labs/**
labs/*.clab.yaml
labs/**/topology.resolved.yaml
labs/**/results.json
labs/**/results.summary.txt
logs / pcaps / evidence
```

Editing these artifacts is **unsupported and undefined behavior**.

Validation outcomes must only change through:

```
topologies/
src/
```

---

## Runtime components

Runtime behavior may be defined by:

```
images/**
```

Examples:

```
images/frr/
images/nft-fw/
```

ai-netsim **orchestrates execution**, it does not emulate device logic internally.

---

# 2) Core product guarantees

## Determinism (non-negotiable)

Given identical:

* topology YAML
* code version
* container images
* declared timeouts

ai-netsim **must produce identical outcomes**:

* identical resolved topology
* identical generated configs
* identical test results
* identical scenario verdicts

Forbidden behavior:

* randomness
* heuristic retries
* adaptive timing
* hidden backoff logic
* nondeterministic ordering

All waits, retries, and timing behaviors must be **explicit and recorded**.

---

## Explicitness

ai-netsim must **never**:

* guess intent
* auto-fix configuration
* mutate user design outside Resolve

Defaults are allowed **only when**:

* applied during Resolve
* visible in `topology.resolved.yaml`
* deterministic

---

## Auditability

Every execution must produce a **stable artifact directory** containing:

```
topology.resolved.yaml
results.json
results.summary.txt
```

Artifacts must be sufficient to:

* reproduce results
* diagnose failures
* explain outcomes

---

# 3) Execution lifecycle (fixed order)

The lifecycle is **strictly ordered**.

```
resolve → generate → deploy → provision → test → collect → destroy
```

No feature may introduce additional phases.

---

## Resolve

* validate schema
* apply defaults
* expand packs
* expand scenarios
* emit `topology.resolved.yaml`

---

## Generate

* containerlab topology
* per-node configuration
* provisioning artifacts

---

## Deploy

* deploy runtime environment
* verify containers running

---

## Provision

* apply host addressing
* apply firewall configuration
* apply runtime configuration
* deterministic readiness checks

ai-netsim **does not infer routing intent**.

---

## Test

* execute atomic tests
* execute scenarios
* no hidden remediation

---

## Collect

* write `results.json`
* write summaries and evidence

---

## Destroy

* deterministic teardown
* no leaked containers

---

# 4) Gate-first UX (LOCKED)

## netsim test

Authoritative validation.

Behavior:

* clean-state execution
* deterministic lifecycle
* binary verdict
* CI-safe exit codes

---

## netsim run

Exploration mode.

Behavior:

* non-authoritative
* supports iterative experimentation
* never used for CI gating

---

# 5) Scenario contract

Scenarios model **deterministic event sequences**.

Scenarios are:

* explicit
* ordered
* deterministic
* replay-stable
* fail-fast on ambiguity

---

## Scenario step structure

Each step must contain **exactly one action**.

Example:

```yaml
steps:
  - run:
      command: ping hostA hostB
```

Unknown keys are rejected.

---

## Scenario action extensibility

Scenario actions are **extensible**.

The contract does **not freeze a fixed action list**.

Instead, every action must satisfy the following requirements.

---

## Scenario action requirements

All scenario actions must be:

### Explicit

Required parameters must be declared.

No implicit targets.

---

### Deterministic

The same step must always produce the same effect.

Forbidden:

* randomness
* adaptive behavior
* probabilistic operations

---

### Replay-stable

Scenario steps must behave identically when replayed.

Replay must reproduce:

* actions
* timing
* outcomes

---

### Artifact-recorded

Actions affecting network state or evidence must be recorded in:

```
results.json
```

---

### Fail-fast on ambiguity

If an action cannot be resolved unambiguously, execution must stop.

Example:

```
ERROR: ambiguous link target
```

---

# 6) Scenario action categories

Actions typically fall into one of the following deterministic classes.

These categories describe **behavioral expectations**, not a fixed list.

---

## Execution actions

Execute commands within nodes.

Examples:

```
run
```

---

## Fault / degradation actions

Introduce deterministic environmental changes.

Examples:

```
link_down
link_up
interface_down
interface_up
packet_loss
latency
bandwidth_cap
prefix_blackhole
```

Grey failures are deterministic degradations implemented within this class.

Fault actions must be **reversible and explicitly scoped**.

---

## Convergence actions

Wait for deterministic conditions.

Examples:

```
wait
wait_for
wait_for_bgp
```

All waits must declare:

```
timeout
expected condition
```

---

## Evidence capture actions

Capture runtime evidence.

Examples:

```
pcap_start
pcap_stop
```

Evidence capture must **not influence verdicts directly**.

---

# 7) Test contract

Atomic tests remain the **primary authority for validation**.

Supported test classes include:

```
ping
tcp
bgp_neighbor
invariant
```

Additional deterministic tests may be added through contract amendment.

---

## Required test fields

Each test must record:

```
expected
observed
verdict
evidence
```

---

## Negative tests

If:

```
expected: fail
```

and failure occurs:

```
observed: fail
verdict: pass
```

---

# 8) Routing invariant contract

Routing invariants provide **deterministic routing intent validation**.

Invariants execute during the **TEST phase**.

Invariant results appear as **standard test results**.

Example:

```
kind: invariant
type: bgp_session_up
```

Invariant evaluation must be:

* deterministic
* binary
* replay-stable

---

# 9) AI contract (authoritative boundary)

AI features are **assistive only**.

AI may:

* explain results
* analyze artifacts
* suggest improvements

AI may **never**:

* influence verdicts
* modify topology
* execute lifecycle steps
* alter artifacts

AI must always operate on:

```
topology.resolved.yaml
results.json
```

---

# 10) Model vs runtime backend

Topology model must remain **runtime-agnostic**.

Backends implement execution:

```
containerlab (current)
vm runtime (future)
```

Backend logic must not leak into topology schema.

---

# 11) Security & hygiene

Required guarantees:

* no shell injection
* no implicit network access
* deterministic teardown
* no leaked processes

---

# 12) Change control

Every change must satisfy:

1. Deterministic
2. Auditable
3. Inputs authoritative
4. Outputs generated
5. Replay-stable

If any answer is **no**, the change is invalid unless explicitly gated.

---

# 13) Explicit non-goals (LOCKED)

ai-netsim will **never become**:

* a lab platform
* a chaos engine
* a heuristic validator
* an AI decision system

Forbidden:

* AI-driven pass/fail
* auto-remediation
* probabilistic validation
* silent configuration mutation

---

# Contract authority

This document is **authoritative**.

If implementation, documentation, or AI suggestions conflict with this contract:

**the contract wins.**

Changes must be redesigned or deferred.

---

**End of contract.**
