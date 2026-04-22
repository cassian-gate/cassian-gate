````md
# Cassian Gate Design Contract (Authoritative)

**Version:** v2.0  
**Status:** LOCKED  
**Scope:** Applies to v2 and all future versions unless explicitly amended

This document defines the **non-negotiable behavioral guarantees** of Cassian Gate.

Its purpose is to ensure Cassian Gate remains a:

- deterministic
- auditable
- artifact-authoritative
- CI-safe
- clean-state
- evidence-first network validation gate

even as features expand.

If any change conflicts with this contract, the change **must be redesigned, deferred, or explicitly gated in a way that preserves default constitutional behavior**.

This contract operates under the project’s full authoritative doctrine.
If any implementation, milestone, feature, extension, runtime, AI integration, or commercial layer conflicts with this contract, the contract wins unless amended through explicit constitutional change.

---

# 1) Repository structure & sources of truth

## Authoritative inputs

The following are the **only inputs allowed to influence authoritative validation outcomes**:

```text
topologies/*.yaml
src/*
````

### `topologies/`

User-declared authoritative network intent, including:

* nodes
* links
* addressing
* tests
* scenarios
* expectations

### `src/`

Authoritative execution engine implementation, including:

* resolvers
* generators
* runtime adapters
* test semantics
* scenario semantics
* artifact generation logic
* validation rules

### Contract rule

Only changes to these locations may change authoritative validation results.

---

## Generated outputs (never authoritative)

Generated artifacts include:

```text
labs/**
labs/*.clab.yaml
labs/**/topology.resolved.yaml
labs/**/results.json
labs/**/results.summary.txt
logs / pcaps / evidence
```

Editing generated artifacts is **unsupported and undefined behavior**.

Validation outcomes must only change through:

```text
topologies/
src/
```

Generated artifacts are evidence, not authoritative inputs.

---

## Runtime components

Runtime behavior may be defined by:

```text
images/**
```

Examples:

```text
images/frr/
images/nft-fw/
images/sonic-vm/
```

Cassian Gate **orchestrates execution**.
It does not internally emulate vendor logic as its primary correctness model.

### Runtime-boundary rule

Runtime evolution is allowed, but backend/runtime changes may not alter:

* lifecycle law
* authority boundaries
* pass/fail semantics
* clean-state gate guarantees
* artifact-authority semantics

---

# 2) Core product guarantees

## Determinism (non-negotiable)

Cassian Gate must be deterministic in what it **authoritatively owns and evaluates**.

This includes:

* lifecycle ordering
* interpretation of declared authoritative input
* default application during Resolve
* guardrail enforcement
* test and scenario verdict semantics
* authoritative artifact semantics
* fail-fast behavior on invalidity and ambiguity

Cassian Gate must not rely on:

* randomness
* heuristic retries
* adaptive timing guesses
* hidden backoff logic
* nondeterministic ordering
* silent conditional behavior

All waits, retries, and timing behaviors affecting authoritative execution must be:

* explicit
* deterministic in definition
* auditable in evidence

### Determinism boundary clarification

Cassian Gate does **not** claim authority over all external runtime-environment variance.

Environmental factors outside Cassian Gate’s authority boundary, such as:

* host scheduling variance
* container-runtime timing variance
* real-time convergence timing variance

do not redefine:

* authoritative meaning
* verdict semantics
* artifact authority

Cassian Gate guarantees deterministic **authority semantics**, not total control over all external runtime physics.

---

## Explicitness

Cassian Gate must **never**:

* guess intent
* auto-fix authoritative input
* silently coerce declarations
* reinterpret materially ambiguous intent
* mutate user design outside Resolve

Defaults are allowed **only when** all of the following are true:

* applied during Resolve
* deterministic
* visible in `topology.resolved.yaml`
* they do not conceal ambiguity
* they do not substitute for missing required intent

Ambiguity is a design error.

---

## Hard-fail authoritative input handling

Authoritative input must be either explicitly accepted or explicitly rejected.

Before authoritative execution proceeds, Cassian Gate must reject authoritative input that is:

* malformed
* schema-invalid
* structurally ambiguous
* partially invalid in a way that affects intended execution meaning
* contradictory in a way that removes deterministic meaning
* unsupported in a way that could mislead operator interpretation
* unrecognized in a way that could conceal author intent or operator error

Cassian Gate must **not**:

* silently coerce authoritative input
* partially accept invalid declarations
* ignore unsupported or unrecognized authoritative structure in a way that could misrepresent intent
* continue on a best-effort basis when authoritative input is invalid or ambiguous

### Unknown-key strictness

Unknown or unrecognized authoritative keys, fields, structures, or declarations are **hard-fail by default**.

If non-authoritative metadata namespaces are ever permitted, they must be:

* explicitly defined
* explicitly bounded
* explicitly non-authoritative

Absent such explicit definition, permissive ignoring of unknown authoritative structure is forbidden.

---

## Auditability

Every authoritative execution must produce a stable artifact directory containing at minimum:

```text
topology.resolved.yaml
results.json
results.summary.txt
```

Artifacts must be sufficient to:

* audit authoritative outcomes
* diagnose failures
* explain outcomes
* preserve machine-consumable pass/fail meaning

---

# 3) Execution lifecycle (fixed order)

The lifecycle is **strictly ordered**:

```text
resolve → generate → deploy → provision → test → collect → destroy
```

No feature may introduce additional hidden phases.

No feature may insert implicit conditional phases.

Later phases must not mutate earlier authoritative meaning.

---

## Resolve

Resolve may:

* validate authoritative input
* reject invalid or ambiguous declarations
* apply visible deterministic defaults
* expand packs
* expand scenarios
* emit `topology.resolved.yaml`

Resolve may not:

* conceal ambiguity
* silently repair unsupported declarations
* reinterpret materially unclear operator intent
* create hidden operator meaning

---

## Generate

Generate may produce:

* containerlab topology artifacts
* per-node configuration
* provisioning artifacts
* generated execution material derived from resolved authoritative input

Generate may not mutate authoritative intent beyond what Resolve already made explicit.

---

## Deploy

Deploy may:

* deploy runtime environment
* verify runtime presence
* establish the execution environment for deterministic validation

Deploy failures are hard failures, not validation outcomes.

---

## Provision

Provision may:

* apply addressing
* apply firewall configuration
* apply runtime configuration
* perform deterministic readiness checks

Cassian Gate does **not** infer routing intent.

Provision may not silently compensate for missing or ambiguous user intent.

---

## Test

Test is the authoritative behavior-validation phase.

It may:

* execute atomic tests
* execute deterministic scenarios
* evaluate deterministic invariants

It may not:

* perform hidden remediation
* reinterpret failures as success
* introduce authority outside declared validation logic

---

## Collect

Collect must:

* write `results.json`
* write summaries and evidence
* preserve authoritative machine-consumable result meaning
* separate authoritative from supporting evidence

---

## Destroy

Destroy must provide:

* deterministic teardown
* no leaked containers or runtime residue that weakens authoritative gate trust

---

# 4) Gate-first UX (LOCKED)

## `cassian test`

Authoritative validation.

Behavior:

* clean-state execution
* deterministic lifecycle
* binary verdict
* CI-safe exit behavior
* authoritative artifacts

### Clean-state rule

`cassian test` must execute from a clean authoritative context.

No fast mode, cached-state path, incremental reuse path, idempotent shortcut, partial lab reuse, or convenience workflow may weaken the clean-state guarantee of authoritative gating.

Any weakening of clean-state gate semantics requires explicit constitutional amendment.

---

## `cassian run`

Exploration mode.

Behavior:

* non-authoritative
* supports iterative experimentation
* never used for CI gating
* never a substitute for authoritative validation

No exploratory surface may inherit or approximate authoritative gate status implicitly.

---

# 5) Scenario contract

Scenarios model **deterministic event sequences**.

Scenarios are:

* explicit
* ordered
* deterministic
* artifact-recorded
* fail-fast on ambiguity

Scenario execution must not become a general scripting surface.

---

## Scenario step structure

Each step must contain **exactly one declared action category**.

Example:

```yaml
steps:
  - run:
      command: ping hostA hostB
```

A step may not bundle multiple action categories into a single compound execution unit.

Ordered multi-step composition is permitted.
Implicit multi-action compression within one step is forbidden.

Unknown or unrecognized scenario structure is rejected under the same hard-fail authoritative input rules as the rest of the topology.

---

## Scenario action extensibility

Scenario actions are **extensible**.

The contract does **not** freeze a fixed action list.

Instead, every action must satisfy the following requirements.

---

## Scenario action requirements

All scenario actions must be:

### Explicit

Required parameters must be declared.

No implicit targets.
No hidden scopes.

---

### Deterministic

The same step must always produce the same intended effect under the same authoritative conditions.

Forbidden:

* randomness
* adaptive behavior
* probabilistic operations

---

### Replay-stable in authority semantics

Scenario steps must preserve the same authoritative meaning when replayed.

Replay must preserve the meaning of:

* actions
* sequencing
* outcome semantics

Replay does not require total elimination of all external runtime timing variance.

---

### Artifact-recorded

Actions affecting network state, evidence, or authoritative interpretation must be recorded in:

```text
results.json
```

---

### Fail-fast on ambiguity

If an action cannot be resolved unambiguously, execution must stop.

Example:

```text
ERROR: ambiguous link target
```

---

# 6) Scenario action categories

These categories describe **behavioral expectations**, not a fixed action list.

---

## Execution actions

Execute commands within nodes.

Examples:

```text
run
```

---

## Fault / degradation actions

Introduce deterministic environmental changes.

Examples:

```text
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

Fault actions must be:

* explicitly scoped
* reversible where applicable
* artifact-recorded

---

## Convergence actions

Wait for deterministic conditions.

Examples:

```text
wait
wait_for
wait_for_bgp
```

All waits must declare:

```text
timeout
expected condition
```

No hidden convergence heuristics are permitted.

---

## Evidence capture actions

Capture runtime evidence.

Examples:

```text
pcap_start
pcap_stop
```

Evidence capture may support diagnosis and auditability.

Evidence capture must **not influence verdicts directly**.

---

# 7) Test contract

Atomic tests remain the **primary authority for validation**.

Supported test classes include:

```text
ping
tcp
bgp_neighbor
invariant
```

Additional deterministic tests may be added if they preserve this contract.

---

## Required test fields

Each authoritative test result must record semantics sufficient to represent:

```text
expected
observed
verdict
evidence
```

---

## Negative tests

If:

```text
expected: fail
```

and failure occurs:

```text
observed: fail
verdict: pass
```

Negative validation is first-class behavior, not an exception.

---

## Results completeness

Declared validation items must be represented explicitly in authoritative results.

Absence must never imply pass.

Where non-execution states exist and materially affect auditability, they must be explicit rather than implied by omission.

Silence must not equal success.

---

# 8) Routing invariant contract

Routing invariants provide **deterministic routing-intent validation**.

Invariants execute during the **TEST** phase.

Invariant results appear as **standard authoritative test results**.

Example:

```text
kind: invariant
type: bgp_session_up
```

Invariant evaluation must be:

* deterministic
* binary
* replay-stable in authority semantics

Invariant support is bounded and named.
It is not generic NOS feature parity.

---

# 9) AI contract (authoritative boundary)

AI features are **assistive only**.

AI may:

* explain results
* analyze artifacts
* summarize evidence
* suggest improvements for human review

AI may **never**:

* influence verdicts
* modify topology
* execute lifecycle steps
* alter authoritative artifacts
* alter authoritative meaning
* introduce non-deterministic authority

AI must operate on authorized artifacts such as:

```text
topology.resolved.yaml
results.json
```

AI must remain:

* explicit
* optional
* outside the authority chain
* validly absent without weakening the deterministic engine

---

# 10) Model vs runtime backend

Topology model must remain **runtime-agnostic**.

Backends implement execution:

```text
containerlab (current)
vm runtime (future)
```

Backend logic must not leak into authoritative topology schema in ways that mutate constitutional meaning.

Runtime variety is allowed.
Authority drift is not.

---

# 11) Security & hygiene

Required guarantees:

* no shell injection through normal operation
* no implicit network access expansion
* deterministic teardown
* no leaked processes or runtime residue that weakens trust
* explicit authority over what is executed and why

Security-related convenience may not bypass explicitness or authority rules.

---

# 12) Artifact contract

Authoritative artifacts must remain:

* stable in meaning
* auditable
* machine-consumable
* sufficient for authoritative interpretation

They must not depend on advisory interpretation for pass/fail meaning.

Backward compatibility **must** be preserved unless an explicit artifact versioning mechanism is introduced.

Generated summaries, state capture, logs, and similar outputs remain supporting evidence unless explicitly designated authoritative.

---

# 13) Change control

Every change must satisfy all of the following:

1. Deterministic in authority semantics
2. Auditable
3. Inputs authoritative
4. Outputs generated
5. Clean-state gate identity preserved
6. AI boundary preserved
7. Negative-test semantics preserved
8. No silent mutation introduced

If any answer is **no**, the change is invalid unless explicitly redesigned or constitutionally amended.

---

# 14) Explicit non-goals (LOCKED)

Cassian Gate will **never become**, as part of authoritative correctness:

* a lab platform
* a chaos engine
* a heuristic validator
* an AI decision system
* a generic scripting engine for validation authority
* a feature-parity NOS platform
* a controller-style execution authority system

Forbidden:

* AI-driven pass/fail
* auto-remediation
* probabilistic validation
* silent configuration mutation
* hidden authority transfer
* soft exploratory modes becoming gate substitutes

---

# Contract authority

This document is **authoritative**.

If implementation, documentation, roadmap discussion, AI suggestions, or external review conflict with this contract:

**the contract wins.**

Changes must be redesigned, deferred, or explicitly amended through constitutional process.

---

**End of contract.**

```
```
