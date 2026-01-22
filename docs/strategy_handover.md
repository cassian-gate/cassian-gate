# ai-netsim — Strategy & Milestone Handover (Authoritative)

> **This document replaces prior strategy chats.**  
> It is the single source of truth for scope, authority, workflow, and roadmap alignment.
>
> Any proposal that conflicts with this document is **out of scope** unless explicitly amended here.

---

## 0) Project Identity (Non-Negotiable)

**ai-netsim is:**

- a **deterministic network change-validation gate**
- **CI-first**, **artifact-driven**
- **behavior-validated**, not configuration-validated
- **engineer-first**, not lab-first
- **AI-assisted**, never AI-driven

**ai-netsim is NOT:**

- a general-purpose network lab
- a topology designer
- a cloud or provider simulator
- an AI that decides correctness
- an auto-remediation or healing system

---

## 1) One Rule Above All (Authority Model)

> **Tests and scenarios are authoritative.**  
> **AI explains results.**  
> **Humans approve changes.**

This authority model must never be violated.

---

## 2) Design Contract (Binding Summary)

The full `design-contract.md` is binding.  
This section summarizes its non-negotiable principles.

### Determinism

- Same inputs → same outputs → same verdicts
- No randomness, heuristics, or hidden retries
- All defaults applied during **Resolve** and made visible

### Explicitness

- No guessing intent
- Ambiguity → **fail fast**
- No silent remediation or mutation

### Auditability

Every run produces authoritative artifacts:

- `topology.resolved.yaml`
- `results.json`
- deterministic summaries and timelines

### Lifecycle (Order Must Not Change)

Resolve → Generate → Deploy → Provision → Test → Collect → Destroy

No later phase may modify earlier artifacts implicitly.

---

## 3) Deterministic Core vs Probabilistic Edge (LOCKED)

### Deterministic Core (Authoritative)

- topology resolution
- test execution
- scenario orchestration
- fault injection
- verdicts
- exit codes

### Probabilistic Edge (Advisory Only)

- AI explanations
- coverage suggestions
- blast-radius discussion
- onboarding guidance

**AI must never:**

- affect pass/fail outcomes
- affect exit codes
- mutate runtime state
- invent or infer intent

---

## 4) v1 Scope — What v1 *Is*

v1 is complete **only when all three pillars exist**.

### A) Deterministic Validation Core

- atomic tests:
  - `ping`
  - `tcp`
  - `bgp_neighbor` (v1.x binary control-plane invariant)
- negative tests (first-class)
- strict schema validation
- fail-fast guardrails
- artifact-first truth model

> `bgp_neighbor` asserts session state only.  
> It does **not** validate routing correctness, policy, or best-path selection.

### B) Scenario-Based Failure Choreography

- ordered scenario steps
- deterministic faults (node / link / interface)
- explicit waits (`wait_for`, `wait_for_bgp`)
- authoritative timelines in artifacts

### C) Assistive AI (v1 Requirement)

v1 **includes AI**, but only as **assistive**:

- `netsim ai explain`
- `netsim ai review`
- `netsim ai coach`

AI in v1 is:

- post-execution only
- artifact-only input
- optional
- explicitly invoked
- advisory only
- schema-validated and CI-safe

---

## 5) v1 Explicit Non-Goals (LOCKED)

The following are **out of scope for v1**:

- EVPN control-plane inspection or semantic validation (MAC/IP routes, VNI/VTEP behavior)
- protocol modeling or metric interpretation
- grey failures (loss, jitter, delay)
- VM runtime
- vendor NOS execution
- state-based approval (“no diff = pass”)
- performance or ASIC simulation

These belong to **v1.5+**.

---

## 6) VXLAN / EVPN Strategy (No Drift)

### EVPN Clarification (v1 — Important)

**v1 does not implement EVPN control-plane semantics.**

In v1, EVPN/VXLAN is validated **only implicitly via outcome-based tests**, such as:

- reachability
- non-reachability (must-not)
- failure survival
- convergence via scenarios

v1 explicitly does **not**:

- parse EVPN routes (MAC/IP, IMET, Type-5)
- model VNI or VTEP semantics
- inspect EVPN control-plane state
- derive intent from EVPN configuration

EVPN may exist in the runtime (e.g. preconfigured images), but ai-netsim **observes outcomes only**.

### v1

- outcome-based validation only
- minimal representative fabrics
- no EVPN internals

### v1.5

- explicit EVPN awareness
- VNI semantics
- overlay invariants
- SONiC / FRR EVPN (open source)

### v2

- vendor NOS confidence runs
- comparative validation
- user-provided images only
- still deterministic, still advisory evidence

---

## 7) Adoption & Demo Strategy (v1.x)

To reduce first-run friction **without violating v1 authority**, v1.x includes
**preconfigured demo runtimes and UX hardening helpers**.

### Principles

- Routing may exist **outside** ai-netsim authority
- ai-netsim never generates or validates routing logic
- Tests and scenarios remain the sole authority

### Mechanism

- FRR nodes declare explicit `frr_mode`:

  - `generated` (default): routing-neutral, v1-pure
  - `preconfigured`: routing provided by the image/config

- Multi-hop `expect: pass` is allowed **only** when all relevant nodes are explicitly preconfigured.

### UX & Ops Helpers (v1.x, non-authoritative)

- `netsim test --list-scenarios`
- `netsim cleanup --all [--yes]`
- scenario timelines in `results.summary.txt`
- fail-fast, educational CLI error messaging

These helpers improve onboarding and CI signal quality without affecting authority.

---

## 8) Pre/Post Operational State Capture (Supporting Evidence)

**Authority:** NON-AUTHORITATIVE

### v1

- minimal, opt-in, profile-based
- evidence only
- never gates
- never “no diff = pass”

### v1.5

- richer profiles
- improved AI explanation context
- still advisory

### v2 / Enterprise

- vendor profile packs
- compliance bundles
- artifact retention and integrations

---

## 9) Versioning & Monetization Model (LOCKED)

### v1 — Free / Open Core

- deterministic validation gate
- scenarios
- assistive AI
- basic evidence capture
- demo-ready onboarding

### Pro — Paid (Individual Engineers)

- richer advisory features
- coverage awareness
- behavioral invariants
- **no additional authority**

### Enterprise — Paid (Organizations)

- scale
- governance
- reporting
- integrations
- vendor invariants (user-provided images)

> **Core safety is never paywalled.**

---

## 10) Current Status (Truthful Snapshot)

### v1 / v1.x

✅ deterministic engine  
✅ scenario semantics  
✅ fault determinism  
✅ convergence handling  
✅ negative regression suite  
✅ assistive AI (hardened)  
✅ adoption demos & onboarding  
✅ UX & ops helpers  

**v1 semantics are considered complete and stable.**

---

## 11) Current Focus (“NEXT”)

> **Begin v1.5 work: advisory static preflight, candidate-config workflows, EVPN awareness.**

v1 will receive **only**:
- bug fixes
- UX clarity improvements
- guardrail hardening

---

## 12) Implementation Workflow (LOCKED)

Every change follows this loop:

1. Declare the target version
2. Paste current code
3. Receive surgical instructions
4. Implement locally
5. Run verification
6. Lock the change

No refactors.  
No batching.  
No guessing.

---

## 13) Adoption Guardrails (LOCKED)

- `netsim test` is authoritative
- clean-state execution
- binary verdicts
- precise error messages
- reproducible artifacts

Adoption success looks like:

> “The gate failed — let’s improve the tests.”

Not:

> “The tool feels wrong.”

---

## 14) Change Control (Important)

This document is amended **only** when:

- scope boundaries change, OR
- authority model changes, OR
- version definitions change

Implementation details **do not belong here**.

---

## Appendix A — Locked Decisions Index

- Tests & scenarios decide outcomes
- AI explains; never decides
- v1 includes assistive AI
- EVPN semantics are v1.5+
- Routing mechanics never appear in topology
- State capture is non-authoritative
- Vendor NOS images are user-provided
- Pro = individual paid tier
- Enterprise = org-scale tier
- Gate-first clean-state UX is mandatory

---

## Final Statement (Pinned)

> **ai-netsim replaces guesswork with proof.**  
> **AI accelerates understanding, never authority.**  
> **Determinism is sacred.**
