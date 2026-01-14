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

## 3) Deterministic Core vs Probabilistic Edge (Locked)

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

- atomic tests (ping, tcp)
- negative tests
- strict schema validation
- fail-fast guardrails

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

---

## 5) v1 Explicit Non-Goals

The following are **out of scope for v1**:

- EVPN control-plane inspection
- MAC/IP route parsing
- grey failures (loss, jitter, delay)
- VM runtime
- vendor NOS execution
- state-based approval (“no diff = pass”)
- performance or ASIC simulation

These belong to **v1.5+**.

---

## 6) VXLAN / EVPN Strategy (No Drift)

### v1

- EVPN validated **implicitly via outcomes**
- minimal representative fabrics
- reachability + failure survival
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

## 7) Pre/Post Operational State Capture (Supporting Evidence)

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

## 8) Versioning & Monetization Model (Locked)

### v1 — Free / Open Core

- deterministic validation
- scenarios
- assistive AI
- basic evidence capture

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

## 9) Current Status (Truthful Snapshot)

### v1 Core

✅ deterministic engine  
✅ scenario semantics  
✅ fault determinism  
✅ convergence handling  
✅ negative regression suite  
✅ validation-only mode  

### Remaining for v1

🚧 Assistive AI implementation (`ai explain / review / coach`)

Nothing else blocks v1.

---

## 10) Current Focus (“NOW”)

> **Implement v1 Assistive AI (Advisory Only)**

Hard rules:

- artifact-only inputs
- explicit invocation
- zero side effects
- always exit `0`
- must state **“advisory only”**

Offline deterministic AI scaffolding is acceptable.
Online BYO-key AI may be layered later.

---

## 11) Implementation Workflow (Locked)

Every change follows this loop:

1. Declare the target (v1-safe)
2. Paste current code
3. Receive surgical instructions
4. Implement locally
5. Run verification
6. Lock the change

No refactors.  
No batching.  
No guessing.

---

## 12) Adoption Guardrails (Locked)

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

## 13) How This Document Is Used

- Paste this document at the start of any **Milestone Strategy chat**
- Refer to it explicitly when rejecting scope creep
- Do **not** rely on chat memory
- If something is missing, update this file — **not the chat**

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
- EVPN internals are v1.5+
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

---

