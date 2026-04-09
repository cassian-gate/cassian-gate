# 🔮 FUTURE IMPLEMENTATION HANDOVER — Change Context (Post-v1)

## Purpose

This document records **intentionally deferred work** related to **Change Context**
beyond **v1 / v1.x**.

It exists to:

- prevent loss of intent
- avoid re-debating settled design decisions
- preserve authority boundaries
- provide a safe on-ramp for **v1.5 / v2 / Pro / Enterprise**

This document is **not a commitment** and does **not** modify scope, timelines,
or the v1 Design Contract.

---

## Current State (Baseline — LOCKED)

As of **v1 / v1.x**:

- Change Context is:
  - **non-authoritative**
  - **advisory-only**
  - **artifact-only**
  - **post-execution**
  - **offline-first**
- Implemented capabilities:
  - topology-declared `candidate_changes` (v1 scope only)
  - deterministic change bundles
  - change-aware `netsim ai review`
  - change-aware `netsim ai explain`
- All deterministic guardrails are preserved
- No execution, verdict, or exit-code influence

**v1 Change Context is complete and locked.**

No further expansion of **topology-declared Change Context** is planned.

---

## Design Invariants (Must Never Change)

All future Change Context work **must preserve**:

1. Candidate config or change metadata **never affects**:
   - execution
   - verdicts
   - exit codes
2. AI remains:
   - advisory-only
   - post-execution
   - artifact-only
3. Tests and scenarios remain the **sole authority**
4. No live device access
5. No vendor-specific parsing that affects outcomes
6. Determinism and CI safety are non-negotiable
7. Topology schema remains **intent + proof targets only**

Any proposal violating these invariants **must be rejected or deferred**.

---

## v1.5 — Visibility & Confidence (Advisory Only)

### Goals

- Improve **confidence and clarity**
- Reduce uncertainty in AI suggestions
- Surface **what is missing**, not what is “wrong”
- Align Change Context with **coverage-first preflight**

---

### Key Directional Shift (IMPORTANT)

From **v1.5 onward**:

- **Change Context inputs move out of topology**
- Inputs are provided via:
  - CLI flags
  - artifact directories
  - CI metadata
- Topology remains immutable and authoritative

This prevents:
- schema creep
- hidden intent
- mixed authority

---

### Deferred Capabilities (v1.5)

#### 1️⃣ Deterministic Change Classification (Non-AI)

- Lightweight, deterministic classification:
  - routing
  - firewall
  - NAT
  - VRF
  - L2/VLAN
  - interface
- Implemented via:
  - explicit user hints
  - filename / directory conventions
  - simple regex (never heuristics)
- Used only to:
  - improve wording
  - highlight validation gaps
- Never authoritative

---

#### 2️⃣ Advisory Coverage & Intent Gaps (Static Preflight)

Aligned with the **v1.5 advisory preflight model**.

- Deterministic analysis of:
  - topology
  - declared tests
  - declared scenarios
- Example outputs:
  - “Routing-affecting change detected but no failure scenario exists”
  - “Firewall change detected but no negative tests exist”
- Produces:
  - `preflight.json`
  - explicit `authority: advisory`

Rules:

- No gating
- No scoring
- No inference of correctness
- Never merged into execution artifacts

---

#### 3️⃣ Optional Change-Aware `netsim ai coach`

- Coach may become **lightly change-aware**
- Focus:
  - how to think about proving a change
  - how to avoid blind spots
- Explicitly **not**:
  - a fix generator
  - a config reviewer
  - a correctness oracle

---

## v2 — Depth & Scenario Intelligence (Still Advisory)

### Goals

- Better failure reasoning
- Richer scenario thinking
- Improved explainability at scale

---

### Deferred Capabilities (v2)

#### 1️⃣ Change-Aware Scenario Pattern Suggestions

- Suggest **failure choreography patterns**, e.g.:
  - link down → wait → re-test
  - node down → convergence → must-not checks
- Suggestions only
- Never auto-applied
- Never gating

---

#### 2️⃣ Blast Radius Reasoning (Descriptive Only)

- Explain:
  - what breaks
  - who is affected
  - which paths are involved
- Outcome-based only
- Never predictive
- Never authoritative

---

#### 3️⃣ Intent ↔ Invariant Traceability (Visibility)

- Optional mapping:
  - “This intent is covered by these tests”
  - “This invariant has no validation”
- Visibility only
- No enforcement
- No implied correctness

---

## Pro — Productivity & Acceleration (Individuals)

### Goals

- Faster iteration
- Less boilerplate
- Same safety guarantees

---

### Deferred Capabilities (Pro)

#### 1️⃣ Intent Packs

- Curated, copy-paste templates for common changes:
  - add BGP peer
  - ACL modification
  - NAT change
  - VRF migration
- Suggested only
- Never enforced
- Human-applied only

---

#### 2️⃣ Patch-Style Suggestions

- AI may emit:
  - YAML test / scenario snippets
- Explicitly labeled:
  - “Human review required”
- Never auto-mutated
- Never authoritative

---

## Enterprise — Governance & Consistency

### Goals

- Organizational adoption
- Auditability
- Consistent change quality

---

### Deferred Capabilities (Enterprise)

#### 1️⃣ Deterministic Policy Guardrails

- Explicit org rules, e.g.:
  - firewall changes require negative tests
- Deterministic enforcement
- Opt-in only
- Never AI-driven

---

#### 2️⃣ Artifact Retention & Traceability

- `change_id` propagation
- candidate config hashing
- CI / ticket system integration
- Long-term audit trails

---

#### 3️⃣ Vendor Evidence Packs (Non-Authoritative)

- Allow-listed show commands
- Evidence only
- AI may summarize
- Never used for pass/fail

---

## Explicit Non-Goals (All Future Versions)

Change Context will **never**:

- auto-fix configs
- generate device-specific commands
- read live device state
- infer correctness from config text
- bypass tests or scenarios
- become a “smart linter”

---

## Why This Work Is Deferred

- v1 adoption feedback must come first
- Intelligence increases authority-creep risk
- Visibility before enforcement
- Safety before convenience

---

## Final Reminder

Change Context exists to answer:

> “What should I prove before I touch production?”

It must **never** answer:

> “Is this config correct?”
