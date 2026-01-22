# ai-netsim — Implementation Handover
## Change Context + Advisory Intent Builder (All Versions)

> **Purpose**  
> This document describes *how* ai-netsim implements a friendly, high-value UX for engineers making production changes — **without violating determinism, authority, or CI safety**.

This document is **implementation guidance**, not authority.  
If it conflicts with `docs/STRATEGY_HANDOVER.md` or `docs/design-contract.md`, **those documents win**.

---

## 1) The One Big Idea (Canonical)

> **Attach the candidate change → translate it into what must be proven → prove it deterministically.**

ai-netsim supports engineers by allowing them to attach **any candidate NOS configuration** (any vendor, any format) as **context only**, and then uses **advisory AI** to:

- interpret the *likely* impact of the change
- propose **intent**
- propose **invariants**
- propose **tests and scenarios**
- highlight **coverage gaps and risks**

**Only tests and scenarios are authoritative.**

Candidate configs and AI **never** affect verdicts, execution, or exit codes.

---

## 2) Core Concepts (Applies to All Versions)

### 2.1 Change Context (Non-Authoritative)

- Users may attach **any candidate change material**:
  - full config
  - diff
  - snippet
  - ticket / PR reference
  - plain-text notes
- Vendor-agnostic (Junos, EOS, IOS-XR, FortiOS, Palo Alto, SONiC, FRR, etc.)
- Stored in the topology and copied into run artifacts
- **Never consumed by the deterministic execution engine**

**Purpose:**  
Human understanding + AI advisory reasoning only.

---

### 2.2 Candidate Change Storage Convention

**Strongly recommended pattern (all versions):**

- **Topology**
  - contains references + metadata only
  - acts as the *index and intent anchor*
- **Filesystem**
  - holds the actual candidate content

Example repository layout:

topologies/change-bgp-policy.yaml
changes/2026-01-15-bgp-policy.diff
changes/fw-acl-snippet.txt


**Benefits:**

- keeps topology readable
- avoids accidental secret sprawl
- improves PR diffs and reviews
- scales to large vendor configs
- preserves determinism and CI reproducibility

Inline config text in the topology is allowed **only for small snippets**.

---

### 2.3 Advisory Intent Builder (AI)

AI may use:

- the resolved topology
- candidate change context
- (optionally) prior run artifacts

To produce **suggestions only**, never decisions:

1. Change interpretation (with explicit uncertainty)
2. Proposed intent (plain language)
3. Proposed invariants (testable statements)
4. Suggested tests / scenarios (copy-paste YAML)
5. Coverage gaps & risk checklist
6. Blast-radius explanations (descriptive only)

Every AI output must explicitly declare:

> **“Advisory only — tests and scenarios are the sole authority.”**

---

### 2.4 Gate Semantics Are Untouched

- `netsim test`
  - clean-state
  - deterministic
  - binary verdict
- `netsim run`
  - exploratory only
- AI commands
  - post-execution only
  - exit code always `0`
  - no side effects
  - no runtime mutation

---

## 3) UX Pillars Engineers Respond To

These principles apply everywhere, regardless of version or tier.

### A) “What Changed?” Summary

- First thing shown
- Grounds the engineer
- Reduces fear and ambiguity

---

### B) “Am I Missing Something?” Checklist

- Missing negative tests
- Missing failure scenarios
- Missing must-not invariants
- Missing return-path validation

Feels like a senior-engineer review.

---

### C) Minimal Proof Set

- Smallest recommended test/scenario set
- Explicitly labeled as *minimal*
- Respects time pressure

---

### D) Blast Radius (Advisory)

- “If this fails, what breaks?”
- Plain language
- Never predictive or gating

---

### E) Scope-of-Change Warnings

- “You changed routing but only test firewall”
- “Change touches more systems than expected”

---

### F) Calm, On-Call-Friendly Explanations

- Especially for `netsim ai explain`
- Optimized for 3am clarity

---

## 4) Version-Specific Implementation Blocks

---

## v1 / v1.x — Open Core (Implemented & Locked)

### Goals

- Immediate usability
- Zero vendor parsing
- Zero authority risk

---

### Block 1 — Change Context Declaration (v1)

**Implemented**

- `candidate_changes` in topology schema
- Each entry supports:
  - `id`
  - `type` (`diff|snippet|full|ticket|note`)
  - exactly one of `path` or `text`
  - optional `targets`
  - optional `vendor`
  - optional `change_id`

**Rules**

- Engine ignores this section completely
- Schema-validated only
- Deterministic ordering in resolved topology

---

### Block 2 — Change Context Bundling (v1)

**Implemented**

- Candidate content included in AI bundles:
  - size-limited
  - deterministic ordering
  - truncation metadata for large files
- No runtime, deploy, or execution access

---

### Block 3 — `netsim ai review` (v1)

**Implemented**

- Offline-first advisory output:
  - “What changed?”
  - risk checklist
  - minimal proof suggestions
- Exit code always `0`

---

### Block 4 — `netsim ai explain` (v1)

**Implemented**

- Explains failures using:
  - `results.json`
  - resolved topology
  - candidate change context
- No fixes
- No authority leakage

---

## v1.5 — Confidence & Coverage (Deferred)

> See `docs/future/CHANGE_CONTEXT_FUTURE.md`

Planned focus:
- deterministic change classification
- coverage awareness
- richer advisory signals

No execution or verdict authority added.

---

## Pro — Individual Engineer Accelerator (Deferred)

> See `docs/future/CHANGE_CONTEXT_FUTURE.md`

Focus:
- intent packs
- copy-paste test/scenario suggestions
- zero auto-mutation

---

## Enterprise — Governance & Evidence (Deferred)

> See `docs/future/CHANGE_CONTEXT_FUTURE.md`

Focus:
- policy-driven deterministic guardrails
- artifact retention
- vendor evidence packs (non-authoritative)

---

## 5) Non-Negotiable Rules (All Versions)

1. Candidate config is **never authoritative**
2. AI never affects verdicts or exit codes
3. Tests & scenarios are the only gate
4. AI suggestions are never auto-applied
5. Confidence signals are human-facing only

---

## 6) External Mental Model (Pinned)

> “ai-netsim doesn’t tell you if a config is correct.  
> It helps you decide **what to prove**, then proves it deterministically.”

This sentence should guide every UX and AI decision.