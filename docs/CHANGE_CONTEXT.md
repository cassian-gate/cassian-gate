---
# ai-netsim — Implementation Handover
## Change Context + Advisory Intent Builder (All Versions)

> **Purpose**  
> This document describes *how* ai-netsim implements a friendly, high-value UX for engineers making production changes — **without violating determinism, authority, or CI safety**.

This document is **implementation guidance**, not authority.  
If it conflicts with `docs/STRATEGY_HANDOVER.md` or `design-contract.md`, **those documents win**.

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

- Users may attach **any candidate config**:
  - full config
  - diff
  - snippet
  - ticket / PR reference
  - plain-text notes
- Vendor-agnostic (Junos, EOS, IOS-XR, FortiOS, Palo Alto, SONiC, FRR, etc.)
- Stored in the topology and copied into run artifacts
- **Never consumed by the deterministic engine**

**Purpose:**  
Human understanding + AI advisory reasoning only.

---

### 2.2 Candidate Config Storage Convention (All Versions)

**Recommended pattern (strongly encouraged):**

- **Topology**
  - references + metadata only
  - acts as the *index and intent anchor*
- **Filesystem**
  - holds the actual candidate config content

Example repository layout:

```

topologies/change-bgp-policy.yaml
changes/2026-01-15-bgp-policy.diff
changes/fw-acl-snippet.txt

```

**Benefits:**

- keeps topology readable
- avoids accidental secret sprawl
- improves PR diffs and reviews
- scales to large vendor configs
- preserves determinism and CI reproducibility

Inline config text in the topology is allowed **only for small snippets**.

---

### 2.3 Advisory Intent Builder (AI)

AI uses:

- topology model
- candidate change context
- (optionally) prior run artifacts

To produce **suggestions**, never decisions:

1. Change interpretation (with explicit uncertainty)
2. Proposed intent (plain language)
3. Proposed invariants (testable statements)
4. Suggested tests / scenarios (copy-paste YAML)
5. Coverage gaps & risk checklist
6. Blast-radius explanations (descriptive only)

Every AI output must declare:

> **“Advisory only — tests and scenarios are the sole authority.”**

---

### 2.4 Gate Remains Untouched

- `netsim test`
  - clean-state
  - deterministic
  - binary verdict
- `netsim run`
  - exploratory only
- AI commands
  - post-execution
  - exit code always `0`
  - no side effects
  - no runtime mutation

---

## 3) UX Pillars Engineers Love (All Versions)

These principles apply everywhere, regardless of tier.

### A) “What Changed?” Summary

- First thing shown
- Grounds the engineer
- Reduces fear and confusion

---

### B) “Am I Missing Something?” Checklist

- Missing negative tests
- Missing failure scenarios
- Missing must-not invariants
- Missing return-path validation

Feels like senior-engineer review.

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
- “Change touches more than expected”

---

### F) Calm, On-Call-Friendly Explanations

- Especially for `netsim ai explain`
- Optimized for 3am clarity

---

## 4) Version-Specific Implementation Blocks

---

## v1 — Open Core (Required, Minimal, Safe)

### Goals

- Make ai-netsim immediately friendly
- Zero vendor parsing
- Zero authority risk

---

### Block 1 — Change Context Declaration

**Implement**

- Add `candidate_changes` to topology schema
- Each entry supports:
  - `id`
  - `type` (`diff|snippet|full|ticket|note`)
  - exactly one of `path` or `text`
  - optional `targets` (node names)
  - optional `vendor`
  - optional `change_id`

**Rules**

- Large configs should be referenced via `path`
- Inline `text` limited to small snippets
- Engine must ignore this section completely

**Verification**

- Schema validation
- Negative tests for invalid combinations
- Deterministic ordering in resolved topology

---

### Block 2 — Bundle Change Context (Artifact-Only)

**Implement**

- Include candidate config content in AI bundles:
  - size-limited
  - deterministic ordering
  - basic redaction hooks
- Large files truncated with metadata

**Verification**

- Golden bundle fixtures
- Redaction safety checks
- No runtime or deploy access

---

### Block 3 — `netsim ai review` (Offline-First)

**Implement**

- Deterministic advisory output:
  - “What changed?”
  - risk checklist
  - minimal proof set
- No vendor parsing
- No online dependency required

**Verification**

- Golden fixtures
- Exit code always `0`

---

### Block 4 — `netsim ai explain` (On-Call Friendly)

**Implement**

- Explain failures using:
  - `results.json`
  - resolved topology
  - candidate change context
- Plain language, no fixes

**Verification**

- Known failure fixtures
- No authority leakage

---

## v1.5 — Trust & Coverage Upgrade

### Goals

- Increase confidence
- Reduce AI uncertainty
- Improve safety signals

---

### Block 5 — Deterministic Change Classification

**Implement**

- Regex/tag-based classifier (no AI)
- Categories:
  - routing
  - firewall
  - NAT
  - VRF
  - L2/VLAN
  - interface

**Use**

- warnings only
- confidence signals only

---

### Block 6 — Coverage Awareness (Advisory)

**Implement**

- Map tests/scenarios to:
  - nodes
  - paths
  - must / must-not semantics
- Compare against change categories

**Output**

- “You changed X but did not test Y”

---

## Pro — Individual Engineer Accelerator

### Goals

- Faster iteration
- Better guidance
- Zero safety compromise

---

### Block 7 — Intent Packs

**Implement**

- Curated test/scenario templates:
  - add BGP peer
  - change ACL
  - modify NAT
  - VRF change
- Suggested by AI, never auto-applied

---

### Block 8 — Patch-Style Output

**Implement**

- Copy-paste YAML blocks only
- Explicit “human must apply” warning

---

## Enterprise — Governance & Evidence

### Goals

- Organizational adoption
- Auditability
- Consistency at scale

---

### Block 9 — Policy-Driven Deterministic Guardrails

**Implement**

- Explicit policy rules:
  - e.g. firewall change → require negative tests
- Deterministic enforcement
- Explicit opt-in

---

### Block 10 — Artifact Retention & Integrations

**Implement**

- Stable artifact metadata
- change_id propagation
- CI + ticketing hooks

---

### Block 11 — Vendor Evidence Packs (Non-Authoritative)

**Implement**

- Allowlisted command capture
- Evidence only
- AI may summarize, never gate

---

## Optional (Any Version ≥ v1.1)

### Block X — Sanitized AI Output Fixtures

**Purpose**

- Validate AI output *structure*, not content

**Implement**

- Sanitize free text → placeholders
- Assert:
  - schema validity
  - allowed keys only
  - advisory markers present
  - redaction enforced
- Behind explicit flag

---

## 5) Non-Negotiable Rules (All Versions)

1. Candidate config is **never authoritative**
2. AI never affects verdicts or exit codes
3. Tests & scenarios are the only gate
4. AI suggestions are never auto-applied
5. Confidence signals are human-facing only

---

## 6) External Mental Model

> “ai-netsim doesn’t tell you if a config is correct.  
> It helps you decide **what to prove**, then proves it deterministically.”

This sentence should guide every UX decision.

---
```

---
