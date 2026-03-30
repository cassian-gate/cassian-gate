````markdown
# ai-netsim — Extension & Adoption Guide

## Purpose

ai-netsim is designed to be extended by engineers, teams, and vendors.

The goal is to make it easy to:
- add validation coverage
- model real-world network behavior
- share reusable test logic
- integrate new environments safely

This document explains **how to extend ai-netsim correctly**.

---

## Core Principle

ai-netsim is a **deterministic validation engine**, not a lab platform.

Everything must remain:
- explicit
- reproducible
- testable
- deterministic

Extensions must **never change execution behavior or verdict logic**.

---

## What You Can Extend

ai-netsim is intentionally extensible in a few key areas.

### 1. Invariants

Invariants are deterministic validation checks.

Examples:
- route is present
- route is not advertised
- BGP attribute equals expected value

**Use when:**
- you need strict, reusable validation logic
- the behavior must be binary (pass/fail)

---

### 2. Test Packs (Invariant Packs)

Packs are reusable groups of invariants.

Example:
```yaml
packs:
  - datacenter-bgp-safety
````

**Use when:**

* you want to standardize validation across environments
* you want to share best practices

---

### 3. Scenarios (Failure Choreography)

Scenarios define ordered failure testing.

Examples:

* link down → verify failover → restore → verify recovery
* node reboot → convergence → validation

**Use when:**

* testing resiliency
* validating failover behavior
* proving real-world change impact

---

### 4. Topologies

Topologies define:

* nodes
* links
* tests
* scenarios

**Use when:**

* modeling real networks
* creating reproducible validation environments

---

### 5. State Profiles (Evidence Collection)

State profiles define what operational data to collect.

Examples:

* interfaces
* routing tables
* firewall rules

**Important:**

* state is **supporting evidence only**
* it does NOT affect pass/fail results

---

### 6. Candidate Config (Input Only)

Candidate config allows you to express intended changes.

**Important:**

* config is input only
* behavior validation is what matters
* config does NOT determine success

---

### 7. NOS Extensions (Advanced)

Advanced users and vendors can add support for new NOS types.

A NOS extension may include:

* runtime definition (how it runs)
* control-surface readiness
* optional state capture support
* optional invariant pack compatibility

**Important:**

* NOS support must NOT change core execution behavior
* all validation remains in the shared engine

---

## What You CANNOT Extend

The following are **strictly part of the core engine**:

* lifecycle execution
* pass/fail logic
* exit codes
* artifact authority
* deterministic behavior

Do NOT attempt to:

* modify execution flow
* override validation results
* introduce hidden logic
* create plugin-style runtime hooks

---

## How to Contribute

### Step 1 — Start with YAML

Most extensions require **no code**.

Start by creating:

* a topology
* tests or scenarios
* optional packs

---

### Step 2 — Validate Locally

```bash
netsim test <topology.yaml>
```

Ensure:

* deterministic results
* clear pass/fail behavior
* no ambiguity

---

### Step 3 — Add Reusable Logic

If useful:

* extract tests into packs
* define scenarios
* document usage

---

### Step 4 — Share

You can contribute:

* example topologies
* invariant packs
* scenario patterns
* NOS extensions (advanced)

---

## Design Rules for Extensions

All extensions must follow these rules:

* explicit inputs only
* no hidden defaults
* deterministic output
* reproducible results
* no side effects
* no authority over verdicts

---

## Anti-Patterns (Avoid These)

Do NOT:

* mix validation and execution logic
* introduce randomness or timing dependencies
* rely on external state
* hide behavior behind abstraction
* create “magic” automation

---

## Adoption Strategy

The easiest way to adopt ai-netsim is:

1. start with a small topology
2. add simple tests
3. introduce scenarios
4. reuse packs
5. expand coverage over time

---

## Contribution Philosophy

ai-netsim grows through:

* shared validation logic
* reusable scenarios
* real-world examples
* deterministic behavior

Not through:

* complex frameworks
* plugin ecosystems
* hidden abstractions

---

## Summary

ai-netsim is designed to be:

* simple to extend
* strict in behavior
* deterministic in execution
* reliable for production validation

If your extension:

* improves validation clarity → good
* improves reproducibility → good
* improves real-world coverage → good

If it:

* introduces ambiguity → reject
* weakens determinism → reject

---

## Final Rule

If you are unsure:

→ prefer explicit, simple, deterministic solutions

This is how ai-netsim remains trustworthy.

```
```

