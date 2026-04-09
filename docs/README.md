````markdown
# Cassian Gate Documentation

**Status:** AUTHORITATIVE  
**Audience:** Network engineers, platform engineers, CI/CD operators  
**Scope:** Cassian Gate v1 / v1.x documentation set  

This repository contains the **authoritative documentation** for **Cassian Gate**, a deterministic, CI-first **network change-validation gate**.

These documents define **how Cassian Gate is intended to be used**, **what is supported**, and **what is explicitly out of scope** for each version.

If documentation here conflicts with implementation **at the level of intent, scope, or authority**, **the documentation wins**.  
Implementation bugs are fixed to match documented behavior.

---

## 🚀 First 2 Minutes — See It Work

Before reading the full documentation, verify your environment and run a deterministic gate:

```bash
cassian doctor
cassian test examples/dci-failover.yaml
````

Expected behavior:

* `cassian doctor` verifies your environment (Docker, containerlab, required images).
* `cassian test examples/dci-failover.yaml` runs an **authoritative clean-state gate**:

  1. Deploys the topology
  2. Executes declared tests
  3. Writes artifacts under `labs/clab-<labname>/`
  4. Tears down the lab
  5. Returns deterministic exit code

     * `0` = PASS
     * `1` = FAIL

You can also observe failure behavior:

```bash
cassian test examples/dci-failover-broken.yaml
```

This is the intended first experience of Cassian Gate.

Cassian Gate is designed so that a single command produces a reproducible, CI-safe verdict.

---

## What Cassian Gate Is

Cassian Gate is:

* a **deterministic network change-validation gate**
* **artifact-driven** and **CI-safe**
* **behavior-validated**, not configuration-validated
* **engineer-first**, not lab-first
* **AI-assisted**, never AI-driven

Cassian Gate exists to answer one question reliably:

> *“Will this change behave the way we expect before we deploy it?”*

---

## What Cassian Gate Is NOT

Cassian Gate is **not**:

* a general-purpose network lab
* a topology designer
* a routing **mechanics** simulator (protocols, metrics, policies)
* a performance or ASIC emulator
* an AI that decides correctness
* an auto-remediation system

---

## Repository Structure

This repository is intentionally small, explicit, and **version-scoped**.

```
.
├── admin-guide-v1.md
├── topology-schema-v1.md
├── cli-reference-v1.md
└── README.md
```

Future versions (v1.5, v2) will introduce **new files**, not overwrite v1 documents.

---

## Document Roles

| File                    | Purpose                                       |
| ----------------------- | --------------------------------------------- |
| `admin-guide-v1.md`     | How to operate Cassian Gate correctly and safely |
| `topology-schema-v1.md` | Exact topology YAML structure and semantics   |
| `cli-reference-v1.md`   | Complete CLI command reference                |
| `README.md`             | Orientation and navigation (this file)        |

---

## Document Hierarchy (Important)

Read and trust documents in this order:

1. **Admin Guide**
   Defines mental model, authority, and correct usage.

2. **Topology Schema Guide**
   Defines what topology YAML *means* and what is allowed.

3. **CLI Reference**
   Defines available commands and flags.

This mirrors Cassian Gate’s own design:

> **Intent → Structure → Execution**

---

## Versioning Policy

This repository follows **strict version scoping**.

* `v1 / v1.x` documents describe **stable, implemented behavior**
* Anything not documented here is **out of scope**
* Future versions (v1.5, v2) will live alongside, not overwrite, v1 docs

No speculative features are documented.

---

## Authority & Contract Alignment

Cassian Gate is governed by a **design contract**:

* Tests and scenarios are authoritative
* AI is advisory only
* Determinism is non-negotiable
* Ambiguity fails fast

All documents in this repository are written to **enforce that contract**, not weaken it.

---

## How This Repo Is Meant to Be Used

This repository is intended to be:

* read by humans
* referenced during change reviews
* linked in CI pipelines
* cited during incidents and postmortems

It assumes readers already understand networking fundamentals.
It documents **Cassian Gate behavior and guarantees**, not networking theory.

---

## Contributing / Changes

Changes to documentation must:

1. Declare the target version
2. Respect existing scope boundaries
3. Preserve authority model
4. Avoid speculative features
5. Remain consistent with implementation

If a change alters authority, scope, or version semantics, it must be **explicitly justified**.

---

## One-Sentence Summary

> **This repository defines how Cassian Gate is used, trusted, and kept honest.**

```

---

If you'd like, I can now:

- Provide a slightly more enterprise-polished version  
- Or create a **developer-facing README** variant (different audience tone)  
- Or add a minimal CI example block (GitHub Actions snippet)
```
