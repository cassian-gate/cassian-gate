````markdown
# ai-netsim — Extension Strategy (Maintainer Internal)

## Status

Authoritative internal maintainer reference.

## Purpose

This document captures the deeper architectural intent behind ai-netsim’s extension model so future decisions remain aligned with the project’s core identity.

It is not a contributor guide.
It is not a marketing document.
It is not a feature list.

It exists to help maintainers answer questions like:

- What should be extensible, and what must remain locked in core?
- How should community and vendor contributions be structured?
- What kind of SDK, if any, should exist?
- How should NOS support evolve without turning ai-netsim into a generic network platform?
- What should be released in v2, and what should wait?
- How do we scale ecosystem contributions without weakening determinism or authority?

This document should be used as a reference when planning backlog items, evaluating PRs, deciding on architecture splits, and reviewing future roadmap changes.

---

# 1. Foundational Product Identity

ai-netsim is a **deterministic network change validation engine**.

Its center of gravity is:

- execution-backed proof
- explicit tests, invariants, and scenarios
- replayable outcomes
- authoritative verdicts
- reduction of production change risk

It is **not** primarily:

- a general network lab
- a config authoring platform
- a vendor feature abstraction layer
- a plugin host
- a generic AI orchestration tool

This identity must remain stable across releases.

## Core rule

If a proposed extension increases flexibility but weakens determinism, authority clarity, or replay stability, it is a bad extension.

If a proposed extension increases coverage, usability, or ecosystem participation while preserving determinism and authority boundaries, it is a good extension.

---

# 2. Why Extension Strategy Matters

If ai-netsim grows only through core-maintainer code, it will stay trustworthy but scale slowly.

If ai-netsim allows arbitrary plugins or deep hooks, it may scale faster in the short term but will lose:

- determinism
- supportability
- reviewability
- trust

So the extension strategy must achieve two goals at once:

1. make contribution easy enough for adoption
2. make contribution narrow enough to preserve trust

That is why the right model is **bounded extension surfaces**, not “plugins”.

---

# 3. Core vs Extension Boundary

This is the most important section in the whole document.

## 3.1 What must remain in shared core

The following must remain owned by the shared deterministic core:

- lifecycle ordering
  - resolve → generate → deploy → provision → test → collect → destroy
- run vs test authority model
- verdict semantics
- exit code contract
- authoritative artifact semantics
- replay semantics
- negative-test semantics
- scenario execution semantics
- invariant evaluation semantics
- explicit asymmetry enforcement
- mandatory deny-all enforcement where applicable
- deterministic failure ownership
- shared CLI behavior
- shared artifact labeling
- AI advisory-only enforcement

This is the part of ai-netsim that answers:

- what is truth?
- what is a pass?
- what is a fail?
- what is authoritative?
- what is advisory?
- what is deterministic?
- what is reproducible?

This part must not become vendor-shaped or community-shaped.

## 3.2 What may be extended

The following may be extended if done within approved boundaries:

- invariant packs
- scenario templates
- topology examples
- state capture profiles
- blast-radius or other non-authoritative evidence inputs, if schema-governed
- NOS bundles
- capability declarations
- candidate-config templates or patterns
- bounded evidence extraction declarations
- bounded AI advisory module routing inputs
- future registry metadata

These surfaces are allowed because they add coverage or usability without taking over authority.

## 3.3 Core principle

Extensions may add **content**, **coverage**, **inputs**, and **supporting evidence**.

Extensions may not add **authority**, **execution control**, or **verdict semantics**.

---

# 4. Why ai-netsim Must Avoid a Plugin System

A generic plugin system is attractive because it promises flexibility, but it creates exactly the kind of ambiguity ai-netsim is designed to eliminate.

## 4.1 What a generic plugin system would cause

- hidden lifecycle mutation
- hidden verdict logic
- inconsistent exit behavior
- non-replayable runs
- review difficulty
- support burden explosion
- “works on my machine” integrations
- vendor-specific branching buried in extension code
- impossible-to-police trust boundaries

## 4.2 Why plugins are the wrong abstraction

Plugins assume the host application is comfortable giving up some control over behavior.

ai-netsim cannot do that, because its product value is exactly its control over:

- execution
- verdicts
- artifacts
- reproducibility

So plugins are the wrong model.

## 4.3 Replacement model

Instead of plugins, ai-netsim should use:

- declarative schemas
- strict validators
- bounded extension surfaces
- optional controlled adapters where absolutely necessary
- explicit support contracts

This makes contribution possible without making behavior opaque.

---

# 5. The Correct Extension Model

The right extension model is:

> **declarative, validator-backed, deterministic, and bounded**

This means contributors should mostly be able to add value through data, not code.

## 5.1 Preferred contribution format

The default extension mechanism should be:

- YAML
- static files
- schemas
- deterministic examples
- strict validation tooling

## 5.2 Preferred contributor workflow

The intended contribution flow is:

1. copy an example
2. modify a few fields
3. run a validator or test command
4. get deterministic feedback
5. share or open a PR

This is the adoption engine.

## 5.3 Why “examples are the SDK”

For early ecosystem growth, examples are more important than a formal SDK.

Examples are:

- easier to understand
- easier to copy
- easier to review
- easier to validate
- easier to adopt

A formal SDK should only come later, when patterns have stabilized.

---

# 6. Community and Vendor Contribution Strategy

## 6.1 Contribution priority order

For adoption, contributors should be encouraged to add, in this rough order:

1. example topologies
2. scenarios
3. invariant packs
4. state capture profiles
5. NOS bundles
6. capability declarations
7. advanced domain packs

This is the order because it matches how users adopt the system:

- first they need something they can run
- then they want reusable validation content
- only later do they need deeper ecosystem surfaces

## 6.2 Community contributions

Community is best suited to contribute:

- generic examples
- common routing packs
- common scenario patterns
- state profiles for open-source stacks
- debugging-oriented evidence profiles
- reference validation patterns

Community should not be encouraged to contribute core behavior.

## 6.3 Vendor contributions

Vendors are best suited to contribute:

- NOS bundles
- examples built around their images
- state capture profiles
- capability declarations
- domain-specific packs
- reference validation topologies
- documentation for readiness and support boundaries

Vendors should not be allowed to inject execution logic into the core engine.

---

# 7. Supported Extension Surfaces (Detailed)

## 7.1 Invariant packs

### What they are

Declarative groupings of existing invariants.

### Why they matter

They provide reusable, trustworthy validation building blocks and are ideal for:
- adoption
- standardization
- domain reuse
- vendor/community sharing

### Why they are safe

They expand into explicit invariant declarations during resolve.
They do not change lifecycle or verdict logic.
They are content, not engine behavior.

### Long-term guidance

Invariant packs should remain:
- declarative
- non-executable
- schema-validated
- deterministic
- replay-safe

### Anti-patterns

Do not allow packs to:
- inject scripts
- introduce custom logic
- alter phase behavior
- define new verdict rules
- depend on host environment implicitly

## 7.2 Scenario templates

### What they are

Reusable declarative scenario patterns for failures and recoveries.

### Why they matter

They let users and contributors encode real-world failure choreography without touching engine code.

### Why they are safe

Scenarios are already part of the explicit model and remain:
- ordered
- deterministic
- inspectable

### Long-term guidance

Scenario contributions should remain:
- explicit
- fail-fast
- free of scripts
- free of heuristics

### Anti-patterns

Do not allow:
- custom imperative step logic
- dynamic branching inside scenario definitions
- non-deterministic wait semantics

## 7.3 Example topologies

### What they are

Runnable, reference-grade examples demonstrating topology + tests + scenarios.

### Why they matter

They are one of the most important adoption levers.
A strong example is more valuable than an abstract feature description.

### Why they are safe

They are just authoritative inputs to the existing engine.

### Long-term guidance

Examples should:
- be runnable with one command
- be minimal but realistic
- prove a point clearly
- include tests and, where relevant, scenarios

### Anti-patterns

Do not let examples become:
- stale
- non-deterministic
- overcomplicated pseudo-labs
- unvalidated marketing content

## 7.4 State capture profiles

### What they are

Declarative sets of commands or state collection definitions.

### Why they matter

They improve evidence quality for:
- debugging
- AI explanation
- operator confidence

### Why they are safe

State is non-authoritative.
Profiles only expand evidence; they do not decide pass/fail.

### Long-term guidance

Profiles should remain:
- non-authoritative
- deterministic
- explicit
- bounded by allowlists

### Anti-patterns

Do not let state capture:
- influence verdicts
- silently change execution behavior
- become a hidden correctness engine

## 7.5 Candidate-config templates and patterns

### What they are

Reusable ways to express change intent for supported workflows.

### Why they matter

Candidate config is important for enterprise realism and adoption.

### Why they are risky

Config surfaces often try to become the product center, which is not ai-netsim’s strategy.

### Long-term guidance

Candidate-config support must remain:
- input-only
- change-intent oriented
- subordinate to behavioral validation

### Anti-patterns

Do not let candidate config become:
- the source of truth for correctness
- a config-generation framework
- a generic multi-vendor authoring abstraction layer

## 7.6 NOS bundles

### What they are

Declarative packages that define how a NOS can be used as a runtime substrate.

### Why they matter

They allow vendors/community to bring their own NOS without waiting for deep built-in support.

### Why they are safe if done correctly

If bundles are declarative and validator-backed, they extend substrate support without taking over core behavior.

### Long-term guidance

NOS bundles should define only bounded surfaces:
- image/runtime type
- readiness probe
- capability declarations
- state profile references
- examples
- optional pack compatibility declarations

### Anti-patterns

Do not allow NOS bundles to:
- include Python code
- hook into lifecycle
- change verdict logic
- rewrite execution semantics
- inject fallback logic

## 7.7 Capability declarations

### What they are

Structured descriptions of what a NOS or bundle supports.

### Why they matter

They help reject unsupported usage early and make support boundaries explicit.

### Why they are safe

They are descriptive, not executable.

### Long-term guidance

Capability declarations should remain:
- explicit
- deterministic
- versioned if needed
- non-authoritative

### Anti-patterns

Do not allow capability declarations to:
- imply support beyond what is proven
- become dynamic feature-detection heuristics
- drive verdict logic directly

---

# 8. NOS Strategy (Maintainer View)

This is one of the most important strategic guardrails.

## 8.1 What a NOS is in ai-netsim

A NOS is not “support for a device.”
A NOS is a **bundle of bounded extension surfaces**.

Examples of surfaces:
- runtime / control-surface interaction
- readiness
- identity / detection
- capability declarations
- state capture support
- invariant-pack compatibility
- optional candidate-config support
- optional evidence adapters

This is the correct mental model.

## 8.2 What a NOS is not

A NOS is not:
- a monolithic vendor module
- a plugin
- a feature parity target
- a correctness authority

## 8.3 Why this matters

If ai-netsim treats “NOS support” as one big thing, future architecture will drift toward:
- vendor spaghetti
- duplicated logic
- unclear support claims
- silent capability widening

If ai-netsim treats NOS support as bounded surfaces, support can scale safely.

## 8.4 Strict rule

A new NOS must only add explicit extension surfaces.
It must never redefine:
- lifecycle
- verdict semantics
- exit codes
- artifact authority
- replay semantics

---

# 9. netsim.py Guardrail

## 9.1 Intended role of netsim.py

`netsim.py` should remain:
- thin
- shared
- orchestration-facing
- mostly registration/wiring/dispatch

It may know that extension surfaces exist.
It must not become the place where deep NOS logic lives.

## 9.2 Objective split signal

Repeated vendor-specific branching in `netsim.py` is an objective signal that the codebase has reached the right time for further splitting.

Examples of warning signs:
- repeated `if nos == ...`
- vendor-specific runtime readiness branches
- vendor-specific evidence extraction branches
- vendor-specific candidate-config apply logic
- vendor-specific artifact shaping logic

## 9.3 What to do when the signal appears

When branching becomes repetitive and structural, move logic into bounded modules.

Do not split too early for style reasons.
Do not wait too long once clear repetition exists.

This is a design discipline rule, not just a refactor preference.

---

# 10. Why the Contribution Model Should Start Without a Formal SDK

## 10.1 Adoption-first reality

Early contributors do not want to learn a framework.
They want to:
- copy something
- edit it
- run it
- share it

A formal SDK too early would increase friction.

## 10.2 Recommended early model

Start with:
- examples
- templates
- validator commands
- strict schemas
- contribution CI

That is enough to unlock adoption.

## 10.3 When an SDK becomes justified

A formal SDK becomes justified only when:
- contribution volume is real
- duplication appears
- schemas stabilize
- people need tooling to author valid contributions faster

## 10.4 What kind of SDK would be acceptable

If an SDK appears later, it should be:
- declarative-first
- schema-driven
- non-executable by default
- mostly a safe authoring/validation toolkit

It should not be:
- a lifecycle hook framework
- a verdict plugin API
- a runtime behavior extension system

---

# 11. Practical “Bring Your Own NOS” Model

This is the most practical and adoption-friendly way to allow community/vendor NOS growth.

## 11.1 Contribution unit

A NOS should be contributed as a self-contained declarative bundle, for example:

```text
contrib/nos/<name>/
  nos.yaml
  README.md
  examples/
    smoke.yaml
  profiles/
    state-basic.yaml
````

## 11.2 Why this works

This is easy for contributors because they can:

* add files, not code
* validate locally
* reuse examples
* submit a PR safely

It is easy for maintainers because it:

* keeps changes reviewable
* preserves engine boundaries
* scales contribution safely

## 11.3 What a bundle may include

Allowed:

* image/runtime declaration
* readiness probe declaration
* capability declaration
* state capture profiles
* example topologies
* scenarios
* pack references or compatibility declarations

Not allowed:

* Python code
* lifecycle hooks
* execution logic
* verdict logic
* exit code changes

## 11.4 Recommended tooling

Eventually ai-netsim should support something like:

```bash
netsim validate-contrib contrib/nos/vendoros-vm
```

This should check:

* schema validity
* required files
* unsupported fields
* deterministic shape

A helper like:

```bash
netsim init-nos-bundle <name>
```

would also be helpful later, but it is not required for initial adoption.

---

# 12. Candidate Config Strategy

This deserves explicit treatment because it is strategically important and easy to misuse.

## 12.1 What candidate config is for

Candidate config exists to let users express realistic intended changes.

It helps ai-netsim stay relevant to real change workflows.

## 12.2 What candidate config is not for

It is not for turning ai-netsim into:

* a config management system
* a vendor normalization layer
* a generic config linter
* a universal parser platform

## 12.3 Long-term rule

Candidate config may increase realism.
It must not become the center of authority.

Behavioral validation remains primary.

## 12.4 Practical guardrail

Use candidate config to express intent.
Use tests, invariants, and scenarios to prove outcome.

---

# 13. State Capture and Evidence Strategy

## 13.1 State is supporting evidence only

This must remain absolute.

Captured state:

* helps debugging
* helps AI
* helps operators
* does not decide verdicts

## 13.2 Why this matters

If state becomes semi-authoritative, ai-netsim becomes harder to reason about and trust is weakened.

## 13.3 Long-term rule

Any future evidence surface must be:

* deterministic
* labeled non-authoritative
* replay-stable if retained
* clearly separated from verdict artifacts

---

# 14. AI Integration Guardrail

## 14.1 AI is first-class but bounded

AI is useful for:

* explanation
* review
* coverage suggestions
* failure interpretation
* human-facing summaries

## 14.2 AI must remain outside the deterministic path

AI must never:

* execute lifecycle steps
* decide pass/fail
* modify authoritative artifacts silently
* become required for CI or correctness

## 14.3 Why this matters

If AI affects authority, ai-netsim stops being trustworthy as a deterministic engine.

That is unacceptable.

---

# 15. What Must Be Easy for v2 Adoption

The following are the highest-value extension surfaces for adoption in or around v2:

* 3–5 strong example topologies
* at least 1 useful invariant pack
* at least 1 deterministic failure scenario
* simple state capture profiles
* a clear `contrib/` structure
* possibly a validator for contributed content

These matter more for adoption than:

* a formal SDK
* a large number of invariants
* broad NOS support claims

Examples are the first adoption engine.

---

# 16. Release Philosophy for v2

## 16.1 v2 is a trust milestone, not a feature-count milestone

v2 should ship when the system is:

* deterministic
* understandable
* trustworthy
* usable in real workflows

Not when every conceivable extension exists.

## 16.2 Recommended release boundary

The true release boundary is when:

* execution model is clear
* scenario correctness is stable
* AI interface is bounded and useful
* UX is adoption-friendly
* NOS architecture guardrail is locked
* registry/trust tier direction is defined enough to avoid future chaos

Deeper state capture and advanced NOS invariants can wait post-release.

---

# 17. Backlog Classification Rule (Important Process Learning)

This was an important lesson from recent work and should be remembered.

Not every backlog item is a net-new implementation item.

Backlog items should be classified explicitly as one of:

* implementation
* formalization/proof

A formalization/proof item may complete with **zero code changes** if:

* the capability already exists
* deterministic proof is completed
* failure classes are verified
* contracts are clarified and locked

This distinction should be kept visible in future planning so effort is not misread.

---

# 18. Anti-Patterns to Reject

These should be treated as architectural red flags.

## 18.1 Mixing core and extension logic

Bad:

* NOS readiness logic mixed into shared lifecycle code
* invariant pack expansion logic mixed with runtime behavior
* candidate-config semantics embedded in verdict code

## 18.2 Monolithic vendor module

Bad:

* one giant file per vendor containing runtime, evidence, config, packs, and validation logic

Better:

* bounded surfaces by responsibility

## 18.3 Silent support widening

Bad:

* “it booted once, therefore we support it”
* “we can capture state, therefore invariants work”
* “we can apply config, therefore the NOS is supported”

Support must be explicit per surface.

## 18.4 Contributor code execution

Bad:

* allowing community/vendor code to run inside core lifecycle

## 18.5 Heuristics in core

Bad:

* guessy detection
* fallback login behavior
* ambiguous environment-specific logic hidden in core

## 18.6 Authority leakage

Bad:

* state diff influencing verdict
* blast radius treated as pass/fail evidence
* AI output treated as correctness

---

# 19. Decision Heuristics for Future Maintainer Choices

When making future extension decisions, use the following questions.

## 19.1 Does this extension add coverage or change behavior?

If it changes behavior, be suspicious.
If it adds coverage, it is more likely safe.

## 19.2 Is the extension data-defined or code-defined?

Prefer data-defined almost always.

## 19.3 Can a contributor add this without understanding internals?

If yes, good sign.
If no, the surface may be too deep.

## 19.4 Can the result be validated deterministically?

If no, it is not ready.

## 19.5 Does this create a new authority surface?

If yes, reject or redesign.

## 19.6 Will this push vendor logic into netsim.py?

If yes, it may be time to split a bounded module rather than patch core.

---

# 20. Recommended Public/Internal Document Split

This should remain the internal reference.

The public-facing counterpart should stay simpler and more practical.

Recommended public doc:

* `docs/extension-and-adoption.md`

Recommended internal doc:

* `docs/maintainer/extension-strategy-internal.md`

Why both are needed:

* public doc helps contributors
* internal doc preserves intent and guardrails for future maintainers

---

# 21. Maintainer Default Recommendations

If unsure, default to:

* examples before SDK
* schemas before plugins
* explicit support surfaces before “general support”
* advisory evidence before new authority
* demand-led invariants before broad invariant growth
* thin shared core before clever abstractions
* split by bounded surfaces when vendor branching repeats
* release on trust readiness, not feature count

---

# 22. Final Maintainer Rule

If a decision improves flexibility but weakens determinism, reject it.

If a decision improves adoption without weakening determinism, prefer it.

If a decision makes contributors more productive but blurs authority, redesign it.

If a decision increases ecosystem value while keeping extensions declarative, validator-backed, and bounded, it is probably the right direction.

The product is not “all the features.”
The product is **trustworthy proof before production**.

Everything in the extension strategy must reinforce that.

```
```

