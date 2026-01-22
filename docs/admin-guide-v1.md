
---

# ai-netsim v1 Administrator Guide

**Version:** v1 / v1.x
**Status:** STABLE
**Audience:** Network engineers, platform engineers, CI/CD operators
**Scope:** Operating ai-netsim v1 safely, correctly, and intentionally

This document explains **what ai-netsim v1 is**, **how it is meant to be used**, and **how to interpret its results**.

It is written for engineers who want **deterministic proof before production**, not a flexible lab.

---

## 1) What ai-netsim Is (and Is Not)

ai-netsim is a:

* **deterministic network change-validation gate**
* **CI-first** and **artifact-driven**
* **behavior-validated**, not configuration-validated
* **engineer-first**, not lab-first
* **AI-assisted**, never AI-driven

ai-netsim answers one question:

> *“Given this intent, does the network behave the way I expect?”*

---

### What ai-netsim Is NOT

ai-netsim is **not**:

* a general-purpose network lab
* a routing simulator
* a topology design tool
* a performance or ASIC emulator
* an AI that decides correctness
* an auto-remediation system

If you want exploration, improvisation, or heuristic behavior, ai-netsim is the wrong tool — **by design**.

---

## 2) Authority Model (Critical)

ai-netsim has a **strict authority model**.

**Only these things decide correctness:**

* declared **tests**
* declared **scenarios**

Everything else exists to support that authority.

| Component      | Role                    |
| -------------- | ----------------------- |
| Topology YAML  | Declares intent         |
| Tests          | Define correctness      |
| Scenarios      | Define failure behavior |
| Runtime images | Execute behavior        |
| AI             | Explains outcomes only  |

> **AI never decides pass/fail.**

If AI is disabled, unavailable, or removed, ai-netsim still works identically.

---

## 3) Determinism Guarantees

Given:

* identical topology YAML
* identical ai-netsim version
* identical container images
* identical timeouts

ai-netsim **must produce**:

* identical resolved topology
* identical test verdicts
* identical artifacts
* identical exit codes

There is:

* no randomness
* no hidden retries
* no heuristic guessing
* no silent defaults

If something is ambiguous, **ai-netsim fails fast**.

---

## 4) Gate-First Workflow

### Authoritative path: `netsim test`

`netsim test` is the **gate**.

It:

* starts from a clean state
* destroys any existing lab
* executes deterministically
* produces a binary verdict
* writes authoritative artifacts

Example:

```bash
netsim test three-frr-two-hosts-fw-routed
```

If this command fails, the change **must not be deployed**.

---

### Exploratory path: `netsim run`

`netsim run` exists for **debugging only**.

It:

* is explicitly non-authoritative
* may leave labs running
* must never be used in CI gating

Use it to understand failures — not to approve changes.

---

## 5) Topology Files Are Authoritative

Topology YAML files declare **intent**.

They are one of the **only inputs** that can affect validation outcomes.

ai-netsim v1 will:

* validate schema strictly
* reject unknown fields
* reject ambiguous references
* fail fast on invalid intent

Editing anything under `labs/` is unsupported and undefined.

---

## 6) Nodes and Runtime Behavior

Nodes represent containers participating in validation.

Each node must declare:

* a unique `name`
* a valid `type`

Example:

```yaml
nodes:
  - name: h1
    type: host
```

---

### Node Types (v1)

ai-netsim v1 supports a **small, explicit set of node types**.

No others are allowed.

---

#### `host`

A simple Linux endpoint.

* no routing semantics
* used as traffic source or destination
* suitable for `ping` and `tcp` tests

---

#### `frr`

A router node running FRR.

FRR nodes have **two mutually exclusive modes**:

```yaml
- name: r1
  type: frr
  frr_mode: generated | preconfigured
  image: <optional>
```

##### `frr_mode: generated` (default)

* ai-netsim generates minimal FRR config
* no routing intent is inferred
* suitable for routing-neutral validation

This keeps v1 **honest and routing-agnostic**.

---

##### `frr_mode: preconfigured`

* routing config is baked into the image
* ai-netsim does not touch `/etc/frr/*`
* required for multi-hop `expect: pass` tests

This mode exists **only** to support demos and onboarding.

---

#### `nft-fw`

A Linux firewall node using nftables.

* forwarding enabled
* rules generated deterministically
* explicit allow/deny semantics
* ideal for negative tests

---

## 7) Links (Connectivity Only)

Links define **L2 connectivity**, not routing.

```yaml
links:
  - endpoints: ["h1:eth1", "r1:eth1"]
```

Rules:

* endpoints must be explicit
* exactly two endpoints per link
* ambiguity fails fast
* ai-netsim never guesses

---

## 8) Tests (The Source of Truth)

Tests define **expected behavior**.

They are the **only authority** for pass/fail outcomes.

---

### Supported Atomic Tests (v1 / v1.x)

* `ping`
* `tcp`
* `bgp_neighbor`

No others are permitted.

---

### `ping`

```yaml
tests:
  - name: h1_to_r1
    type: ping
    from: h1
    to: r1
    expect: pass
```

Negative intent:

```yaml
expect: fail
```

Blocked traffic is **success** when failure is expected.

---

### Multi-Hop Guardrail (Very Important)

This fails fast in v1:

```yaml
type: ping
from: h1
to: h2
expect: pass
```

Unless **all routers in the path** declare:

```yaml
frr_mode: preconfigured
```

ai-netsim never assumes routing exists.

---

### `tcp`

```yaml
type: tcp
from: h1
to_ip: 192.168.2.10
port: 443
expect: pass
```

* IPv4 literal only
* deterministic timeout handling
* negative intent supported

---

### `bgp_neighbor` (v1.x)

```yaml
type: bgp_neighbor
node: r1
neighbor: 10.0.0.1
expect: pass
```

Asserts **session state only**.

No policy or routing validation.

---

## 9) Scenarios (Failure Choreography)

Scenarios orchestrate **ordered, deterministic failures**.

They reuse atomic tests.

Example:

```yaml
scenarios:
  - id: interface_failure
    steps:
      - fault:
          interface_down:
            node: r1
            interface: eth1

      - wait_for_bgp:
          node: r2
          timeout: 30

      - run:
          include: all
```

Rules:

* ordered
* explicit
* exactly one action per step
* ambiguity fails fast

---

## 10) Demo Experience (v1.x)

The demo experience exists to provide a **<10-minute success path** without violating v1 semantics.

### Why demos exist

v1 is intentionally routing-agnostic.

New users still need:

* a passing gate
* real routing behavior
* meaningful failures

---

### Demo FRR Images

Preconfigured FRR images include baked routing config.

Examples:

* `frr-demo-bgp-r1:v1x`
* `frr-demo-bgp-r2:v1x`
* `frr-demo-static-r1:v1x`
* `frr-demo-static-r2:v1x`

These images:

* own `/etc/frr/*`
* start FRR internally
* are explicitly opt-in

---

### Demo Topologies

Shipped demos include:

* `examples/01_connected_smoke.yaml`
  *Direct connectivity, zero routing assumptions*

* `examples/02_bgp_multihop_tcp.yaml`
  *Real BGP neighbor + multi-hop TCP*

* `examples/03_static_multihop_ping.yaml`
  *Static routing without BGP*

* `three-frr-two-hosts-fw-routed.yaml`
  *Firewall behavior + fault injection*

These demos **teach the contract** — they do not weaken it.

---

## 11) Artifacts and Evidence

Authoritative artifacts:

* `topology.resolved.yaml`
* `results.json`

Human-readable:

* `results.summary.txt`

Logs and state capture are **evidence only** — never gating.

---

## 12) Assistive AI (Optional)

AI commands:

* `netsim ai explain`
* `netsim ai review`
* `netsim ai coach`

AI:

* runs post-execution only
* consumes artifacts only
* never affects verdicts
* never affects exit codes

If AI fails, ai-netsim still exits `0`.

---

## 13) What v1 Explicitly Does NOT Do

* no routing protocol modeling
* no EVPN semantics
* no VM runtime
* no performance simulation
* no AI-driven decisions

These belong to **v1.5+**.

---

## 14) Final Mental Model

* topology declares intent
* tests define correctness
* scenarios define failure behavior
* routing lives outside v1 authority
* determinism is sacred

If ai-netsim fails, it is telling you something **important**.

---

**End of ai-netsim v1 Administrator Guide**

---

