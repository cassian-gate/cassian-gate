---

# Cassian Gate v1 Topology Schema Guide

**Version:** v1 / v1.x
**Status:** STABLE
**Scope:** Topology YAML structure and semantics
**Audience:** Engineers authoring Cassian Gate topologies

This document explains **how topology YAML is structured**, what each section means, and what is **explicitly allowed or forbidden** in Cassian Gate v1.

This is a **schema guide**, not a tutorial and not a routing reference.

---

## 1) Topology Files Are Authoritative

Topology YAML files define **user intent**.

They are one of the **only authoritative inputs** that can affect validation outcomes.

Cassian Gate v1 will:

* validate schema strictly
* reject unknown or ambiguous fields
* fail fast on invalid intent

Editing generated files under `labs/` is unsupported and has undefined behavior.

---

## 2) Top-Level Structure

A valid topology file may contain the following top-level keys:

```yaml
nodes:
links:
tests:
scenarios:
```

Rules:

* all keys are optional, but meaningless topologies are rejected
* unknown top-level keys fail validation
* ordering is not significant

---

## 3) Nodes

Nodes represent containers participating in validation.

Each node **must** declare:

* a unique `name`
* a valid `type`

### Minimal example

```yaml
nodes:
  - name: h1
    type: host
```

---

## 3.1) Node Types (v1)

Cassian Gate v1 supports a **small, explicit set of node types**.

No other node types are allowed.

---

### `host`

A simple Linux endpoint.

Properties:

* no routing semantics
* used as traffic source or destination
* suitable for `ping` and `tcp` tests

Example:

```yaml
- name: h1
  type: host
```

---

### `frr`

A router node running FRR.

FRR nodes have **two mutually exclusive modes** that define how routing is handled.

```yaml
- name: r1
  type: frr
  frr_mode: generated | preconfigured
  image: <optional>
```

#### `frr_mode: generated` (default)

* Cassian Gate generates minimal FRR config
* no routing intent is inferred
* suitable for single-hop or routing-neutral validation

This mode exists to keep v1 **routing-agnostic**.

---

#### `frr_mode: preconfigured`

* the container image owns `/etc/frr/*`
* routing is provided entirely by the image
* Cassian Gate does not bind or overwrite FRR config
* **required for multi-hop `expect: pass` tests**

This mode is used by demo images and onboarding scenarios.

---

### `nft-fw`

A Linux firewall node using nftables.

Properties:

* forwarding enabled
* rules generated deterministically from topology
* explicit allow/deny behavior
* suitable for negative tests

Example:

```yaml
- name: fw1
  type: nft-fw
```

---

## 4) Links

Links define L2 connectivity between node interfaces.

Example:

```yaml
links:
  - endpoints: ["h1:eth1", "r1:eth1"]
```

Rules:

* endpoints must be explicit (`node:interface`)
* exactly two endpoints per link
* ambiguous interface references fail fast
* Cassian Gate never guesses interface mapping

Links define **connectivity only**, not routing.

---

## 5) Tests (Authoritative)

Tests define **expected behavior**.

They are the **only authority** for pass/fail outcomes.

---

### Supported test types (v1 / v1.x)

* `ping`
* `tcp`
* `bgp_neighbor`

No other test types are permitted.

---

### `ping`

Validates ICMP reachability or intentional non-reachability.

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
tests:
  - name: blocked_path
    type: ping
    from: h1
    to: h2
    expect: fail
```

Rules:

* destination must be a node name or IPv4 literal
* DNS names, CIDR ranges, IPv6, and `IP:port` are rejected
* `expect: fail` is **fail-fast** (no retries)

---

### Multi-hop Guardrail (Critical)

Cassian Gate v1 **does not infer routing**.

Therefore, this fails fast:

```yaml
type: ping
from: h1
to: h2
expect: pass
```

Unless **all FRR nodes in the path** explicitly declare:

```yaml
frr_mode: preconfigured
```

This guardrail prevents false confidence.

---

### `tcp`

Validates L4 reachability.

```yaml
tests:
  - name: https_check
    type: tcp
    from: h1
    to_ip: 192.168.2.10
    port: 443
    expect: pass
```

Rules:

* destination must be an IPv4 literal
* negative intent supported
* deterministic timeout handling

---

### `bgp_neighbor` (v1.x)

Asserts BGP session health only.

```yaml
tests:
  - name: r1_r2_bgp
    type: bgp_neighbor
    node: r1
    neighbor: 10.0.0.1
    expect: pass
```

Important:

* asserts session state only
* does **not** validate routing correctness, policies, or prefixes

---

## 6) Scenarios (Failure Choreography)

Scenarios orchestrate **ordered, deterministic failures and recovery**.

They reuse the same atomic tests defined above.

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

---

### Scenario Rules

* scenarios are optional
* steps are ordered
* each step must contain **exactly one action**
* unknown keys are rejected
* ambiguity fails fast

Allowed step types:

* `run`
* `fault`
* `wait_for`
* `wait_for_bgp`

---

### Fault Semantics

* node, link, or interface must be explicit
* **1 fault step → 1 fault event**
* no hidden remediation
* restoration should be explicit

---

## 7) Demo Topologies (v1.x Onboarding)

The following demo topologies ship with v1.x:

* `examples/01_connected_smoke.yaml`
* `examples/02_bgp_multihop_tcp.yaml`
* `examples/03_static_multihop_ping.yaml`
* `three-frr-two-hosts-fw-routed.yaml`

They exist to:

* teach the v1 contract
* demonstrate outcomes safely
* provide fast onboarding

They do **not** change v1 authority.

---

## 8) What This Schema Does NOT Do (v1)

The topology schema does not support:

* routing protocol configuration
* EVPN semantics
* performance modeling
* VM execution
* vendor NOS features

These belong to v1.5+.

---

## 9) Mental Model to Keep

* topology declares intent
* tests define correctness
* scenarios model failure
* routing lives outside v1 authority

If something is ambiguous, Cassian Gate will fail — **by design**.

---

**End of Cassian Gate v1 Topology Schema Guide**

---
