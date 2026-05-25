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

#### Optional `ospf:` block (v1.5+)

An FRR node may optionally declare an `ospf:` block to advertise OSPF area membership and network prefixes. This is the topology-level declaration consumed by Cassian Gate's Generate phase to render `ospfd=yes` in the node's `daemons` file and a `router ospf` block in `frr.conf`.

```yaml
- name: r1
  type: frr
  router_id: 1.1.1.1
  ospf:
    area: 0
    networks:
      - 10.0.0.0/16
      - 1.1.1.1/32
```

Rules:

* `area` is required; integer ≥ 0
* `networks` is required; non-empty list of canonical IPv4 CIDR strings (host bits unset; non-canonical or non-IPv4 forms are rejected)
* declaring `ospf:` requires the node to also declare a top-level `router_id` (which is reused as the OSPF router-id); validation hard-fails otherwise
* unknown keys under `ospf:` are rejected — including timer customization keys (`hello-interval`, `dead-interval`, `spf-delay` and similar)
* single-area-per-node only; multi-area is out of scope in v1.5

For the corresponding `ospf_neighbor_up` invariant test type (which asserts an OSPF neighbor reaches a declared FSM state), the per-test-record `observed_state` payload schema, and the comprehensive 10-FSM-literal closed-set documentation, see `docs/topology-schema-v1.5.md` §4.8.

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

For the corresponding `interface_state` invariant test type (which asserts an interface declared by a `links:` endpoint has a specific administrative/operational state inside its node's network namespace), the per-test-record `observed_state` payload schema, the asymmetric verdict predicate, and the iproute2 capability dependency, see `docs/topology-schema-v1.5.md` §4.9.

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

### `wait_for` (condition-based convergence)

`wait_for` is a scenario step that polls a deterministic predicate until it is satisfied or until `timeout` is reached. It anchors a scenario to **observable convergence** rather than to fixed elapsed time. A successful `wait_for` step **does not** produce a test verdict; verdicts come only from items declared in `tests:`. The wait_for step records its own pass/fail in the scenario step record.

Prefer `wait_for` with an invariant condition over fixed `wait: { seconds: N }` whenever the desired outcome is a verifiable convergence condition.

#### Required keys (every `wait_for` step)

| Key | Type | Meaning |
|---|---|---|
| `type` | string | One of the accepted condition types (see below) |
| `from` | string | Source node name (the vantage point from which the condition is evaluated) |
| `expect` | `pass` \| `fail` | Whether the condition is expected to converge to satisfied (`pass`) or to remain unsatisfied at `timeout` (`fail`) |
| `timeout` | int | Upper bound in seconds; the step fails on timeout |
| `interval_s` | number | Fixed polling interval in seconds (no jitter, no backoff) |

Optional: `per_attempt_timeout_s` (int ≥ 1).

Unknown keys are rejected.

#### Accepted condition types

`wait_for.type` must be one of these nine condition types:

* `ping` — ICMP reachability from `from` to `to`. Per-type required: `to` (node name or IPv4 literal). Optional: `count`, `src_ip`, `src_if`.
* `tcp` — TCP reachability from `from` to `to:port`. Per-type required: `to`, `port`. Optional: `src_ip`, `src_if`.
* `route_prefix` — RIB presence of `prefix` on `from`. Per-type required: `prefix` (CIDR). The key `src` (or its alias `on`) names the same vantage as `from`.
* `bgp_session_up` — BGP session to neighbor IP reaches Established. Per-type required: `dst` (IPv4 literal of the BGP neighbor).
* `route_present` — Prefix appears in the RIB on `from`. Per-type required: `prefix` (CIDR).
* `route_advertised_to` — Prefix appears in the advertised-routes set toward a named peer. Per-type required: `peer` (node name), `prefix` (CIDR).
* `evpn_bgp_session_up` — EVPN BGP session to a peer node reaches Established. Per-type required: `peer` (node name).
* `evpn_vni_route_present` — At least one EVPN type-2 / type-3 route is present for the named VNI. Per-type required: `vni` (integer).
* `evpn_mac_route_present` — EVPN type-2 MAC route for the named MAC and VNI is present. Per-type required: `mac` (canonical MAC literal), `vni` (integer).

#### Parameter cross-link

For the six invariant-derived condition types (`bgp_session_up`, `route_present`, `route_advertised_to`, `evpn_bgp_session_up`, `evpn_vni_route_present`, `evpn_mac_route_present`), the per-type parameter requirements match the corresponding invariant type as defined in `docs/topology-schema-v1.5.md` §2 (Supported Invariant Types) — the **required-fields** column is the authoritative reference. The `wait_for` step uses the same parameter names as the invariant table, **except** that `wait_for` uses `from:` for the source node where the invariant table uses `node:`.

Note: the `observed_state` payload schema documented in `docs/topology-schema-v1.5.md` §4 is **not** part of the `wait_for` surface. `observed_state` is produced only on failed-invariant test records (`kind: invariant`), not on `wait_for` scenario step records.

#### Example scenario

```yaml
scenarios:
  - id: post_failure_convergence
    steps:
      - fault:
          link_down:
            endpoints: ["r1:eth1", "r2:eth1"]

      - wait_for:
          type: bgp_session_up
          from: r1
          dst: 10.0.0.2
          expect: pass
          timeout: 60
          interval_s: 2

      - run:
          include: all
```

This scenario fails a link, waits up to 60 seconds for the BGP session from `r1` to neighbor `10.0.0.2` to re-establish (polling every 2 seconds), then runs all declared tests. The `wait_for` step records `verdict: pass` if the session converges within `timeout`, `verdict: fail` otherwise.

#### Semantics

* The polling loop is deterministic: fixed `interval_s` cadence, no jitter, no exponential backoff.
* `expect: fail` inverts the convergence semantics: the step succeeds if the condition does **not** become satisfied within `timeout`. This supports negative-convergence assertions (e.g., proving a route does not appear after a withdrawal).
* `wait_for` is distinct from `wait_for_bgp`: `wait_for_bgp` is a coarse "all neighbors of one node" readiness check; `wait_for: bgp_session_up` is a single-neighbor session check with explicit `dst` IP. Both remain available; pick the one that matches the convergence question.

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

These belong to v1.5+. See `docs/topology-schema-v1.5.md` for the v1.5 invariant test category, supported invariant types, and `observed_state` payload contract.

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
