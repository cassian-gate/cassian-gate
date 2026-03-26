# ai-netsim v79 — Operator Cheat Sheet

*(Authoritative Operator Reference)*

This document defines the **user-facing execution contract** for ai-netsim.

It reflects **implemented CLI behavior only**.

ai-netsim is a:

> **Deterministic Network Change Validation Gate**

Execution is:

- deterministic
- reproducible
- artifact-backed
- CI-safe
- non-heuristic

---

# 1️⃣ What ai-netsim Is (and Is Not)

ai-netsim **IS**

- a network change validation gate
- a deterministic execution engine
- a CI pipeline safety check
- a behavior validation system

ai-netsim **IS NOT**

- a general network lab builder
- a chaos framework
- a retry system
- a configuration merge engine
- an AI decision system

---

# 2️⃣ Command Index

### Environment

```bash
netsim doctor
netsim validate <topology.yaml>
netsim preflight <topology.yaml>
```

### Execution (Validation)

```bash
netsim test <topology.yaml>
netsim replay <artifacts-dir>
netsim run <topology.yaml>
netsim up <topology.yaml>
netsim down <lab>
netsim destroy <lab>
netsim cleanup --all
```

### Inspection

```bash
netsim status <lab>
netsim exec <lab> <node>
netsim vty <lab> <node> "<command>"
netsim collect <lab>
```

### DevOps Integration

```bash
netsim adapt terraform
netsim adapt ansible
```

````md
### AI Assistance (optional / advisory only)

```bash
netsim ai "why did this fail"
netsim ai --lab <lab> "why did this fail"
netsim ai --artifacts <dir> "why did this fail"
netsim ai --online "why did this fail"
````

AI is **advisory only** and **artifact-only**.

It never affects:

* execution
* verdicts
* authoritative command behavior

AI **never affects execution or verdicts**.

```
```
---

# 3️⃣ Two Execution Modes (CRITICAL)

Understanding this distinction is mandatory.

---

## 🔷 Gate Mode (Authoritative Validation)

Command:

```bash
netsim test <topology.yaml>
```

Gate mode automatically performs:

1. Clean-state destroy (if needed)
2. Deploy
3. Provision
4. Execute tests
5. Collect artifacts
6. Destroy lab

Returns deterministic exit codes.

Gate mode is used for:

- production validation
- CI pipelines
- change validation
- baseline vs candidate comparison

You **do NOT run `netsim up` first**.

Gate mode owns the lifecycle.

---

### PASS with 0 tests

If the topology contains:

- no `tests`
- no `scenarios`

Output:

```text
Tests executed: 0
Scenarios executed: 0
RESULT: PASS
```

Meaning:

> Deployment succeeded (SMOKE validation only)

No routing or connectivity validation occurred.

---

````md
## netsim replay — Deterministic replay of prior artifacts

Replay re-executes a previous ai-netsim run from previously generated artifacts.

Replay is a **reproduction/analysis surface**, not a new authority path.

Authority is preserved from the replayed source context.

### Inputs

Replay consumes artifacts from a previous run:

```text
topology.resolved.yaml
results.json
````

These are **generated replay inputs**.

Important boundary:

* artifact reuse for replay does **not** make replay a new source of authority
* shared artifact shape does **not** imply shared authority
* authority still depends on the replay mode and source context

### Gate replay (authoritative context preserved)

Replay a prior authoritative gate run:

```bash
netsim replay labs/clab-<lab> --gate
```

This preserves **gate / authoritative** context.

Current operator-visible behavior includes authoritative gate-style output such as:

```text
MODE: GATE | AUTHORITATIVE: YES | CLEAN-STATE: YES
Authority: GATE (authoritative)
```

Use this when you want to:

* reproduce a prior gate result
* verify deterministic gate behavior
* confirm replay-stable authoritative outcomes

You can also verify deterministic result equivalence:

```bash
netsim replay labs/clab-<lab> --gate --verify-results
```

If the replayed verdict core differs from the source result, replay exits with:

```text
exit code: 1
```

### Non-gate replay (non-authoritative context preserved)

Replay without `--gate` keeps replay in a **non-authoritative** exploration context.

Example:

```bash
netsim replay labs/clab-<lab>
```

Current operator-visible behavior includes non-authoritative replay labeling such as:

```text
Authority: RUN (non-authoritative)
Mode: replay (exploration artifacts)
```

This path is useful for:

* inspection
* investigation
* iterative debugging
* bringing replayed runtime up for manual follow-up commands

This does **not** upgrade exploration artifacts into gate proof.

### When to use replay

Use replay when you want deterministic reproduction of a prior run.

Typical uses:

* reproducing a prior authoritative gate result
* replaying a prior exploration run for investigation
* checking deterministic stability
* debugging unexpected behavior from existing artifacts

### Important boundary

Replay:

* preserves prior context
* does not create a parallel authority model
* does not make exploration authoritative
* does not change verdict/exit semantics by itself

---

## 🔷 Exploration Mode (Non-Authoritative)

Used for **interactive debugging and inspection**.

Two approaches exist.

---

### Option A — `run`

```bash
netsim run <topology.yaml>
```

This performs:

```text
up → test → collect → destroy
```

By default the lab is destroyed.

Keep the lab running:

```bash
netsim run <topology.yaml> --keep
```

---

### Option B — Explicit Lifecycle

```bash
netsim up <topology.yaml>
netsim status <lab>
netsim test <lab>
netsim down <lab>
```

Use this when you want:

- persistent labs
- manual inspection
- iterative debugging

---

## Lifecycle Comparison

| Feature                | Gate Mode | Exploration |
| ---------------------- | --------- | ----------- |
| Clean-state enforced   | Yes       | Optional    |
| Auto destroy           | Yes       | Optional    |
| CI-safe                | Yes       | No          |
| Interactive inspection | No        | Yes         |
| Authoritative verdict  | Yes       | No          |

---

# 4️⃣ Topology vs Lab Name

Many commands accept **different inputs**.

---

## Commands That Use a Topology File

```bash
netsim gen <topology.yaml>
netsim validate <topology.yaml>
netsim preflight <topology.yaml>
netsim up <topology.yaml>
netsim run <topology.yaml>
netsim test <topology.yaml>
```

---

## Commands That Use a Lab Name

```bash
netsim status <lab>
netsim exec <lab> <node>
netsim vty <lab> <node>
netsim collect <lab>
netsim down <lab>
netsim destroy <lab>
```

---

### Where does lab name come from?

Defined inside topology:

```yaml
name: demo-lab
```

Displayed during execution:

```text
Lab: demo-lab
```

---

# 5️⃣ Topology Authoring

ai-netsim consumes **YAML topology definitions**.

---

## Minimal Example

```yaml
name: demo-lab

nodes:
  - name: r1
    type: frr

  - name: r2
    type: frr

links:
  - endpoints: ["r1:eth1", "r2:eth1"]

tests:
  - name: r1_to_r2_ping
    kind: ping
    src: r1
    dst: 10.0.0.1
    count: 2
    expect: pass
```

---

## Required Keys

Required:

- `name`
- `nodes`
- `links`

Optional:

- `tests`
- `scenarios`
- `packs`
- `fabric`
- `candidate_changes`
- `vlans`

---

## Invariant Packs (Loaded and Expanded During Resolve)

ai-netsim supports declarative invariant packs that are **loaded from the supported local pack surface**, compatibility-checked, and then expanded into explicit invariant declarations during **Resolve**.

Packs are optional authoring shortcuts. The authoritative validation still comes later from the expanded invariant verdicts.

Packs are:

- declarative only
- loaded locally and deterministically
- compatibility-checked before expansion
- expanded deterministically during Resolve
- written as explicit tests in `topology.resolved.yaml`
- non-authoritative by themselves

Packs do **not**:

- execute code
- change lifecycle behavior
- introduce runtime-only semantics
- change authority boundaries
- load from remote registries
- use fallback or best-match lookup

Later validation still comes from the resulting invariant verdicts.

### Pack Declaration

Example:

```yaml
packs:
  - datacenter-bgp-safety
```

Rules:

- `packs` must be a list
- each pack entry must be a non-empty string
- pack lookup is deterministic and local only
- unknown pack names fail fast with exit code `2`
- incompatible pack contents fail fast with exit code `2`
- pack expansion must be deterministic

### Current Supported Pack

```text
datacenter-bgp-safety
```

Current behavior:

- loads from the supported local pack surface
- passes local compatibility enforcement before expansion
- expands during Resolve into explicit invariant tests
- later phases consume only the expanded invariants
- replay and gate execution use the resolved expanded test list

### Example

```yaml
name: pack-local-compatibility-ok

packs:
  - datacenter-bgp-safety

fabric:
  evpn:
    enabled: true
    mode: vlan-aware
    asn: 65100

nodes:
  - name: spine1
    type: frr
    role: spine
    evpn_rr: true
    router_id: 10.255.0.1

  - name: leaf1
    type: frr
    role: leaf
    router_id: 10.255.0.11

  - name: leaf2
    type: frr
    role: leaf
    router_id: 10.255.0.12

  - name: host1
    type: host
    attach: leaf1
    vlan: 10
    ip: 10.10.10.11/24
    gw: 10.10.10.1
    mac: "00:11:22:33:44:55"

  - name: host2
    type: host
    attach: leaf2
    vlan: 10
    ip: 10.10.10.12/24
    gw: 10.10.10.1
    mac: "00:11:22:33:44:66"

links:
  - endpoints: ["spine1:eth1", "leaf1:eth1"]
    ipv4: ["172.16.0.0/31", "172.16.0.1/31"]

  - endpoints: ["spine1:eth2", "leaf2:eth1"]
    ipv4: ["172.16.0.2/31", "172.16.0.3/31"]

  - endpoints: ["host1:eth1", "leaf1:eth2"]
  - endpoints: ["host2:eth1", "leaf2:eth2"]

vlans:
  10:
    vni: 10100

tests: []
```

### Operator Commands

Validate local pack loading and compatibility enforcement:

```bash
netsim validate topologies/pack_local_compatibility_ok.yaml
```

Run authoritative gate execution of the accepted expanded invariants:

```bash
netsim test topologies/pack_local_compatibility_ok.yaml
```

Negative misuse proofs:

```bash
netsim validate topologies/neg/pack_unknown_reference.yaml
netsim validate topologies/neg/pack_incompatible_contents.yaml
```

Expected behavior:

- valid local pack topology → exit `0`
- unknown pack reference → exit `2`
- incompatible pack contents → exit `2`

### Artifact Note

After Resolve, the expanded invariant list appears explicitly in:

```text
labs/clab-<lab-name>/topology.resolved.yaml
```

These expanded tests are generated inputs for later execution only.

Authority still comes from the later invariant verdicts in:

```text
results.json
```

---

# 6️⃣ Nodes

Supported node types:

| Type     | Description       |
| -------- | ----------------- |
| frr      | FRR router        |
| host     | Linux host        |
| nft-fw   | nftables firewall |
| sonic-vm | SONiC VM runtime  |

---

# 7️⃣ Links

Example:

```yaml
- endpoints: ["r1:eth1", "r2:eth1"]
  ipv4: ["10.0.0.0/31", "10.0.0.1/31"]
```

If `ipv4` is omitted:

- `/31` addresses auto-assigned

View assigned addresses:

```text
labs/clab-<lab>/topology.resolved.yaml
```

---

# 8️⃣ EVPN Runtime Substrate (Generation Support)

ai-netsim supports a **deterministic EVPN topology/config generation substrate** for a limited, explicit proof shape.

This support exists to produce runtime EVPN control-plane state for later validation work.

It does **not** make EVPN generation itself authoritative.

Generated EVPN state is **supporting runtime substrate only**.

Truth still comes from:

- tests
- invariants

---

## Supported EVPN Intent Surface

Declare EVPN only under:

```yaml
fabric:
  evpn:
    enabled: true
    mode: vlan-aware
    asn: 65100
```

Required EVPN fields:

- `fabric.evpn.enabled`
- `fabric.evpn.mode`
- `fabric.evpn.asn`

Supported mode:

- `vlan-aware`

---

## Supported Node Shape

EVPN participants currently use `frr` nodes with explicit roles.

Example:

```yaml
nodes:
  - name: spine1
    type: frr
    role: spine
    evpn_rr: true
    router_id: 10.255.0.1

  - name: leaf1
    type: frr
    role: leaf
    router_id: 10.255.0.11

  - name: leaf2
    type: frr
    role: leaf
    router_id: 10.255.0.12
```

Rules:

- EVPN participant nodes must use `type: frr`
- spine nodes must declare `evpn_rr: true`
- leaf nodes must not declare `evpn_rr: true`
- EVPN participant nodes require `router_id`
- leaves must have an explicit direct link to at least one RR spine

---

## VLAN ↔ VNI Mapping

EVPN requires a top-level `vlans` mapping.

Example:

```yaml
vlans:
  10:
    vni: 10100
```

Rules:

- each VLAN must map to exactly one VNI
- duplicate VNI reuse is rejected
- invalid or missing VNI fails fast

---

## Host Attachment Requirements

Host attachment must be explicit.

Example:

```yaml
- name: host1
  type: host
  attach: leaf1
  vlan: 10
  ip: 10.10.10.11/24
  gw: 10.10.10.1
  mac: "00:11:22:33:44:55"
```

Required host fields for EVPN proof substrate:

- `attach`
- `vlan`
- `ip`
- `mac`

Rules:

- attached host must connect explicitly to an EVPN leaf
- host VLAN must exist in the declared VLAN/VNI map
- host MAC must be explicit
- host must have exactly one explicit link to its attached leaf

---

## Minimal Supported Proof Shape

Supported proof shape is intentionally narrow:

- leaf/spine only
- explicit RR spine
- explicit host attachment
- one VLAN is sufficient
- deterministic MAC/IP declarations required

This support is intended to produce:

- EVPN BGP control-plane sessions
- deterministic VLAN/VNI configuration
- deterministic host attachment semantics
- deterministic runtime substrate for later MAC-route observation

---

## Unsupported / Rejected Shapes

ai-netsim fails fast on unsupported EVPN topology intent.

Examples include:

- EVPN declared outside `fabric.evpn`
- ambiguous EVPN participant selection
- unsupported node role combinations
- missing RR spine
- missing or invalid VNI
- missing explicit host attachment semantics
- shapes requiring out-of-band configuration
- heuristic peer inference

These are misuse / invalid-topology errors.

---

## Example EVPN Runtime Generation Topology

```yaml
name: evpn-runtime-generation

fabric:
  evpn:
    enabled: true
    mode: vlan-aware
    asn: 65100

nodes:
  - name: spine1
    type: frr
    role: spine
    evpn_rr: true
    router_id: 10.255.0.1

  - name: leaf1
    type: frr
    role: leaf
    router_id: 10.255.0.11

  - name: leaf2
    type: frr
    role: leaf
    router_id: 10.255.0.12

  - name: host1
    type: host
    attach: leaf1
    vlan: 10
    ip: 10.10.10.11/24
    gw: 10.10.10.1
    mac: "00:11:22:33:44:55"

  - name: host2
    type: host
    attach: leaf2
    vlan: 10
    ip: 10.10.10.12/24
    gw: 10.10.10.1
    mac: "00:11:22:33:44:66"

links:
  - endpoints: ["spine1:eth1", "leaf1:eth1"]
    ipv4: ["172.16.0.0/31", "172.16.0.1/31"]

  - endpoints: ["spine1:eth2", "leaf2:eth1"]
    ipv4: ["172.16.0.2/31", "172.16.0.3/31"]

  - endpoints: ["host1:eth1", "leaf1:eth2"]
  - endpoints: ["host2:eth1", "leaf2:eth2"]

vlans:
  10:
    vni: 10100

tests: []
```

---

## Operator Commands

Validate the EVPN topology:

```bash
netsim validate topologies/evpn_runtime_generation.yaml
```

Bring up EVPN runtime substrate:

```bash
netsim up topologies/evpn_runtime_generation.yaml
```

Run authoritative gate proof:

```bash
netsim test topologies/evpn_runtime_generation.yaml
```

Replay deterministically:

```bash
netsim replay labs/clab-evpn-runtime-generation --gate --verify-results
```

Negative misuse proofs:

```bash
netsim test topologies/neg/evpn_invalid_vni.yaml
netsim test topologies/neg/evpn_invalid_roles.yaml
```

---

## Artifact Note

`topology.resolved.yaml` may include additive EVPN-resolved fields for the generated proof substrate.

These fields remain **generated** and **non-authoritative**.

They support deterministic execution only.

---

## Important Boundary

EVPN topology/config generation support:

- configures deterministic EVPN runtime substrate
- does not prove EVPN correctness by itself
- does not validate dataplane forwarding
- does not validate EVPN invariants by itself
- does not change authority semantics

Use later tests/invariants to establish truth.

---

# 9️⃣ Tests and Invariants

ai-netsim supports both:

- active behavior tests
- deterministic invariant checks

Both produce standard authoritative results in gate mode.

---

## Standard test kinds

Supported kinds:

- `ping`
- `tcp`

---

## Ping Example

```yaml
- name: r1_to_r2
  kind: ping
  src: r1
  dst: 10.0.0.1
  count: 2
  expect: pass
```

Required fields:

- `name`
- `kind`
- `src`
- `dst`

---

## TCP Example

```yaml
- name: tcp_test
  kind: tcp
  src: h1
  dst: r2
  port: 443
  listener: true
  expect: pass
```

Required fields:

- `name`
- `kind`
- `src`
- `dst`

---

## Invariant tests

Invariant tests use:

```yaml
kind: invariant
```

They validate declared truth conditions and return authoritative pass/fail results like any other test.

---

## Routing Invariants

Routing invariants validate specific routing truth on a named node.

They are useful when you need to prove policy outcome, path preference, route advertisement boundaries, or route attributes.

### BGP Local Preference Invariant

Invariant type:

```text
bgp_localpref_equals
```

Purpose:

Verify that a BGP route installed on a node has the expected **LOCAL_PREF** value.

This is useful for validating routing policy behavior such as:

- inbound route-maps
- outbound policy manipulation
- policy-based path preference
- iBGP policy consistency

Required fields:

| Field    | Description                           |
| -------- | ------------------------------------- |
| node     | Node where the route must be observed |
| prefix   | Prefix being validated                |
| expected | Expected BGP local preference value   |

Example:

```yaml
tests:
  - name: r2_sees_1_1_1_1_32_with_localpref_200
    kind: invariant
    type: bgp_localpref_equals
    node: r2
    prefix: 1.1.1.1/32
    expected: 200
    expect: pass
```

Behavior:

- The invariant inspects the routing information on the specified node.
- The route must exist and contain the declared LOCAL_PREF value.
- If the route is present but the LOCAL_PREF differs from the expected value, the invariant fails.
- If the invariant definition itself is invalid, the run fails with misuse exit code `2`.

Exit behavior:

| Condition                              | Exit Code |
| -------------------------------------- | --------- |
| invariant satisfied                    | 0         |
| invariant mismatch                     | 1         |
| invariant misuse / invalid declaration | 2         |

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```text
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

Example result entry:

```json
{
  "name": "r2_sees_1_1_1_1_32_with_localpref_200",
  "kind": "invariant",
  "type": "bgp_localpref_equals",
  "verdict": "pass"
}
```

Determinism guarantees:

- invariant evaluation occurs during the **TEST** phase
- results are deterministic under identical topology, code version, and runtime conditions
- replay verification (`netsim replay --gate --verify-results`) must reproduce identical results

### Route Advertised To Invariant

Invariant type:

```text
route_advertised_to
```

Purpose:

Verify that a specific route is being advertised from the specified node to the specified peer.

This is useful for validating routing advertisement boundaries such as:

- expected route export to a peer
- intended prefix propagation across a boundary
- prevention of missing outbound advertisements
- verification that a route is actually being sent to a named neighbor

Required fields:

| Field  | Description                                   |
| ------ | --------------------------------------------- |
| node   | Node where the route advertisement is checked |
| peer   | Named peer that must receive the route        |
| prefix | Prefix being validated                        |

Example:

```yaml
tests:
  - name: r1_advertises_10_10_10_0_24_to_r2
    kind: invariant
    type: route_advertised_to
    node: r1
    peer: r2
    prefix: 10.10.10.0/24
    expect: pass
```

Behavior:

- The invariant inspects supported structured advertisement evidence on the specified node.
- It passes when the specified prefix is observed as advertised to the named peer.
- It fails when the prefix is not observed as advertised to that peer.
- If the invariant definition itself is invalid, the run fails with misuse exit code `2`.

Exit behavior:

| Condition                              | Exit Code |
| -------------------------------------- | --------- |
| invariant satisfied                    | 0         |
| invariant mismatch                     | 1         |
| invariant misuse / invalid declaration | 2         |

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```text
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

Replay:

This invariant is replay-verifiable with standard gate replay:

```bash
netsim replay labs/clab-route-advertised-to --gate --verify-results
```

Scope boundary:

This invariant validates only peer-scoped route advertisement presence.

It does **not** by itself prove:

- generic routing policy correctness
- attribute correctness
- community / AS-path behavior
- broader route-map intent

### Route Not Advertised To Invariant

Invariant type:

```text
route_not_advertised_to
```

Purpose:

Verify that a specific route is not being advertised from the specified node to the specified peer.

This is useful for validating routing advertisement boundaries such as:

- expected suppression of a prefix to a peer
- prevention of route leaks
- verification that a route is withheld from a named neighbor
- confirming that local route presence does not imply outbound advertisement

Required fields:

| Field  | Description                                   |
| ------ | --------------------------------------------- |
| node   | Node where the route advertisement is checked |
| peer   | Named peer that must not receive the route    |
| prefix | Prefix being validated                        |

Example:

```yaml
tests:
  - name: r1_does_not_advertise_10_10_10_0_24_to_r2
    kind: invariant
    type: route_not_advertised_to
    node: r1
    peer: r2
    prefix: 10.10.10.0/24
    expect: pass
```

Behavior:

- The invariant inspects supported structured advertisement evidence on the specified node.
- It passes when the specified prefix is not observed as advertised to the named peer.
- It fails when the prefix is observed as advertised to that peer.
- If the invariant definition itself is invalid, the run fails with misuse exit code `2`.

Exit behavior:

| Condition                              | Exit Code |
| -------------------------------------- | --------- |
| invariant satisfied                    | 0         |
| invariant mismatch                     | 1         |
| invariant misuse / invalid declaration | 2         |

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```text
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

Replay:

This invariant is replay-verifiable with standard gate replay:

```bash
netsim replay labs/clab-route-not-advertised-to --gate --verify-results
```

Scope boundary:

This invariant validates only peer-scoped route advertisement absence.

It does **not** by itself prove:

- generic routing policy correctness
- attribute correctness
- community / AS-path behavior
- broader route-map intent

---

## EVPN Invariants

ai-netsim supports deterministic EVPN invariant checks as standard authoritative test results.

### EVPN MAC Route Present

Validates that a specific MAC route is present for the specified VNI on the specified node.

Example:

```yaml
tests:
  - name: leaf2_sees_host1_mac_route
    kind: invariant
    type: evpn_mac_route_present
    node: leaf2
    mac: "00:11:22:33:44:55"
    vni: 10100
    expect: pass
```

Required fields:

- `kind: invariant`
- `type: evpn_mac_route_present`
- `node`
- `mac`
- `vni`

### EVPN MAC Route Absent

Validates that a specific MAC route is absent for the specified VNI on the specified node.

Example:

```yaml
tests:
  - name: leaf2_does_not_see_mac_route
    kind: invariant
    type: evpn_mac_route_absent
    node: leaf2
    mac: "00:11:22:33:44:55"
    vni: 10100
    expect: pass
```

Required fields:

- `kind: invariant`
- `type: evpn_mac_route_absent`
- `node`
- `mac`
- `vni`

### EVPN VNI Route Present

Validates that EVPN control-plane route presence exists for the specified VNI on the specified node.

Example:

```yaml
tests:
  - name: leaf2_sees_vni_10100
    kind: invariant
    type: evpn_vni_route_present
    node: leaf2
    vni: 10100
    expect: pass
```

Required fields:

- `kind: invariant`
- `type: evpn_vni_route_present`
- `node`
- `vni`

### EVPN BGP Session Up

Validates that the EVPN BGP session to the specified peer is up on the specified node.

Example:

```yaml
tests:
  - name: leaf1_evpn_session_to_spine1_up
    kind: invariant
    type: evpn_bgp_session_up
    node: leaf1
    peer: spine1
    expect: pass
```

Required fields:

- `kind: invariant`
- `type: evpn_bgp_session_up`
- `node`
- `peer`

### Expected outcomes

These invariants behave like other authoritative test results:

- `expect: pass` → invariant must be observed as true
- mismatch → test fails with exit code `1`
- invalid invariant declaration → usage / contract error with exit code `2`

### Evidence and authority

For EVPN invariants:

- runtime EVPN route/session data is **supporting evidence**
- the invariant verdict in `results.json` is **authoritative**

The check is deterministic and replay-safe.

### Positive proof examples

```bash
netsim test topologies/evpn_mac_route_present.yaml
netsim test topologies/evpn_vni_route_present.yaml
netsim test topologies/evpn_bgp_session_up.yaml
```

### Negative validation example

```bash
netsim test topologies/evpn_mac_route_absent_expected_present.yaml
```

### Negative misuse example

```bash
netsim test topologies/neg/evpn_invalid_mac_invariant.yaml
```

### Replay

These invariants are replay-verifiable with standard gate replay:

```bash
netsim replay labs/clab-evpn-mac-route-present --gate --verify-results
netsim replay labs/clab-evpn-vni-route-present --gate --verify-results
netsim replay labs/clab-evpn-bgp-session-up --gate --verify-results
```

### Scope boundary

EVPN invariants validate only the declared EVPN truth being tested.

They do **not** by themselves prove:

- full dataplane forwarding
- broader EVPN feature correctness
- non-EVPN control-plane behavior

---

# 🔟 Scenarios (Failure Choreography)

Scenarios define **ordered fault injection sequences**.

Example:

```yaml
scenarios:
  - id: failover
    steps:

      - run: r1_to_r2

      - fault:
          link_down:
            endpoints: ["r1:eth1", "r2:eth1"]

      - wait_for_bgp:
          node: r1
          timeout: 30

      - run: r1_to_r2
```

---

## Step Types

- `run`
- `fault`
- `wait`
- `wait_for`
- `wait_for_bgp`

No implicit retries.
Timeout = failure.

---

## Grey Failures (Deterministic Degradation)

Grey failures are **scenario-only capabilities**, not standalone CLI commands.

Scenarios can model **partial network degradation**, not only full outages.

Supported grey-failure actions:

- `packet_loss`
- `latency`
- `bandwidth_cap`
- `prefix_blackhole`

These actions are:

- deterministic
- explicit
- replay-stable
- recorded in `results.json`

Grey failures affect the **network condition**, not the verdict logic.

Verdicts still come from the test results that run after the fault step.

---

### Example: Packet Loss

```yaml
scenarios:
  - id: loss5_ping_still_passes
    steps:
      - fault:
          packet_loss:
            node: h1
            if: eth1
            loss: 5

      - run: h1_to_fw1_ping
```

Meaning:

> Apply 5% packet loss on `h1:eth1`, then run the declared test.

---

### Example: Latency

```yaml
scenarios:
  - id: delayed_path
    steps:
      - fault:
          latency:
            node: h1
            if: eth1
            latency_ms: 100

      - run: app_check
```

---

### Example: Bandwidth Cap

```yaml
scenarios:
  - id: slow_link
    steps:
      - fault:
          bandwidth_cap:
            node: h1
            if: eth1
            bandwidth_mbps: 10

      - run: transfer_check
```

---

### Example: Prefix Blackhole

```yaml
scenarios:
  - id: blackhole_prefix
    steps:
      - fault:
          prefix_blackhole:
            node: r1
            prefix: 192.168.50.0/24

      - run: reachability_check
```

---

### Target Forms

Grey failures support two target styles.

#### Interface target

```yaml
fault:
  packet_loss:
    node: h1
    if: eth1
    loss: 5
```

#### Link target

Useful when you want to degrade both ends of a declared link.

```yaml
fault:
  packet_loss:
    a: r1
    b: r2
    a_if: eth1
    b_if: eth1
    loss: 5
```

If multiple links exist between the same nodes, explicit interfaces are required.

---

### Parameter Rules

`packet_loss`

- `loss` or `loss_percent`
- integer
- valid range: `0..100`

`latency`

- `latency_ms`
- integer
- must be `>= 0`

`bandwidth_cap`

- `bandwidth_mbps`
- integer
- must be `>= 1`

`prefix_blackhole`

- `node`
- `prefix`

Invalid values fail fast with exit code `2`.

---

### How to Run

```bash
netsim test topologies/fixtures/grey_failure_direct_pass.yaml --scenario loss5_ping_still_passes
```

Replay deterministically:

```bash
netsim replay labs/clab-grey-failure-direct-pass --gate --verify-results
```

---

### Artifact Evidence

Grey failures are recorded in `results.json` as `scenario_fault` events.

Example shape:

```json
{
  "type": "scenario_fault",
  "scenario_id": "loss5_ping_still_passes",
  "step": 1,
  "meta": {
    "action": "packet_loss",
    "loss_percent": 5,
    "target": "h1:eth1"
  }
}
```

This provides deterministic evidence that the degradation was applied before the test step ran.

---

# 1️⃣1️⃣ Candidate Configuration (Gate Only)

Apply candidate changes during validation.

```bash
netsim test <topology.yaml> \
  --candidate-config <dir>
```

Directory layout:

```text
<dir>/
  <node-name>/
    <config-files>
```

Currently proven supported examples:

```text
<dir>/
  frr/<node>.conf
  nft/<node>.nft
```

Rules:

- full replacement
- no merge
- atomic apply
- failure aborts gate
- candidate config is non-authoritative input only
- verdicts still come only from tests / scenarios / invariants

Important current boundary for vendor NOS VM nodes:

- candidate-config for supported `sonic-vm` / NOS VM nodes is **not currently a supported candidate-config surface**
- unsupported or undefined NOS VM candidate-config input is rejected explicitly
- current truthful behavior for unsupported NOS VM candidate-config input is:
  - misuse / invalid candidate-config surface
  - exit code `2`

Example of current unsupported behavior:

```bash
netsim test topologies/vendor_nos_smoke.yaml \
  --candidate-config tests/fixtures/vendor-nos-cand-neg-unsupported
```

Expected outcome:

```text
ERROR: Candidate config directory structure invalid: <dir>
exit code: 2
```

Scope boundary:

- candidate config support is currently proven only for the existing supported candidate-apply surfaces
- this does not currently establish candidate-config support for `sonic-vm` or other vendor NOS VM node types
- any future NOS VM candidate-config support requires an explicit contract surface and proof

---

# 1️⃣2️⃣ Status Command

Inspect running labs.

```bash
netsim status <lab>
```

Useful options:

- `--summary`
- `--interfaces`
- `--bgp`
- `--bgp-verbose`
- `--routes`
- `--routes-verbose`
- `--json`
- `--strict`

Example:

```bash
netsim status demo-lab --summary
```

---

# 1️⃣3️⃣ Cleanup & Lab Management

Destroy a running lab:

```bash
netsim down <lab>
```

Force destroy + artifact purge:

```bash
netsim destroy <lab> --purge-artifacts
```

Clean up abandoned labs:

```bash
netsim cleanup --all
netsim cleanup --all --yes
```

Dry-run occurs unless `--yes` is provided.

---

# 1️⃣4️⃣ DevOps Integration

Generate adapter artifacts.

---

## Terraform

```bash
netsim adapt terraform \
  --plan plan.json
```

Input:

```text
terraform show -json
```

---

## Ansible

```bash
netsim adapt ansible \
  --dir rendered_configs/
```

Adapters are **advisory only**.

---

# 1️⃣5️⃣ AI Assistance (Optional)

AI is **assistive only**.

It never affects:

- execution
- verdicts
- exit codes

---

````md
````md
## Unified AI Assistance

Use the same conversational entrypoint for failure explanation, coverage review, topology review, scenario interpretation, invariant explanation, and blast-radius explanation.

### Common human path

```bash
netsim ai "why did this fail"
````

Uses the most recent valid artifact context when available.

### Explicit lab path

```bash
netsim ai --lab <lab> "why did this fail"
```

Uses the specified lab when it contains the required artifacts.

### Explicit artifacts path

```bash
netsim ai --artifacts <dir> "why did this fail"
```

This is the most explicit override and is useful for proof/debug workflows.

### Optional online-enriched rendering

Enable online-enriched advisory rendering explicitly:

```bash
netsim ai --online "why did this fail"
netsim ai --lab <lab> --online "why did this fail"
netsim ai --artifacts <dir> --online "why did this fail"
```

Rules:

* online-enriched rendering is explicit opt-in only
* local advisory rendering remains the baseline behavior
* online rendering does not change authority, verdicts, or execution behavior
* if online rendering is explicitly requested but unavailable, `netsim ai` refuses with exit code `2`

### Rendering modes

`netsim ai` discloses the rendering mode it used:

* `local advisory rendering`
* `online-enriched advisory rendering`

Both remain advisory-only.

### Deterministic context selection

Context selection priority is:

1. explicit artifacts
2. explicit lab
3. most recent valid artifact context

Required artifacts:

```text
topology.resolved.yaml
results.json
```

If the required artifacts are missing, `netsim ai` refuses with a deterministic advisory error.

### Important boundary

`netsim ai`:

* reads artifacts only
* does not execute lifecycle actions
* does not modify topology, tests, scenarios, or configs
* does not affect verdicts
* remains advisory-only

```
```


```
```

---

# 1️⃣6️⃣ Artifacts

Artifacts are written to:

```text
labs/clab-<lab-name>/
```

Key files:

- `topology.resolved.yaml`
- `results.json`
- `results.summary.txt`
- `artifacts/`
- `artifacts/blast-radius/blast_radius.json`

---

## topology.resolved.yaml

Contains the **fully expanded deterministic model** used for execution.

Includes:

- resolved defaults
- auto IP assignments
- normalized topology
- explicit invariant expansion from declared `packs`
- additive EVPN-resolved fields when EVPN runtime substrate is used

---

## Structured State Diff (Advisory Only)

ai-netsim can produce a **structured pre/post operational state diff** when state capture is explicitly enabled for both phases.

This artifact is:

- advisory only
- non-authoritative
- deterministic
- generated only from the explicitly captured state

It does **not**:

- change verdicts
- change exit codes
- replace `results.json`
- score differences as good or bad

### How it works

When enabled, ai-netsim captures the declared command/profile state:

- once before tests (`pre`)
- once after tests (`post`)

It then compares those two captured state sets and writes a structured diff artifact.

This is a diff between:

- pre-state captured command output
- post-state captured command output

for the **same run**.

It is **not** a diff between:

- two different runs
- two different topologies
- baseline vs candidate config directories
- intended config vs actual config

### Command Example

```bash
netsim test topologies/three-frr-two-hosts-fw-routed.yaml \
  --state-capture both \
  --state-profile linux-net-basic \
  --state-profile frr-interfaces-basic \
  --state-profile frr-routing-basic \
  --state-profile nft-ruleset-basic
```

### Artifact Path

```text
labs/clab-<lab-name>/artifacts/state-diff/state_diff.json
```

### What to inspect

Typical fields include:

- `schema`
- `authority`
- `capture_profiles`
- `compared_objects`
- `added`
- `removed`
- `changed`
- `counts`

### Operator meaning

Use this artifact when you want to understand:

- what operational state changed during the run
- which captured command surfaces changed between pre and post
- supporting evidence for review or explanation

Keep the authority boundary clear:

- `results.json` = authoritative verdict surface
- `state_diff.json` = supporting evidence only

---

## Blast Radius (Advisory Only)

ai-netsim can produce a **blast radius artifact** that shows:

- what the executed tests/scenarios directly covered
- what additional nodes/links are potentially affected based on deterministic topology connectivity

This artifact is:

- advisory only
- non-authoritative
- deterministic
- generated during **Collect**

It does **not**:

- change verdicts
- change exit codes
- replace `results.json`
- score severity or risk
- infer live routing/runtime behavior

### Artifact Path

```text
labs/clab-<lab-name>/artifacts/blast-radius/blast_radius.json
```

### Supporting `results.json` Surface

`results.json` may also include a clearly labeled non-authoritative supporting section:

```text
blast_radius
```

This remains:

- supporting evidence only
- non-authoritative
- not part of verdict logic

Keep the authority boundary clear:

- `results.json` verdict fields = authoritative
- `results.json` `blast_radius` section = supporting evidence only
- `artifacts/blast-radius/blast_radius.json` = detailed advisory artifact

### What it contains

Typical fields include:

- `schema`
- `authority`
- `topology`
- `coverage_basis`
- `directly_covered`
- `potentially_affected`
- `counts`

### Operator meaning

Use this artifact when you want to understand:

- what your declared tests directly touched
- what else is connected to that tested scope
- where additional coverage may be useful

### Example

```bash
netsim test topologies/blast_radius_ok.yaml

python -m json.tool \
  labs/clab-blast-radius-ok/artifacts/blast-radius/blast_radius.json
```

### Important Boundary

Blast radius currently reflects:

- resolved topology structure
- declared coverage surfaces
- deterministic conservative graph expansion

It does **not** currently prove:

- live routing impact
- actual traffic path usage
- runtime failure propagation
- business severity

---

# 1️⃣7️⃣ Common Operator Tasks

Validate a topology:

```bash
netsim validate topology.yaml
```

Run validation gate:

```bash
netsim test topology.yaml
```

Validate invariant-pack compatibility:

```bash
netsim validate topologies/pack_local_compatibility_ok.yaml
```

Run invariant-pack gate proof:

```bash
netsim test topologies/pack_local_compatibility_ok.yaml
```

Validate invalid pack misuse handling:

```bash
netsim validate topologies/neg/pack_unknown_reference.yaml
netsim validate topologies/neg/pack_incompatible_contents.yaml
```

Replay a previous gate deterministically:

```bash
netsim replay labs/clab-<lab> --gate
```

Explore a lab interactively:

```bash
netsim run topology.yaml --keep
netsim status <lab>
netsim exec <lab> r1
```

Bring up EVPN runtime substrate:

```bash
netsim up topologies/evpn_runtime_generation.yaml
```

Run a routing attribute invariant proof:

```bash
netsim test topologies/bgp_localpref_equals.yaml
```

Run a route advertisement invariant proof:

```bash
netsim test topologies/route_advertised_to.yaml
netsim test topologies/route_not_advertised_to.yaml
```

Run an EVPN invariant proof:

```bash
netsim test topologies/evpn_mac_route_present.yaml
```

Replay an EVPN proof deterministically:

```bash
netsim replay labs/clab-evpn-mac-route-present --gate --verify-results
```

Clean up labs:

```bash
netsim cleanup --all --yes
```

Run scenario testing:

```bash
netsim test topology.yaml --all-scenarios
```

Run a grey-failure scenario:

```bash
netsim test topologies/fixtures/grey_failure_direct_pass.yaml --scenario loss5_ping_still_passes
```

Replay the same grey-failure scenario deterministically:

```bash
netsim replay labs/clab-grey-failure-direct-pass --gate --verify-results
```

Run a blast radius proof:

```bash
netsim test topologies/blast_radius_ok.yaml
```

Inspect blast radius output:

```bash
python -m json.tool \
  labs/clab-blast-radius-ok/artifacts/blast-radius/blast_radius.json
```

Inspect structured state diff output:

```bash
netsim test topologies/three-frr-two-hosts-fw-routed.yaml \
  --state-capture both \
  --state-profile linux-net-basic \
  --state-profile frr-interfaces-basic \
  --state-profile frr-routing-basic \
  --state-profile nft-ruleset-basic

python -m json.tool labs/clab-three-frr-two-hosts-fw-routed/artifacts/state-diff/state_diff.json
```

---

# 1️⃣8️⃣ Exit Codes

| Code | Meaning                |
| ---- | ---------------------- |
| 0    | PASS                   |
| 1    | Test failure           |
| 2    | Usage / contract error |

Examples:

- invariant truth mismatch → `1`
- unsupported EVPN topology shape → `2`
- invalid invariant declaration → `2`
- incompatible pack contents → `2`

---

# 1️⃣9️⃣ First 10 Minutes

Recommended onboarding workflow:

```bash
netsim doctor
netsim validate topology.yaml
netsim test topology.yaml
```

For exploration:

```bash
netsim run topology.yaml --keep
netsim status <lab>
```

For EVPN runtime + proof:

```bash
netsim validate topologies/evpn_runtime_generation.yaml
netsim test topologies/evpn_mac_route_present.yaml
```

---

# End of ai-netsim v79 Operator Cheat Sheet