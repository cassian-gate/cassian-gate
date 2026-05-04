# Cassian Gate v79 — Operator Cheat Sheet

*(Operator reference — supporting surface; execution and artifacts remain authoritative)*

This document describes the **user-facing execution model** for Cassian Gate.

It reflects **implemented CLI behavior only** and does not replace deterministic execution or authoritative artifacts.

Cassian Gate is a deterministic, artifact-authoritative network change-validation gate.

It is for:
- network engineers validating planned changes before production
- platform and infrastructure engineers using a CI-safe network gate
- operators who need explicit pass/fail artifacts and deterministic execution

It is **not yet** for:
- users seeking a broad network automation platform
- users expecting generic multi-vendor feature parity
- users wanting exploratory labs or AI output to act as deployment authority

Cassian Gate is a:

> **Deterministic Network Change Validation Gate**

Execution is:

- deterministic
- reproducible
- artifact-backed
- CI-safe
- non-heuristic

---

# 1️⃣ What Cassian Gate Is (and Is Not)

Cassian Gate **IS**

- a network change validation gate
- a deterministic execution engine
- a CI pipeline safety check
- a behavior validation system

Cassian Gate **IS NOT**

- a general network lab builder
- a chaos framework
- a retry system
- a configuration merge engine
- an AI decision system

---

# 2️⃣ Command Index

### Environment

```bash
cassian doctor
cassian validate <topology.yaml>
cassian validate-contrib <path>
cassian preflight <topology.yaml>
```

### Execution (Validation)

```bash
cassian test <topology.yaml>
cassian replay <artifacts-dir>
cassian run <topology.yaml>
cassian up <topology.yaml>
cassian down <lab>
cassian cleanup --all
```

### Inspection

```bash
cassian status <lab>
cassian exec <lab> <node>
cassian vty <lab> <node> "<command>"
cassian collect <lab>
```

### DevOps Integration

```bash
cassian adapt terraform
cassian adapt ansible
```

### AI Assistance (optional / advisory only)

```bash
cassian ai --lab <lab-name> "<question>"
cassian ai --artifacts <path> "<question>"
cassian ai "<question>"
cassian ai --lab <lab-name> --online "<question>"
cassian ai --artifacts <path> --online "<question>"
```

AI **never affects execution or verdicts**.

---

# 3️⃣ Two Execution Modes (CRITICAL)

Understanding this distinction is mandatory.

---

## 🔷 Gate Mode (Authoritative Validation)

Command:

```bash
cassian test <topology.yaml>
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

You **do NOT run `cassian up` first**.

Gate mode owns the lifecycle.

### Important summary boundary

The human-readable `results.summary.txt` file is not the verdict authority.

Use:

- `results.json` for authoritative verdict sharing in CI, tickets, and PRs
- `results.summary.txt` for human-readable explanation only

The summary now explicitly states:

- what PASS means
- what PASS does not mean
- what FAIL means
- which artifact to share

---

### Zero-assertion gate runs are rejected

If the topology contains:

- no `tests`
- no `scenarios`

then:

```text
ERROR: no assertions defined

A validation gate must include at least one test or scenario.
This run would produce a vacuous PASS and is therefore rejected.
```

Meaning:

- `cassian test <topology.yaml>` requires at least one declared assertion
- a zero-assertion topology is not a valid validation gate
- no PASS or FAIL verdict is produced
- no lifecycle execution begins
- no lab/artifacts are created
- exit code is `2` (usage / contract error)

Important boundary:

- this rule applies to authoritative gate execution with `cassian test <topology.yaml>`
- it does **not** block `cassian run <topology.yaml>`
- it does **not** change replay behavior

---

## cassian replay — Deterministic replay of prior artifacts

Replay re-executes a previous Cassian Gate run from previously generated artifacts.

Replay is a **reproduction/analysis surface**, not a new authority path.

Authority is preserved from the replayed source context.

### Inputs

Replay consumes artifacts from a previous run:

```text
topology.resolved.yaml
results.json
```

These are **generated replay inputs**.

Important boundary:

- artifact reuse for replay does **not** make replay a new source of authority
- shared artifact shape does **not** imply shared authority
- authority still depends on the replay mode and source context

### Gate replay (authoritative context preserved)

Replay a prior authoritative gate run:

```bash
cassian replay labs/clab-<lab> --gate
```

This preserves **gate / authoritative** context.

Meaning:

- authoritative validation path
- clean-state lifecycle context is preserved from the source gate run
- CI-safe verdict semantics remain tied to the original authoritative context

You can also verify deterministic result equivalence:

```bash
cassian replay labs/clab-<lab> --gate --verify-results
```

With `--verify-results`, replay checks deterministic result equivalence against the source artifacts and fails on mismatch.

### Non-gate replay (non-authoritative context preserved)

Replay without `--gate` keeps replay in a **non-authoritative** exploration context.

Example:

```bash
cassian replay labs/clab-<lab>
```

Meaning:

- replayed exploration context remains non-authoritative
- useful for inspection/debugging only

This path is useful for:

- inspection
- investigation
- iterative debugging
- bringing replayed runtime up for manual follow-up commands

This does **not** upgrade exploration artifacts into gate proof.

### When to use replay

Use replay when you want deterministic reproduction of a prior run.

Typical uses:

- reproducing a prior authoritative gate result
- replaying a prior exploration run for investigation
- checking deterministic stability
- debugging unexpected behavior from existing artifacts

### Replay summary boundary

Replay preserves the same authority boundary messaging in `results.summary.txt`.

Meaning:

- replay does not create a new authority model
- `results.json` remains authoritative
- `results.summary.txt` remains explanatory only

### Important boundary

Replay:

- preserves prior context
- does not create a parallel authority model
- does not make exploration authoritative
- does not change verdict/exit semantics by itself

---

## 🔷 Exploration Mode (Non-Authoritative)

Used for **interactive debugging and inspection**.

Two approaches exist.

---

### Option A — `run`

```bash
cassian run <topology.yaml>
```

Meaning:

- exploration only
- non-authoritative
- useful for debugging, not for proof

Typical workflow shape:

```text
up → test → collect → destroy
```

By default the lab is destroyed.

Keep the lab running:

```bash
cassian run <topology.yaml> --keep
```

### Exploration summary boundary

Even when run mode produces results artifacts, `results.summary.txt` remains explanatory only.

Use `results.json` as the authoritative verdict artifact when you need the exact recorded result.
Run mode itself remains non-authoritative as a workflow mode.

---

### Option B — Explicit Lifecycle

```bash
cassian up <topology.yaml>
cassian status <lab>
cassian exec <lab> <node>
cassian down <lab>
```

Use this when you want:

- a persistent exploratory lab
- manual inspection
- iterative debugging

Important boundary:

- this path is for exploration and inspection
- authoritative validation still runs through `cassian test <topology.yaml>`

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
cassian gen <topology.yaml>
cassian validate <topology.yaml>
cassian preflight <topology.yaml>
cassian up <topology.yaml>
cassian run <topology.yaml>
cassian test <topology.yaml>
```

---

## Commands That Use a Lab Name

```bash
cassian status <lab>
cassian exec <lab> <node>
cassian vty <lab> <node>
cassian collect <lab>
cassian down <lab>
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

Cassian Gate consumes **YAML topology definitions**.

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

Cassian Gate supports declarative invariant packs that are **loaded from the supported local pack surface**, compatibility-checked, and then expanded into explicit invariant declarations during **Resolve**.

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

Typical behavior for supported pack usage:

- loads from the supported local pack surface
- undergoes compatibility checks before expansion
- expands during Resolve into explicit invariant tests
- later phases consume the expanded invariants

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
cassian validate topologies/pack_local_compatibility_ok.yaml
```

Run authoritative gate execution of the accepted expanded invariants:

```bash
cassian test topologies/pack_local_compatibility_ok.yaml
```

Negative misuse proofs:

```bash
cassian validate topologies/neg/pack_unknown_reference.yaml
cassian validate topologies/neg/pack_incompatible_contents.yaml
```

Typical outcomes:

- valid local pack topology is accepted
- unknown pack references are rejected
- incompatible pack contents are rejected

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

Cassian Gate supports a **deterministic EVPN topology/config generation substrate** for a limited, explicit proof shape.

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

Cassian Gate fails fast on unsupported EVPN topology intent.

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
cassian validate topologies/evpn_runtime_generation.yaml
```

Bring up EVPN runtime substrate:

```bash
cassian up topologies/evpn_runtime_generation.yaml
```

Run authoritative gate proof:

```bash
cassian test topologies/evpn_runtime_generation.yaml
```

Replay deterministically:

```bash
cassian replay labs/clab-evpn-runtime-generation --gate --verify-results
```

Negative misuse proofs:

```bash
cassian test topologies/neg/evpn_invalid_vni.yaml
cassian test topologies/neg/evpn_invalid_roles.yaml
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

Cassian Gate supports both:

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

### Blocked declared validation items

If a declared test or selected scenario reaches authoritative execution scope but cannot execute normally because execution is blocked later in the gate path, Cassian Gate records that item explicitly in `results.json`.

This prevents omission from being misread as success.

Typical blocked representation:

- `observed: blocked`
- `verdict: fail`
- `error: blocked before execution`

Example meaning:

- the declared validation item existed
- it was in authoritative scope
- it did not run normally
- the result was recorded explicitly rather than omitted

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

Typical required fields:

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

Typical exit semantics follow the standard Cassian Gate model:

- satisfied invariant → passing gate outcome
- invariant mismatch → validation failure
- invalid invariant declaration → usage / contract error

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

Determinism notes:

- invariant evaluation occurs during the **TEST** phase
- replay is intended to preserve the same authority semantics as the source gate context

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

Typical exit semantics follow the standard Cassian Gate model:

- satisfied invariant → passing gate outcome
- invariant mismatch → validation failure
- invalid invariant declaration → usage / contract error

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```text
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

Replay:

This invariant can be checked again using standard gate replay workflows.

```bash
cassian replay labs/clab-route-advertised-to --gate --verify-results
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

Typical exit semantics follow the standard Cassian Gate model:

- satisfied invariant → passing gate outcome
- invariant mismatch → validation failure
- invalid invariant declaration → usage / contract error

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```text
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

Replay:

This invariant can be checked again using standard gate replay workflows.

```bash
cassian replay labs/clab-route-not-advertised-to --gate --verify-results
```

Scope boundary:

This invariant validates only peer-scoped route advertisement absence.

It does **not** by itself prove:

- generic routing policy correctness
- attribute correctness
- community / AS-path behavior
- broader route-map intent

### BGP Session Up Invariant

Invariant type:

```
bgp_session_up
```

Purpose:

Verify that an IPv4-AFI BGP session from the specified node to a declared neighbor IPv4 address is in the FRR `Established` state.

This is useful for validating BGP session establishment such as:

- iBGP session presence to a known neighbor
- eBGP session presence to a known neighbor
- post-change BGP session re-establishment
- guarded assertion of session up before further routing-policy invariants

Required fields:

| Field  | Description                                                         |
| ------ | ------------------------------------------------------------------- |
| node   | Node where the BGP session is checked (FRR-typed)                   |
| dst    | IPv4 literal of the configured neighbor on that node                |

Example:

```yaml
tests:
  - name: r1_bgp_up_to_10_0_0_2
    kind: invariant
    type: bgp_session_up
    node: r1
    dst: 10.0.0.2
    expect: pass
```

Behavior:

- The invariant runs `vtysh -c 'show bgp summary json'` on the specified node and parses the structured output.
- It passes when the queried neighbor is present in FRR's BGP summary and its session state is `Established`.
- It fails when the session is in any other FRR FSM state (`Idle`, `Active`, `Connect`, `OpenSent`, `OpenConfirm`), when the neighbor is not configured (engine-synthesized state literal `NotConfigured`), or when vtysh fails or its output is not parseable as JSON (engine-synthesized state literal `Unknown`).
- If the invariant definition itself is invalid (missing or malformed `dst` IPv4 literal), the run fails with misuse exit code `2`.
- The retry policy mirrors the existing `bgp_neighbor` test surface: retries are bounded by the test's `timeout_s` (default 15 seconds) and `retry_interval_s` (default 1.0 seconds); the loop terminates on first vtysh-rc success and the post-retry block reads the parsed state.

Typical exit semantics follow the standard Cassian Gate model:

- satisfied invariant → passing gate outcome
- invariant mismatch → validation failure
- invalid invariant declaration → usage / contract error

Artifacts produced:

The invariant result is recorded in the standard artifacts:

```
labs/<lab>/results.json
labs/<lab>/results.summary.txt
```

When `verdict: fail`, the test record carries a structured `observed_state` payload with deterministic keys (`type`, `peer`, `state`, `last_error`, `source_node`). See "Failed-Invariant Observed State" below and `docs/topology-schema-v1.5.md` §4.1 for the full per-type schema.

Positive proof example:

```bash
cassian test topologies/bgp_invariant.yaml
```

Replay:

This invariant can be checked again using standard gate replay workflows.

```bash
cassian replay labs/clab-bgp-invariant --gate --verify-results
```

Scope boundary:

This invariant validates only IPv4-AFI BGP session-Established truth from one node to one neighbor IPv4.

It does **not** by itself prove:

- EVPN-AFI session state (use `evpn_bgp_session_up`)
- route presence or attribute correctness
- route advertisement boundaries
- generic routing policy correctness

---

## EVPN Invariants


Cassian Gate supports deterministic EVPN invariant checks as standard authoritative test results.

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

- `expect: pass` means the declared invariant should be observed as true
- mismatch leads to a validation failure
- invalid invariant declarations are treated as usage / contract errors

### Evidence and authority

For EVPN invariants:

- runtime EVPN route/session data is **supporting evidence**
- the invariant verdict in `results.json` is **authoritative**

The check is intended to preserve deterministic authority semantics and replay consistency.

### Positive proof examples

```bash
cassian test topologies/evpn_mac_route_present.yaml
cassian test topologies/evpn_vni_route_present.yaml
cassian test topologies/evpn_bgp_session_up.yaml
```

### Negative validation example

```bash
cassian test topologies/evpn_mac_route_absent_expected_present.yaml
```

### Negative misuse example

```bash
cassian test topologies/neg/evpn_invalid_mac_invariant.yaml
```

### Replay

These invariants can be checked again using standard gate replay workflows:

```bash
cassian replay labs/clab-evpn-mac-route-present --gate --verify-results
cassian replay labs/clab-evpn-vni-route-present --gate --verify-results
cassian replay labs/clab-evpn-bgp-session-up --gate --verify-results
```

### Scope boundary

EVPN invariants validate only the declared EVPN truth being tested.

They do **not** by themselves prove:

- full dataplane forwarding
- broader EVPN feature correctness
- non-EVPN control-plane behavior

---

## Failed-Invariant Observed State

When an invariant test produces `verdict: fail`, the test record in `results.json` carries a structured `observed_state` payload alongside the existing `observed` string. This is the authoritative deterministic failure-reason artifact.

Where it appears:

- on records in `results["tests"]` whose `kind == "invariant"` AND `verdict == "fail"`
- on records in `results["events"]` whose `type == "scenario_test_run"` AND `kind == "invariant"` AND `verdict == "fail"`

Where it does NOT appear:

- on passing-invariant records
- on non-invariant test kinds (`ping`, `tcp`)
- on `prereq` failure paths (those surface as `hard_failure:` in the summary)
- on records with `observed: blocked, verdict: fail, error: blocked before execution` (those are recorded explicitly per the Blocked declared validation items rules above)

Determinism contract:

- every value in `observed_state` is derived from declared topology / test inputs or from deterministically-computable scalars in parsed `vtysh` JSON
- environmental nondeterminism (host clocks, container IDs, runtime PIDs, hostnames-of-the-runner, containerlab-allocated veth MAC addresses) MUST NOT enter `observed_state`
- two clean runs of the same topology produce byte-identical `observed_state` payloads

Per-record byte ceiling:

- a single record's `observed_state` is bounded at 8192 bytes of canonical JSON
- when a payload would exceed the ceiling, the engine deterministically suffix-drops trailing entries from the longest list field until it fits and sets `observed_state_truncated: true` on the record
- the supporting `evidence` field still carries the full pre-truncation list

Example failed-invariant record shape in `results.json`:

```json
{
  "name": "leaf2_evpn_mac_route_for_unknown_mac",
  "kind": "invariant",
  "type": "evpn_mac_route_present",
  "verdict": "fail",
  "observed": "fail",
  "observed_state": {
    "type": "evpn_mac_route_present",
    "mac": "de:ad:be:ef:00:01",
    "vni": 10100,
    "evpn_routes": [
      {"mac": "00:11:22:33:44:55", "vni": 10100, "rd": "", "prefix": "", "route_type": 2}
    ],
    "source_node": "leaf2"
  }
}
```

Summary rendering in `results.summary.txt`:

Each failed-invariant line in the `failed_tests:` block is followed by an indented `observed:` block. Indentation is fixed: header at 4-space, key/value lines at 6-space, list entries at 8-space. List values are capped at 5 entries with a trailing `(+<N> more)` over-cap line. When the record carries `observed_state_truncated: true`, the renderer emits a literal trailing line `(observed_state truncated; full payload in results.json)` at 6-space indent.

Example summary block:

```text
failed_tests:
 - leaf2_evpn_mac_route_for_unknown_mac (invariant) leaf2-> : evpn_mac_route_present mismatch (expected pass, observed fail)
    observed:
      evpn_routes:
        - mac=00:11:22:33:44:01, prefix=, rd=, route_type=2, vni=10100
        - mac=00:11:22:33:44:02, prefix=, rd=, route_type=2, vni=10100
        (+58 more)
      mac: de:ad:be:ef:00:01
      source_node: leaf2
      type: evpn_mac_route_present
      vni: 10100
      (observed_state truncated; full payload in results.json)
```

Authority boundary unchanged:

- `results.json` `observed_state` field = authoritative structured failure reason
- `results.summary.txt` `observed:` block = explanatory rendering only

For the per-type `observed_state` schema (which keys are required for each invariant type) see `docs/topology-schema-v1.5.md` §4.

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

Currently implemented scenario step types:

- `run`
- `fault`
- `wait`
- `wait_for`
- `wait_for_bgp`
- `pcap_start`
- `pcap_stop`

### `wait` (explicit elapsed-time pause)

Canonical form:

```yaml
- wait:
    seconds: 5
```

Rules:

- payload must be a mapping
- payload must contain exactly one field: `seconds`
- `seconds` must be a positive integer
- scalar form such as `- wait: 5` is invalid
- extra keys are invalid
- `wait` executes only as an explicit elapsed-time pause
- `wait` does **not** prove readiness, BGP convergence, reachability, or service health

Use `wait_for` or `wait_for_bgp` when you want condition-based convergence checks.

No implicit retries.
Timeout = failure.

---

### `wait_for` (condition-based convergence)

Polls a deterministic predicate until satisfied or `timeout`. Records a scenario step verdict (no test verdict).

Required keys (every `wait_for` step):

- `type` — one of the nine condition types listed below
- `from` — source node name
- `expect` — `pass` or `fail`
- `timeout` — int (seconds)
- `interval_s` — number (polling cadence)

Optional: `per_attempt_timeout_s`.

Accepted condition types:

- `ping` — ICMP from `from` to `to` (node name or IPv4 literal)
- `tcp` — TCP from `from` to `to:port`
- `route_prefix` — `prefix` (CIDR) present in RIB on `from`
- `bgp_session_up` — BGP session to `dst` (IPv4 neighbor) reaches Established
- `route_present` — `prefix` (CIDR) present in BGP RIB on `from`
- `route_advertised_to` — `prefix` (CIDR) advertised toward `peer` (node name)
- `evpn_bgp_session_up` — EVPN BGP session to `peer` (node name) reaches Established
- `evpn_vni_route_present` — EVPN type-2/3 route present for `vni` (integer)
- `evpn_mac_route_present` — EVPN type-2 route for `mac` + `vni` is present

Per-type parameter requirements: see `docs/topology-schema-v1.md` §6 (`### wait_for`) and `docs/topology-schema-v1.5.md` §2.

Notes:

- A successful `wait_for` step does **not** count as a passing test. Verdicts come only from items in `tests:`.
- `expect: fail` inverts the convergence semantics (succeeds if the condition does not become satisfied within `timeout`).
- `wait_for: bgp_session_up` is a single-neighbor check (explicit `dst`); `wait_for_bgp` is a coarse all-neighbors-of-one-node readiness check. Both remain available.

Prefer `wait_for` with an invariant condition over fixed `wait: { seconds: N }` for convergence purposes.

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
cassian test topologies/fixtures/grey_failure_direct_pass.yaml --scenario loss5_ping_still_passes
```

Replay deterministically:

```bash
cassian replay labs/clab-grey-failure-direct-pass --gate --verify-results
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
cassian test <topology.yaml> \
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
cassian test topologies/vendor_nos_smoke.yaml \
  --candidate-config tests/fixtures/vendor-nos-cand-neg-unsupported
```

Expected outcome:

```text
ERROR: Candidate config directory structure invalid: <dir>
exit code: 2
```

Meaning: this candidate-config surface is unsupported or malformed for the current command/topology.

Support boundary:

- supported current surfaces: generated FRR and nft-fw candidate files only
- unsupported current surfaces: vendor NOS / sonic-vm candidate-config input

Scope boundary:

- candidate config support is currently proven only for the existing supported candidate-apply surfaces
- this does not currently establish candidate-config support for `sonic-vm` or other vendor NOS VM node types
- any future NOS VM candidate-config support requires an explicit contract surface and proof

---

# 1️⃣2️⃣ Status Command

Inspect running labs.

```bash
cassian status <lab>
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
cassian status demo-lab --summary
```

---

# 1️⃣3️⃣ Cleanup & Lab Management

Destroy a running lab:

```bash
cassian down <lab>
```

Clean up abandoned labs:

```bash
cassian cleanup --all
cassian cleanup --all --yes
```

Dry-run occurs unless `--yes` is provided.

Example cleanup flow:

```bash
cassian down <lab>
cassian cleanup --all --yes
```

Meaning:

- `cassian down <lab>` tears down the named lab
- `cassian cleanup --all --yes` removes any remaining Cassian Gate-owned labs discovered by the cleanup plan
- cleanup stays explicit because dry-run remains the default without `--yes`

---

# 1️⃣4️⃣ DevOps Integration

Generate adapter artifacts.

---

## Terraform

```bash
cassian adapt terraform \
  --plan plan.json
```

Input:

```text
terraform show -json
```

---

## Ansible

```bash
cassian adapt ansible \
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

## AI Advisory (Optional, Non-Authoritative)

```bash
cassian ai --lab <lab-name> "<question>"
cassian ai --artifacts <path> "<question>"
cassian ai "<question>"
```

Purpose:

- Provides **advisory explanations and guidance** based on artifacts
- Helps interpret:
  - failures
  - coverage gaps
  - missing tests/scenarios
  - control-plane intent

Authority:

- advisory only
- does **not** affect:
  - verdicts
  - exit codes
  - execution
  - artifacts

Input:

- `topology.resolved.yaml`
- `results.json`

---

## Unified AI Assistance

Use the same conversational entrypoint for failure explanation, coverage review, topology review, scenario interpretation, invariant explanation, and blast-radius explanation.

### Common human path

```bash
cassian ai "why did this fail"
```

Uses the most recent valid artifact context when available.

### Explicit lab path

```bash
cassian ai --lab <lab> "why did this fail"
```

Uses the specified lab when it contains the required artifacts.

### Explicit artifacts path

```bash
cassian ai --artifacts <dir> "why did this fail"
```

This is the most explicit override and is useful for proof/debug workflows.

### Optional online-enriched rendering

Enable online-enriched advisory rendering explicitly:

```bash
cassian ai --online "why did this fail"
cassian ai --lab <lab> --online "why did this fail"
cassian ai --artifacts <dir> --online "why did this fail"
```

Rules:

- online-enriched rendering is explicit opt-in only
- local advisory rendering remains the baseline behavior
- online rendering does not change authority, verdicts, or execution behavior
- unavailable online rendering should be treated as a non-authoritative advisory-path failure, not a change in execution authority

### Rendering modes

`cassian ai` may indicate whether local or online-enriched advisory rendering was used.

Both remain advisory-only.

### Context selection

When possible, prefer explicit artifact or lab selection for clarity.

Required artifacts include:

```text
topology.resolved.yaml
results.json
```

If the required artifacts are missing, the advisory path should not be treated as available.

### Important boundary

`cassian ai`:

- reads artifacts only
- does not execute lifecycle actions
- does not modify topology, tests, scenarios, or configs
- does not affect verdicts
- remains advisory-only

---

## AI Output Structure

`cassian ai` is intended to present grounded, advisory explanations based on artifacts.

Typical output includes:

```text
Summary
Grounded evidence
Advisory interpretation
Recommended next steps
Optional draft suggestions
```

Treat the exact wording and formatting as supporting guidance rather than release-surface authority.

---

## Draft Format (Copy-Paste Ready)

Drafts are structured and labeled:

```text
Draft 1 — <type>
-----
<content>
-----
```

Common draft types:

- `topology guidance`
- `test block`
- `scenario block`
- `firewall-side fix`
- `test-side fix`

Example:

```text
Draft 1 — test block
-----
tests:
  - name: h1_to_h2_ping_should_pass
    kind: ping
    src: h1
    dst: h2
    expect: pass
-----
```

Notes:

- drafts are safe to copy/paste
- drafts are non-authoritative
- drafts require human review

---

## Supported Question Styles (Flexible)

`cassian ai` supports **multiple phrasings** for the same intent.

### Scenario Questions

- "what scenario am I missing"
- "what scenario should I add"
- "how would you test failover here"

### Invariant Questions

- "what invariant would help here"
- "what invariant should I add first"

### Coverage / Validation

- "what tests should I add next"
- "give me a concrete validation plan"

### Failure Analysis

- "why did this fail"
- "what should I change first"
- "what should I prove first"

### Topology Improvement

- "how would you improve this topology"
- "provide an improved topology"

Behavior:

- different phrasings can still target the same advisory intent
- AI remains advisory-only regardless of phrasing

---

## Local vs Online Rendering

### Local (default)

```bash
cassian ai --lab <lab> "<question>"
```

- deterministic, built-in reasoning
- no external dependency
- always available

### Online (optional)

```bash
cassian ai --lab <lab> --online "<question>"
```

Requirements depend on the configured online AI path.

Behavior:

- online rendering is optional
- it may provide richer explanations or phrasing
- it does not change verdicts, artifacts, or execution

---

## How to Use AI Effectively

Best practice flow:

1. Run deterministic gate:

```bash
cassian test <topology.yaml>
```

2. If failure:

```bash
cassian ai --lab <lab> "why did this fail"
```

3. Improve coverage:

```bash
cassian ai --lab <lab> "what should I prove first"
```

4. Expand validation:

```bash
cassian ai --lab <lab> "give me a concrete validation plan"
```

### Key Insight

- passing tests ≠ proven design
- AI helps identify:
  - missing **positive proofs**
  - missing **failure scenarios**
  - missing **control-plane invariants**

---

## AI Guardrails

- AI is **never authoritative**
- AI cannot:
  - run commands
  - modify topology
  - change configs
  - alter results
- AI output must always be:
  - human-reviewed
  - explicitly applied

---

## Verification Behavior

AI verification details belong to the implementation and verification surfaces. For operator use, keep the important boundary clear: AI remains optional and advisory-only.

---

## Example: AI Identifies Missing Invariant

AI may suggest:

```text
Draft 1 — test block
-----
tests:
  - name: fw1_advertises_192.168.2.0_24_to_r2
    kind: invariant
    type: route_advertised_to
    node: fw1
    peer: r2
    prefix: 192.168.2.0/24
    expect: pass
-----
```

Meaning:

- you are not proving control-plane correctness yet
- add route-level proof before expanding scenarios

---

# 1️⃣6️⃣ Artifacts

Artifacts are written to:

```text
labs/clab-<lab-name>/
```

Artifacts are typically written under:

```text
labs/clab-<lab-name>/
```

Interpret them using the authority boundary already established in the project:

- `topology.resolved.yaml` is generated execution input
- `results.json` is the authoritative verdict artifact
- `results.summary.txt` is explanatory only

Key files:

- `topology.resolved.yaml`
- `results.json`
- `results.summary.txt`
- `artifacts/`
- `artifacts/blast-radius/blast_radius.json`

---

## results.json

`results.json` is the authoritative verdict artifact.

It explicitly records declared validation items that executed, and when materially relevant, declared validation items that were blocked after entering authoritative execution scope.

Important boundary:

- omission does not mean success
- a blocked declared item should appear explicitly in `results.json`
- failed-invariant records carry a structured `observed_state` payload — see §9 "Failed-Invariant Observed State" and `docs/topology-schema-v1.5.md` §4 for the schema

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

Cassian Gate can produce a **structured pre/post operational state diff** when state capture is explicitly enabled for both phases.

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

When enabled, Cassian Gate captures the declared command/profile state:

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
cassian test topologies/three-frr-two-hosts-fw-routed.yaml \
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

Inspect the structured diff for the captured objects, changed elements, and supporting evidence relevant to your review.

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

Cassian Gate can produce a **blast radius artifact** that shows:

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

Inspect the blast-radius artifact for the covered scope, potentially affected objects, and other supporting evidence relevant to your review.

### Operator meaning

Use this artifact when you want to understand:

- what your declared tests directly touched
- what else is connected to that tested scope
- where additional coverage may be useful

### Example

```bash
cassian test topologies/blast_radius_ok.yaml

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
cassian validate topology.yaml
```

Validate contrib content structurally:

```bash
cassian validate-contrib contrib/
```

Run validation gate:

```bash
cassian test topology.yaml
```

Note:

- `cassian test <topology.yaml>` now requires at least one declared test or scenario
- if you only want to prove deploy/provision smoke behavior, use exploration mode instead of gate mode

Validate invariant-pack compatibility:

```bash
cassian validate topologies/pack_local_compatibility_ok.yaml
```

Run invariant-pack gate proof:

```bash
cassian test topologies/pack_local_compatibility_ok.yaml
```

Validate invalid pack misuse handling:

```bash
cassian validate topologies/neg/pack_unknown_reference.yaml
cassian validate topologies/neg/pack_incompatible_contents.yaml
```

Replay a previous gate deterministically:

```bash
cassian replay labs/clab-<lab> --gate
```

Explore a lab interactively:

```bash
cassian run topology.yaml --keep
cassian status <lab>
cassian exec <lab> r1
```

Bring up EVPN runtime substrate:

```bash
cassian up topologies/evpn_runtime_generation.yaml
```

Run a routing attribute invariant proof:

```bash
cassian test topologies/bgp_localpref_equals.yaml
```

Run a route advertisement invariant proof:

```bash
cassian test topologies/route_advertised_to.yaml
cassian test topologies/route_not_advertised_to.yaml
```

Run an EVPN invariant proof:

```bash
cassian test topologies/evpn_mac_route_present.yaml
```

Replay an EVPN proof deterministically:

```bash
cassian replay labs/clab-evpn-mac-route-present --gate --verify-results
```

Clean up labs:

```bash
cassian cleanup --all --yes
```

Run scenario testing:

```bash
cassian test topology.yaml --all-scenarios
```

Run a specific scenario in exploration mode:

```bash
cassian run topology.yaml --scenario <scenario-id>
```

Run a scenario with an explicit wait step:

```bash
cassian test topologies/h2_wait_runtime_positive.yaml --scenario simple_wait_runtime
cassian run topologies/h2_wait_runtime_positive.yaml --scenario simple_wait_runtime
```

Run a grey-failure scenario:

```bash
cassian test topologies/fixtures/grey_failure_direct_pass.yaml --scenario loss5_ping_still_passes
```

Replay the same grey-failure scenario deterministically:

```bash
cassian replay labs/clab-grey-failure-direct-pass --gate --verify-results
```

Run a blast radius proof:

```bash
cassian test topologies/blast_radius_ok.yaml
```

Inspect blast radius output:

```bash
python -m json.tool \
  labs/clab-blast-radius-ok/artifacts/blast-radius/blast_radius.json
```

Inspect structured state diff output:

```bash
cassian test topologies/three-frr-two-hosts-fw-routed.yaml \
  --state-capture both \
  --state-profile linux-net-basic \
  --state-profile frr-interfaces-basic \
  --state-profile frr-routing-basic \
  --state-profile nft-ruleset-basic

python -m json.tool labs/clab-three-frr-two-hosts-fw-routed/artifacts/state-diff/state_diff.json
```

Inspect a blocked declared-item result:

```bash
cassian test topologies/neg/blocked_precheck_bgp_results.yaml
python -m json.tool labs/clab-blocked-precheck-bgp-results/results.json
```

Look for:

- the declared test present in `tests`
- `observed: blocked`
- `verdict: fail`
- summary counts reflecting the blocked item

Use AI to explain a failure from the most recent run:

```bash
cassian ai "why did this fail"
```

Use AI against a specific lab:

```bash
cassian ai --lab <lab> "what should I prove first"
```

Use AI to expand validation coverage:

```bash
cassian ai --lab <lab> "give me a concrete validation plan"
```

Use optional online-enriched AI rendering:

```bash
cassian ai --lab <lab> --online "why did this fail"
```

---

## `cassian validate-contrib` — Structural validation for contrib content

Validate supported contrib content without running any lifecycle phases.

Command:

```bash
cassian validate-contrib <path>
```

Purpose:

- checks contrib content structurally
- rejects malformed or unsupported contrib layout
- does not deploy anything
- does not create lab artifacts
- does not affect verdicts, replay, or authority

Important boundary:

`validate-contrib` is:

- structural only
- non-authoritative
- explicit only

It does **not**:

- run resolve → deploy → test lifecycle phases
- produce PASS / FAIL validation verdicts
- generate `results.json`
- validate runtime behavior
- score content quality
- infer meaning or intent

Supported contrib surfaces are limited to the contrib content types documented by the current project documentation.

Typical behavior:

- validates only the path you explicitly pass
- checks for supported contrib layout and required structure
- rejects unsupported or malformed contrib content

Examples:

```bash
cassian validate-contrib contrib/
cassian validate-contrib contrib/packs
cassian validate-contrib contrib/state-profiles
cassian validate-contrib contrib/topologies/first-run-proof
```

Typical exit semantics follow the standard structural-validation pattern:

- accepted supported contrib content returns success
- invalid or unsupported contrib content is rejected as a usage / contract error

---

# 1️⃣8️⃣ Exit Codes

| Code | Meaning                |
| ---- | ---------------------- |
| 0    | PASS                   |
| 1    | Test failure           |
| 2    | Usage / contract error |

Examples:

- invariant truth mismatch → `1`
- validation failure after declared proof ran → `1`
- unsupported EVPN topology shape → `2`
- invalid invariant declaration → `2`
- incompatible pack contents → `2`
- zero-assertion gate run (`cassian test <topology.yaml>` with no tests/scenarios) → `2`
- valid contrib validation (`cassian validate-contrib contrib/`) → `0`
- invalid contrib structure (`cassian validate-contrib <broken-path>`) → `2`

Misuse / usage / contract error example:

```bash
cassian test does-not-exist.yaml
```

Typical outcome:

- the command is rejected before validation runs
- the failure is treated as a usage / contract error

Meaning:

- this is misuse / invalid invocation
- validation did **not** run
- exit code remains `2`

Validation failure example:

```text
RESULT: FAIL (validation)
```

Meaning:

- the system ran validation correctly
- the declared proof failed
- exit code remains `1`

A FAIL can also mean a declared validation item was blocked after authoritative execution began.

In that case, inspect `results.json`.

Typical blocked-result shape:

```json
{
  "name": "<declared-check-name>",
  "observed": "blocked",
  "verdict": "fail",
  "error": "blocked before execution"
}
```

These UX clarifications do **not** change:

- lifecycle order
- authority model
- verdict semantics
- artifact schema
- replay authority
- deterministic execution
- exit code contract

---

# 1️⃣9️⃣ First 10 Minutes

Recommended onboarding workflow:

```bash
cassian doctor
cassian validate topology.yaml
cassian test topology.yaml
```

Note:

- `cassian test <topology.yaml>` now requires at least one declared test or scenario
- if you only want to prove deploy/provision smoke behavior, use exploration mode instead of gate mode

For exploration:

```bash
cassian run topology.yaml --keep
cassian status <lab>
```

For EVPN runtime + proof:

```bash
cassian validate topologies/evpn_runtime_generation.yaml
cassian test topologies/evpn_mac_route_present.yaml
```

For AI-assisted explanation after a gate run:

```bash
cassian ai "why did this fail"
```

---

# End of Cassian Gate v79 Operator Cheat Sheet