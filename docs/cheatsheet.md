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

### AI Assistance (optional / advisory only)

```bash
netsim ai explain
netsim ai review
netsim ai coach
```

AI **never affects execution or verdicts**.

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

## netsim replay — Re-run a previous test deterministically

Replay re-executes a previous ai-netsim run using the **exact artifacts** that produced the original result.

This verifies that the result is **reproducible and deterministic**.

### Inputs

Replay consumes artifacts from a previous run:

```text
topology.resolved.yaml
results.json
```

These artifacts are treated as **authoritative inputs**.

### Example

Run a test:

```bash
netsim test topologies/rc_cold_baseline.yaml
```

Artifacts are created:

```text
labs/clab-rc-cold-baseline/
```

Replay the same run:

```bash
netsim replay labs/clab-rc-cold-baseline --gate
```

ai-netsim will:

1. Load the resolved topology from the artifacts
2. Create a temporary replay lab
3. Re-run the full lifecycle

```text
GENERATE → DEPLOY → PROVISION → TEST → COLLECT → DESTROY
```

### Verify deterministic results

You can also confirm the replay produces identical results:

```bash
netsim replay labs/clab-rc-cold-baseline --gate --verify-results
```

If the results differ, replay exits with:

```text
exit code: 1
```

### When to use replay

Replay is useful when you want to confirm that a result is **not accidental**.

Common scenarios:

- validating CI pipeline determinism
- verifying network change simulations
- reproducing previous test results
- debugging unexpected behavior

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
- `fabric`
- `candidate_changes`
- `vlans`

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

They are useful when you need to prove policy outcome, path preference, or route attributes.

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

| Field    | Description                               |
| -------- | ----------------------------------------- |
| node     | Node where the route must be observed     |
| prefix   | Prefix being validated                    |
| expected | Expected BGP local preference value       |

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
  frr/<node>.conf
  nft/<node>.nft
```

Rules:

- full replacement
- no merge
- atomic apply
- failure aborts gate

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

## Explain Failures

```bash
netsim ai explain <target>
```

Explains failure causes using artifacts.

---

## Review Test Coverage

```bash
netsim ai review <topology.yaml>
```

Suggests missing tests.

---

## Coaching

```bash
netsim ai coach
```

Provides general guidance.

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

---

## topology.resolved.yaml

Contains the **fully expanded deterministic model** used for execution.

Includes:

- resolved defaults
- auto IP assignments
- normalized topology
- additive EVPN-resolved fields when EVPN runtime substrate is used

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

Run a routing invariant proof:

```bash
netsim test topologies/bgp_localpref_equals.yaml
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