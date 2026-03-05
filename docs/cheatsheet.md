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
````

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

* production validation
* CI pipelines
* change validation
* baseline vs candidate comparison

You **do NOT run `netsim up` first**.

Gate mode owns the lifecycle.

---

### PASS with 0 tests

If the topology contains:

* no `tests`
* no `scenarios`

Output:

```
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

```
topology.resolved.yaml
results.json
```

These artifacts are treated as **authoritative inputs**.

### Example

Run a test:

```
netsim test topologies/rc_cold_baseline.yaml
```

Artifacts are created:

```
labs/clab-rc-cold-baseline/
```

Replay the same run:

```
netsim replay labs/clab-rc-cold-baseline --gate
```

ai-netsim will:

1. Load the resolved topology from the artifacts
2. Create a temporary replay lab
3. Re-run the full lifecycle

```
GENERATE → DEPLOY → PROVISION → TEST → COLLECT → DESTROY
```

### Verify deterministic results

You can also confirm the replay produces identical results:

```
netsim replay labs/clab-rc-cold-baseline --gate --verify-results
```

If the results differ, replay exits with:

```
exit code: 1
```

### When to use replay

Replay is useful when you want to confirm that a result is **not accidental**.

Common scenarios:

* validating CI pipeline determinism
* verifying network change simulations
* reproducing previous test results
* debugging unexpected behavior

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

```
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

* persistent labs
* manual inspection
* iterative debugging

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

```
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

* `name`
* `nodes`
* `links`

Optional:

* `tests`
* `scenarios`
* `fabric`
* `candidate_changes`

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

* `/31` addresses auto-assigned

View assigned addresses:

```
labs/clab-<lab>/topology.resolved.yaml
```

---

# 8️⃣ Tests

Required fields:

* `name`
* `kind`
* `src`
* `dst`

Supported kinds:

* `ping`
* `tcp`

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

---

# 9️⃣ Scenarios (Failure Choreography)

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

* `run`
* `fault`
* `wait`
* `wait_for`
* `wait_for_bgp`

No implicit retries.
Timeout = failure.

---

# 🔟 Candidate Configuration (Gate Only)

Apply candidate changes during validation.

```bash
netsim test <topology.yaml> \
  --candidate-config <dir>
```

Directory layout:

```
<dir>/
  frr/<node>.conf
  nft/<node>.nft
```

Rules:

* full replacement
* no merge
* atomic apply
* failure aborts gate

---

# 1️⃣1️⃣ Status Command

Inspect running labs.

```bash
netsim status <lab>
```

Useful options:

* `--summary`
* `--interfaces`
* `--bgp`
* `--bgp-verbose`
* `--routes`
* `--routes-verbose`
* `--json`
* `--strict`

Example:

```bash
netsim status demo-lab --summary
```

---

# 1️⃣2️⃣ Cleanup & Lab Management

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

# 1️⃣3️⃣ DevOps Integration

Generate adapter artifacts.

---

## Terraform

```bash
netsim adapt terraform \
  --plan plan.json
```

Input:

```
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

# 1️⃣4️⃣ AI Assistance (Optional)

AI is **assistive only**.

It never affects:

* execution
* verdicts
* exit codes

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

# 1️⃣5️⃣ Artifacts

Artifacts are written to:

```
labs/clab-<lab-name>/
```

Key files:

* `topology.resolved.yaml`
* `results.json`
* `results.summary.txt`
* `artifacts/`

---

## topology.resolved.yaml

Contains the **fully expanded deterministic model** used for execution.

Includes:

* resolved defaults
* auto IP assignments
* normalized topology

---

# 1️⃣6️⃣ Common Operator Tasks

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

Clean up labs:

```bash
netsim cleanup --all --yes
```

Run scenario testing:

```bash
netsim test topology.yaml --all-scenarios
```

---

# 1️⃣7️⃣ Exit Codes

| Code | Meaning                |
| ---- | ---------------------- |
| 0    | PASS                   |
| 1    | Test failure           |
| 2    | Usage / contract error |

---

# 1️⃣8️⃣ First 10 Minutes

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

---

# End of ai-netsim v79 Operator Cheat Sheet