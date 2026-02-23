# ai-netsim v78 — Operator Cheat Sheet v2

*(Authoritative & UX-Hardened)*

> This document defines the **user-facing execution contract** for ai-netsim (snapshot v78).
> It reflects implemented behavior only.
> This is the authoritative reference for user validation and operator use.

---

# 1️⃣ Core Philosophy

ai-netsim is a:

> **Deterministic network change validation gate**

It is **not**:

* A general lab builder
* A chaos engine
* A retry framework
* A config merge tool
* An AI decision system

Execution must be:

* Explicit
* Deterministic
* Reproducible
* Artifact-backed
* Non-heuristic

---

# 2️⃣ Two Execution Modes (CRITICAL)

Understanding this distinction is mandatory.

---

## 🔷 Gate Mode (Authoritative Validation)

Command:

```bash
netsim test <topology.yaml>
```

This is the **validation gate**.

Gate mode automatically performs:

1. Clean-state destroy (if needed)
2. Deploy
3. Provision
4. Execute tests
5. Collect artifacts
6. Destroy lab
7. Exit with deterministic code

You do **NOT** run `netsim up` first.

Gate mode owns the full lifecycle.

Use Gate Mode for:

* Production validation
* CI pipelines
* Change validation
* Baseline vs candidate comparison

---

### 🔍 Important: PASS with 0 tests

If a topology contains:

* No `tests`
* No `scenarios`

Gate mode validates only that the lab deploys successfully.

You will see:

```
Tests executed: 0
Scenarios executed: 0
RESULT: PASS
```

This means:

> Lab deployed successfully (SMOKE validation only).

It does **not** validate routing or traffic behavior.

---

## 🔷 Exploration Mode (Non-Authoritative)

Exploration mode is for interactive debugging and inspection.

There are two primary approaches.

---

### Option A — run (up + test + collect)

```bash
netsim run <topology.yaml>
```

⚠️ By default, `run` **destroys the lab at the end**.

To keep the lab running:

```bash
netsim run <topology.yaml> --keep
```

Use this when you want:

* Quick deploy + validation
* Optional lab retention

---

### Option B — Explicit Up / Down

```bash
netsim up <topology.yaml> --reconfigure
netsim status <lab-name>
netsim test <lab-name>
netsim down <lab-name>
```

This gives full manual control.

Use this when you want:

* Persistent lab
* Manual inspection
* Iterative debugging

---

## 🔥 Lifecycle Comparison

| Feature                | Gate Mode | Exploration Mode               |
| ---------------------- | --------- | ------------------------------ |
| Clean-state enforced   | Yes       | Optional                       |
| Auto destroy           | Yes       | Only if `run` without `--keep` |
| CI-safe                | Yes       | No                             |
| Interactive inspection | No        | Yes                            |
| Authoritative verdict  | Yes       | No                             |

---

# 3️⃣ Topology vs Lab Name (Very Important)

Many commands take different inputs.

---

## Commands That Take a **Topology File**

These expect a YAML file path:

```bash
netsim gen <topology.yaml>
netsim validate <topology.yaml>
netsim preflight <topology.yaml>
netsim up <topology.yaml>
netsim run <topology.yaml>
netsim test <topology.yaml>
```

---

## Commands That Take a **Lab Name**

These expect the `name:` defined inside the topology:

```bash
netsim status <lab-name>
netsim exec <lab-name> <node>
netsim vty <lab-name> <node> "<command>"
netsim collect <lab-name>
netsim down <lab-name>
netsim destroy <lab-name>
```

---

### 🔍 Where does lab name come from?

It is defined in your topology:

```yaml
name: demo-lab
```

You will also see it printed during execution:

```
Lab: demo-lab
```

---

# 4️⃣ Topology Authoring

ai-netsim consumes YAML.

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

# 5️⃣ Nodes

Supported types (v78):

| Type     | Description       |
| -------- | ----------------- |
| frr      | FRR router        |
| host     | Linux host        |
| nft-fw   | nftables firewall |
| sonic-vm | SONiC VM runtime  |

---

## FRR

Optional:

```yaml
asn: 65001
router_id: 1.1.1.1
frr_mode: generated | preconfigured
```

Default: `generated`

If multi-hop ping expects pass:

All FRR nodes must use:

```yaml
frr_mode: preconfigured
```

---

# 6️⃣ Links

```yaml
- endpoints: ["r1:eth1", "r2:eth1"]
  ipv4: ["10.0.0.0/31", "10.0.0.1/31"]
```

If `ipv4` omitted:

* `/31` auto-assigned sequentially.

Auto-assigned addresses appear in:

```
labs/clab-<lab>/topology.resolved.yaml
```

---

# 7️⃣ Tests

Each test requires:

* `name`
* `kind`
* `src`
* `dst`

Supported kinds:

* `ping`
* `tcp`

---

## 🔍 Node Name vs IP in dst

When `dst` is a node name:

* ai-netsim resolves to the appropriate interface IP.
* Resolution must be unambiguous.

For clarity and operator confidence:

> Prefer explicit IP addresses (`dst: 10.0.0.1`) when validating connectivity.

---

## ping Example

```yaml
- name: r1_to_r2
  kind: ping
  src: r1
  dst: 10.0.0.1
  count: 2
  expect: pass
```

---

## tcp Example

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

# 8️⃣ Scenarios

Scenarios define ordered failure choreography.

---

## Example

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
No implicit convergence waits.
Timeout = failure.

---

# 9️⃣ Candidate Configuration (Gate Only)

```bash
netsim test <topology.yaml> --candidate-config <dir>
```

Supported node types:

* frr
* nft-fw

Directory structure:

```
<dir>/
  frr/<node>.conf
  nft/<node>.nft
```

Rules:

* Full replacement only
* No merge
* Atomic
* Failure aborts gate

---

# 🔟 status Command

Used to inspect a running lab.

```bash
netsim status <lab-name>
```

Useful options:

* `--summary`
* `--interfaces`
* `--bgp`
* `--json`
* `--strict`

Example:

```bash
netsim status demo-lab --summary
```

If lab is not deployed:

* status will report an error.

---

# 1️⃣1️⃣ Artifacts

Located under:

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

This file contains:

* Fully expanded topology
* Auto-assigned IP addresses
* Resolved defaults
* Normalized execution input

It represents the exact deterministic model used for execution.

---

# 1️⃣2️⃣ First 10 Minutes

```bash
netsim doctor
netsim validate <topology.yaml>
netsim test <topology.yaml>
```

If you want to inspect the lab:

```bash
netsim run <topology.yaml> --keep
netsim status <lab-name>
```

---

# End of v78 Operator Contract (v2 UX-Hardened)

---
