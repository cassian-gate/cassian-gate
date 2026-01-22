# ai-netsim Design Contract (Authoritative)

**Version:** v1  
**Status:** LOCKED  
**Scope:** Applies to v1 and all future versions unless explicitly amended

This document defines the **non-negotiable behavior** of ai-netsim.

Its purpose is to ensure ai-netsim remains a **deterministic, auditable, CI-safe validation gate**, even as features expand (including AI-assisted capabilities).

If a change conflicts with this contract, the change **must be redesigned**, **explicitly deferred**, or **placed behind a clearly named opt-in flag** that preserves default behavior.

---

## 1) Repo structure & sources of truth

### Authoritative inputs (source of truth)

- `topologies/*.yaml`  
  User-declared **intent**: nodes, links, addressing, tests, scenarios, expectations.

- `src/`  
  Execution engine, resolvers, generators, runtime adapters, test semantics.

**Contract rule:**  
Only these inputs may change validation outcomes.

---

### Generated outputs (never authoritative)

- `labs/**`
- `labs/*.clab.yaml`
- `labs/**/topology.resolved.yaml`
- `labs/**/results.json`
- `labs/**/results.summary.txt`
- any logs, pcaps, or evidence artifacts

**Contract rule:**  
Editing anything under `labs/` is unsupported and has undefined behavior.

The only supported way to change outcomes is by editing:
- `topologies/`
- `src/`

---

### Runtime components

- `images/**` (e.g. `images/nft-fw/Dockerfile`)
- Container images define runtime behavior
- ai-netsim **orchestrates**, it does not emulate device logic internally

Developer tooling (`.venv/`, `.vscode/`) must never be required for correctness.

---

## 2) Core product guarantees

### Determinism (non-negotiable)

Given:
- identical topology YAML
- identical code version
- identical container images (tags or digests)
- identical declared timeouts

ai-netsim **must produce**:
- identical resolved topology
- identical generated configs
- identical test & scenario verdicts

**Contract rule:**
- No hidden randomness
- No heuristic retries
- No time-based guessing
- All retries, waits, and timeouts must be explicit and recorded

---

### Explicitness

ai-netsim must **never**:

- guess user intent
- silently auto-fix misconfigurations
- mutate requested design outside Resolve

Defaults are allowed **only if**:
- applied during **Resolve**
- documented
- visible in `topology.resolved.yaml`

---

### Auditability

Each run must produce:
- a stable artifact directory under `labs/`
- a machine-readable `results.json`
- artifacts sufficient to reproduce and explain outcomes

---

## 3) Execution lifecycle (fixed order)

ai-netsim executes strictly in this order:

1. **Resolve**
   - Validate schema and intent
   - Apply defaults
   - Expand scenarios
   - Emit `topology.resolved.yaml`

2. **Generate**
   - Generate containerlab topology
   - Generate per-node configs
   - Generate provisioning artifacts

3. **Deploy**
   - Deploy via runtime backend
   - Verify containers exist and are running

4. **Provision**
   - Apply host addressing
   - Apply firewall rules
   - Apply **runtime configuration owned by the image or backend**
   - Perform deterministic readiness checks

   > ai-netsim does **not** own routing intent or correctness in v1.  
   > Routing may exist via preconfigured images or user exploration, but is never inferred or validated here.

5. **Test**
   - Execute atomic tests
   - Execute scenarios (if declared)
   - No hidden remediation

6. **Collect**
   - Write authoritative `results.json`
   - Write non-authoritative summaries/evidence

7. **Destroy**
   - Tear down lab deterministically
   - No leaked containers or processes

**Contract rule:**  
Later phases must not mutate artifacts from earlier phases.

---

## 4) Gate-first UX (LOCKED)

### `netsim test` (authoritative)

- Always starts from a **clean state**
- Destroys any existing lab
- Executes deterministically
- Returns a **binary verdict**
- Produces authoritative artifacts

### `netsim run` (non-authoritative)

- Explicitly exploratory
- No guarantees
- Never used for CI gating

**Contract rule:**  
Gate semantics must never be bypassed or softened.

---

## 5) Scenario contract (v1)

### Scenarios are:

- Optional
- Explicit
- Ordered
- Deterministic
- Fail-fast on ambiguity

### Scenario steps

Each step must contain **exactly one** action:

- `run`
- `fault`
- `wait_for`
- `wait_for_bgp`

Unknown keys are rejected.

---

### Fault semantics

- `link_*` requires unambiguous link resolution
- `interface_*` requires explicit interface
- **1 fault step → 1 fault event** in `results.json`
- No hidden side effects

---

### Convergence semantics

- Global prechecks apply to default tests
- Scenarios skip global prechecks by default
- `wait_for_bgp` is authoritative inside scenarios
- All convergence waits are explicit and recorded

---

## 6) Test contract

### Supported atomic test types (v1 / v1.x)

- `ping`
- `tcp`
- `bgp_neighbor` (binary control-plane health invariant)

No other atomic test types are permitted unless explicitly added via contract amendment.

---

### Required test result fields

Each test must record:

- `expected`
- `observed`
- `verdict`
- `evidence`

---

### Negative tests

If `expected: fail` and failure occurs:
- `observed: fail`
- `verdict: pass`

Blocked traffic counts as **success** when failure is expected.

---

### Timeouts & retries

- Explicit
- Deterministic
- Recorded in artifacts

---

## 7) Failure policy

### Hard failures (stop execution)

- Deploy failure
- Provision failure
- Invalid topology/schema
- Runtime execution failure

Must report:
- phase
- node/test
- actionable reason

---

### Test failures

- Normal outcome
- Recorded
- Do not crash the engine unless configured

---

## 8) AI contract (authoritative boundary)

AI in ai-netsim is **assistive only**.

AI commands:
- are post-execution
- consume artifacts only
- are explicitly invoked
- never affect verdicts
- never affect exit codes
- never mutate state

AI must always declare:

**Contract rule:**  
Tests and scenarios are the sole authority.

---

## 9) Model vs backend (future-proofing)

- Topology model is runtime-agnostic
- Backends (containerlab today, VM later) implement execution
- Backend-specific logic must not leak into schema

---

## 10) Security & hygiene

- No shell injection
- No implicit network access
- Clean teardown
- No leaked listeners or processes

---

## 11) Change control

Every change must answer **yes** to:

1. Deterministic?
2. Auditable?
3. Inputs authoritative?
4. Outputs generated?
5. Negative tests preserved?

If **any answer is no**, the change is invalid unless explicitly gated.

---

## 12) Explicit non-goals (LOCKED)

- No AI-driven pass/fail
- No auto-remediation
- No lab-first workflows
- No nondeterministic behavior
- No silent intent mutation
- No probabilistic gating

---

## Contract authority

This document is **authoritative**.

If implementation, documentation, or AI suggestions conflict with this contract:
- the contract wins
- the change must be redesigned or deferred

**End of contract.**
