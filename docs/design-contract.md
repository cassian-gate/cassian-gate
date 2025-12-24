# ai-netsim Design Contract (v1)

This document defines the non-negotiable behavior of ai-netsim. Its purpose is to keep the simulator **deterministic, auditable, and reproducible** as features grow (including when code is written with AI assistance).

If a change conflicts with this contract, the change must be redesigned or placed behind an explicit opt-in mode/flag that preserves determinism and auditability.

---

## 1) Repo structure and sources of truth

### Authoritative inputs (source of truth)
- `topologies/*.yaml`  
  User-defined intent: nodes, links, addressing intent, and tests.
- `src/netsim.py` (and any imported modules under `src/`)  
  Execution engine + resolver + generators + test runner behavior.

### Generated outputs (never authoritative)
- `labs/**`  
  Per-lab generated artifacts (containerlab files, node configs, resolved topology, results).
- `labs/*.clab.yaml` (and any `*.clab.yaml` produced)
- `labs/**/results.json`
- `labs/**/topology.resolved.yaml` (or equivalent resolved output)

**Contract rule:** Editing files under `labs/` is unsupported and has undefined behavior.  
The only supported way to change outcomes is by editing `topologies/` inputs or code in `src/`.

### Runtime building blocks
- `images/nft-fw/Dockerfile` (and future images under `images/`)  
  These define runtime components. ai-netsim orchestrates them; it does not “simulate” device behavior internally.

Tooling/IDE:
- `.venv/`, `.vscode/` are developer environment only and must not be required for runtime correctness.

---

## 2) Core product guarantees

### Determinism
Given:
- the same `topologies/*.yaml`
- the same code version
- the same container images (or pinned tags/digests)
- the same declared timeouts

ai-netsim must produce:
- the same resolved topology output
- the same generated configs
- the same test verdicts (within the defined timeout semantics)

**Contract rule:** No hidden randomness. No time-based “smart behavior”. Any retry/timeout must be explicit and recorded.

### Explicitness
ai-netsim must not guess intent, auto-remediate silently, or mutate the requested design unless:
- the behavior is a documented default applied during **resolve**, and
- the applied default is visible in the resolved topology output.

### Auditability
Each run must produce:
- a stable artifact directory under `labs/`
- a machine-readable `results.json` with test evidence
- logs that make it possible to reproduce and debug outcomes

---

## 3) Execution lifecycle (must remain in this order)

ai-netsim runs a lab through these phases:

1. **Resolve**
   - Read `topologies/<name>.yaml`
   - Apply defaults/templates
   - Validate schema and required fields
   - Emit a resolved topology (e.g., `labs/<lab>/topology.resolved.yaml`)

2. **Generate**
   - Generate containerlab topology (`*.clab.yaml` or equivalent)
   - Generate per-node configs under `labs/<lab>/nodes/<node>/...`
   - Generate any provisioning scripts/rules needed

3. **Deploy**
   - Deploy the lab via containerlab into `labs/<lab>/...`
   - Confirm containers exist and are running (readiness gating)

4. **Provision**
   - Apply host addressing/routes
   - Apply FRR config (or equivalent) to FRR nodes
   - Apply nftables rules to `nft-fw` nodes
   - Confirm provisioning completion deterministically

5. **Test**
   - Execute tests declared in the topology (e.g., ping/tcp)
   - Collect evidence (exit codes, stdout/stderr snippets, etc.)

6. **Collect**
   - Write `results.json` with the full structured outcomes
   - Persist any additional evidence files under `labs/<lab>/`

7. **Destroy** (unless explicitly kept)
   - Tear down the lab deterministically
   - No orphan containers, no lingering listeners, no leaked state

**Contract rule:** No later phase may implicitly modify earlier-phase artifacts.  
Example: tests must not “fix routing” to make themselves pass.

---

## 4) Defaults policy

Defaults are allowed only if they meet all conditions:
- Applied only during **Resolve**
- Documented in this contract or in a single clearly-named defaults module/file
- Visible in `topology.resolved.yaml` (or equivalent)

**Contract rule:** Provision/Test phases must not introduce hidden defaults.

---

## 5) Test contract (ping/tcp and future tests)

### Required test output fields
Every test result must include:
- `expected` — desired outcome (e.g., `"pass"` or `"fail"`)
- `observed` — what actually happened (e.g., `"pass"` or `"fail"`)
- `verdict` — whether observed matched expected (`"pass"` or `"fail"`)
- `evidence` — minimal proof used to determine observed (exit code, error string, etc.)

### Negative tests are first-class
If a test expects failure:
- `expected: "fail"`
- and the connection is blocked / unreachable / refused within the defined semantics:
  - `observed: "fail"`
  - `verdict: "pass"`

**Contract rule:** A blocked connection counts as a PASS when failure is expected.

### Timeouts & retries
- Timeouts must be explicit per test type (or per test)
- Retries must be explicit and deterministic
- Any retry behavior must be recorded in evidence/logging

---

## 6) Failure policy

### Hard failures (stop the run)
- Deployment failure (containers not created/running)
- Provisioning failure (required node config cannot be applied)
- Missing required nodes/links
- Internal exceptions that prevent a meaningful test run

Hard failures should exit non-zero and clearly state:
- which phase failed
- which node/test failed
- why (actionable message)

### Test failures (do not crash the engine)
A test failure is a normal outcome:
- recorded in `results.json`
- contributes to overall run status
- does not terminate other tests unless explicitly configured

---

## 7) Model vs backend (future-proofing)

### Model layer
The topology model should not assume containerlab forever.
- `topologies/` describe intent (nodes/links/tests), not container-specific wiring.

### Backend adapter (today: containerlab)
Containerlab is the current execution backend.
Future backends (VM/QEMU/vrnetlab/libvirt) must be able to reuse the same model and test semantics.

**Contract rule:** Do not bake containerlab-only assumptions into the topology schema if avoidable. Keep them in backend adapters.

---

## 8) Security and hygiene constraints (v1)

- No shell injection: any user-provided strings used in commands must be safely handled.
- No hidden network access beyond what the lab declares.
- Clean teardown: no long-running listeners after `test`, no leaked processes.

---

## 9) Change control (how this contract is enforced)

Any change must answer:
1. Does it preserve determinism?
2. Does it preserve auditability and stable artifacts?
3. Does it keep inputs authoritative and outputs generated?
4. Does it preserve negative test semantics?

If any answer is “no”, the change must be:
- redesigned, or
- moved into an explicitly named opt-in mode/flag that does not affect default behavior.

---

## 10) v1 non-goals

- Automatic network design or “AI decides topology” during execution
- Automatic remediation/healing during provision/test
- Nondeterministic “best effort” behavior
- Silent mutation of user intent outside Resolve

End of contract.
