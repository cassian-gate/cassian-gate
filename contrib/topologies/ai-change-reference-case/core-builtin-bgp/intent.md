# Intent (human-authored) — core variant (built-in invariant)

**The contract the AI implementation must satisfy. A human wrote it. Identical in the passing and failing variants.**

In plain terms:

> On `r1`, the eBGP session to its neighbor `r2` (`10.0.0.2`) must be up (Established).

Declared as a **built-in** invariant — the shipped `bgp_session_up` type:

```yaml
- name: r1_bgp_session_to_r2_up
  kind: invariant
  type: bgp_session_up
  node: r1
  dst: 10.0.0.2
  expect: pass
```

This is the **core** demonstration (the guardrail story). The bonus `udi-bgp-variant/` tells the complementary detection story with a user-defined invariant.

The `tests:` block is carried **byte-identically** into both `passing/topology.yaml` and `failing/topology.yaml`. Only the **AI-generated implementation** (the BGP config) differs, so the verdict tracks the AI's implementation quality against a fixed human contract — Doctrine §1.12, no AI-privileged path.

## What the failing case actually demonstrates

The failing variant's AI error (wrong `remote_as`) stops the eBGP session from ever establishing. Because the session never converges, the gate's **control-plane precheck blocks the invariant before it can run** and records a genuine authoritative **FAIL** — with `observed: blocked` and an explicit *"structured failure detail unavailable"* note (never a blank). This is the **absent-half** of the failed-invariant surface: the gate refuses to pass a check it could not complete; silence is not read as success.

## How it is proven (lab/CI model)

`bgp_session_up` reaches its verdict by observing live BGP state, so generating the evidence **requires a deployed lab**. Run `cassian test` locally and **commit the resulting evidence** (`labs/clab-*/results.json` + `results.summary.txt`), like `contrib/topologies/first-run-proof`.

The CI harness (`tests/ai_change_reference_case_proof.py`) is **lab-free**: it re-extracts the verdict core from the committed `results.json`, checks replay-stability, and asserts both DC §13(c) render halves on constructed records — it never re-runs the lab. No built-in invariant is lab-free; the lab-free property belongs to the CI verification, not the invariant.
