# Intent (human-authored) — core variant (built-in invariant)

**The contract the AI implementation must satisfy. A human wrote it. Identical in the passing and failing variants.**

In plain terms:

> On `r1`, the eBGP session to its neighbor `r2` (`10.0.0.2`) must be up (Established).

Declared as a **built-in** invariant — the shipped `bgp_session_up` type, no user-defined logic:

```yaml
- name: r1_bgp_session_to_r2_up
  kind: invariant
  type: bgp_session_up
  node: r1
  dst: 10.0.0.2
  expect: pass
```

This is the **core** demonstration (LD-G): the truth is asserted with a built-in invariant from Cassian's catalog. The UDI (`exec`) variant is the enrichment that tells the same story with a user-defined invariant.

This `tests:` block is carried **byte-identically** into both `passing/topology.yaml` and `failing/topology.yaml`. Only the **AI-generated implementation** (the BGP config) differs. The verdict therefore tracks the AI's implementation quality against a fixed human contract — Doctrine §1.12, no AI-privileged path.

## How it is proven (read this — corrected lab/CI model)

`bgp_session_up` reaches its verdict by observing live BGP state on `r1`, so generating the evidence **requires a deployed lab**. Run `cassian test` locally and **commit the resulting evidence** (`labs/clab-*/results.json` + `results.summary.txt`), exactly as `contrib/topologies/first-run-proof` commits its lab artifacts.

The CI harness (`tests/ai_change_reference_case_proof.py`) is **lab-free**: it re-extracts the verdict core from the committed `results.json`, checks replay-stability, and asserts both DC §13(c) render halves — it never re-runs the lab. *(No built-in invariant evaluates lab-free; the lab-free property belongs to the CI verification of committed evidence, not to the invariant. This corrects the original REQ-4_9-6 wording.)*
