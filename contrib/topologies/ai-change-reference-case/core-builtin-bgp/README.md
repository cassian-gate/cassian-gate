# AI-Change Reference Case — core variant (built-in invariant, guardrail story)

The **core** demonstration of the §4.9 AI-change reference case, using the built-in `bgp_session_up` invariant. The bonus `udi-bgp-variant/` tells the complementary **detection** story with a user-defined invariant.

## What it proves

An AI agent configured eBGP peering between `r1` (AS 65001) and `r2` (AS 65002). The gate checks the AI's work against a human-authored contract — the same way it checks a human's (Doctrine §1.12: no AI-privileged path).

- `passing/topology.yaml` — AI got it right → session up → **PASS**
- `failing/topology.yaml` — AI fat-fingered one `remote_as` → session never establishes → **FAIL**

## What the failing case shows (the guardrail story)

The AI's wrong `remote_as` stops the eBGP session converging. The gate's **control-plane precheck** detects that BGP did not converge and **blocks the invariant before it runs**, recording a genuine authoritative **FAIL** with `observed: blocked` and an explicit *"structured failure detail unavailable"*. It is a loud failure, never a silent pass — the gate **refuses to pass a check it could not complete** (the §13(c) absent-half; silence ≠ success).

## The boundary

Each file has two banner-marked regions: **[HUMAN-AUTHORED INTENT]** (the `tests:` block — byte-identical across both, see `intent.md`) and **[AI-GENERATED IMPLEMENTATION]** (the `nodes:` BGP config). The intent is constant; only the AI implementation differs.

## Commands

```bash
cassian test failing/topology.yaml     # failing first
cassian test passing/topology.yaml     # then passing
```

Expected: `failing/` → **FAIL** (existing non-zero validation code, `observed: blocked`); `passing/` → **PASS** (exit 0).

## Lab and CI model

`bgp_session_up` observes live BGP state, so `cassian test` here **deploys a lab**. Run it locally and **commit the evidence**, like `contrib/topologies/first-run-proof`. The CI harness (`tests/ai_change_reference_case_proof.py`) is **lab-free** — it re-extracts the verdict core from the committed `results.json`, checks replay-stability, and asserts both DC §13(c) render halves on constructed records, without a lab. No built-in invariant is lab-free; the lab-free property is the CI verification of committed evidence.

Authoritative artifact: `results.json`. Human-readable only: `results.summary.txt`.
