# AI-Change Reference Case — core variant (built-in invariant)

This is the **core** demonstration of the §4.9 AI-change reference case. It uses a **built-in** invariant (`bgp_session_up`) from Cassian's catalog. The `udi-bgp-variant/` sibling tells the same story with a user-defined invariant (the LD-G enrichment).

## What it proves

An AI agent configured eBGP peering between `r1` (AS 65001) and `r2` (AS 65002). The gate checks the AI's work against a human-authored contract — the same way it checks a human's (Doctrine §1.12: no AI-privileged path).

- `passing/topology.yaml` — AI got it right → session up → **PASS**
- `failing/topology.yaml` — AI fat-fingered one `remote_as` → session never comes up → **FAIL**

## The boundary

Each file has two banner-marked regions: **[HUMAN-AUTHORED INTENT]** (the `tests:` block — byte-identical across both, see `intent.md`) and **[AI-GENERATED IMPLEMENTATION]** (the `nodes:` BGP config). The intent is constant; only the AI implementation differs, so the verdict difference is caused solely by the AI's implementation quality.

## Commands

```bash
cassian test failing/topology.yaml     # failing first
cassian test passing/topology.yaml     # then passing
```

Expected: `failing/` → **FAIL** (existing non-zero validation code); `passing/` → **PASS** (exit 0).

## Lab and CI model (important — corrected)

`bgp_session_up` reaches its verdict by observing live BGP state, so `cassian test` here **deploys a lab**. Run it locally and **commit the evidence** (`labs/clab-*/results.json` + `results.summary.txt`), like `contrib/topologies/first-run-proof`.

There is **no lab-free built-in invariant** in Cassian — every invariant observes runtime state. The lab-free property lives in the **CI harness** (`tests/ai_change_reference_case_proof.py`), which re-extracts the verdict core from the committed `results.json`, checks replay-stability, and asserts both DC §13(c) render halves — without a lab. CI never re-runs the gate. *(This corrects the original REQ-4_9-6 wording, which implied the invariant itself was lab-free.)*

Authoritative artifact: `results.json`. Human-readable only: `results.summary.txt`.
