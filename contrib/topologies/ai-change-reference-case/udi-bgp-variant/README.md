# AI-Change Reference Case — bonus variant (`exec` UDI, detection story)

The **user-defined-invariant enrichment** for the §4.9 AI-change reference case (REQ-4_9-14). It tells the **detection** story — the gate inspects the resulting network state and reports a bad route — complementing the core variant's **guardrail** story (the gate refusing to pass an un-evaluable check).

## What it proves

An AI agent configured eBGP peering between `r1` (AS 65001) and `r2` (AS 65002) and was supposed to advertise r1's loopback `1.1.1.1/32`. The gate checks the AI's work against a human-authored contract — the same way it checks a human's (Doctrine §1.12: no AI-privileged path).

- `passing/topology.yaml` — AI advertised the route → r2 learns it → **PASS**
- `failing/topology.yaml` — AI configured peering correctly but **forgot to advertise** the route → r2 never learns it → **FAIL**

## Why this is the detection / present-half story

The peering is correct in **both** variants, so the session **converges**. The control-plane precheck therefore passes and the `exec` invariant **runs**: it reads r2's BGP table and observes whether `1.1.1.1/32` is present. In the failing variant it is absent, so the gate records a **FAIL with the observed (empty) state rendered** — the §13(c) **present-half**. (The core variant, by contrast, shows the **absent-half**: a flaw so basic the session never converges and the check is blocked before it can run.) Together the two variants exercise both halves from real lab evidence.

## The boundary

Each file has two banner-marked regions: **[HUMAN-AUTHORED INTENT]** (the `tests:` block — byte-identical across both, see `intent.md`) and **[AI-GENERATED IMPLEMENTATION]** (the `nodes:` config — here the difference is whether r1 has a `networks:` advertisement).

## Commands

```bash
cassian test failing/topology.yaml     # failing first
cassian test passing/topology.yaml     # then passing
```

Expected: `failing/` → **FAIL** (route absent, observed state rendered); `passing/` → **PASS** (exit 0).

## Lab and CI model

`exec` runs a command on a live node, so `cassian test` here **deploys a lab**. Run it locally and **commit the evidence** (`labs/clab-*/results.json` + `results.summary.txt`), like `contrib/topologies/first-run-proof`. The CI harness (`tests/ai_change_reference_case_proof.py`) verifies the committed evidence **lab-free** — it never re-runs the lab (REQ-4_9-6 corrected / B07: no lab in CI).

When you generate evidence, confirm the `contains: "1.1.1.1/32"` assertion against real FRR output (present → contains the prefix; absent → `{}`); swap to a structured `field` check if you prefer, after verifying the JSON shape.

Authoritative artifact: `results.json`. Human-readable only: `results.summary.txt`.
