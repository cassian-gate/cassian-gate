# AI-Change Reference Case — UDI (`exec`) variant

This is the **user-defined-invariant enrichment** for the §4.9 AI-change reference case (REQ-4_9-14). It tells the same story as the core variant, but the declared truth is a user-defined invariant (`kind: exec`) instead of a built-in one.

## What it proves

An AI agent was asked to configure eBGP peering between `r1` (AS 65001) and `r2` (AS 65002). The gate checks the AI's work against a human-authored contract — **the same way it would check a human's work** (Doctrine §1.12: no AI-privileged path).

- `passing/topology.yaml` — the AI got it right → session `Established` → **PASS**
- `failing/topology.yaml` — the AI fat-fingered one `remote_as` value → session never comes up → **FAIL**

## The boundary (read this)

Each topology file has two clearly-banner-marked regions:

- **[HUMAN-AUTHORED INTENT]** — the `tests:` block. The declared truth: *"on r1, the BGP peer to 10.0.0.2 must be Established."* It is **byte-identical** in both files (see `intent.md`).
- **[AI-GENERATED IMPLEMENTATION]** — the `nodes:` BGP config. The candidate the gate validates.

Because the intent is constant and only the AI implementation differs, the verdict difference is caused *solely* by the AI's implementation quality. That is the architectural point made visible.

## Commands

```bash
cassian test failing/topology.yaml     # run the failing variant first
cassian test passing/topology.yaml     # then the passing variant
```

Expected verdict difference:

- `failing/topology.yaml` → **FAIL** (existing non-zero validation exit code)
- `passing/topology.yaml` → **PASS** (exit 0)

## Note on labs and CI

`kind: exec` runs a read-only command on a live node, so `cassian test` here **deploys a containerlab lab**. Run these locally and **commit the produced evidence** (`labs/clab-*/results.json` + `results.summary.txt`), the same way `contrib/topologies/first-run-proof` commits its lab artifacts.

The lab-free CI harness (`tests/ai_change_reference_case_proof.py`) does **not** re-run this lab. It asserts this variant's **committed evidence** at the render boundary (verdict core consistent; the failing record renders both §13(c) halves). The **core variant works the same way** — its built-in invariant also needs a lab to generate evidence; what is lab-free is the harness's verification of committed evidence, not the invariant (REQ-4_9-6 corrected / B07: no lab in CI).

Authoritative artifact: `results.json`. Human-readable only: `results.summary.txt`.
