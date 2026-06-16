# The AI-change reference case

An AI coding assistant can propose a network change, open a pull request, and have it merged — sometimes faster than a human reviewer can read it. Cassian Gate's answer to that is deliberately unremarkable: an AI-authored change is validated by exactly the same gate as a human-authored one. There is no separate path for "AI changes," no provenance score, no trust dial. The verdict is reached the only way the gate ever reaches a verdict — by executing the declared scenario on clean-state runtime and binding the result to a declared expectation. (See [Scope and scale discipline](../scope-discipline.md): in Cassian Gate, AI never holds verdict authority.)

This page walks the canonical reference case that demonstrates that property. The example ships in the repository under `contrib/topologies/ai-change-reference-case/`.

## The shape

The reference case is two small BGP topologies, each in a `passing/` and a `failing/` form, with the gate's own as-shipped evidence committed alongside them:

- **`core-builtin-bgp/`** asserts a built-in invariant — `bgp_session_up` — that the session between two routers establishes.
- **`udi-bgp-variant/`** asserts a [user-defined `exec` invariant](exec-user-defined-invariants.md) — that a specific route is present in a peer's table.

In both variants the *passing* form is a correct change and the *failing* form is a realistic mistake of the kind an assistant might introduce. Nothing about the topology tells the gate who wrote it.

## Two ways a change fails — and neither passes silently

The two failing forms are chosen to show the two shapes a gate failure takes, because a gate is only as trustworthy as its weakest "looks fine to me."

**The session that never comes up.** In `core-builtin-bgp/failing/`, the change carries a mismatched autonomous-system number, so the BGP session never converges. The gate's control-plane precheck catches this before the invariant runs: the invariant is *blocked*, and the run is an authoritative **FAIL** that says so — `observed: blocked`, with an explicit note that structured detail is unavailable for a check that never got to execute. The point is what does *not* happen: the gate does not shrug and report success because nothing ran. Silence is not a pass.

**The session that comes up missing a route.** In `udi-bgp-variant/failing/`, the change is subtler — the session is healthy, but the router never advertises the prefix it was supposed to. Here the `exec` invariant *does* execute: it runs a read-only `show bgp ipv4 unicast 1.1.1.1/32 json` on the peer, observes an empty table, and **FAILs with the observed state rendered** — the command, the return code, and the empty output that proves the route is absent.

One failure renders an explicit "couldn't observe"; the other renders exactly what it observed. Both are bound to the same declared expectation (`expect: pass`), and both fail the gate.

## What the reference case does *not* claim

It is worth being precise about the boundary this case draws, because "AI safety" invites overclaiming:

- The gate does **not** detect that a change was authored by an AI. There is no provenance field, no origin flag, no special handling — and the included proof harness checks the engine source to keep it that way.
- The gate does **not** score, rank, or rate AI changes. A change is correct or it is not, and that is decided by execution.
- AI holds **no** verdict authority. It can propose the change and even draft the invariants; the PASS/FAIL is still produced by running the declared scenario. (This is the same boundary described for autonomous operations and agentic platforms in [Scope and scale discipline](../scope-discipline.md).)

In other words, the reference case is not a new capability bolted on for AI. It is a demonstration that the gate's existing commitment — execute the change, observe the result, bind it to a declared expectation — already does the right thing when the author happens to be a machine.

## Try it

From a checkout, run either variant the same way you would run any topology:

```bash
cassian test contrib/topologies/ai-change-reference-case/udi-bgp-variant/passing/topology.yaml   # PASS
cassian test contrib/topologies/ai-change-reference-case/udi-bgp-variant/failing/topology.yaml   # FAIL (route absent)
```

The committed `evidence/` directory next to each topology holds the gate's own `results.json` and human-readable summary from a real run, so you can read the exact verdict surface without standing up a lab. The behaviour above is pinned by a lab-free proof harness, `tests/ai_change_reference_case_proof.py`, which runs in CI on every change.

## See also

- [Scope and scale discipline](../scope-discipline.md) — where AI sits relative to the gate's authority
- [Project principles](../project-principles.md) — the gate's full authority boundary
- [Writing a user-defined invariant (`exec`)](exec-user-defined-invariants.md) — the mechanics behind the UDI variant
