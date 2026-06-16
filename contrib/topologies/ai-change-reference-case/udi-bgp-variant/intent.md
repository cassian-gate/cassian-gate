# Intent (human-authored) — bonus variant (user-defined invariant, detection story)

**The contract the AI implementation must satisfy. A human wrote it. Identical in the passing and failing variants.**

In plain terms:

> `r2` must learn the route `1.1.1.1/32` (r1's loopback) over BGP.

Declared as a **user-defined** invariant (`kind: exec`) that the gate evaluates by reading live route state on r2:

```yaml
- name: r2_learns_route_1_1_1_1_32
  kind: exec
  src: r2
  command: vtysh -c "show bgp ipv4 unicast 1.1.1.1/32 json"
  assertion:
    contains: "1.1.1.1/32"
  expect: pass
```

Read aloud: on `r2`, run `show bgp ipv4 unicast 1.1.1.1/32 json`; the route must be present.

This `tests:` block is carried **byte-identically** into both `passing/` and `failing/`. Only the **AI-generated implementation** (whether r1 advertises the route) differs — Doctrine §1.12, no AI-privileged path.

## Why this variant produces the present-half

The peering is configured correctly in **both** variants, so the eBGP session **converges**. That means the gate's control-plane precheck passes and the `exec` invariant actually **runs**: it reads r2's BGP table and either finds the route (PASS) or finds it absent and reports the observed (empty) state (FAIL). This is the **present-half** of the failed-invariant surface — the gate observes the bad state and renders it — complementing the core variant's blocked/absent-half story.

## Lab/CI model

`exec` runs a command on a live node, so generating the evidence **requires a deployed lab**. Run `cassian test` locally and **commit the evidence**. The CI harness verifies the committed evidence lab-free; it never re-runs the lab (REQ-4_9-6 corrected / B07: no lab in CI).

## One thing to confirm at evidence generation
The `contains: "1.1.1.1/32"` assertion matches the prefix string in the `show bgp ipv4 unicast … json` output. When you run it on a real FRR lab, confirm the present output contains `1.1.1.1/32` and the absent output is empty (`{}`); if you prefer a structured check, swap to `field: { path: [prefix], op: "==", value: "1.1.1.1/32" }` after verifying FRR's exact JSON shape.
