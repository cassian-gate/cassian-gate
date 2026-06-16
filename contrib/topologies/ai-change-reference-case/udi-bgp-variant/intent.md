# Intent (human-authored)

**This is the contract the AI implementation must satisfy. A human wrote it. It does not change between the passing and failing variants.**

In plain terms:

> On `r1`, the eBGP session to its neighbor `r2` (`10.0.0.2`) must reach the `Established` state.

Declared, authoritatively, as a user-defined invariant (`kind: exec`) that the gate evaluates:

```yaml
- name: r1_bgp_peer_r2_established
  kind: exec
  src: r1
  command: vtysh -c "show bgp summary json"
  assertion:
    field:
      path: [ipv4Unicast, peers, "10.0.0.2", state]
      op: "=="
      value: Established
  expect: pass
```

Read aloud: run `show bgp summary json` on `r1`, walk into `ipv4Unicast → peers → 10.0.0.2 → state`, and require it to equal `Established`.

This exact `tests:` block is carried **byte-identically** into both `passing/topology.yaml` and `failing/topology.yaml`. The only thing that differs between the two files is the **AI-generated implementation** (the BGP configuration). The verdict therefore depends solely on the quality of the AI's implementation against a fixed human contract — which is the whole point (Doctrine §1.12: no AI-privileged path).
