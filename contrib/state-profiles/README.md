# State Profiles

This directory contains supporting state-capture profile content.

State profiles are secondary adoption content.
They do not replace failure-demonstrating examples, the official first-run proof family, or the recipe bridge.

## frr-routing-basic

Captures the IPv4 and IPv6 routing tables from the FRR zebra daemon via `vtysh -c "show ip route json"` and `vtysh -c "show ipv6 route json"`. Use this profile when debugging missing routes, unexpected next-hops, ECMP behaviour, or protocol-source attribution in the RIB; the runtime FRR node must have at least one routing protocol installing routes (BGP, OSPF, or static) for captures to contain meaningful entries.

## frr-bgp-basic

Captures BGP control-plane state from the FRR bgpd daemon via `vtysh -c "show bgp summary json"`, `vtysh -c "show bgp neighbors json"`, and `vtysh -c "show bgp ipv4 unicast json"`. Use this profile when debugging BGP session establishment, neighbor capability negotiation, policy outcomes, or IPv4-unicast prefix advertisement and reception; the runtime FRR node must have BGP configured with at least one declared neighbor for captures to contain meaningful entries.

## frr-ospf-basic

Captures OSPFv2 control-plane state from the FRR ospfd daemon via `vtysh -c "show ip ospf neighbor json"`, `vtysh -c "show ip ospf interface json"`, and `vtysh -c "show ip ospf database json"`. Use this profile when debugging OSPF neighbor adjacency state, per-interface OSPF posture, or link-state database content; the runtime FRR node must declare an `ospf:` block (topology-schema-v1 §3.1 / topology-schema-v1.5 §4.8) for ospfd to be enabled and captures to contain meaningful entries.

## frr-interfaces-basic

Captures interface administrative and operational state from the FRR node's network namespace using the Linux iproute2 primitives `ip -j link show` and `ip -j addr show` (not vtysh). Use this profile when debugging interface admin/operational state, link-layer attributes (MAC, MTU, master/slave bridging), or per-interface IPv4/IPv6 addressing as seen by the kernel; this is the NOS-agnostic substrate that pairs naturally with the `interface_state` invariant. The FRR container image's iproute2 must support the `-j` JSON flag (engine default suffices).

## frr-comprehensive

Aggregates the routing, BGP, OSPF, and interface diagnostic surfaces of `frr-routing-basic`, `frr-bgp-basic`, `frr-ospf-basic`, and `frr-interfaces-basic` into a single 10-command capture. Use this profile when the specific FRR failure domain is unknown and you want a broad snapshot — incident triage, post-mortem evidence, AI advisory consumption — at the cost of larger captured artifacts. OSPF commands are included unconditionally; on non-OSPF topologies they produce empty or daemon-not-running output recorded non-fatally without affecting verdicts.

## Non-authoritative boundary

State profiles are explicitly non-authoritative.

They may support evidence collection.
They do not:

- determine pass/fail
- change exit codes
- replace `results.json`
- become a separate authority source

Use them only as supporting evidence within existing current engine behavior.
