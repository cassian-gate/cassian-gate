---

# Cassian Gate v1.5 Topology Schema Guide — Invariant Tests and observed_state

**Version:** v1.5
**Status:** STABLE (Phase 1a Handover 2 onward)
**Scope:** Invariant test category, supported invariant types, and `observed_state` failure-payload contract
**Audience:** Engineers authoring Cassian Gate topologies that exercise routing, BGP, or EVPN behavior

This document is the v1.5 companion to `docs/topology-schema-v1.md`. It documents the additional surface that `docs/topology-schema-v1.md` §8 explicitly defers to v1.5+: the `kind: invariant` test category, the supported invariant types, and the structured `observed_state` payload that every failed invariant test record carries.

The v1 contract (`ping`, `tcp`, `bgp_neighbor`) is unchanged. Everything in this document is additive on top of v1.

This is a **schema guide**, not a tutorial and not a routing reference.

---

## 1) The `kind: invariant` Test Category

Cassian Gate v1.5 introduces a `kind:` discriminator on test records. The v1.x test types (`ping`, `tcp`, `bgp_neighbor`) continue to be addressed via the `type:` field; v1.5 adds a `kind: invariant` category that addresses control-plane truths beyond raw L3/L4 reachability.

```yaml
tests:
  - name: leaf1_evpn_session_to_spine1
    kind: invariant
    type: evpn_bgp_session_up
    node: leaf1
    peer: spine1
    expect: pass
```

Rules:

* a test with `kind: invariant` MUST also declare `type:` set to one of the supported invariant types listed in §2
* `kind: invariant` and the v1.x test types (`ping`, `tcp`, `bgp_neighbor`) are mutually exclusive on a given test record
* every invariant test MUST declare `expect:` (`pass` or `fail`); the engine's verdict for each test is computed from `observed` versus `expected`, exactly as for v1.x test types
* invariant tests run after the v1.x prerequisite phases (`Resolve` → `Generate` → `Deploy` → `Provision`); they execute during the `Test` phase
* the `kind:` discriminator is required because the `type:` namespace overlaps with v1.x test types only up to the ordinary disambiguation rule (`kind: invariant` selects the invariant evaluator dispatch path)

---

## 2) Supported Invariant Types

v1.5 supports the following invariant types. Each type maps to a single deterministic evaluator inside the Cassian Gate engine.

| Type | Category | Required fields (in addition to `kind`, `type`, `name`, `expect`) |
|---|---|---|
| `bgp_session_up` | BGP session | `node`, `neighbor` (IPv4 literal of the BGP neighbor; canonical alias `dst` accepted) |
| `evpn_bgp_session_up` | BGP session | `node`, `peer` (a known node name) |
| `route_present` | Route | `node`, `prefix` (CIDR) |
| `route_absent` | Route | `node`, `prefix` (CIDR) |
| `route_advertised_to` | BGP policy | `node`, `peer` (a known node name), `prefix` (CIDR) |
| `route_not_advertised_to` | BGP policy | `node`, `peer` (a known node name), `prefix` (CIDR) |
| `bgp_med_equals` | BGP policy | `node`, `prefix` (CIDR), `expected` (integer) |
| `bgp_localpref_equals` | BGP policy | `node`, `prefix` (CIDR), `expected` (integer) |
| `evpn_vni_route_present` | EVPN | `node`, `vni` (integer) |
| `evpn_mac_route_present` | EVPN | `node`, `mac` (canonical MAC literal), `vni` (integer) |
| `evpn_mac_route_absent` | EVPN | `node`, `mac` (canonical MAC literal), `vni` (integer) |

Rules:

* `peer` fields MUST reference a node declared in `nodes:`; the engine's blast-radius validator rejects unknown node references with a hard-failure
* IPv4 literals (`dst` for `bgp_session_up`) bypass the node-name check and pass through verbatim
* `prefix` fields MUST be canonical IPv4 CIDR notation (e.g. `10.0.0.0/24`); non-canonical values are rejected at validation time
* `mac` fields MUST be canonical lowercase colon-separated form (e.g. `00:11:22:33:44:55`)
* `vni` MUST be a positive integer matching a VNI declared in the topology's `vlans:` map
* `route_absent` and `route_not_advertised_to` and `evpn_mac_route_absent` are the negative complements of their `_present` / `_advertised_to` peers; the verdict semantics flip accordingly (`expect: pass` means the route IS NOT present / IS NOT advertised / IS NOT in the EVPN MAC table)

---

## 3) Failure Verdicts and `observed_state`

Every invariant test record that resolves to `verdict: fail` carries a structured `observed_state` payload alongside the existing `observed` string field. The `observed_state` payload is the **deterministic** structured failure-reason artifact.

This payload is added in v1.5 and is the basis of `results.summary.txt`'s `observed:` block under each failed-invariant line.

### 3.1) Where `observed_state` appears

* On records in `results["tests"]` whose `kind == "invariant"` AND `verdict == "fail"`.
* On records in `results["events"]` whose `type == "scenario_test_run"` AND `kind == "invariant"` AND `verdict == "fail"`.
* It does NOT appear on passing-invariant records, on non-invariant test kinds (`ping`, `tcp`, `bgp_neighbor`), on `prereq` failure paths, or on records whose `verdict` is anything other than `fail`.

The presence and absence of `observed_state` is byte-stable across runs given identical input and identical control-plane state.

### 3.2) Determinism contract

Every value in `observed_state` is derived from one of:

* a declared input field of the test (e.g. `prefix`, `peer`, `mac`, `vni`)
* a declared input field of the topology (e.g. host node MAC literals)
* a deterministically-computable scalar from parsed `vtysh` JSON (e.g. BGP session state strings)
* an engine-synthesized deterministic literal string from a closed, documented set (e.g. the `bgp_session_up` evaluator's `state` literals `NotConfigured` / `Unknown` and its `last_error` diagnostic literals; see §4.1)

Environmental nondeterminism (host clock timestamps, container IDs, runtime PIDs, hostnames-of-the-runner, containerlab-allocated veth MAC addresses) MUST NOT enter `observed_state`. Such tokens MAY appear in the existing supporting `evidence` channel, which is explicit non-authoritative supporting evidence and tolerates non-determinism.

In particular, EVPN MAC route lists in `observed_state.evpn_routes` are filtered to MAC literals declared in the topology's host nodes; any environmentally-allocated MAC entries are excluded from `observed_state` (they remain in the `evidence` channel).

### 3.3) Truncation discipline

A single invariant record's `observed_state` payload is bounded by an 8192-byte canonical-JSON ceiling. When a payload would exceed this ceiling, the engine deterministically suffix-drops trailing entries from the longest list field (alphabetical key tie-break) until the payload fits. When truncation occurs, the engine sets `observed_state_truncated: true` on the record. The summary renderer responds by emitting a literal trailing line (`(observed_state truncated; full payload in results.json)`) at 6-space indent in the `observed:` block. The full pre-truncation list remains derivable from the supporting `evidence` channel of the same record.

The 8192-byte ceiling is per-record. Multiple failing invariants in one run each receive their own ceiling.

---

## 4) `observed_state` Schema Per Invariant Type

Every key listed below is REQUIRED on the failed-invariant record's `observed_state`. Keys are documented in canonical-sorted order matching the on-disk JSON.

### 4.1) `bgp_session_up`

```json
{
  "last_error": "<string>",
  "peer": "<IPv4 literal of the configured neighbor>",
  "source_node": "<node where the test runs>",
  "state": "<BGP FSM state string, or 'Unknown' when no neighbor entry exists>",
  "type": "bgp_session_up"
}
```

* `peer` is the test's `dst` field, which is required to be an IPv4 literal. Operators write the user-facing form `neighbor:` (the natural BGP vocabulary); the resolver aliases `neighbor:` to the canonical `dst:` at Resolve, hard-failing if both are declared with disagreeing values.
* `state` reflects the FRR BGP FSM state for the configured neighbor (`Idle`, `Active`, `Connect`, `OpenSent`, `OpenConfirm`, `Established`); the literal `NotConfigured` when vtysh succeeds but the queried peer is not present in FRR's BGP summary; or the literal `Unknown` when vtysh fails, vtysh output cannot be parsed as JSON, or the test's `dst`/`src` input is missing or invalid.
* `last_error` carries the neighbor's `lastResetReason` from FRR when present, or one of a closed set of engine-synthesized deterministic literal strings on the diagnostic paths: `"neighbor not present in summary"` when the queried peer is absent from FRR's BGP summary, `"peers not found in summary"` when FRR's BGP summary contains no peer dictionary at any expected key, `"vtysh command failed"` when the vtysh invocation returns a non-zero exit, `"vtysh output not parseable as JSON"` when vtysh succeeds but its output is not valid JSON, `"dst missing or invalid (expected non-empty IPv4 literal)"` when the test record's `dst` field is absent or not an IPv4 literal, or `"src missing or empty"` when the test record's source node is absent or empty. Empty string when none of these conditions applies.

### 4.2) `evpn_bgp_session_up`

```json
{
  "last_reset_reason": "<string>",
  "peer": "<node name>",
  "source_node": "<node where the test runs>",
  "state": "<BGP EVPN FSM state string, or 'Unknown'>",
  "type": "evpn_bgp_session_up"
}
```

* `peer` is the test's `peer` field, a known node name.
* `state` reflects the EVPN-AFI BGP session state.
* `last_reset_reason` carries the most recent reset reason from FRR.

### 4.3) `route_present` and `route_absent`

```json
{
  "prefix": "<CIDR>",
  "routes": [
    {
      "next_hop": "<IPv4>",
      "prefix": "<CIDR>",
      "protocol": "<bgp|connected|static|...>"
    }
  ],
  "source_node": "<node where the test runs>",
  "type": "route_present"
}
```

* `routes` is the deterministic list of route entries observed in the source node's IPv4 routing table that match the queried `prefix`. Empty list `[]` is the explicit empty-set form (R22) when no matching route exists.
* `route_absent` payloads use `"type": "route_absent"`; otherwise the schema is identical.

### 4.4) `route_advertised_to` and `route_not_advertised_to`

```json
{
  "advertised_routes": [
    {
      "as_path": "<string>",
      "metric": <int|null>,
      "next_hop": "<IPv4>",
      "prefix": "<CIDR>",
      "protocol": "<string>"
    }
  ],
  "none_advertised": <bool>,
  "peer": "<node name>",
  "prefix": "<CIDR>",
  "source_node": "<node where the test runs>",
  "type": "route_advertised_to"
}
```

* `advertised_routes` is the full deterministic list of prefixes the source node advertises to the named peer. Each entry includes the queried prefix or any other prefix actually being advertised (the diagnostic intent is to show the operator the actual advertised set when the queried prefix is not in it).
* `none_advertised` is `true` when the advertised list is empty, `false` otherwise. This is a redundant boolean for ergonomic summary reading.
* `route_not_advertised_to` payloads use `"type": "route_not_advertised_to"`; otherwise the schema is identical.

### 4.5) `bgp_med_equals` and `bgp_localpref_equals`

```json
{
  "actual": <int|null>,
  "expected": <int>,
  "peer": "<string, or empty when undeclared>",
  "prefix": "<CIDR>",
  "source_node": "<node where the test runs>",
  "type": "bgp_med_equals"
}
```

* `actual` is the integer value observed in the BGP route entry, or `null` when the prefix is not in BGP.
* `expected` is the test's declared `expected` field.
* `peer` carries the test's `peer` if declared; empty string otherwise.
* `bgp_localpref_equals` payloads use `"type": "bgp_localpref_equals"`; otherwise the schema is identical.

### 4.6) `evpn_vni_route_present`

```json
{
  "evpn_routes": [
    {
      "mac": "<MAC literal>",
      "prefix": "<string, often empty>",
      "rd": "<string, often empty>",
      "route_type": <int|string>,
      "vni": <int>
    }
  ],
  "source_node": "<node where the test runs>",
  "type": "evpn_vni_route_present",
  "vni": <int>
}
```

* `evpn_routes` is the deterministic list of EVPN type-2 / type-5 routes observed for the queried `vni`, filtered to MAC literals declared in the topology's host nodes.
* The `route_type` field may appear as either integer `2` or string `"2"` due to FRR's vtysh JSON output normalization; both forms are deterministic and pre-existing in the engine's evidence dedup.

### 4.7) `evpn_mac_route_present` and `evpn_mac_route_absent`

```json
{
  "evpn_routes": [
    {
      "mac": "<MAC literal>",
      "prefix": "<string, often empty>",
      "rd": "<string, often empty>",
      "route_type": <int|string>,
      "vni": <int>
    }
  ],
  "mac": "<queried MAC literal>",
  "source_node": "<node where the test runs>",
  "type": "evpn_mac_route_present",
  "vni": <int>
}
```

* `mac` is the test's queried MAC literal (lowercased canonical form).
* `vni` is the test's queried VNI.
* `evpn_routes` is filtered identically to §4.6 (declared host MACs only).
* `evpn_mac_route_absent` payloads use `"type": "evpn_mac_route_absent"`; otherwise the schema is identical.

---

## 5) Summary Rendering

A failed-invariant record's `observed_state` is rendered by the summary renderer as a multi-line `observed:` block immediately under the failed-test line in `results.summary.txt`. The rendering is deterministic and indentation-fixed.

Rendering rules:

* the block header (`observed:`) is at 4-space indent
* each `<key>: <value>` line is at 6-space indent in canonical-sorted key order
* list-bearing keys (`routes`, `advertised_routes`, `evpn_routes`) render multi-line at 8-space indent
* lists render up to 5 entries with a trailing `(+<N> more)` line at 8-space indent when the source list exceeds the cap
* empty lists render inline as `[]`
* when `observed_state_truncated: true`, the renderer emits the trailing line `(observed_state truncated; full payload in results.json)` at 6-space indent (the post-truncation list cap and the truncation marker line can co-occur)

`results.summary.txt` is human-only and non-authoritative. The structured `observed_state` in `results.json` is the authoritative artifact.

---

## 6) Suppression Rules

The `observed:` block is NEVER rendered on:

* passing-invariant records (`verdict == "pass"`)
* non-invariant test kinds (`ping`, `tcp`, `bgp_neighbor`)
* `prereq` failure paths (those surface as `hard_failure:` in the summary, not as `failed_tests:` entries)
* records with a missing or non-dict `observed_state` field (defensive — should not occur in normal runs)

The above rules guarantee that v1.x topologies exercising only `ping` / `tcp` / `bgp_neighbor` produce `results.summary.txt` byte-identical to pre-v1.5 output.

---

## 7) Cross-references

* The supported invariant evaluator dispatch is implemented in `cassian_engine.py` `run_invariant_test`.
* The summary rendering is implemented in `cassian_tests.py` `_format_test_summary` and its `_format_observed_state_*` helpers.
* The truncation discipline is implemented in `cassian_engine.py` `_observed_state_finalize_in_results` and `_observed_state_truncate`.
* The negative-case proof topology exercising one invariant per category lives at `topologies/neg/h2_invariant_observability_demo.yaml`.
* The synthetic large-payload truncation fixture lives at `topologies/neg/h2_truncation_proof.yaml`.

---

## 8) What This Schema Guide Does NOT Do

This document does not:

* enumerate every BGP / EVPN protocol semantic — those are FRR's responsibility
* document scenario actions or fault choreography (see `docs/topology-schema-v1.md` §6)
* document the v1.x test types (`ping`, `tcp`, `bgp_neighbor`) — those remain in `docs/topology-schema-v1.md`
* document Cassian Gate's CLI — see `cassian --help`

---

**End of Cassian Gate v1.5 Topology Schema Guide — Invariant Tests and observed_state**

---
