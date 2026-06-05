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
| `ospf_neighbor_up` | OSPF | `src`, `neighbor` (IPv4 literal of the peer's router-ID); optional `state` (one of the 8 declarable FSM literals; default `Full`) |
| `interface_state` | Linux interface | `node`, `interface` (interface name as seen inside the node namespace, e.g. `eth1`); optional `state` (one of `up`, `down`; default `up` materialised at Resolve) |

Rules:

* `peer` fields MUST reference a node declared in `nodes:`; the engine's blast-radius validator rejects unknown node references with a hard-failure
* IPv4 literals (`dst` for `bgp_session_up`) bypass the node-name check and pass through verbatim
* `ospf_neighbor_up`'s `neighbor` field MUST be an IPv4 literal of the peer's OSPF router-ID (NOT a node name); the resolver's IPv4-literal validator hard-fails on non-IPv4 input. The `src` field MUST reference a node of `type: frr` declared in `nodes:` (FRR-only NOS-tag enforcement; non-FRR `src` is rejected at validation with a deterministic error)
* `interface_state`'s `interface` field MUST reference an interface present in the referenced node's resolved interface set (its link interfaces, `lo`, and any `interfaces:` declared on the node); a reference to an absent interface is rejected at validation time with a hard-failure (exit code `2`), parallel to the unknown-node reference rejection
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

### 4.8) `ospf_neighbor_up`

```json
{
  "expected_state": "<one of the 8 declarable FSM literals>",
  "last_error": "<string>",
  "neighbor": "<IPv4 literal of the peer's OSPF router-ID>",
  "source_node": "<node where the test runs>",
  "state": "<one of the 10 FSM-literal closed-set members>",
  "type": "ospf_neighbor_up"
}
```

* `neighbor` is the test's `neighbor` field, which is an IPv4 literal of the peer's OSPF router-ID. Unlike `bgp_session_up` (which aliases user-facing `neighbor` to the canonical `dst`), `ospf_neighbor_up` keeps `neighbor` as the canonical field name; there is no aliasing.
* `expected_state` is the test's declared `state` field (one of the 8 declarable FSM literals; default `Full` materialised at Resolve when the test omits the field, visible in `topology.resolved.yaml`).
* `state` reflects the OSPF neighbor FSM state for the configured peer, drawn from a closed set of 10 literal members. The 8 **declarable** literals (any of which may be supplied via the test record's `state` field) reflect FRR's standard OSPF FSM transitions:
  * `Down` — initial state; no Hellos seen yet, or the neighbor went unreachable.
  * `Attempt` — non-broadcast network (NBMA) only; sending Hellos to a configured neighbor that has not yet responded.
  * `Init` — Hellos received from the neighbor but two-way communication has not yet been confirmed (own router-id absent from neighbor's Hello neighbor list).
  * `2-Way` — bidirectional Hello exchange confirmed (own router-id present in neighbor's Hello neighbor list); on broadcast networks, only DR/BDR proceed beyond this state.
  * `ExStart` — beginning of database synchronization; routers negotiate master/slave roles and initial sequence number.
  * `Exchange` — exchanging database description (DBD) packets summarizing each router's link-state database contents.
  * `Loading` — sending link-state requests for any link-state advertisements (LSAs) the neighbor advertised but the local router does not yet have.
  * `Full` — full adjacency formed; link-state databases synchronized; the neighbor is included in the local SPF computation. This is the steady-state value for a healthy OSPF adjacency.
  The 2 **observed-only** literals (engine-synthesized; never declared in test records) signal the diagnostic shape of the failure:
  * `NotConfigured` — vtysh succeeded but the queried neighbor is not present in FRR's `show ip ospf neighbor json` output (e.g. Hellos rejected upstream due to area mismatch, network mismatch, or no OSPF activation on the link interface).
  * `Unknown` — vtysh failed, vtysh output cannot be parsed as JSON, or FRR returned an `nbrState` literal outside the 8 declarable members.
* `last_error` is empty string `""` on the predicate-mismatch path (vtysh succeeded, JSON parsed, neighbor present, but observed FSM state does not match the declared `expected_state`); otherwise one of a closed set of engine-synthesized deterministic literal strings on the diagnostic paths: `"neighbor not present in ospf neighbor table"` when the queried neighbor's router-ID is not a key in FRR's neighbor dictionary; `"ospf neighbor table empty"` when FRR returned a neighbors dictionary that is structurally empty; `"vtysh command failed"` when the vtysh invocation returns a non-zero exit; `"vtysh output not parseable as JSON"` when vtysh succeeds but its output is not valid JSON; `"neighbor missing or invalid (expected non-empty IPv4 router-id literal)"` when the test record's `neighbor` field is absent or not an IPv4 literal (defensive validation at dispatch); `"src missing or empty"` when the test record's source node is absent or empty (defensive validation at dispatch).
* The runtime evaluator strips role-qualifier suffixes from FRR's `nbrState` field before mapping to the closed set: literals like `Full/DR`, `Full/Backup`, `Full/DROther`, `2-Way/DROther` are split on `/` and the leading FSM literal is used.

The retry loop driving `expect: pass` evaluation uses LD-4 defaults: `timeout_s=60`, `retry_interval_s=1.0` (seconds). Both values may be overridden per-test via the test record's `timeout_s` and `retry_interval_s` fields. For `expect: fail`, evaluation is single-attempt (no retry).

The test record additionally carries a `meta` audit-trail dict on every record (PASS or FAIL), with eight keys: `type`, `neighbor`, `expected_state`, `state`, `attempts`, `timeout_s`, `retry_interval_s`, `last_rc`. The `meta` dict is a sibling field of `observed_state` and is NOT subject to the FAIL-only emission gate; it is present on PASS records as well.

OSPF topology declaration (companion schema): each FRR node in the topology may declare an `ospf:` block carrying `area:` (integer ≥ 0, required) and `networks:` (non-empty list of canonical IPv4 CIDR strings, required); no other keys are accepted (Unknown-Key Strictness; timer customization keys such as `hello-interval`, `dead-interval`, `spf-delay` are out of scope and rejected). Declaring `ospf:` requires the node also declare a top-level `router_id` (single-area-per-node only — multi-area is out of scope).

---

### 4.9) `interface_state`

```json
{
  "admin_state": "<one of: up, down, unknown>",
  "carrier": "<one of: present, absent, unknown>",
  "expected_state": "<one of: up, down>",
  "interface": "<interface name, e.g. eth1>",
  "last_error": "<string>",
  "operstate": "<one of the 7 RFC 2863 closed-set literals>",
  "source_node": "<node where the test runs>",
  "type": "interface_state"
}
```

* `interface` is the test's `interface` field, which is the interface name as seen inside the node's network namespace (e.g. `eth1`). Unlike OSPF (`neighbor` is an IPv4 router-ID), this is an OS-level interface identifier.
* `expected_state` is the test's declared `state` field (one of `up` or `down`; default `up` materialised at Resolve when the test omits the field, visible in `topology.resolved.yaml`).
* `source_node` is the user-facing `node` field as declared in the test record; the resolver aliases user-facing `node` to the internal `src` field, and the rendered `source_node` reflects the user-facing value.
* `admin_state` reflects the kernel's administrative interface flag (the presence of the `UP` flag in `ip -j link show <iface>` JSON output), drawn from the closed set `{up, down, unknown}`. `unknown` appears only on diagnostic paths where probe succeeded but flag extraction did not produce a definitive value.
* `operstate` reflects the kernel's operational interface state, drawn from a closed set of 7 RFC 2863 literals: `UP`, `DOWN`, `UNKNOWN`, `LOWERLAYERDOWN`, `NOTPRESENT`, `TESTING`, `DORMANT`. Any value outside this set is mapped to `UNKNOWN` AND triggers `last_error: "ip output structurally unexpected"`.
* `carrier` reflects the kernel's link-layer carrier signal (the presence of the `LOWER_UP` flag in `ip -j link show <iface>` JSON output), drawn from the closed set `{present, absent, unknown}`. `carrier` is reported in `observed_state` for operator diagnosis but does NOT participate in the verdict predicate (see asymmetry note below).
* `last_error` is empty string `""` on the predicate-mismatch path (probe succeeded, JSON parsed, interface present, but observed `admin_state`/`operstate` did not match the declared `expected_state`); otherwise one of a closed set of engine-synthesized deterministic literal strings on the diagnostic paths: `"ip -j flag not supported by node's iproute2"` when the node's `ip` binary does not support the `-j` JSON flag (typically BusyBox `ip`; see iproute2 capability dependency below); `"interface not present"` when `ip` exits non-zero with stderr indicating the interface does not exist; `"ip command failed"` when `ip` exits non-zero for other reasons (permission, namespace error, etc.); `"ip output not parseable as JSON"` when `ip` exits zero but stdout is not valid JSON; `"ip output structurally unexpected"` when the parsed JSON shape is not a list of one dict OR `operstate` is outside the 7-literal closed set; `"interface field missing or empty"` and `"node field missing or empty"` when the dispatch-time defensive checks fire (Resolve enforces both fields; these defensive paths exist for future-regression resilience).

The verdict predicate is **asymmetric** between the two declarable states:

* `state: up` requires `admin_state == "up"` AND `operstate == "UP"` (conjunction; both must hold).
* `state: down` requires `admin_state == "down"` OR `operstate != "UP"` (disjunction; either suffices).

The asymmetry reflects an operator-correctness principle: a confidently-up interface requires both administrative and operational confirmation, while a confidently-down interface need only fail either confirmation. `carrier` is orthogonal to both predicates and is reported in `observed_state` for diagnostic clarity (an admin-up interface with `carrier: absent` is a meaningful operator signal even when the verdict resolves to `pass` via the `state: up` conjunction failing).

The retry loop driving `expect: pass` evaluation uses LD-2 defaults: `timeout_s=10`, `retry_interval_s=0.5` (seconds). Both values may be overridden per-test via the test record's `timeout_s` and `retry_interval_s` fields. For `expect: fail`, evaluation is single-attempt (no retry).

The test record additionally carries a `meta` audit-trail dict on every record (PASS or FAIL), with seven keys: `type`, `interface`, `expected_state`, `attempts`, `timeout_s`, `retry_interval_s`, `last_rc`. The `meta` dict is a sibling field of `observed_state` and is NOT subject to the FAIL-only emission gate; it is present on PASS records as well. Note that `meta` does NOT carry a `state` key — operators read the three orthogonal axes `admin_state`, `operstate`, `carrier` from the FAIL record's `observed_state` instead.

iproute2 capability dependency (companion schema constraint): the runtime probe uses `ip -j link show <iface>` and requires an `ip` binary that supports the `-j` JSON flag. BusyBox `ip` (the default in `alpine:latest`, which is the engine's default image for `host` and `nft-fw` node types) does NOT support `-j` and produces non-JSON help-text output on the unrecognized flag. Topologies exercising `interface_state` on `host` or `nft-fw` nodes MUST pin an image with full iproute2 (e.g. `nicolaka/netshoot:v0.15`) explicitly in the node declaration. FRR's default image (`frrouting/frr:latest`) already includes full iproute2 and requires no override. The engine performs a per-(lab, node) capability probe at first use; on capability-probe failure, the per-test record fails with `last_error: "ip -j flag not supported by node's iproute2"` and the operator is directed to pin a compatible image.

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

When a failed-invariant record's `observed_state` is absent or non-dict, the present `observed:` block above cannot be rendered; the renderer then emits an explicit **absence indicator** in its place — never silence — so a failed invariant always surfaces an `observed:` block in one of two forms (present payload block, or absence indicator). The absence indicator uses the same `observed:` header at 4-space indent with 6-space `<key>: <value>` lines, carrying, in order: `type:` (the specific invariant type), `target:` (the invariant's source node plus its declaration-derived locator, e.g. `peer=` / `prefix=` / `neighbor=`), `expected:` (the declared expectation), and a literal `detail: (structured failure detail unavailable for this invariant type)` line. Per the §3.2 determinism contract, only declared and declaration-derived locator fields enter `target:`; runtime-variant tokens are excluded, so the indicator is byte-stable across runs.

`results.summary.txt` is human-only and non-authoritative. The structured `observed_state` in `results.json` is the authoritative artifact.

---

## 6) Suppression Rules

The present `observed:` payload block is NEVER rendered on:

* passing-invariant records (`verdict == "pass"`)
* non-invariant test kinds (`ping`, `tcp`, `bgp_neighbor`)
* `prereq` failure paths (those surface as `hard_failure:` in the summary, not as `failed_tests:` entries)

The above rules guarantee that v1.x topologies exercising only `ping` / `tcp` / `bgp_neighbor` produce `results.summary.txt` byte-identical to pre-v1.5 output.

A failed-invariant record with a missing or non-dict `observed_state` field (defensive — should not occur in normal runs) is NOT a suppression case: the present payload block is omitted, but the explicit absence indicator (§5) renders in its place, so a failed invariant never produces a silent `observed:`-less line.

---

## 7) Cross-references

* The supported invariant evaluator dispatch is implemented in `cassian_engine.py` `run_invariant_test`.
* The summary rendering is implemented in `cassian_tests.py` `_format_test_summary` and its `_format_observed_state_*` helpers.
* The truncation discipline is implemented in `cassian_engine.py` `_observed_state_finalize_in_results` and `_observed_state_truncate`.
* The negative-case proof topology exercising one invariant per category lives at `topologies/neg/h2_invariant_observability_demo.yaml`.
* The synthetic large-payload truncation fixture lives at `topologies/neg/h2_truncation_proof.yaml`.
* The positive proof topology exercising `ospf_neighbor_up` end-to-end (area 0 mutual, expect: pass) lives at `topologies/ospf_neighbor_up.yaml`.
* The negative proof topology demonstrating the mismatched-area FAIL pathology and the deterministic six-key `observed_state` payload lives at `topologies/neg/ospf_neighbor_up_mismatched_area.yaml`.

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
