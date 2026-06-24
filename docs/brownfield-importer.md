# Brownfield Importer

The brownfield importer turns committed, offline source data about an existing
network into an **authoritative Cassian pair** — a `topology.yaml` plus a set of
starter invariants — that you can then validate, deploy, and gate like any other
Cassian topology.

It is invoked with [`cassian import`](cli-reference-v1.md):

```bash
cassian import path/to/siteA --out path/to/out
```

The importer is **fully offline**: it reads only files you provide, never a live
NetBox instance or live devices. It is **deterministic**: identical inputs always
produce byte-identical output.

## Source directory layout

`cassian import` reads a single source directory:

```text
siteA/
├── netbox_export.json        # the defined input contract (see below)
└── rendered/                 # optional: rendered FRR device configs
    ├── leaf1.conf
    └── spine1.conf
```

* `netbox_export.json` (required) — a JSON document in the contract described
  below.
* `rendered/*.conf` (optional) — rendered **FRR** configs, one per device, named
  for the device. When present they corroborate and supplement facts from the
  export (for example `router_id` and `asn`). `frr` is the only platform
  supported in this release; any other platform value is rejected.

## Input contract

!!! important "This is a defined contract, not a raw NetBox API dump"
    `netbox_export.json` is **Cassian's own input contract** — a small, flat,
    documented shape. It is **not** the output of NetBox's REST API. A real
    NetBox export is paginated, split across per-object-type endpoints
    (`/api/dcim/devices/`, `/api/ipam/ip-addresses/`, …), and nested with numeric
    IDs. Moreover, **BGP and static routes are not part of NetBox core** — BGP is
    provided by the separate `netbox-bgp` plugin, and static routes likewise are
    not a native core model. To feed a real NetBox, you run a thin export/transform
    step that produces this contract from the relevant API objects. Building and
    validating that adapter against a real instance is tracked on the roadmap
    below.

The contract is a single JSON object:

```json
{
  "site": { "name": "siteA" },
  "devices": [
    { "name": "leaf1",  "platform": "frr", "asn": 65001, "router_id": "1.1.1.1" },
    { "name": "spine1", "platform": "frr", "asn": 65002, "router_id": "2.2.2.2" }
  ],
  "cables": [
    {
      "a": { "device": "leaf1",  "interface": "eth1" },
      "b": { "device": "spine1", "interface": "eth1" },
      "a_ip": "10.0.0.1/30",
      "b_ip": "10.0.0.2/30"
    }
  ],
  "bgp_sessions": [
    { "local_device": "leaf1",  "peer_ip": "10.0.0.2", "remote_asn": 65002 },
    { "local_device": "spine1", "peer_ip": "10.0.0.1", "remote_asn": 65001 }
  ],
  "static_routes": [
    { "device": "leaf1", "prefix": "192.0.2.0/24" }
  ]
}
```

Field reference:

* `site.name` — the site / topology name.
* `devices[]` — `name` and `platform` (must be `frr`); `asn` and `router_id`
  optional (may instead be read from the rendered config).
* `cables[]` — each end is `{device, interface}` referencing a declared device;
  `a_ip` / `b_ip` are optional interface addresses. A cable that references an
  undeclared device is rejected.
* `bgp_sessions[]` — `local_device` (a declared device), `peer_ip`, and optional
  `remote_asn`.
* `static_routes[]` — `device` (a declared device) and `prefix`.

Only `devices` is structurally essential; the other lists may be empty or omitted
and the importer will simply generate fewer starter invariants.

## What it produces

The output directory receives the authoritative pair:

```text
out/
├── topology.yaml                 # authoritative topology, with embedded tests
└── tests/
    └── starter_invariants.yaml   # the generated starter invariants
```

Starter invariants are generated **only from explicitly declared facts**, using a
fixed allowlist — never inferred or synthesized:

* a `bgp_session` invariant for each declared BGP session,
* an `interface_state` invariant for each declared cable endpoint,
* a `route_present` invariant for each declared static route.

Anything the importer does not understand is **omitted**, not guessed at.

## Guarantees

* **Offline.** No network or live-device access; only the files you provide.
* **Deterministic.** Identical inputs produce byte-identical output; all source
  iteration is sorted and serialization is canonical.
* **No synthesis.** Invariants come only from declared facts via the allowlist.
* **Fail-closed.** Unsupported or malformed input is rejected with **exit 2** and
  an actionable message naming the offending field, the issue, and the corrective
  action. The importer never emits a partial or invalid pair.

## Status and roadmap

This is a first, lab-free importer. It has been validated against hand-built
fixtures, and the topologies it emits are checked against Cassian's real
validators. It has **not** yet been validated against data from a real NetBox
instance, and real-deployment validation (bringing the resulting topology up and
confirming the invariants against running devices) is out of scope for this
release.

Tracked for future work:

* **Real-NetBox export adapter** — a thin, documented step that produces this
  contract from a real NetBox (including BGP via the `netbox-bgp` plugin and
  static-route data), so the importer can consume real-world inventories.
* **Real-export validation** — exercise the full path against a real NetBox export
  and real rendered configs before any production reliance, to confirm the
  contract and field mapping hold against live data.
