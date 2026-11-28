# Brownfield Importer

The brownfield importer turns committed, offline source data about an existing
network into an **authoritative Cassian pair** — a `topology.yaml` plus a set of
starter invariants — that you can then validate, deploy, and gate like any other
Cassian topology.

It is invoked with [`cassian import`](cli-reference-v1.md), with one of two
backends:

```bash
cassian import path/to/siteA --out path/to/out                          # netbox: Cassian's contract
cassian import path/to/bundle --out path/to/out --backend netbox-dump   # netbox-dump: a NetBox dump bundle
```

* **`netbox`** (the default) reads `netbox_export.json`, a small, flat contract
  defined by Cassian ([Input contract](#input-contract)).
* **`netbox-dump`** reads a bundle captured from a NetBox instance's REST API:
  a manifest and four endpoint files ([The `netbox-dump` reader](#the-netbox-dump-reader)).

Both backends share one build path, so the checks on sessions, links and routes,
the output, and the guarantees below are the same for both.

The importer is **fully offline**: it reads only files you provide, never a live
NetBox instance or live devices. It is **deterministic**: identical inputs always
produce byte-identical output.

## Source directory layout

`cassian import` reads a single source directory. Its layout depends on the
backend:

```text
siteA/                           # --backend netbox (the default)
├── netbox_export.json           # the defined input contract (see below)
└── rendered/                    # optional: rendered FRR device configs
    ├── leaf1.conf
    └── spine1.conf

bundle/                          # --backend netbox-dump
├── manifest.json                # what was captured, from which versions
├── dcim_devices.json            # the four endpoint files
├── dcim_cables.json
├── ipam_ip_addresses.json
├── plugins_bgp_session.json
└── rendered/                    # optional, as above
```

* `netbox_export.json` (required for `netbox`) — a JSON document in the
  contract described below.
* `manifest.json` and the four endpoint files (required for `netbox-dump`) —
  see [The `netbox-dump` reader](#the-netbox-dump-reader).
* `rendered/*.conf` (optional, either backend) — rendered **FRR** configs, one
  per device, named for the device. They **corroborate `asn` and `router_id`
  only**: a value they give is used where the source has none, and a value that
  disagrees with the source is rejected. They supply nothing else. `frr` is the
  only platform supported in this release; any other platform value is rejected.

There is no fallback between the two layouts. Selecting a backend on the other
layout is rejected at exit 2, for example:

```text
ERROR: Invalid NetBox import: siteA: the 'netbox' backend expects netbox_export.json and the 'netbox-dump' backend expects manifest.json; the selected backend 'netbox-dump' found no manifest.json here, and netbox_export.json is present. Select the backend that matches the layout and re-run.
```

## Input contract

!!! important "This is a defined contract, not a raw NetBox API dump"
    `netbox_export.json` is **Cassian's own input contract** — a small, flat,
    documented shape. It is **not** the output of NetBox's REST API. A real
    NetBox export is paginated, split across per-object-type endpoints
    (`/api/dcim/devices/`, `/api/ipam/ip-addresses/`, …), and nested with numeric
    IDs. Moreover, **BGP and static routes are not part of NetBox core** — BGP is
    provided by the separate `netbox-bgp` plugin, and static routes likewise are
    not a native core model. To read a capture of a NetBox instance's API, use
    the `netbox-dump` backend ([below](#the-netbox-dump-reader)).

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

| Object | Keys | Rules |
|---|---|---|
| top level | `site`, `devices`, `cables`, `bgp_sessions`, `static_routes` | `site.name` is required; `devices` must be a non-empty list |
| a device | `name`, `platform`, `asn`, `router_id` | `platform` must be `frr`; `asn` an integer and `router_id` an IPv4 address, each optional unless the device has a BGP session; device names unique |
| a cable | `a`, `b`, `a_ip`, `b_ip` | each end is `{device, interface}` on a declared device; the interface name is a Linux interface name (1 to 15 bytes; no `/`, `:` or whitespace; not `.` or `..`); `a_ip` and `b_ip` both or neither, two distinct addresses of one IPv4 subnet, each written address/length |
| a BGP session | `local_device`, `peer_ip`, `remote_asn` | `local_device` a declared device; `peer_ip` an IPv4 address; `remote_asn` an integer, **required**; one session per local device and peer address |
| a static route | `device`, `prefix` | `device` a declared device; `prefix` an IPv4 network with no host bits set; one per device and prefix |

* **Every key is checked.** A key the table does not list is rejected at exit 2,
  naming the file, the object and the key. A value of the wrong type (for
  example `"65001"` or `true` for an integer) is rejected, never coerced.
* **A device with a BGP session needs both `asn` and `router_id`**, from the
  export or from its rendered config; the generated configuration renders BGP
  only when both are present. A device with no session needs neither.
* **Every entry present is checked.** Only `devices` must be non-empty; the
  other lists may be empty or omitted. An entry that breaks a rule above is
  rejected at exit 2 with a message naming the file, the entry and the fix; it is
  never skipped.

### How a session's peer is resolved

The topology names a BGP neighbour by its **node name**, resolved through the
links, as the configuration generator reads it. For a session from device `L`
with peer address `X`:

| Where `X` is | Result |
|---|---|
| the far-end address of exactly one of `L`'s links | resolved: the neighbour is that link's far-end node |
| the far-end address of more than one of `L`'s links | rejected at exit 2, naming the links |
| resolved to a peer node that `L` reaches over more than one link | rejected at exit 2, naming the links |
| inside the subnet of one of `L`'s links, but not its far-end address | rejected at exit 2 (a mistyped peer address) |
| an address of a link `L` is not on | **excluded and named** as a non-adjacent peer: a generated lab configures a neighbour only over the node's own links |
| inside the subnet of a link `L` is not on, but neither of its addresses | rejected at exit 2 |
| outside every declared link's subnet | **excluded and named** as a peer outside the declared topology |
| matching more than one declared link in different ways | rejected at exit 2 (overlapping link addressing) |

An excluded session produces no neighbour and no starter check; the import
still exits 0 if nothing else is wrong. Both exclusions are in the
[exclusion list](#exclusion-kinds-and-reasons).

## The `netbox-dump` reader

The `netbox-dump` backend reads a **bundle**: the objects of one NetBox site,
captured from the REST API of NetBox **4.6.8** with the **`netbox-bgp` plugin
0.19.0** (the proven set). The capture and seed scripts are in
`contrib/netbox-seed/` (`capture.py`, `seed.py`, and their `README.md`).

### The bundle and its manifest

```json
{
  "format": 1,
  "netbox_version": "4.6.8",
  "plugins": {"netbox_bgp": "0.19.0"},
  "site": "site-a",
  "endpoints": {
    "dcim/devices": "dcim_devices.json",
    "dcim/cables": "dcim_cables.json",
    "ipam/ip-addresses": "ipam_ip_addresses.json",
    "plugins/bgp/session": "plugins_bgp_session.json"
  },
  "schema": {"file": "schema.json", "sha256": "<digest>", "source": "published"}
}
```

* The manifest's keys are exactly these six. An unknown key, a `format` other
  than 1, or a NetBox or plugin version outside the proven set is rejected at
  exit 2. `schema.source` is `published` or `plugin serializer`; the reader
  records the schema's identity and does not open `schema.json`.
* Each endpoint file is a JSON list of that endpoint's objects, pages already
  merged by the capture. A named file that is missing or is not a list is
  rejected.
* `site` is a site slug. Every device's `site.slug` must equal it; a device of
  another site in the bundle is rejected at exit 2.

**What a site's bundle holds:** the site's devices (every `site.slug` equal to
the manifest's `site`); the cables, IP addresses and BGP sessions that point at
those devices; and whatever else the capture wrote into the four files. An
object that points at a device the bundle does not hold is **outside the site**:
it is excluded and named, by the names its nested objects carry, never by a
numeric ID. A session's remote address is read from the session itself and need
not be in the bundle (an ISP peer, or another site's interface). IDs are used
only to match a reference to a device: two objects with one ID, one interface ID
with two names, and a device object without a `local_context_data` key are
rejected at exit 2.

### The field map

| Contract field | Read from (NetBox 4.6.8, `netbox-bgp` 0.19.0) | Rule |
|---|---|---|
| `site.name` | the manifest's `site`; every device's `site.slug` equals it | another site → exit 2 |
| device `name` | `dcim/devices[].name` | null or empty → exit 2; duplicate names → exit 2 |
| device platform | `platform.slug` through the table `frr` → `frr` | null or unmapped → exit 2 |
| device `asn` | `local_as` of the device's kept sessions, all agreeing; or a rendered config | disagreement → exit 2; required on a device with a session |
| device `router_id` | `local_context_data.cassian.router_id`, or a rendered config | not an IPv4 address → exit 2; required on a device with a session |
| cable endpoints | `dcim/cables[]` `a_terminations` / `b_terminations`: one `dcim.interface` per side, on a device of the bundle | another termination type → excluded; more than one termination on a side → exit 2 |
| link addresses | `ipam/ip-addresses[]` assigned to a cabled `dcim.interface`, IPv4 | two IPv4 addresses on one interface → exit 2; IPv6, or on no imported link → excluded |
| BGP session | `plugins/bgp/session[]`: `device` → `local_device`; the address part of the nested `remote_address.address` → `peer_ip`, never looked up in `ipam/ip-addresses`; `remote_as.asn` → `remote_asn` | missing device or remote address → exit 2; then [peer resolution](#how-a-sessions-peer-is-resolved) and the required `remote_asn`, as for the contract |
| static route | `local_context_data.cassian.static_routes[].prefix` | see below |

A device whose only sessions are excluded by the filter needs no `asn` or
`router_id`, and an excluded session's `local_as` takes no part in the `asn`
check.

### Static routes and router IDs: `local_context_data.cassian`

NetBox has no static-route model, so the reader takes static routes, and an
optional router ID, from the **`cassian` key of each device's local context
data**:

```json
{
  "cassian": {
    "static_routes": [
      {"prefix": "192.0.2.0/24"}
    ],
    "router_id": "1.1.1.1"
  }
}
```

* Both keys are optional. Any other key inside `cassian`, or any key other than
  `prefix` in a `static_routes` entry (a `next_hop`, for example), is rejected at
  exit 2: Cassian Gate checks only that a declared route is present, not its
  next hop. A prefix is an IPv4 network with no host bits set, once per device.
* Other top-level keys of `local_context_data` belong to other tools; the reader
  neither reads nor names them.
* A `local_context_data` of `null`, which NetBox writes for a device with no
  context data, reads as `cassian` absent. A value that is neither `null` nor a
  JSON object is rejected at exit 2.

### The key lists

The reader meets Cassian's hard-fail rule on unknown input **by enumeration**.
For each endpoint, and for each nested object it reads into, it carries two
lists, both derived from the API schema NetBox 4.6.8 publishes (recorded with
the capture): the keys it **reads**, and the keys it **knows and does not read**.
A key in neither list is rejected at exit 2, naming the file, the object and the
key. A key it does not read is never descended into, so a free-form field
(`custom_fields`, `tags`, `comments`, `description`, and `local_context_data`
outside `cassian`) is one entry and is not inspected.

* **Interface objects (ruling `46-S4-R1`).** NetBox's schema types a cable
  termination's `object`, and an IP address's `assigned_object`, as an untyped
  object. When the object's own type field (`object_type`,
  `assigned_object_type`) is `dcim.interface`, the reader checks it with the
  `interface` lists below, which come from the schema's `BriefInterface`
  component; its nested `device` uses the `device` lists (`BriefDevice`).
* **Other termination objects (ruling `46-S4-R2`).** For a termination of any
  other type (a front port, a circuit termination, a power port), the schema
  publishes no shape, so that object is **not key-checked**. The reader takes
  from it only what it needs to name the excluded cable, each where present: its
  `device` (checked with the `device` lists), its `name`, and for a circuit
  termination `circuit.cid` (with the `circuit` lists) and `term_side`.

#### Keys per object

| Object | Keys read | Keys known and not read |
|---|---|---|
| `dcim/devices` | `id`, `local_context_data`, `name`, `platform`, `site`, `status` | `airflow`, `asset_tag`, `cluster`, `comments`, `config_context`, `config_template`, `console_port_count`, `console_server_port_count`, `created`, `custom_fields`, `description`, `device_bay_count`, `device_type`, `display`, `display_url`, `face`, `front_port_count`, `interface_count`, `inventory_item_count`, `last_updated`, `latitude`, `location`, `longitude`, `module_bay_count`, `oob_ip`, `owner`, `parent_device`, `position`, `power_outlet_count`, `power_port_count`, `primary_ip`, `primary_ip4`, `primary_ip6`, `rack`, `rear_port_count`, `role`, `serial`, `tags`, `tenant`, `url`, `vc_position`, `vc_priority`, `virtual_chassis` |
| `dcim/cables` | `a_terminations`, `b_terminations`, `id`, `status` | `bundle`, `color`, `comments`, `created`, `custom_fields`, `description`, `display`, `display_url`, `label`, `last_updated`, `length`, `length_unit`, `owner`, `profile`, `tags`, `tenant`, `type`, `url` |
| `ipam/ip-addresses` | `address`, `assigned_object`, `assigned_object_type`, `id`, `status`, `vrf` | `assigned_object_id`, `comments`, `created`, `custom_fields`, `description`, `display`, `display_url`, `dns_name`, `family`, `last_updated`, `nat_inside`, `nat_outside`, `owner`, `role`, `tags`, `tenant`, `url` |
| `plugins/bgp/session` | `device`, `id`, `local_as`, `remote_address`, `remote_as`, `status` | `comments`, `created`, `custom_fields`, `description`, `display`, `export_policies`, `extra_attributes`, `import_policies`, `last_updated`, `local_address`, `max_prefixes`, `name`, `peer_group`, `prefix_list_in`, `prefix_list_out`, `remote_as_macro`, `site`, `tags`, `tenant`, `url`, `virtualmachine` |
| `asn` | `asn` | `description`, `display`, `id`, `url` |
| `circuit` | `cid` | `description`, `display`, `id`, `provider`, `url` |
| `device` | `id`, `name` | `description`, `display`, `url` |
| `interface` | `device`, `id`, `name` | `_occupied`, `cable`, `description`, `display`, `url` |
| `ip-address` | `address` | `description`, `display`, `dns_name`, `family`, `id`, `nat_inside`, `nat_outside`, `url` |
| `platform` | `slug` | `_depth`, `description`, `device_count`, `display`, `id`, `name`, `url`, `virtualmachine_count` |
| `site` | `slug` | `description`, `display`, `id`, `name`, `url` |
| `status` | `value` | `label` |
| `termination` | `object`, `object_type` | `object_id` |
| `vrf` | `name` | `description`, `display`, `id`, `rd`, `url` |

#### Which lists a nested object is checked with

| In | Key | Checked with |
|---|---|---|
| `dcim/devices` | `platform` | `platform` |
| `dcim/devices` | `site` | `site` |
| `dcim/devices` | `status` | `status` |
| `dcim/cables` | `a_terminations` | `termination`, for each item of the list |
| `dcim/cables` | `b_terminations` | `termination`, for each item of the list |
| `dcim/cables` | `status` | `status` |
| `ipam/ip-addresses` | `assigned_object` | `interface`, when the object's type is `dcim.interface` (`46-S4-R1`) |
| `ipam/ip-addresses` | `status` | `status` |
| `ipam/ip-addresses` | `vrf` | `vrf` |
| `plugins/bgp/session` | `device` | `device` |
| `plugins/bgp/session` | `local_as` | `asn` |
| `plugins/bgp/session` | `remote_address` | `ip-address` |
| `plugins/bgp/session` | `remote_as` | `asn` |
| `plugins/bgp/session` | `status` | `status` |
| `interface` | `device` | `device` |
| `termination` | `object` | `interface`, when the object's type is `dcim.interface` (`46-S4-R1`) |

## The reader's filter

The reader keeps only what NetBox marks as in service, in the global table,
inside the site. It runs in this order:

1. **Load checks** on every object: the manifest, the endpoint files, IDs,
   names and the key lists. A filtered object still meets these.
2. **The filter**, below. An object it excludes takes no part in any later
   check.
3. **Checks on kept objects**: the field map and the checks shared with the
   contract.

| Object | Field read | In service when | Otherwise |
|---|---|---|---|
| device (`dcim/devices`) | `status.value` | `active` | excluded and named, with everything that hangs on it: its cables, its interfaces' addresses, its sessions |
| any object pointing at a device | the nested device's ID | the device is in the bundle | excluded and named by its nested names |
| cable (`dcim/cables`) | `status.value`; the terminations' type | `connected`; one `dcim.interface` per side | excluded and named |
| IP address (`ipam/ip-addresses`) | `status.value`; `vrf`; the address family; its interface's link | `active`; `vrf` null; IPv4; on a kept link | excluded and named |
| BGP session (`plugins/bgp/session`) | `status.value`; the remote address's family | `active`; not a valid IPv6 address | excluded and named |

* **Instance-defined statuses.** NetBox's `FIELD_CHOICES` setting lets an
  administrator replace or extend the status choices of devices and IP
  addresses. A value other than the in-service one above is **not in service**:
  an instance's own "production" status is excluded and named, never imported
  unseen.
* **What the filter does not see:** an interface's `enabled` flag. A disabled
  interface that carries a connected cable and an active address becomes a link.
* **When the filter leaves too little.** If no device is in service after the
  filter, the import is rejected at exit 2, naming the first excluded device and
  its reason. If the filter excludes one address of a link and keeps the other,
  the link would keep one address: that is rejected at exit 2, naming the
  excluded address and its reason.

### Exclusion kinds and reasons

Every excluded object is named on output, on one line, after the success block:

```text
   excluded: <kind> <object>: <reason>
```

Lines are sorted by kind, then device, then object. An object has one line and
one reason: the first that applies, in the table's order for its kind. Objects
are named by names, never by numeric IDs; `-` stands for a name the export does
not carry.

| Kind | Object | Reason (`<…>` filled from the object), in precedence order | Req-ID |
|---|---|---|---|
| `bgp-session` | `<L> -> <X>` | `device <L> is not in this site's bundle` | REQ-46-71 |
| `bgp-session` | `<L> -> <X>` | `device <L> is excluded` | REQ-46-64 |
| `bgp-session` | `<L> -> <X>` | `status <status> is not active` | REQ-46-45 |
| `bgp-session` | `<L> -> <X>` | `IPv6 peer; the importer reads IPv4 sessions only` | REQ-46-45 |
| `bgp-session` | `<L> -> <X>` | `non-adjacent peer: <X> is an address of link <ep0><-><ep1>, which <L> is not on; a generated lab configures a neighbour only over the node's own links` | REQ-46-19 |
| `bgp-session` | `<L> -> <X>` | `peer outside the declared topology: <X> lies outside every declared link's subnet` | REQ-46-21 |
| `cable` | `<side a> <-> <side b>` | `device <name> is not in this site's bundle` | REQ-46-71 |
| `cable` | `<side a> <-> <side b>` | `device <name> is excluded` | REQ-46-64 |
| `cable` | `<side a> <-> <side b>` | `status <status> is not connected` | REQ-46-65 |
| `cable` | `<side a> <-> <side b>` | `termination <termination type> is not an interface; links connect interfaces` | REQ-46-43 |
| `device` | `<name>` | `status <status> is not active` | REQ-46-64 |
| `ip-address` | `<device>:<interface> <address>` | `device <device> is not in this site's bundle` | REQ-46-71 |
| `ip-address` | `<device>:<interface> <address>` | `device <device> is excluded` | REQ-46-64 |
| `ip-address` | `<device>:<interface> <address>` | `status <status> is not active` | REQ-46-66 |
| `ip-address` | `<device>:<interface> <address>` | `in VRF <vrf>; the importer models the global table only` | REQ-46-67 |
| `ip-address` | `<device>:<interface> <address>` | `IPv6 address; the importer reads IPv4 link addresses only` | REQ-46-44 |
| `ip-address` | `<device>:<interface> <address>` | `interface is on no imported link, so no link carries the address` | REQ-46-44 |

* `<L> -> <X>` is a session's local device and peer address. A cable side is
  `<device>:<interface>` for an interface, and otherwise its termination type as
  the export names it, then, where the nested object has them, its device and
  name (`dcim.frontport leaf1 fp1`), or a circuit's `cid` and termination side
  (`circuits.circuittermination CID-1001 A`). For a cable, `<name>` is the first
  such device, side a before side b.
* `<status>` is the object's status value as the export writes it (for example
  `planned`); `<vrf>` is the VRF's name; `<ep0><-><ep1>` is a link's two
  endpoints as the topology writes them.
* The two session reasons `non-adjacent peer` and `peer outside the declared
  topology` come from the shared build path and apply to both backends; every
  other kind is the `netbox-dump` reader's filter.

## What it produces

The output directory receives the authoritative pair:

```text
out/
├── topology.yaml                 # authoritative topology, with embedded tests
└── tests/
    └── starter_invariants.yaml   # the starter invariants, and the set-aside section
```

On success, `cassian import` prints exactly these four lines, then one
`excluded:` line per excluded object:

```text
✅ IMPORT OK (authoritative input; backend: <backend>): wrote <out>/topology.yaml
   starter invariants (<n>): embedded in topology.yaml, copied to <out>/tests/starter_invariants.yaml
   set aside, need device configuration (<m>): <out>/tests/starter_invariants.yaml
   excluded by filter (<k>)
```

All three counts print even when they are 0.

Starter invariants are generated **only from explicitly declared facts**, using a
fixed allowlist — never inferred or synthesized:

* a `bgp_session_up` invariant for each resolved BGP session,
* an `interface_state` invariant for each declared cable endpoint,
* a `route_present` invariant for each declared static route, **set aside**
  (below).

**The set-aside section.** Cassian Gate does not configure static routes on the
nodes it generates, so a `route_present` check would fail in a generated lab.
These checks are written to a `needs_device_configuration` section of
`tests/starter_invariants.yaml`, with a fixed `reason`, and are not embedded in
`topology.yaml`:

```yaml
needs_device_configuration:
  reason: route_present checks for declared static routes. Cassian Gate does not
    configure static routes on the nodes it generates, so these pass only where
    routing comes from device configuration. They are not in topology.yaml.
  tests:
  - expect: pass
    kind: invariant
    name: starter_route_present_leaf1_192_0_2_0_24
    node: leaf1
    prefix: 192.0.2.0/24
    type: route_present
tests:
- (exactly the list topology.yaml embeds)
```

The section is present exactly when it holds a check.

Nothing is dropped silently. Input the importer cannot read correctly is
**rejected** at exit 2; an object outside its scope is **excluded and named** on
an `excluded:` line; nothing is guessed at.

## Guarantees

* **Offline.** No network or live-device access; only the files you provide.
* **Deterministic.** Identical inputs produce byte-identical output; all source
  iteration is sorted and serialization is canonical. A bundle whose files list
  their objects in a different order produces the same pair, and the pair
  carries no provenance of the capture.
* **No synthesis.** Invariants come only from declared facts via the allowlist.
* **Fail-closed.** Unsupported or malformed input is rejected with **exit 2** and
  one message in the form `Invalid NetBox import: <file>: <object>: <issue>.
  <corrective action> and re-run.`, naming the input file, the object and the
  fix. The importer never emits a partial or invalid pair.

## Status and roadmap

This is a first, lab-free importer. It has been validated against an export from a NetBox instance seeded for the purpose: NetBox 4.6.8 with the `netbox-bgp` plugin 0.19.0, static routes held in device local context data, captured with the seed script in `contrib/netbox-seed/`. It has not been validated against a production NetBox inventory. The topology it emits from the `siteA` fixture is brought up in CI and its starter invariants pass (`tests/importer/import_deploy_proof.py`). Static-route checks are set aside in `tests/starter_invariants.yaml`, because Cassian Gate does not configure static routes on the nodes it generates.

Tracked for future work:

* **Validation against a production NetBox inventory** — exercise the
  `netbox-dump` reader on a real site's capture before any production reliance,
  to confirm the field map and the filter hold against live data.
