# contrib/netbox-seed

These scripts produced the seeded NetBox export committed at `tests/importer/fixtures/netbox-seeded/`. That export is real output from a pinned NetBox instance, so `cassian import` is proven against what the NetBox API actually returns rather than a hand-written file (REQ-46-33).

This is a non-authoritative helper and is not run in CI. The proofs read the committed bundle offline; they never start NetBox.

## Files

| File | What it is |
|---|---|
| `pins.env` | The versions the bundle was captured at: NetBox 4.6.8, `netbox-bgp` 0.19.0, the `netbox-docker` image `netboxcommunity/netbox:v4.6.8-5.0.2`, and the PostgreSQL 18 and Valkey 9.1 images, each pinned by digest. It also sets the site slug, `site-a`. |
| `seed.py` | Seeds a fresh instance through the REST API. Standard library only; it writes no file. |
| `capture.py` | Runs the captures, each on a fresh stack: build, start, token, seed, capture, token check, teardown. Standard library only. |

## The seeded site

`site-a` is built from what the importer admits. Router IDs and static routes live in each device's local context data under the key `cassian`.

| What | Imported |
|---|---|
| Devices | `leaf1` (AS 65001, router ID 1.1.1.1, static route 192.0.2.0/24); `spine1` (AS 65002, 2.2.2.2); `leaf2` (AS 65003, 3.3.3.3). All three are on platform `frr` with status active |
| Links | leaf1 `eth1` 10.0.0.1/30 ↔ spine1 `eth1` 10.0.0.2/30; leaf2 `eth1` 10.0.0.5/30 ↔ spine1 `eth2` 10.0.0.6/30 |
| BGP sessions | four `netbox-bgp` sessions, one for each side of each link, all active |

The site also holds four objects that the importer must name and exclude. The import still exits 0. Each is excluded for one reason:
- `leaf9`, a planned device cabled to spine1 `eth3`;
- `2001:db8::1/64`, an IPv6 address on leaf1 `eth1`;
- `172.16.0.1/24`, an address in VRF `mgmt` on spine1 `eth1`;
- spine1's session to the outside peer 203.0.113.1 (AS 64999), whose address is assigned to no interface.

## What one capture does

1. **Build and start.** It builds the pinned NetBox image with the `netbox-bgp` plugin, using `netbox-docker`'s plugin method. It starts that image with PostgreSQL and Valkey in a throwaway Compose project, published on 127.0.0.1 only. Every password and key is generated in memory and passed by environment.
2. **Token.** It creates a v2 API token inside the instance. The plaintext reaches `capture.py` through a pipe and is never printed or written.
3. **Versions and seed.** It checks the instance's NetBox and `netbox-bgp` versions against `pins.env`, then runs `seed.py`.
4. **Capture.** It captures the four endpoints the importer reads, with pages merged:
   - devices and cables, selected by site;
   - IP addresses and BGP sessions, selected by device.

   It also captures the published API schema (`/api/schema/?format=json`).
5. **Write.** It writes the bundle: the four endpoint files, `schema.json` and `manifest.json`. The manifest holds the versions, the site, the endpoint files, and the schema's file name, sha256 and source. The source is `published` when the schema carries `/api/plugins/bgp/session/`.
6. **Token check.** Before teardown, it fails if any file it wrote holds any part of the token.
7. **Teardown.** It removes the containers, the volumes and the built image.

After every capture it prints each file's sha256 and size.

## Run

You need Docker with the Compose plugin, and network access to Docker Hub and PyPI.

```bash
# Offline: shows each guard firing, then passing
python3 contrib/netbox-seed/capture.py --self-test

# Two captures; the folder must not exist yet
python3 contrib/netbox-seed/capture.py --out /tmp/netbox-seeded --captures 2
```

Each capture writes to `<out>/capture-<n>/`. A second capture on a fresh stack gets different IDs, timestamps and URLs, but the importer's output from it must be byte-identical to its output from the first.

## The committed bundle

`tests/importer/fixtures/netbox-seeded/` is capture 1 of the run of 2026-11-16, unchanged, and its manifest's versions equal `pins.env`. The run made two captures, each on a fresh stack, and every file's sha256 was recorded for both. Capture 2 is kept as evidence and is not committed.
