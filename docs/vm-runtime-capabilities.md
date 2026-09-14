# VM Runtime Capabilities (Non-Authoritative)

This document is supporting guidance only.
Authoritative behavior remains defined by the Cassian Gate Design Contract, deterministic execution, and the generated authoritative artifacts such as `results.json`.

## Requirements (VM runtime)

Supported host requirements:
- Linux host with KVM available and accessible (`/dev/kvm`)
- container runtime and containerlab available per normal Cassian Gate setup

Unsupported:
- WSL2 for VM-runtime execution

If VM runtime prerequisites are not met, Cassian Gate should be expected to reject or fail the VM-runtime path rather than silently approximating it. `cassian doctor` reports the VM-runtime prerequisites (sonic-vm image present-or-pullable, `/dev/kvm`, containerlab version) as advisory checks.

## Substrate vs NOS: what each exec verb reaches

A `sonic-vm` node has two layers: the **substrate** (the vrnetlab wrapper container that hosts QEMU) and the **NOS** (the SONiC guest running inside QEMU). Two verb families address them, and the split is explicit:

- **Bare verbs reach the NOS (the guest).** `exec`, `sh`, and `copy_*` are directed at the guest NOS. On a `sonic-vm` node these reach the guest over the VM transport (SSH), not the wrapper.
- **`substrate_*` verbs reach the substrate (the wrapper).** `substrate_exec`, `substrate_sh`, and `substrate_copy_from` are directed at the vrnetlab wrapper container itself.

The default is **bare = NOS**. Choosing the wrong verb family targets the wrong entity, so the distinction is deliberate and is enforced in CI (a bare exec/sh carrying a substrate-only operation is caught by the target-preservation guard).

## Supported test surfaces on vm-runtime nodes

vm-runtime nodes currently support **lifecycle** (`up` / `status` / `down`), **node readiness**, and **ping tests** (executed against the guest). A ping whose `src` is a `sonic-vm` node runs against the guest NOS and produces an authoritative verdict.

Other test kinds are **deferred** (DC v2.1 §10, "Model vs runtime backend"). The following are explicitly **not supported** against a vm-runtime node and are rejected at validation time (exit code `2`):

| Test kind on a vm node | Status |
| ---------------------- | ------ |
| `ping` (`src:` the guest) | **supported** — runs against the guest NOS |
| `tcp` | not supported (deferred) |
| `bgp_neighbor` | not supported (deferred) |
| invariant kinds (e.g. `invariant`, `ospf_neighbor_up`) | not supported (deferred) |
| `route_prefix` | not supported (deferred) |

The rejection is explicit and names the valid surface: give the referencing node a `container`-runtime, or use one of the supported surfaces above.

## File copy on vm-runtime nodes

Copying is stated honestly rather than approximated:

- **`copy_*` to/from the guest NOS is UNSUPPORTED on vm-runtime nodes** and is deferred to §4.5-f. The guest-file direction is not available in this release.
- **`substrate_copy_from` works** — it retrieves a file from the vrnetlab wrapper (the substrate), not the guest.
- **`substrate_copy_to` is intentionally absent** — it is demand-led and not shipped until a concrete need appears.

## Readiness: how the VM-runtime path fails

When a `sonic-vm` node is brought up, Cassian Gate polls the guest for readiness and fails with a §13-grade, direction-accurate message rather than a silent approximation. The classes are:

- **(a) unreachable** — the SSH transport never answered (ssh rc=255): the wrapper and QEMU are up, but nothing is listening on the guest's forwarded SSH port yet.
- **(b) auth-fail** — the transport answered but authentication failed (sshpass rc=5). Polling cannot cure wrong credentials, so this fails fast and names the credential provenance (see below).
- **(c) timeout** — the transport answered but the guest never returned `rc=0` to a trivial command within the readiness window.

(A defensive host-key-unknown class (rc=6) exists but cannot occur under the pinned transport options `StrictHostKeyChecking=no` / `UserKnownHostsFile=/dev/null`; if seen, the transport has been modified.)

## Credentials (boot-time provenance)

The VM transport authenticates to the guest with username `admin` and password `admin`.

These are a **boot-time property of the launcher, not a build-time image constant.** The vrnetlab `launch.py` overwrites the guest password over the serial console at every boot; the guest logs `BAD PASSWORD: shorter than 8 characters` and accepts it anyway. There is **no topology or schema key** for credentials — they are not operator-configurable through YAML. To use an image whose launcher sets different credentials, build it via `contrib/sonic-image-build/` (launcher defaults), or supply an image whose launcher credentials match these constants. See `contrib/sonic-image-build/` for the build path and the credential provenance in full.

## CI ceiling (single SONiC node)

On the reference runner, a SONiC guest needs roughly 4 GiB against ~9.5 GiB available, which imposes a **single-SONiC-node ceiling** in CI: the assertion topology deploys exactly one `sonic-vm` node. Multi-node SONiC topologies do not fit the current CI host and are out of scope for the gate.

## OSPF (honest limitation)

OSPF neighbour invariants (e.g. `ospf_neighbor_up`) are **not currently supported on vm-runtime nodes.** Like the other invariant kinds, they are exec-into gated and deferred; a topology asserting an OSPF invariant with a `sonic-vm` `src` is rejected at validation time. This limitation is stated here rather than presented as a silent gap.

## Canonical VM topologies

Assertion-leg smoke (single node + directly-connected FRR peer, one ping from the guest):
- `topologies/vm-assertion-smoke.yaml`

Fuller VM proof topology (substrate-era outcomes fixture):
- `topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml`

Validate:

```bash
cassian validate topologies/vm-assertion-smoke.yaml
```

Run the authoritative gate:

```bash
cassian test vm-assertion-smoke
```

Use these commands when you want to validate a declared VM-runtime topology through the normal Cassian Gate operator surface.

## Acquisition (bring-your-own NOS image)

Cassian Gate does not distribute NOS images; you supply a vrnetlab-built container image. A scripted build path, with the honest sourcing caveats, is under `contrib/sonic-image-build/`.

## Boundary reminder

This page does not expand authority.
It does not make VM-runtime guidance authoritative by itself.
For deploy/no-deploy meaning, rely on the authoritative gate path and the generated artifacts from execution.
