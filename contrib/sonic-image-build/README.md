# contrib/sonic-image-build

Scripted build path for a vrnetlab-wrapped SONiC VM image usable as a Cassian Gate
`sonic-vm` node.

Non-authoritative helper. It builds an artifact **you own**; it does not change any
Cassian Gate contract, and its presence implies no runtime support claim.

## Why this exists (bring-your-own NOS)

Cassian Gate **does not distribute NOS images.** You supply a vrnetlab-built
container image for `sonic-vm` nodes. This is the same rule that already applies to
commercial NOSes (Arista cEOS, vJunos, Cisco) — their terms forbid redistribution,
so bring-your-own is the only rule that is uniform across the whole product. It is
also the convention every comparable tool uses (containerlab, vrnetlab, GNS3,
EVE-NG are all bring-your-own).

This directory closes the *acquisition* gap — telling you exactly how to build the
image — **without** turning Cassian Gate into a *distribution* channel for it. Those
are different things: the rule is untouched; only the instructions are added.

## What you need first (honest sourcing caveats)

You must obtain a SONiC `.qcow2` disk image yourself. Sourcing it is the genuinely
awkward step, and the honest picture is:

- Community builds are published at `sonic.software` — **unofficial**, and by
  containerlab's own documentation the mirror *"may be down sometimes."*
- The official route is the Azure DevOps pipeline artifacts, which are a maze to
  navigate (containerlab's docs call it *"a pita"*).

Cassian Gate cannot make this step reliable — it is upstream of the product. Budget
time for it, and verify the image boots before wiring it into a gate.

## Build

```bash
# 1. obtain a SONiC qcow2 (see caveats above) and place it here as sonic-vm.qcow2
# 2. run the build helper
./build.sh sonic-vm.qcow2 202405
```

The helper clones vrnetlab, stages the qcow2 into its `sonic` build context, runs
the vrnetlab make target, and tags the result `local/sonic-vm:<version>` (default
`202405`) — the tag the shipped example topologies expect.

## Credentials (boot-time provenance)

The built image authenticates as username `admin`, password `admin`.

This is a **boot-time property of the launcher, not a build-time image constant.**
vrnetlab's `launch.py` overwrites the guest password over the serial console at
every boot; the guest logs `BAD PASSWORD: shorter than 8 characters` and accepts it.
There is no Cassian Gate schema key for credentials — they are not configurable via
topology YAML. If you build an image whose launcher sets different credentials, the
VM-runtime transport will fail readiness with an auth-fail (rc=5) message. Keep the
launcher defaults, or align the launcher credentials with `admin`/`admin`.

## Scope

- Builds a bring-your-own artifact; changes no contract (DC §1 untouched).
- Not a distribution channel; sets no precedent for hosting NOS images.
- Not a runtime plugin; the presence of this directory implies no NOS runtime
  support beyond what the VM-runtime backend already documents in
  `docs/vm-runtime-capabilities.md`.
