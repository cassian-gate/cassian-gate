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

**Check for one you already have first.** If a vrnetlab checkout exists on the host,
a previously-downloaded disk may already be staged in its `sonic/` directory:

```bash
ls -la ~/vrnetlab/sonic/*.qcow2 ~/vrnetlab/sonic/*.img 2>/dev/null
```

A staged image is easy to miss because nothing records it, and it is the same
artifact the upstream routes below would fetch. Verify whatever you find before
building (see *Verify the disk* below).

If you do need to fetch one, you must obtain a SONiC `.qcow2` disk image yourself.
Sourcing it is the genuinely awkward step, and the honest picture is:

- Community builds are published at `sonic.software` — **unofficial**, and by
  containerlab's own documentation the mirror *"may be down sometimes."*
- The official route is the Azure DevOps pipeline artifacts, which are a maze to
  navigate (containerlab's docs call it *"a pita"*).

Cassian Gate cannot make this step reliable — it is upstream of the product. Budget
time for it, and verify the image boots before wiring it into a gate.

### Verify the disk before building

```bash
qemu-img info <your-image>
```

Must report `file format: qcow2`. SONiC publishes the file named `.img`, but it *is*
qcow2 — the rename is cosmetic. A report of `raw`, or an error, means a truncated or
failed download (an HTML error page saved under the expected filename is the common
case). Checking here costs a second; discovering it after a build costs the build.

Record the `sha256sum` of the disk you build from. It is the only durable link
between a built image and its source.

## Build

```bash
# 1. obtain a SONiC qcow2 (see caveats above) and place it here as sonic-vm.qcow2
# 2. run the build helper
./build.sh sonic-vm.qcow2 202405
```

The helper clones vrnetlab, stages the qcow2 into its `sonic` build context, runs
the vrnetlab make target, and tags the result `local/sonic-vm:<version>` (default
`202405`) — the tag the shipped example topologies expect.

### Two traps in the underlying vrnetlab build

These are properties of vrnetlab's own Makefile, not of this helper. They apply
whether you use `build.sh` or run `make` in a vrnetlab checkout directly.

**1. The filename determines the tag, and a wrong name fails quietly.**
vrnetlab derives the version by stripping `sonic-vs-` and `.qcow2` from the
filename. A file named `sonic-vs.qcow2` (no version segment) does not match the
first pattern, so the version becomes the literal string `sonic-vs` and you get
`vrnetlab/sonic_sonic-vs:sonic-vs`. The Makefile's guard only catches a *total*
regex failure, not this partial one — **the build succeeds and the tag is wrong.**
Name the file `sonic-vs-<version>.qcow2`, e.g. `sonic-vs-202405.qcow2`.

**2. Only one image may sit in the build directory.**
vrnetlab's `IMAGE_GLOB` is `*.qcow2` and it loops over *every* match, running a
full build per file. Two disks means two builds and two tags. Move any other
`.qcow2` out of the directory before building — move rather than delete, so the
source is preserved.

**Verify the build actually produced something new:**

```bash
docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}' | grep -i sonic
```

The new image ID must differ from any image that was present beforehand. The
`vrnetlab-version` label records the *vrnetlab checkout's* git commit, not the
build — so it is identical across rebuilds from an unchanged checkout and
**cannot** be used to tell a fresh build from an old one. The image ID can.

## Credentials (boot-time provenance)

The built image authenticates as username `admin`, password `admin`.

This is a **boot-time property of the launcher, not a build-time image constant.**
vrnetlab's `launch.py` overwrites the guest password over the serial console at
every boot; the guest logs `BAD PASSWORD: shorter than 8 characters` and accepts it.
There is no Cassian Gate schema key for credentials — they are not configurable via
topology YAML. If you build an image whose launcher sets different credentials, the
VM-runtime transport will fail readiness with an auth-fail (rc=5) message. Keep the
launcher defaults, or align the launcher credentials with `admin`/`admin`.

Note that vrnetlab's `launch.py` carries a `DEFAULT_PASSWORD` of `YourPaSsWoRd`,
not `admin`. In practice containerlab passes credentials explicitly and `admin`/
`admin` has been observed to work, but the default is worth knowing if readiness
fails with rc=5 on an image you built yourself.

## Startup config: two paths, opposite semantics

A SONiC guest can receive configuration two ways, and **they do not behave the
same**. This matters if you supply a *partial* config.

| Path | Mechanism | Effect |
|---|---|---|
| Boot-time mount at `/config/config_db.json` | vrnetlab `launch.py` → `backup.sh restore` → `config replace` + `config save -y` | **Replaces** the whole ConfigDB, then persists to disk |
| Running node | `config load <file> -y` → `sonic-cfggen --write-to-db` | **Merges** at field level; redis only, on-disk config untouched |

The boot-time path replaces wholesale. A partial config supplied that way removes
everything it does not mention — including platform-owned tables such as `PORT`,
and `hwsku` / `platform` / `mac` under `DEVICE_METADATA` — and `config save -y`
makes the removal survive a reboot.

If your configuration is a complete ConfigDB, either path works. If it is an
overlay, use the running-node path.

## Scope

- Builds a bring-your-own artifact; changes no contract (DC §1 untouched).
- Not a distribution channel; sets no precedent for hosting NOS images.
- Not a runtime plugin; the presence of this directory implies no NOS runtime
  support beyond what the VM-runtime backend already documents in
  `docs/vm-runtime-capabilities.md`.
