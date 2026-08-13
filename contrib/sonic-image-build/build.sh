#!/usr/bin/env bash
#
# contrib/sonic-image-build/build.sh — scripted vrnetlab build path for a SONiC VM
# image usable as a Cassian Gate `sonic-vm` node.
#
# Non-authoritative helper. It builds an artifact you own (bring-your-own NOS); it
# is not a distribution channel and changes no Cassian Gate contract.
#
# Usage:
#   ./build.sh <sonic-vm.qcow2> [version]
#
#   <sonic-vm.qcow2>  a SONiC qcow2 disk image you have obtained yourself. Sourcing
#                     it is the awkward step: sonic.software (unofficial, "may be
#                     down sometimes") or the Azure DevOps pipeline artifacts ("a
#                     pita"). Cassian Gate cannot make this reliable — it is upstream.
#   [version]         tag suffix; default 202405. Produces local/sonic-vm:<version>,
#                     the tag the shipped example topologies expect.
#
# Credentials (boot-time): the built guest authenticates as admin/admin. This is a
# launcher behaviour — vrnetlab's launch.py overwrites the password over serial at
# every boot (the guest logs "BAD PASSWORD: shorter than 8 characters" and accepts
# it). There is no schema key for credentials. Keep the launcher defaults.

set -euo pipefail

QCOW2="${1:-}"
VERSION="${2:-202405}"

if [[ -z "$QCOW2" || ! -f "$QCOW2" ]]; then
  echo "ERROR: provide a SONiC qcow2 you have obtained yourself." >&2
  echo "  usage: $0 <sonic-vm.qcow2> [version]" >&2
  echo "  sourcing caveats: see README.md (sonic.software unofficial; Azure pipeline maze)." >&2
  exit 2
fi

for tool in git make docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' is required and was not found." >&2; exit 2; }
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Cloning vrnetlab into $WORKDIR"
git clone --depth 1 https://github.com/hellt/vrnetlab.git "$WORKDIR/vrnetlab"

SONIC_CTX="$WORKDIR/vrnetlab/sonic/sonic-vs"
if [[ ! -d "$SONIC_CTX" ]]; then
  # vrnetlab layout has moved over time; fall back to the sonic dir root.
  SONIC_CTX="$WORKDIR/vrnetlab/sonic"
fi

echo "==> Staging $(basename "$QCOW2") into the vrnetlab sonic build context"
cp "$QCOW2" "$SONIC_CTX/"

echo "==> Building the vrnetlab SONiC image (this pulls a builder image and can take a while)"
( cd "$SONIC_CTX" && make )

# vrnetlab tags as vrnetlab/sonic-vs:<qcow2-version>; retag to the Cassian Gate
# convention local/sonic-vm:<version> that the example topologies pin.
BUILT_TAG="$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'sonic' | head -n1 || true)"
if [[ -z "$BUILT_TAG" ]]; then
  echo "ERROR: build produced no sonic image tag — inspect the vrnetlab make output above." >&2
  exit 1
fi

echo "==> Retagging $BUILT_TAG -> local/sonic-vm:$VERSION"
docker tag "$BUILT_TAG" "local/sonic-vm:$VERSION"

cat <<EOF

Done. Built: local/sonic-vm:$VERSION

Use it by pinning the tag in a topology, e.g.:

  nodes:
    - name: s1
      type: sonic-vm
      runtime: vm
      image: local/sonic-vm:$VERSION

Credentials are admin/admin (boot-time launcher default). See README.md.
EOF
