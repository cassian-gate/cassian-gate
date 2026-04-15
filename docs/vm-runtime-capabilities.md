# VM Runtime Capabilities (Non-Authoritative)

This document is supporting guidance only.
Authoritative behavior remains defined by the Cassian Gate Design Contract, deterministic execution, and the generated authoritative artifacts such as `results.json`.

## Requirements (VM runtime)

Supported host requirements:
- Linux host with KVM available and accessible
- container runtime and containerlab available per normal Cassian Gate setup

Unsupported:
- WSL2 for VM-runtime execution

If VM runtime prerequisites are not met, Cassian Gate should be expected to reject or fail the VM-runtime path rather than silently approximating it.

## Canonical VM proof topology

Topology:
- `topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml`

Validate:

```bash
cassian validate topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml
```

Run the authoritative gate:

```bash
cassian test topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml
```

Use these commands when you want to validate the declared VM-runtime proof topology through the normal Cassian Gate operator surface.

## Boundary reminder

This page does not expand authority.
It does not make VM-runtime guidance authoritative by itself.
For deploy/no-deploy meaning, rely on the authoritative gate path and the generated artifacts from execution.
