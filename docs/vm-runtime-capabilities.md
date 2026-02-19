# VM Runtime Capabilities (Non-Authoritative)

This document is **guidance only**.
Authoritative behavior is defined by the ai-netsim Design Contract and `results.json`.

## Requirements (VM runtime)

Supported host:
- Linux host with KVM available and accessible (`/dev/kvm` readable+writable)
- Container runtime and containerlab available per ai-netsim setup

Unsupported:
- WSL2 (VM runtime must fail fast)

## Canonical VM proof topology (explicit invocation)

Topology:
- `topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml`

Validate:
```bash
./src/netsim.py validate topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml ; echo "exit=$?"
