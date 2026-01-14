# Artifacts & Authority

## Authoritative artifacts
- `topology.resolved.yaml` (resolved intent; authoritative)
- `results.json` (authoritative outcomes and timeline)

## Human convenience artifact (non-authoritative)
- `results.summary.txt` (human-readable summary only)

## AI input rule (hard)
AI commands may read only:
- resolved topology and results artifacts
- optional evidence artifacts (if present later)
AI must never read live runtime state or execute commands.

## State capture / PCAP (future)
If present in later milestones:
- they are supporting evidence only
- never used for gating
- never “no diff = pass”

