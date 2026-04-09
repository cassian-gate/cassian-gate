# CLI Contract — Assistive AI (v1) (Authoritative)

This contract prevents AI from becoming authoritative.

## Hard rules
- AI is advisory only; must emit `authority: advisory`
- AI commands never modify verdicts, exit codes, or artifacts
- AI commands never run labs or call runtime
- AI commands exit 0 unless usage/artifact error (exit 2)

## Commands

### `cassian ai explain <lab|topology>`
Inputs (artifact-only):
- labs/clab-<lab>/results.json
- labs/clab-<lab>/topology.resolved.yaml
Optional:
- labs/clab-<lab>/results.summary.txt

Outputs:
- cites exact failures from results.json (test/scenario step ids)
- never invents facts
- provides “evidence summary” even if AI is disabled/unavailable

### `cassian ai review <topology.yaml> [--against <results.json>]`
Inputs:
- topology (or resolved topology)
- optionally results.json for “what ran vs what exists”

Outputs:
- deterministic gap list first (computed without AI)
- bounded suggestions (copy-paste snippets allowed)
- advisory only; never gating

### `cassian ai coach [<topology|lab>]`
Purpose:
- onboarding and guidance (human learning)
Restrictions:
- must NOT generate paste-ready YAML or configs
- may provide high-level templates and explanations only

## Provider boundary
- AI is opt-in:
  - enabled only when explicitly invoked and provider is configured
- BYO key via environment variables only
- If provider missing: print deterministic scaffold output; exit 0

