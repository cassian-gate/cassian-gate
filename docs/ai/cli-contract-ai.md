# CLI Contract — Assistive AI (v1) (Authoritative)

This contract prevents AI from becoming authoritative.

## Hard rules
- AI is advisory only; must emit `authority: advisory`
- AI commands never modify verdicts, exit codes, or artifacts
- AI commands never run labs or call runtime
- AI commands exit 0 unless usage/artifact error (exit 2)

## Commands

### `cassian ai`
Inputs:
- explicitly invoked operator input only
- supporting topology and artifact context when available

Behavior:
- advisory only
- non-authoritative
- never modifies verdicts, exit codes, or artifacts
- never runs labs or calls runtime

Outputs:
- explanations, summaries, and bounded guidance consistent with shipped behavior
- must not invent facts
- must remain outside the authority chain

## Provider boundary
- AI is opt-in:
  - enabled only when explicitly invoked and provider is configured
- BYO key via environment variables only
- If provider missing: print deterministic scaffold output; exit 0

