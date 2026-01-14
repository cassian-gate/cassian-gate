# Workflow (Authoritative)

This is the collaboration loop for implementation work.

## Default loop
1) Read the read-first docs and the relevant code paths
2) Explain current behavior (what is true today)
3) Propose the smallest change that satisfies the milestone
4) Implement only after explicit approval (unless explicitly asked to implement)
5) Verify:
   - add/extend negative validation topologies when applicable
   - add/extend scripts (e.g., verify scripts)
   - ensure determinism and artifact correctness
6) Document:
   - update `docs/ai/NOW.md` focus
   - append new locked decisions to `docs/ai/DECISIONS.md`

## Hard constraints
- No silent defaults
- Fail fast on ambiguity
- No “fixing” user intent
- Tests + scenarios are authoritative
- AI features are advisory only

## Commit discipline (recommended)
- One PR per logical milestone
- Prefer small commits:
  - validation changes
  - engine changes
  - verification changes
  - docs updates

