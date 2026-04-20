# Cassian Gate Agent Rules (Authoritative)

This repository is designed to be worked on with AI assistance **without relying on chat history**.

## Read-first order (MANDATORY)
Before proposing changes, an agent MUST read:
1) `AGENTS.md` (this file)
2) `docs/design-contract.md` (authoritative lifecycle + authority rules)
3) `docs/ai/GUARDRAILS.md` (deterministic core / probabilistic edge)
4) `docs/ai/NOW.md` (current focus)
5) `docs/ai/TASKS.md` (active tasks + priorities)
6) Only then: relevant source files.

If any of the above conflicts with a suggestion, the suggestion is invalid.

---

## Authority model (NON-NEGOTIABLE)
- **Deterministic tests + scenarios are the sole authority for pass/fail**
- **AI is advisory only** (explain/review/coach)
- AI must never influence:
  - verdict logic
  - exit codes of `cassian test`
  - execution semantics
  - runtime mutation

---

## Workflow contract (how we work)
Agents follow the loop:

1) **Read**: relevant docs + current code
2) **Explain**: what is true today + what will change
3) **Propose**: smallest safe change + file list + acceptance criteria
4) **Implement**: only after explicit approval (unless asked directly to implement)
5) **Verify**: update/extend verification scripts and/or negative tests
6) **Document**: update `docs/ai/NOW.md`, and append any new locked decisions to `docs/ai/DECISIONS.md`

---

## Scope guardrails
Cassian Gate is a deterministic **validation gate**, not a lab tool.

Do NOT:
- add exploratory/lab features
- add heuristics or probabilistic gating
- widen scope without updating milestones/tasks and getting explicit approval
- refactor for aesthetics before objective “split/refactor” signals

---

## Output requirements for AI assistance
When proposing changes, always include:
- affected files
- new/changed behavior (explicit)
- what remains unchanged (explicit)
- verification plan
- rollback plan if change is risky

