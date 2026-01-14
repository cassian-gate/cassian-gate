# Tasks (Prioritized)

This is the active, scoped task list. Keep it aligned with milestones.

## v1 (current)
### Assistive AI (required)
1) Implement CLI commands:
   - `netsim ai explain`
   - `netsim ai review`
   - `netsim ai coach`
2) Implement deterministic bundle builders (pre-AI scaffold)
3) Implement safe provider boundary (explicit opt-in, BYO key via env)
4) Add tests:
   - missing artifacts => exit 2
   - AI disabled => exit 0 + scaffold output
   - json output schema validation
   - grep guard: AI module never imports runtime
5) Docs:
   - update `docs/ai/CLI-CONTRACT-AI.md` if behavior changes

## v1.5 (planned, do not implement now)
- VM runtime enablement (runtime-agnostic model)
- limited pre/post operational state capture (supporting evidence only)
- grey failures (tc/netem) and coverage awareness (advisory)

## v2 (planned)
- deterministic replay
- blast-radius reporting (advisory)
- richer AI summarization (still advisory)

