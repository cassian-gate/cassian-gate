# PR Checklist (Required for Merge)

## Determinism / authority
- [ ] No change to `netsim test` authority model
- [ ] No heuristic or probabilistic gating added
- [ ] Fail-fast on ambiguity preserved or strengthened

## Artifacts
- [ ] results.json schema preserved (or backward compatible if changed)
- [ ] Any new fields are deterministic and documented
- [ ] summary.txt remains non-authoritative

## AI-specific
- [ ] AI commands read artifacts only
- [ ] AI module does not import runtime or call execution paths
- [ ] AI commands always emit `authority: advisory`
- [ ] AI commands always exit 0 unless usage/artifact error (exit 2)

## Verification
- [ ] Tests added/updated (unit or golden fixtures)
- [ ] Negative tests updated if validation rules changed
- [ ] Verification script(s) still pass

## Docs
- [ ] `docs/ai/NOW.md` updated if focus shifted
- [ ] New locked decisions appended to `docs/ai/DECISIONS.md` if needed

