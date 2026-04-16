# Guardrails (Authoritative)

## Deterministic Core / Probabilistic Edge
- The core engine is deterministic and authoritative.
- AI is probabilistic and advisory.
- The boundary must never blur.

### Deterministic core (authoritative)
- `cassian test` verdict + exit code semantics
- scenario execution + fault orchestration
- results.json and resolved topology
- fail-fast validation rules

### Probabilistic edge (advisory)
- `cassian ai`
- evidence summarization
- coverage suggestions
- human guidance

## Gate-first UX (locked)
- `cassian test`:
  - runs from clean state
  - destroys any existing lab
  - executes deterministically
  - returns binary verdict
  - produces authoritative artifacts
- `cassian run`:
  - explicitly non-authoritative
  - for exploration/debug only

## No drift / no silent changes
- Defaults must not change without an explicit milestone update and verification updates.
- Any ambiguity must error before execution.
- Any schema addition must be deterministic and validated.

## What Cassian Gate is NOT
- not a general-purpose lab tool
- not chaos engineering
- not a packet analyzer / Wireshark replacement
- not AI-driven validation or auto-remediation

