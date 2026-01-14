# NOW (Current Focus)

Update this file whenever the implementation focus changes.

## Current focus
Implement **v1 Assistive AI** (non-authoritative, artifact-only):

- `netsim ai explain`
- `netsim ai review`
- `netsim ai coach`

## Scope
- Post-execution only
- Artifact-only inputs (results.json, topology.resolved.yaml, summary)
- Always advisory; never gating
- Always exit 0 unless usage/artifact error

## Non-goals
- No runtime interaction
- No config/topology mutation
- No YAML generation from coach
- No pass/fail prediction or confidence scoring

## Definition of done
- Commands work with AI disabled (deterministic scaffold output)
- Commands work with AI enabled (advisory text/json)
- Unit/golden tests added
- No runtime imports/calls from AI module
- PR checklist satisfied

