# Locked Decisions (Append-only)

This file is append-only. Do not rewrite history; add dated entries.

## 2026-01 — Control-plane precheck semantics (scenarios)
- Default tests: global BGP precheck runs
- Scenarios: global precheck skipped by default
- `--precheck-controlplane` re-enables it
- Rationale: convergence must be explicit and scenario-timeline authoritative

## 2026-01 — wait_for (v1 scope)
- `wait_for` is ping-only in v1 (tcp rejected)
- Deterministic retry/timeout behavior; fail-fast validation

## 2026-01 — Scenario determinism
- Fault steps emit exactly one `scenario_fault` event per step
- Fail-fast validation prevents partial execution on invalid scenario references

## 2026-01 — Assistive AI authority boundary
- AI is advisory only
- artifact-only inputs
- never affects verdicts or exit codes
- explicitly invoked only

