# Online AI Support (BYO Key) — Advisory Only

This document explains how **optional online AI** works in **Cassian Gate**.

Online AI is **assistive only** and **never authoritative**.  
It exists to improve explainability and onboarding — **not correctness**.

## Core Rule (Non-Negotiable)

**Online AI must never affect pass/fail outcomes, exit codes, or execution.**

If online AI is unavailable for any reason, Cassian Gate must behave identically to offline mode (same deterministic bundle, same semantics, same gate behavior).

This is enforced by code, verification scripts, and golden-file fixtures.

## What Online AI Is Used For

When explicitly enabled through the shipped `cassian ai` entrypoint, online AI may:
- produce clearer explanations and summaries
- provide richer reasoning and context for suggestions
- give onboarding and workflow guidance

Online AI only consumes deterministic artifacts such as:
- `results.json`
- `topology.resolved.yaml`
- deterministic bundles produced by Cassian Gate

Online AI does **not**:
- run tests
- inject faults
- modify topology/configs
- influence verdicts
- influence exit codes
- influence CI behavior

## Offline-First Design (Authoritative)

Cassian Gate is fully functional without AI.

Offline mode always:
- builds deterministic bundles
- produces authoritative results
- exits deterministically
- supports CI and audit workflows

Online AI is a pure overlay on top of this foundation.

## BYO Key Model (Required)

Cassian Gate does not ship API keys and does not manage credentials.

Users provide their own API key via environment variables.
There is:
- no SaaS dependency
- no background calls
- no hidden uploads
- no telemetry

Online AI is activated only when explicitly invoked through the shipped `cassian ai` surface.

## Installation (Example)

Install the OpenAI SDK locally:

```bash
pip install openai
````

Cassian Gate will not import or use the SDK unless online AI is explicitly invoked through the shipped `cassian ai` surface.

## Configuration

Online AI configuration is read only from environment variables.

Required:

```bash
export AI_NETSIM_AI_PROVIDER=openai
export AI_NETSIM_AI_API_KEY="sk-..."
```

Optional:

```bash
# Optional OpenAI-compatible endpoint (proxy, gateway, etc.)
export AI_NETSIM_AI_BASE_URL="https://api.openai.com/v1"
```

If any required value is missing or invalid, Cassian Gate:

* reports `ai_status: unavailable`
* reports a reason in `ai_error`
* exits `0`
* still emits the deterministic bundle output

## CLI Usage

The shipped AI entrypoint is:

```bash
cassian ai [--online] [--lab LAB] [--artifacts ARTIFACTS] [--format json|text] [question ...]
````

Supported surface:

* `--online`
  Explicit opt-in for online-enriched advisory rendering

* `--lab LAB`
  Provide an explicit lab name as advisory context

* `--artifacts ARTIFACTS`
  Provide an explicit artifacts directory as advisory context

* `--format json|text`
  Select advisory output format

* `[question ...]`
  Optional natural-language advisory question

Online AI is never enabled by default.
````

## Output Semantics

AI commands always emit a deterministic bundle, and may optionally attach `ai_output`.

Offline (default / bundle-only):

```json
{
  "ai_status": "offline",
  "ai_error": "",
  "model_used": null
}
```

Online success:

```json
{
  "ai_status": "ok",
  "model_used": "gpt-4.1-mini",
  "ai_output": {
    "summary": "...",
    "findings": [],
    "suggested_next_tests": []
  }
}
```

Online failure (non-gating):

```json
{
  "ai_status": "unavailable",
  "ai_error": "Error code: 401 - invalid_api_key",
  "model_used": "gpt-4.1-mini"
}
```

Important:

* even when online AI fails, the command exits `0`
* output remains deterministic
* the deterministic bundle is never overwritten by AI output

## Bundle-First Architecture (Critical)

Execution order is fixed:

1. build deterministic bundle
2. optionally write the bundle to disk
3. attempt online AI (optional)
4. attach `ai_output` (advisory only)
5. emit final output

This guarantees reproducibility, auditability, and offline equivalence.

## Security & Privacy

Cassian Gate:

* never logs raw API keys (errors are sanitized)
* never stores credentials
* never makes background network calls
* never uploads data without explicit operator invocation through the shipped AI surface

Only the deterministic artifact/context surface used by the shipped AI entrypoint is sent to the provider when online AI is explicitly invoked.

## CI & Automation Safety

Online AI is CI-safe by design (non-gating), but recommended practice is:

* do not enable optional online AI in CI unless you explicitly want non-gating advisory output
* use deterministic artifacts for PR review
* validate stability via golden fixtures (not live calls)

## Why Online AI Is Optional

Cassian Gate’s authority comes from deterministic execution, not AI.

Online AI exists to:

* reduce resistance
* improve understanding
* accelerate onboarding
* explain failures more clearly

If AI disappeared tomorrow, Cassian Gate would remain fully functional.

## Future Extensions (Non-Binding)

Possible future additions (not commitments):

* additional OpenAI-compatible providers
* stricter JSON schema validation for `ai_output`
* improved prompt design and parsing

All future AI features must obey the rules in this document.

## One-Sentence Summary

Online AI in Cassian Gate is a strictly optional, advisory explanation layer that can fail safely without affecting correctness, determinism, or trust.

````

---

