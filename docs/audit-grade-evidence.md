# Audit-Grade Evidence

Every authoritative gate run writes a `results.json` — the verdict artifact. Cassian Gate enriches that artifact with a small set of **audit-grade evidence** fields so a `results.json` can be read, trusted, and re-verified on its own, without access to the machine that produced it or the source tree that ran it.

These fields are **additive and advisory**: they describe and attest to the run, but they never change the verdict. A run's PASS/FAIL is decided exactly as before; the audit fields sit alongside it.

## What gets written

A finalized `results.json` carries four audit fields in addition to the usual verdict content:

- **`release_version`** — the Cassian Gate version that produced the bundle, as an inline string (for example, `"2.0.2"`). It records *which* gate generated the evidence, so a stored `results.json` remains interpretable as tooling evolves.
- **`tamper_check`** — a self-describing integrity stamp over the authoritative content of the bundle (see below).
- **`intent`** — the operator's declared purpose for the run, echoed verbatim when supplied (see [Declaring intent](#declaring-intent)).
- **`baseline_diff`** — reserved supporting evidence describing how this run compares to a baseline. It is written only when a baseline comparison is in scope and is absent on ordinary single runs.

Because every field is inline and literal, a `results.json` is **self-contained**: it can be interpreted without resolving any external URL, registry, or source file.

## The tamper check

`tamper_check` is an object with a stable shape:

```json
"tamper_check": {
  "algo": "sha256",
  "digest": "<64 hex characters>",
  "domain": "canonical-filtered",
  "state": "verified"
}
```

The `digest` is a SHA-256 computed over a **canonical serialization** (sorted keys, stable encoding) of the bundle's authoritative content. The `domain` names what the digest covers — `canonical-filtered` means the canonical bundle with environment-variant fields filtered out (see below).

To keep the digest meaningful, fields that vary by environment or wall-clock rather than by result are **excluded by name** from the hashed content — run timing, start/finish timestamps, and local filesystem paths. This is deliberate: the same authoritative outcome produces the **same digest** whether it runs on your laptop or a CI runner, and a replay of the same evidence reproduces the same digest. What the digest *does* cover is the verdict-bearing content — change a test's verdict or the overall result, and the digest changes.

`state` is the honest signal of whether the stamp could be computed:

- **`verified`** — the digest was computed over the bundle; it is present and checkable.
- **`unverifiable`** — the stamp could not be computed; **no digest is emitted**. An `unverifiable` stamp is never presented as `verified`, and the absence of a digest is never a token that can be mistaken for a passing check.

### Verifying a bundle

To confirm a stored `results.json` has not been altered, recompute a SHA-256 over the same canonical domain and compare it to the recorded `digest`. Because gate runs are deterministic, re-running the same authoritative evidence yields a byte-identical bundle and therefore the same digest — replay is itself a verification path.

## Declaring intent

`intent` lets an operator record *why* a run happened — a change ticket, a pre-production check, a named validation — directly in the evidence. Declare it as a single top-level string in the topology:

```yaml
name: my-change-validation
intent: "pre-production change validation — ticket-4412"

nodes:
  # ...
```

When declared, `intent` is echoed verbatim into `results.json`. It is an **input field**, validated under the same authoritative-input handling as the rest of the topology: it must be a single declarative string. A malformed `intent` — for example, a structured object instead of a string — is hard-failed at validation with a message that names the field and points to the correction, rather than being silently accepted.

`intent` is **verdict-invariant**: declaring it, omitting it, or changing its text never changes a run's PASS/FAIL. It is evidence about the run, not an input to the decision. When not declared, no `intent` field is synthesized — the bundle simply omits it.

## Baseline comparison

`baseline_diff` is reserved for runs where a comparison against a known-good baseline is in scope. On an ordinary single run it is omitted entirely. When written, it is **supporting evidence only** — never verdict-bearing — it is deterministic across repeats, and it is gated on comparability: if the two runs are not comparing like for like (for example, the topology identity differs), the diff records that the comparison is not valid rather than presenting a misleading delta.

## Why this matters

Taken together, these fields make a `results.json` a durable, portable record: it states which gate produced it, attests to its own integrity, carries the operator's declared purpose, and remains fully interpretable in isolation — the properties an evidence artifact needs to be trusted long after the lab that produced it is gone.
