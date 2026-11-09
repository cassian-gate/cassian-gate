# Audit-Grade Evidence

Every authoritative gate run writes a `results.json` — the verdict artifact. Cassian Gate enriches that artifact with a small set of **audit-grade evidence** fields so a `results.json` can be read, trusted, and re-verified on its own, without access to the machine that produced it or the source tree that ran it.

These fields are **additive and advisory**: they describe and attest to the run, but they never change the verdict. A run's PASS/FAIL is decided exactly as before; the audit fields sit alongside it.

## What gets written

A finalized `results.json` carries four audit fields in addition to the usual verdict content:

- **`release_version`** — the Cassian Gate version that produced the bundle, as an inline string (for example, `"2.1.0"`). It records *which* gate generated the evidence, so a stored `results.json` remains interpretable as tooling evolves.
- **`tamper_check`** — a self-describing integrity stamp over the authoritative content of the bundle (see below).
- **`intent`** — the operator's declared purpose for the run, echoed verbatim when supplied (see [Declaring intent](#declaring-intent)).
- **`baseline_diff`** — supporting evidence describing how a change run compares to its baseline. It is populated by `cassian test --two-run` on the change run, and is absent on ordinary single runs.

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

The recipe, exactly, so the check needs nothing but the file and a SHA-256 tool:

1. Parse `results.json` as JSON.
2. Remove every object member, at any depth, whose name is one of `duration_ms`, `started_at`, `finished_at`, `resolved_topology_mtime`, `resolved_topology_path` or `tamper_check`.
3. Remove the members at these paths: `timing`, `blast_radius.path` and `authority.supporting_evidence.path`. A path names object members from the top of the file; an array does not add a step, so `authority.supporting_evidence.path` is the `path` member of every entry in the `authority.supporting_evidence` array.
4. Serialize what remains as JSON with the keys of every object sorted, an indent of two spaces, `,` between items and `: ` after keys, and non-ASCII characters written as themselves rather than as `\u` escapes — what Python's `json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)` produces. End the text with exactly one line feed.
5. Compute the SHA-256 of that text's UTF-8 bytes. The bundle is unaltered when the lowercase hex digest equals `tamper_check.digest` and `tamper_check.state` is `verified`.

A stamp whose `state` is `unverifiable` carries no digest and cannot be checked this way. Bundles written by earlier versions of Cassian Gate recorded the digest before the run's last edits to the record, so they do not verify by this recipe; re-running the same evidence produces a bundle that does.

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

`baseline_diff` is populated by `cassian test --two-run`. After running the baseline and change topologies from clean state, the change run's `results.json` carries a determinism-safe subset of the behavioural comparison — per-test, per-scenario, and per-step `expected`/`observed`/`verdict` deltas plus a comparability record. On an ordinary single run it is omitted entirely. It is **supporting evidence only** — never verdict-bearing — and it is deterministic across repeats: timing and host-specific noise are excluded from the field, so a replay over the same evidence reproduces a byte-identical `baseline_diff`. It is gated on comparability: if the two runs are not comparing like for like (for example, the topology identity differs), the comparison hard-fails and records that it is not valid rather than presenting a misleading delta.

## Why this matters

Taken together, these fields make a `results.json` a durable, portable record: it states which gate produced it, attests to its own integrity, carries the operator's declared purpose, and remains fully interpretable in isolation — the properties an evidence artifact needs to be trusted long after the lab that produced it is gone.
