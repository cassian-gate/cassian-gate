# Failure narrative — core variant (guardrail / absent-half)

## The change
An AI agent was asked to bring up eBGP peering between `r1` (AS 65001) and `r2` (AS 65002), directly connected over `10.0.0.0/30`.

## The mistake
On `r1`, the AI set the neighbor's `remote_as` to `65003`. It should have been `65002`. One digit. The YAML is well-formed and `cassian validate` passes.

## What actually happens (read this — corrected)
`r1` expects peer AS **65003**; `r2` announces **65002**. They disagree, so the eBGP session **never establishes** — it sits in `Idle`/`Active`.

Because the session never converges, the gate's **control-plane precheck** ("BGP did not converge within 30s") **blocks the invariant before it can run**. The committed evidence shows this exactly: the record is **present** with `"verdict": "fail"`, `"observed": "blocked"`, `"error": "blocked before execution"`, `summary.tests_executed: 0`.

The summary renders the **absent-half** of the failed-invariant surface: it surfaces the invariant identity and the declared expectation, then states explicitly *"structured failure detail unavailable for this invariant type."* It does **not** render an empty or implicitly-absent detail.

## Why this is a clean demonstration
This is a genuine, loud authoritative **FAIL** (exit 1), not a silent pass and not a skipped/absent item. The gate **refused to pass a check it could not complete** — silence is never read as success. That is the doctrine point this variant makes: a fundamental AI error that stops the network converging is caught and failed honestly, with an explicit "detail unavailable" rather than a blank.

The companion **bonus variant** shows the other half of the story: a flaw where the session *does* come up but a route is missing, so the gate inspects the state and reports the bad route directly.

## The point
The AI's config was treated as ordinary candidate input through the same deterministic gate as any human-authored config — no special handling, no benefit of the doubt. The UC-1 trigger event, caught.
