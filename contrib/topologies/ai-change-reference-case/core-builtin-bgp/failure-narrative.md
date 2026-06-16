# Failure narrative — core variant

## The change
An AI agent was asked to bring up eBGP peering between `r1` (AS 65001) and `r2` (AS 65002), directly connected over `10.0.0.0/30` (`r1` = `.1`, `r2` = `.2`).

## The mistake
On `r1`, the AI configured the neighbor toward `r2` with `remote_as: 65003`. It should have been `65002`. One digit. The YAML is well-formed and `cassian validate` passes; a quick review skims past it.

## Why the session never comes up
`r1` opens the session expecting peer AS **65003**; `r2` announces **65002**. The AS numbers disagree, the OPEN is rejected, and the session never reaches `Established` — it sits in `Active`/`Connect`.

## Why the gate catches it
The human-authored intent declares the built-in invariant *"on r1, the BGP session to 10.0.0.2 must be up."* The `bgp_session_up` invariant observes r1's BGP state, finds the session is not Established, and returns **FAIL** — with the observed state rendered in `results.summary.txt`.

## The point
The AI's config was treated as ordinary candidate input and run through the same deterministic gate as any human-authored config. No special handling. A plausible-looking AI change that would have broken peering was caught before it shipped — the UC-1 trigger event, demonstrated with a built-in invariant.
