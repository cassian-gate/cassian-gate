# Failure narrative — what the AI got wrong

## The change
An AI agent was asked to bring up eBGP peering between two routers:

- `r1` — local AS **65001**
- `r2` — local AS **65002**
- directly connected over `10.0.0.0/30` (`r1` = `.1`, `r2` = `.2`)

## The mistake
On `r1`, the AI configured the neighbor toward `r2` with `remote_as: 65003`.

It should have been `65002` — r2's real ASN. One digit. The YAML is well-formed, `cassian validate` passes, and a quick human review can easily skim past it.

## Why the session never comes up
BGP checks the peer's advertised AS against what the local side expects. `r1` opens the session expecting peer AS **65003**; `r2` announces **65002**. The AS numbers disagree, so `r1` rejects the OPEN and the session never reaches `Established` — it sits in `Active`/`Connect`.

## Why the gate catches it
The human-authored intent declares: *on r1, the peer `10.0.0.2` must be `Established`.* The gate runs `show bgp summary json` on r1, reads `peers["10.0.0.2"].state`, finds it is not `Established`, and returns **FAIL** — with the observed state rendered in `results.summary.txt` so the operator can see exactly why.

## The point
The AI's output was treated as ordinary candidate input and run through the same deterministic gate as any human-authored config. No special handling, no benefit of the doubt. A plausible-looking AI change that would have broken peering in production was caught before it shipped — the UC-1 trigger event.
