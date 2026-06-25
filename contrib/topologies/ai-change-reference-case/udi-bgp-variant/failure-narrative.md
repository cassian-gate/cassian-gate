# Failure narrative — bonus variant (detection / present-half)

## The change
An AI agent was asked to set up eBGP between `r1` (AS 65001) and `r2` (AS 65002) **and** advertise r1's loopback `1.1.1.1/32` so r2 can reach it.

## The mistake
The AI got the peering right — correct `remote_as` on both sides — so the session comes up fine. But it **forgot to advertise the route**: there is no `networks:` block on `r1`. The config is well-formed and `cassian validate` passes; the session establishes cleanly, so nothing looks wrong at a glance.

## What actually happens
Because the session **converges**, the gate's control-plane precheck passes and the declared check **runs**. The gate executes `show bgp ipv4 unicast 1.1.1.1/32 json` on `r2`, finds **no route** (`r2` never received the advertisement), and records a **FAIL** — with the observed (empty) state rendered in `results.summary.txt`. This is the gate *observing the bad state and reporting it* — the §13(c) present-half.

## Why the gate catches it
The human-authored intent declares: *"on r2, the route 1.1.1.1/32 must be present."* The AI's silent omission (a missing advertisement) is exactly the kind of plausible-looking change that establishes a healthy session yet quietly breaks reachability. The gate inspects the actual routing state, not just whether the session is up, and reports the missing route.

## The point
The AI's config was treated as ordinary candidate input through the same deterministic gate as any human-authored config. A change that "looks fine" — session up, no errors — but silently drops a route was caught and reported with the observed state. Paired with the core variant (where a more basic flaw blocks the check entirely), this shows the gate catching AI changes both ways: by inspecting-and-reporting, and by refusing to pass what it cannot evaluate.
