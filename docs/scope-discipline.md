# Scope and scale discipline

Cassian Gate is a per-change clean-state lab for the blast-radius scope of a network change. For each change you declare the segment that change can actually affect — a fabric segment, a DCI path, a routing domain, a cloud interconnect, a failure domain — and the gate stands up clean-state runtime for just that segment, executes your declared invariants against it, and returns a binary PASS/FAIL verdict with reproducible artifacts. There is no continuous model of your whole network and no claim of whole-network coverage.

That is a deliberate scale boundary. The question Cassian Gate is built to answer is **"can it deterministically validate the part of the network where this high-risk change can cause damage?"** — not "can it model the entire enterprise?" Everything below follows from that one commitment: because the gate proves the blast radius of a change by executing it, and binds the verdict to a declared expectation, it is explicitly not several adjacent things you may have evaluated.

For the category-level authority boundary — what the gate decides and what it does not — see [Project principles](project-principles.md). This page does the complementary job: it names the specific tools and categories engineers most often place next to Cassian Gate, and draws the architectural line in each case. The distinctions are architectural, not competitive — in most of these cases the other tool and Cassian Gate answer different questions and sit well together.

## What Cassian Gate is not

**Not a whole-network digital twin** (Forward Predict territory). A digital twin maintains a continuous, queryable model of the entire network; Cassian Gate executes a per-change clean-state lab on the declared blast-radius scope and returns a verdict for that one change. Different shape, different commitments — complementary where a team runs both.

**Not an AI-agent operations platform** (Cisco AgenticOps, Arista AVA territory). Those platforms drive operational workflows with AI agents. In Cassian Gate, AI never holds verdict authority — it can advise or annotate, but PASS/FAIL is reached by executing the declared scenario, not by an agent's judgment. An agentic-ops platform could gate its actions on a deterministic verdict like the one Cassian Gate produces.

**Not a configuration analyzer** (Batfish territory). A configuration analyzer reasons about safety from configuration text and modelled state; Cassian Gate reaches its verdict by executing the declared scenario on clean-state runtime and observing what the network actually does. Static analysis and execution-backed validation catch different classes of problem and complement each other.

**Not a chaos engineering tool.** Chaos engineering injects faults into running systems to discover weaknesses empirically; Cassian Gate validates declared invariants in a pre-production clean-state lab before the change ships. They sit at different points in a resilience practice.

**Not a generic scripting surface.** The gate's authority comes from declared invariants and deterministic execution, not from arbitrary scripts whose meaning drifts over time, and every verdict is bound to a declared expectation. Automation frameworks can call the gate as a step, but the gate itself does not turn whatever you script into validation authority.

**Not a SaaS gate.** Cassian Gate runs locally and in CI on infrastructure you control — the same run on a laptop and in the pipeline — with no hosted service standing between your change and its verdict. Hosted platforms trade that for managed convenience; the local-first, CI-safe posture suits teams that need the gate inside their own boundary.

**Not feature-parity NOS modelling.** The goal is not to reproduce every feature of every network operating system; it is to execute the declared invariants that matter for a change on runtime good enough to validate them deterministically. Comprehensive NOS modelling and targeted invariant validation serve different goals.

**Not autonomous network operations.** Cassian Gate does not act on the network and does not remediate. It produces a verdict and reproducible artifacts; a person or a pipeline decides what to do with them. It is the proof step that can sit in front of an action — never the actor.

## Where the boundary comes from

None of these boundaries are authored on this page. The list of what Cassian Gate is not is fixed by the project's Doctrine and Design Contract; the blast-radius scale framing and the named-competitor disambiguation come from the project's Post-v2 Strategy. This page only translates those existing commitments into engineer-facing language — it introduces no new commitment and changes none of them. For the gate's full authority boundary, including how AI stays advisory and why only a recorded, declared-expectation PASS counts, see [Project principles](project-principles.md).
