# Your CI passed. The change still broke production. Here's the gap.

A network engineer kicks off a config change that touches a dozen nodes. They've run it through CI: the YAML lints, the templates render, the diff looks clean, the pipeline is green. They deploy. Three minutes later a BGP session flaps and they're rolling back.

Nothing in that pipeline was wrong. Lint checked syntax. The renderer checked that the templates produce output. The diff showed what the text changed. What none of them did was *run the change and watch what the network actually does* — observe the session come up, the route get advertised, the failover converge. The pipeline validated the artifact. It never validated the behavior.

That gap is what Cassian Gate exists to close, and v2.1 is the release where the gate gets meaningfully harder to fool. This post walks what's new, shows you real input and real output, and is honest about where the boundary sits.

## Why network CI is structurally different from application CI

For application code, CI is a solved shape: run the tests, and the tests execute the code. A passing suite means the code did the thing under conditions close enough to production that you trust it.

Network changes don't get that for free. A configuration can be internally consistent and still be operationally wrong. A route policy can read correctly and still leak or suppress a prefix under real protocol interaction. A failover path can look fine on paper and converge incorrectly under load. The tools that look like "network CI" — linters, template renderers, config diffs, static analyzers — are genuinely useful, but they reason *about* the configuration. They don't stand up the change and execute it.

Cassian Gate's whole premise is that for the changes that can actually hurt you, you want the execution, not the inference. You declare what the change is allowed to affect and what must remain true, and the gate runs it on clean-state runtime and returns a binary verdict bound to that declaration.

## What Cassian Gate is — and the one scale commitment everything follows from

Cassian Gate is a deterministic, execution-backed network change-validation gate. It sits between *change proposed* and *change deployed*. You declare a topology and the invariants you care about; the gate provisions clean-state runtime, executes, and returns an explicit PASS or FAIL with reproducible artifacts. The verdict lives in execution and its artifacts — never in a heuristic, a score, or an AI's opinion.

The architectural commitment that everything else follows from is a scale boundary:

> Cassian Gate is a per-change clean-state lab on the **blast-radius scope** of your change — not a whole-network model.

For each change you declare the segment that change can actually affect: a fabric segment, a DCI path, a routing domain, a cloud interconnect, a failure domain. The gate stands up clean-state runtime for *just that segment*, validates your declared invariants against it, and returns a verdict for that one change. There is no continuous model of your entire network and no claim of whole-network coverage. The question the gate is built to answer is "can it deterministically validate the part of the network where this high-risk change can cause damage?" — not "can it model the whole enterprise?"

That boundary is deliberate, and it's the reason the gate can be deterministic and CI-safe at all. It also draws a clean line against several adjacent tools, which I'll come back to below.

## What v2.1 ships

v2.1 is the second significant release on the v2 line. Most of the work hardens the engine so that what the gate proves, it proves the same way every time — and what it rejects, it rejects with enough detail for you to act. Concretely:

**A standing engineer-experience guarantee on authoritative output.** From this release line forward, every new invariant ships with the §13-mandated actionable output, and §13 is preserved on every change (DC §14): when the gate rejects authoritative input, the rejection tells you *what* was wrong, *where* in the input, and *what would be valid*; when an invariant fails, the human-readable summary shows the invariant identity, the declared expectation, and the **observed state** — the actual data that made it fail — without re-running the gate or reaching for a second tool. Crucially, an engineer who never invokes any AI surface gets all of this directly from the deterministic engine. (You'll see this in the output snippet below.)

**User-defined invariants (`kind: exec`).** The highest-leverage capability in the release. Alongside the built-in invariant types, you can now declare your own check as a read-only command plus a typed assertion (`contains`, `field`, `count`, and more). It runs through the same verdict machinery, with the same pass/fail/expect semantics and the same failed-invariant rendering — so a custom check is a first-class gate citizen, not a bolt-on script.

**Two new built-in BGP invariants.** `bgp_community` matches communities on a received prefix; `bgp_as_path` validates AS-path properties. These bring the built-in invariant catalog to fifteen types, on top of the user-defined `exec` kind.

**Selective execution with `cassian test --tag`.** Tag tests and run a subset. Every test that *isn't* selected is recorded as an explicit `not_executed` verdict — because in a gate, silence must never read as success.

**Audit-grade evidence properties in `results.json`.** Four additive, advisory, verdict-invariant fields: a `release_version` stamp, a `tamper_check` SHA-256 over the canonical artifact domain (reports `verified` / `unverifiable`, with nothing spoofable to fake), an operator-declared `intent` echoed back verbatim, and a reserved `baseline_diff`. These make the artifact more auditable; none of them change a PASS/FAIL. The verdict is still reached the only way it's ever reached — by execution.

**Brownfield first-importer initiation (`cassian import`).** A new command that converts a NetBox-derived JSON description (in Cassian Gate's own declared contract shape) plus optional rendered FRR configs into a `topology.yaml` and a starter-invariants file. It is fully offline, deterministic, and non-synthesizing — it never invents state, and it fails closed on anything ambiguous. This is the *initiation* of brownfield onboarding, not the finished story: a direct real-NetBox export adapter is Phase 2 work, named and deferred rather than half-shipped.

**The AI-change canonical reference case, and the public scope-discipline page.** Two pieces of evidence shipped as docs, covered next.

Alongside these: engine validation hardening, expect-fail invariant semantics tightened across the catalog, a renderer-regression fix, and a documentation grooming pass to bring every page back in line with product reality.

## What declaring a change actually looks like

Here's real input that ships in the repository. The topology declares an eBGP peering, and the `tests:` block declares the human-authored intent — a built-in invariant asserting the session establishes:

```yaml
name: ai-change-core-bgp-passing

nodes:
  - name: r1
    type: frr
    asn: 65001
    router_id: 1.1.1.1
    bgp:
      neighbors:
        - peer: r2
          remote_as: 65002

  - name: r2
    type: frr
    asn: 65002
    router_id: 2.2.2.2
    bgp:
      neighbors:
        - peer: r1
          remote_as: 65001

links:
  - endpoints: ["r1:eth1", "r2:eth1"]
    ipv4: ["10.0.0.1/30", "10.0.0.2/30"]

tests:
  - name: r1_bgp_session_to_r2_up
    kind: invariant
    type: bgp_session_up
    node: r1
    dst: 10.0.0.2
    expect: pass
```

A user-defined invariant is just as short — a read-only command and a typed assertion:

```yaml
tests:
  - name: r2_learns_route_1_1_1_1_32
    kind: exec
    src: r2
    command: vtysh -c "show bgp ipv4 unicast 1.1.1.1/32 json"
    assertion:
      contains: "1.1.1.1/32"
    expect: pass
```

## What running the gate looks like

You run any topology the same way:

```bash
cassian test contrib/topologies/ai-change-reference-case/core-builtin-bgp/passing/topology.yaml
```

A clean pass is unambiguous — `RESULT: PASS`, exit code `0`, artifacts on disk, and a summary that's explicit about what it did and did *not* validate:

```text
=== AUTHORITATIVE TEST VERDICT ===
verdict: PASS
scope: topology=ai-change-core-bgp-passing tests=all scenarios=none

lab: ai-change-core-bgp-passing
result: pass
tests: total=1 passed=1 failed=0

PASS means:
  All declared tests passed against real execution behavior
PASS does not mean:
  Validation of behaviors not declared in this topology
  Coverage of all possible failure modes
```

The more interesting output is a failure. Run the failing form of the user-defined-invariant variant — where the session is healthy but the router never advertises the prefix it should — and the gate fails with the observed state rendered:

```bash
cassian test contrib/topologies/ai-change-reference-case/udi-bgp-variant/failing/topology.yaml
```

```text
verdict: FAIL
failed_tests:
 - r2_learns_route_1_1_1_1_32 (exec) r2-> : exec assertion not satisfied (observed fail, expected pass)
    exec:
      command: vtysh -c "show bgp ipv4 unicast 1.1.1.1/32 json"
      assertion: {"contains": "1.1.1.1/32"}
      expected: pass
    observed:
      command: vtysh -c "show bgp ipv4 unicast 1.1.1.1/32 json"
      returncode: 0
      stdout_excerpt: {
}
```

That `observed` block is the same observed-state rendering the §13 guarantee mandates for built-in invariants, applied here to a user-defined check: the command that ran, its return code, and the empty BGP table that proves the route is absent — enough to diagnose without re-running anything. And note what *didn't* happen: the command exited `0`, but an empty table against a `contains` assertion is still a FAIL. Silence is not a pass.

## Where Cassian Gate sits next to the tools you've probably already evaluated

If you're researching this space in 2026 you've likely encountered several adjacent tools. The distinctions are architectural, not competitive — in most cases the other tool and Cassian Gate answer different questions and sit well together. The full treatment lives on the [scope-and-scale discipline page](https://docs.cassiangate.dev/latest/scope-discipline/); the short version:

**Whole-network digital twins** (Forward Networks' Forward Predict territory) maintain a continuous, queryable model of the entire network and are powerful for asking questions across all of it. Cassian Gate doesn't model the network; it executes a per-change clean-state lab on the declared blast-radius scope and returns a verdict for that one change. Different shape, different commitments — complementary where a team runs both.

**AI-agent operations platforms** (Cisco AgenticOps, Arista AVA territory) drive operational workflows with AI agents and are built for exactly that. In Cassian Gate, AI never holds verdict authority — it can advise or annotate, but PASS/FAIL comes from executing the declared scenario. An agentic-ops platform could gate its own actions on a deterministic verdict like the one Cassian Gate produces.

**Configuration analyzers** (Batfish territory) reason rigorously about safety from configuration text and modelled state, and catch a real class of problems early. Cassian Gate reaches its verdict by executing on clean-state runtime and observing what the network actually does. Static analysis and execution-backed validation catch different classes of problem and complement each other.

The pattern is consistent: Cassian Gate is the execution-backed proof step for a single change, scoped to its blast radius. It is not a chaos tool, not a generic scripting surface, not a SaaS gate, and not autonomous network operations. It produces a verdict and artifacts; a person or a pipeline decides what to do with them.

## The AI-change angle, demonstrated rather than asserted

"AI safety for network changes" invites overclaiming, so v2.1 ships the claim as a runnable [reference case](https://docs.cassiangate.dev/latest/recipes/ai-change-reference-case/) instead of a paragraph. An AI assistant can propose a change and open a PR faster than a human can read it — and the gate's answer is deliberately unremarkable: an AI-authored change is validated by exactly the same gate as a human-authored one. No provenance score, no trust dial, no special path. The reference case is a matched PASS/FAIL pair where the *only* thing that differs is whether the change is correct, and a committed proof harness checks the engine source to keep it that way. AI can draft the change and even draft the invariants; the verdict still comes from running the declared scenario.

## On the audit-evidence properties

A note on framing, because it's easy to read more into this than is there. The artifact-format work in v2.1 — the tamper check, the version stamp, the echoed intent — is *engineering*. It makes `results.json` something you can reasonably attach to a change ticket or a PR and trust as a record. What it is *not*, yet, is a commercial reporting surface. Enterprise artifact rendering and hosted aggregation are deliberately deferred to a much later phase, gated on real buyer pull rather than built ahead of it. Today the value is local and concrete: a more auditable verdict artifact for the engineer running the gate.

## What's next

The next phase is **SONiC** support — the most important open NOS after FRR, and a locked commitment. Bringing up a NOS in Cassian Gate isn't a checkbox; it means working through every NOS-specific and mixed item in the feature inventory until lifecycle, provisioning, and invariant validation all genuinely work on SONiC containers. Completing the brownfield importer — the real-NetBox export path the v2.1 initiation sets up — is also Phase 2 work. A strategic reassessment governs how that phase is scoped before it starts.

## On how this gets built, and an invitation

I built Cassian Gate over roughly the past year and a half, part-time alongside a day job in network engineering. A solo, part-time project staying coherent across that span isn't an accident of discipline-by-vibes; it's the result of a governance spine that's boring on purpose — a locked doctrine that says what the gate *is*, a design contract that binds the output surfaces, an atomic-completion rule that forbids shipping a capability half-finished, and a four-stage review cycle that separates authoring a change from ratifying it. That structure is why "every new invariant ships with actionable failure output" is a guarantee and not an aspiration.

It's all open source under Apache 2.0, and the governance is designed to be transferable — the project can't be locked away. If you work on network changes and any of this resonates, the most useful thing you can do is run it on something real and tell me where it breaks. Honest friction is worth more than stars.

- Install: `pipx install cassian-gate`, then `cassian doctor`
- Repository and issues: <https://github.com/cassian-gate/cassian-gate>
- Discussions (questions, use cases, feedback): <https://github.com/cassian-gate/cassian-gate/discussions>
- Scope-and-scale discipline: <https://docs.cassiangate.dev/latest/scope-discipline/>
- AI-change reference case: <https://docs.cassiangate.dev/latest/recipes/ai-change-reference-case/>

— the Cassian Gate project ([github.com/cassian-gate](https://github.com/cassian-gate/cassian-gate))
