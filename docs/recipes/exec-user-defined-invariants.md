# Recipe: Writing a user-defined invariant (`exec`)

Cassian Gate ships a fixed catalog of built-in invariants — BGP session up, route present, interface state, and so on (see the [Topology Schema Reference](../topology-schema-v1.5.md)). When the truth you need to assert isn't in that catalog, a **user-defined invariant** lets you write it yourself: pick a node, run a read-only command on it, and assert something about the output. The result is authoritative — it passes or fails the gate exactly like a built-in check.

This recipe shows you how to write one.

## The shape

A user-defined invariant is a test with `kind: exec`:

```yaml
tests:
  - name: my_check                     # a name you choose
    kind: exec
    src: r1                            # the node to run on
    command: vtysh -c "show version"   # a read-only command
    assertion:
      contains: FRRouting              # what must be true about the output
    expect: pass                       # pass = the assertion should hold
```

That's the whole anatomy. The four moving parts are the **node**, the **command**, the **assertion**, and the **expectation**.

## Step by step

**1. Name it and point it at a node.** `src` is the node the command runs on — it must be a node in your `nodes:` list. Cassian works out the node's type itself; today that type has to be `frr` or `nft-fw`.

**2. Give it a read-only command.** Cassian only allows commands that *read* state, never change it:

- on an `frr` node: `vtysh -c "show …"` (any `show` command)
- on an `nft-fw` node: `nft list …` (e.g. `nft list ruleset`)

Anything else — a config change, a raw shell — is rejected when you run `cassian validate`, before anything is deployed.

**3. Assert something about the output.** You attach exactly one typed check (no freeform grepping). The simplest is `contains`:

```yaml
assertion:
  contains: FRRouting
```

The full menu is below.

**4. Say what you expect.** `expect: pass` means "this assertion should hold." `expect: fail` flips it — "this assertion should *not* hold" — which is how you write a negative invariant (see [Negative invariants](#negative-invariants)).

## A worked example

Say you want to assert *"on r1, the BGP session to 10.0.0.2 is established."* That state lives in `show bgp summary json`, so reach into that JSON:

```yaml
  - name: bgp_peer_established
    kind: exec
    src: r1
    command: vtysh -c "show bgp summary json"
    assertion:
      field:
        path: [ipv4Unicast, peers, "10.0.0.2", state]
        op: "=="
        value: Established
    expect: pass
```

In plain English: run the command, parse the output as JSON, walk down into `ipv4Unicast` → `peers` → the entry for `10.0.0.2` → its `state`, and check that value equals `Established`. Each item in `path` is one step down. (`"10.0.0.2"` is quoted because it's a key that contains dots — quoting keeps it as one literal step rather than four.)

## The assertion menu

Pick exactly one:

```yaml
assertion: { contains: "FRRouting" }                 # text is present in the output
assertion: { not_contains: "Idle" }                  # text is absent
assertion: { equals: "exact whole output" }          # trimmed output equals this exactly
assertion: { matches: "neighbor .* Established" }    # regex matches somewhere in the output
assertion: { count: { pattern: "Established", op: ">=", value: 2 } }   # regex appears N times
assertion: { field: { path: [k1, "k2"], op: "==", value: X } }        # reach into JSON output
```

A few things worth knowing up front:

- **Quote the operators and any dotted keys** — `op: "=="`, `op: ">="`, and `path: [..., "10.0.0.2", ...]` — so YAML reads them as text rather than guessing.
- **`field` needs JSON.** Use a command whose output is JSON (e.g. `show bgp summary json`), and note it walks *dictionary* keys — it reads `{...: {...: value}}` shapes, not list positions.
- **`==` is exact and type-aware.** `"Established"` won't match `"established"` or a number. `>=` and `<=` only work on numbers.
- **A missing thing is a fail, not a crash.** If the output can't be parsed, a key isn't there, or the command times out, the check simply records `observed: fail` — safely. It never errors out, and it never silently passes.

## Negative invariants

`expect: fail` lets you assert that something must *not* be true. For example, "the BGP peer must not be stuck in Idle":

```yaml
  - name: bgp_peer_not_idle
    kind: exec
    src: r1
    command: vtysh -c "show bgp summary json"
    assertion:
      field:
        path: [ipv4Unicast, peers, "10.0.0.2", state]
        op: "=="
        value: Idle
    expect: fail
```

The assertion *looks for* `Idle`; `expect: fail` says you expect it not to match. So if the peer really is Idle, the assertion holds → the gate fails. If it's anything else, the assertion doesn't hold → the gate passes. (An evaluation error always counts as a fail, so a broken check can never accidentally satisfy a negative invariant.)

## Running it and reading the result

```bash
cassian validate <topology.yaml>    # checks your exec test is well-formed (no deploy)
cassian test <topology.yaml>        # deploys, runs it, writes the authoritative result
```

After a run, the authoritative result is `labs/clab-<lab>/results.json`; `results.summary.txt` is the human-readable view. A passing `exec` record carries the command, the assertion, and the captured output as evidence. A *failing* one additionally carries an `observed:` block showing exactly what was seen — so you can read why it didn't match.

One tip while you're iterating: the gate stops at the first failing test by default. To run every test regardless (handy when you have several invariants in flight), add `--keep-going`:

```bash
cassian test <topology.yaml> --keep-going
```

## See also

- [Topology Schema Reference §2a](../topology-schema-v1.5.md) — the formal `exec` schema: the full key set, the read-only allow-list, and the typed-assertion contract.
- [Cheatsheet](../cheatsheet.md) — quick syntax reference and the four-quadrant verdict table.
