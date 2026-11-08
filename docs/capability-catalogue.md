# Capability Catalogue

`cassian checks` prints a catalogue of what this release of Cassian Gate can check: each check with its parameters and its status on each node type, the profiles that ship, and the effects of each command.

> Status values report what this release's code implements for each check on each node type. This catalogue makes no NOS-support declaration and is not a qualification claim.

## What the catalogue is

The catalogue is computed from the installed code each time `cassian checks` runs. It is not read from a file and it is not maintained by hand. It describes the code: it produces no verdict, writes no file, and is not an input to any other command.

A copy of its JSON output is kept in the repository as a test fixture, `tests/fixtures/checks_catalogue.json`, and continuous integration compares the two byte for byte (see "For contributors" below).

## Running it

| Command | Output |
|---|---|
| `cassian checks` | A fixed-layout summary: the node types, then one line per check, profile and command |
| `cassian checks --json` | The whole catalogue as JSON on standard output |

`checks` takes no other option and no argument. Its output does not depend on the terminal width, on whether output goes to a terminal, or on the root `--verbose` flag. The JSON output is the same bytes on every run, in the `C` and `C.UTF-8` locales and under Python 3.10, 3.11 and 3.12: UTF-8, keys sorted at every level, two-space indent, one final newline.

| Exit code | Meaning |
|---|---|
| 0 | The catalogue was printed |
| 1 | The catalogue could not be built, because the code is internally inconsistent. Nothing is written to standard output, and standard error carries one line, `ERROR: checks: <reason>`. This is a defect in Cassian Gate, not in your input |
| 2 | Usage error: an unknown option, or any argument |

## The shape

Every key is always present, with `null` where a value does not apply, so each kind of entry has one shape. Lists are sorted as stated.

**Top level.**

| Key | Meaning |
|---|---|
| `schema_version` | `"checks.v1"`, the name of this shape |
| `gate_release` | The release of the installed Cassian Gate |
| `provisional` | `true`: the shape carries no stability promise (see "Provisional status") |
| `notices` | Two sentences, in this order: the status notice quoted at the top of this page, and the provisional notice |
| `provenance` | Which parts are read from the code and which are written by hand (see "Provenance") |
| `node_types` | One entry per node type: `type`, and `runtime_requirement`, the runtime the node type requires, or `null` |
| `checks` | One entry per check, sorted by `id` |
| `profiles` | One entry per profile, sorted by `id` |
| `commands` | One entry per runnable command, sorted by `command` |

**Check entry.** `id` is the check's name as you write it in a topology: the `kind` of a test, or the `type` of an invariant. `kind` is the test kind, which is `invariant` for an invariant type. `parameters`, `status` and `limitations` are described below.

**Parameters.** `parameters` holds `unknown_keys`, `params` and `constraints`.

- `unknown_keys` is `rejected` when `cassian validate` refuses a key the check does not declare, and `accepted` when it lets such a key through.
- `params` lists the keys `cassian validate` inspects for the check and the keys its run reads, sorted by `name`. The keys every test carries (`name`, `kind`, and `type` on an invariant) are not listed. Each entry has:
  - `name`: the key the run reads, after `cassian validate` has normalised the test;
  - `aliases`: other spellings that `cassian validate` accepts on their own, whose value the run then reads (sorted);
  - `types`: one or more value-type tokens (sorted);
  - `values`: the allowed strings when `types` includes `enum`, otherwise `null`;
  - `required`: whether the test must give the key;
  - `enforced`: `validate` when `cassian validate` refuses a bad value, or the absence of a required key; `run` when only the run checks it.
- `constraints` lists the rules that tie parameters together, sorted by `operator` and then `params`; `[]` when there are none. Each entry has `operator`, `params` (sorted), `when` and `enforced`. `when` is `null`, or a condition `{"param", "equals", "type"}`: the named parameter equals the value in `equals`, or its value has the value-type token in `type`; the one not used is `null`.

| Operator | Meaning |
|---|---|
| `exactly_one_of` | Exactly one of the listed parameters is given |
| `at_most_one_of` | At most one of the listed parameters is given |
| `forbidden_if` | The listed parameters must not be given when the condition in `when` holds |
| `required_iff` | The listed parameters are required when the condition in `when` holds, and must not be given when it does not |

**Rules that depend on the topology.** The parameter lists state per-key rules: rules about a check's own keys, each on its own (`params`) and taken together (`constraints`). `cassian validate` also applies rules that depend on the rest of the topology, which a parameter list cannot state. One of them is the multi-hop guardrail. A `ping` test with `expect: pass` is refused when its `dst` is not the name of a node linked directly to its `src`; an IP address given as `dst` names no node, so that test is refused too. The refusal does not apply when the topology has at least one `frr` node and every `frr` node declares `frr_mode: preconfigured`. The guardrail reads the `dst` key as written, so a test that gives the address as `to` or `to_ip` is not checked by it. `topology-schema-v1.md` describes the guardrail under "Multi-hop Guardrail".

**Value-type tokens.** The vocabulary is closed.

| Token | Means |
|---|---|
| `string` | a non-empty string |
| `node` | the name of a node declared under `nodes:` |
| `ip` | an IPv4 or IPv6 literal |
| `ipv4` | an IPv4 literal |
| `cidr` | a prefix in CIDR notation |
| `integer` | an integer |
| `number` | an integer or a decimal number, not a boolean |
| `boolean` | `true` or `false` |
| `mac` | a MAC address |
| `as_path_regex` | an AS-path regular expression |
| `community` | one BGP community (`AS:VAL` or a well-known name) |
| `community_list` | a non-empty list of communities |
| `enum` | one of the strings in `values` |
| `exec_assertion` | a typed predicate mapping with exactly one operator |
| `string_list` | a list of strings |

**Status.** `status` has one key per node type in `node_types`, and no other key. Each holds `state`, `reason` and `detail` (see "Status").

**Limitations.** `limitations` is a list of notes, in a fixed order; `[]` when there are none (see "Exclusions and limitations").

**Profile entry.** `id`; `versioned`, which is `false`; and `content`, the invariant pack exactly as the code holds it. A profile is a builtin invariant pack that passes the code's pack rule.

**Command entry.** `command` is the command path, its words separated by spaces. Exactly one of `effects` and `exception` is not `null`. `effects` is a non-empty list of `{"label", "reason"}`, one per effect label, in the order given under "Effect labels"; each `reason` is one line. `exception` is a one-line reason, used instead of `effects` (see "Effect labels").

## Status

For each check and node type, `state` is `implemented` when the code has a path that runs the check with a node of that type in the role the code checks, and `not implemented` when it has none. The role checked is the node the test runs from (`src`, alias `from`) and, for `tcp`, also the destination node (`dst`, alias `to`).

- `reason` is the code's own words for a `not implemented` state, copied verbatim. It is `null` when the state is `implemented`.
- `detail` is check-specific text from the code for an `implemented` state, where the check has any; otherwise `null`.

A status says what this release's code can run. It is not a NOS-support declaration and not a qualification claim: it does not say that a network operating system is fit for any purpose, and it promises nothing about later releases.

## Effect labels

Each runnable command carries a set of effect labels, each with a one-line reason. A label is decided over every invocation of the command, with any flags. **The labels report what the current code does; they are not rulings on constitutional status.**

| Label | In the set when |
|---|---|
| `read-only` | **no** invocation writes a file, changes a lab, or produces a verdict |
| `advisory` | **no** invocation changes a lab or produces a verdict, **and** some invocation writes non-authoritative output files (paths it names or reports) |
| `lab-mutating` | **some** invocation creates, deploys or changes lab state (other than removing it), or runs commands inside lab nodes that can change them |
| `destructive` | **some** invocation can remove lab state or artifacts that existed before it ran |
| `authoritative` | **some** invocation produces the deploy/no-deploy verdict by **running `test`'s gate path** |

**The set rule.** `read-only` and `advisory` never appear together, and neither appears with `lab-mutating`, `destructive` or `authoritative`. Removal alone is `destructive`, not `lab-mutating`. A set is never empty, and its labels always appear in this order: `read-only`, `lab-mutating`, `destructive`, `authoritative`, `advisory`.

**The exception marker.** `import` and `ai` carry `exception` instead of a set, with a one-line reason, because they have effects that no label covers.

**Two readings applied.**

- "Verdict" in the `read-only` and `advisory` rows means the deploy/no-deploy verdict of the `authoritative` row. The `verdict` field that `cassian status --json` emits is a lab-health result set by `--strict`, not that verdict, so `status` is `read-only`.
- "Remove" means deleting a file or directory, or destroying a runtime. Rewriting a file in place is not removal, so `validate`, `collect`, `preflight`, `adapt` and `gen` are not `destructive` because they rewrite their own output.

**Help text.** Where existing help text uses "read-only" or "advisory" in an everyday sense (`adapt`, `adapt ansible`, `ai`), the catalogue's labels follow the definitions on this page instead.

## Provenance

`provenance` sorts every part of the catalogue into two lists.

- `derived_from_code`: read or computed from the code each time the catalogue is built, or a fixed marker. `checks.id`, `checks.kind`, `checks.status`, `commands.command`, `gate_release`, `node_types`, `profiles`, `provisional` and `schema_version`.
- `declared_proof_bound`: written by hand in the catalogue's source, and held to the code by a named proof that fails when the two disagree. `checks.limitations`, `checks.parameters`, `commands.effects`, `commands.exception`, `notices` and `status_classes`.

`status_classes` is not a key of the catalogue. It names the table that says which part of the code decides a check's `status`: the NOS-agnostic core path, the node type's exec rule, or the node type's capability declaration for that check. It also names the vm-gated set: on a node type whose `runtime_requirement` is `vm`, a check of a kind in that set is decided by the node type's capability declaration.

## Provisional status

The shape is provisional. `provisional` is `true`, and the catalogue's own notice says:

> The shape of this catalogue is provisional: no stability promise is made for it, and later releases may change it.

A later change to the shape changes `schema_version`. Do not rely on the shape staying the same between releases.

## Exclusions and limitations

An exclusion is what you chose not to test: you declare it under `exclusions:` in your topology. A limitation is what Cassian Gate cannot establish in a case that a check's status does not show; the catalogue lists each one under the check's `limitations`. Every other gap appears as a `not implemented` state with its reason.

## For contributors

Changing a check, a capability declaration, a pack or a command changes the catalogue. After such a change, run `python3 scripts/regenerate_checks_catalogue.py` and commit the regenerated `tests/fixtures/checks_catalogue.json` in the same change. The script refuses to write unless the release version it resolves equals the one in `pyproject.toml`. Never edit the fixture by hand: continuous integration regenerates the catalogue and fails when the bytes differ.
