# Quickstart (truthful v2 path)

This quickstart is a release-facing supporting guide for Cassian Gate v2.

Cassian Gate is a deterministic network change-validation gate. It is **not** a broad automation platform, a general lab product, or an AI decision system.

Use it when you want a clean, explicit validation path before production. Do **not** treat this page as authoritative proof of safety; authoritative meaning comes from deterministic execution and the generated artifacts.

Cassian Gate is for:
- network engineers validating planned changes before production
- platform and infrastructure engineers using a CI-safe network gate
- teams that need explicit pass/fail artifacts

Cassian Gate is **not yet** for:
- users expecting generic multi-vendor feature parity
- teams seeking a broad network automation platform
- users wanting exploratory workflows or AI output to act as deployment authority

## 1) Check the local environment

```bash
cassian doctor
```

## 2) Validate a topology before execution

Use your actual topology file path.

```bash
cassian validate <topology.yaml>
```

## 3) Run the authoritative gate

`cassian test` is the authoritative validation path. It is the command to use for deploy/no-deploy decisions.

```bash
cassian test <topology.yaml>
```

## 4) Read the right artifacts

After a gate run, inspect:

- `labs/clab-<lab>/results.json` for authoritative verdict meaning
- `labs/clab-<lab>/results.summary.txt` for human-readable explanation
- `labs/clab-<lab>/topology.resolved.yaml` for resolved input visibility

Important boundary:

- `results.json` is authoritative for verdict sharing
- `results.summary.txt` is explanatory only
- release docs and examples are supporting guidance only

## 5) Use exploration deliberately

When you want to inspect a lab interactively, use exploration mode instead of treating a kept lab as gate authority.

```bash
cassian run <topology.yaml> --keep
cassian status <lab>
```

You can then inspect or collect from the kept lab, and tear it down when finished:

```bash
cassian collect <lab>
cassian down <lab>
```

## 6) Recommended first-pass workflow

```bash
cassian doctor
cassian validate <topology.yaml>
cassian test <topology.yaml>
```

That sequence gives you the narrow, truthful v2 path: environment check, input validation, then authoritative gate execution.
