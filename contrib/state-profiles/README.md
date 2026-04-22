# State Profiles

This directory contains supporting state-capture profile content.

State profiles are secondary adoption content.
They do not replace failure-demonstrating examples, the official first-run proof family, or the recipe bridge.

## Current supporting profile

- `frr-routing-basic.yaml`

## Non-authoritative boundary

State profiles are explicitly non-authoritative.

They may support evidence collection.
They do not:

- determine pass/fail
- change exit codes
- replace `results.json`
- become a separate authority source

Use them only as supporting evidence within existing current engine behavior.
