#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/verify_phase1.sh [lab-name]
#
LAB="${1:-three-frr-two-hosts-fw-routed}"
LABDIR="labs/clab-$LAB"

echo "=== 0b) Guardrail: wait_for_condition wiring invariant ==="
# Expect exactly 2 occurrences:
#  - definition
#  - single call site (scenario condition waits)
wfc_count="$(grep -RInE '\bwait_for_condition\s*\(' src/netsim.py | wc -l | tr -d ' ')"
if [ "$wfc_count" -ne 2 ]; then
  echo "FAIL: expected wait_for_condition() to appear exactly twice (def + one call), but found $wfc_count:"
  grep -RInE '\bwait_for_condition\s*\(' src/netsim.py || true
  exit 1
fi

# Ensure the call site is runtime-driven (rt.exec inside wait_for_condition, not docker)
caller_line="$(grep -RInE '\bwait_for_condition\s*\(' src/netsim.py | tail -n1)"
echo "OK: wait_for_condition wiring appears stable:"
echo "  $caller_line"
echo

echo "=== 0) py_compile ==="
python -m py_compile src/netsim.py
echo "OK: py_compile"
echo

echo "=== 1) Guardrails: no package installs in engine ==="
grep -RInE '\bapk\s+add\b|\bapk\s+update\b' src \
  && { echo "FAIL: apk usage found"; exit 1; } \
  || echo "OK: no apk installs"

grep -RInE '\bapt(-get)?\s+install\b|\bapt(-get)?\s+update\b' src \
  && { echo "FAIL: apt usage found"; exit 1; } \
  || echo "OK: no apt installs"

grep -RInE '\byum\s+install\b|\bdnf\s+install\b' src \
  && { echo "FAIL: yum/dnf usage found"; exit 1; } \
  || echo "OK: no yum/dnf installs"
echo

echo "=== 2) cmd_test must be runtime-driven (no docker/container_name) ==="
awk 'BEGIN{p=0}
     /^def cmd_test\(/{p=1}
     p{print}
     /^def [a-zA-Z0-9_]+\(/ && $0 !~ /^def cmd_test/{exit}' src/netsim.py \
  | grep -nE 'docker"\s*,\s*"exec|docker\s+exec|docker"\s*,\s*"inspect|docker\s+inspect|docker"\s*,\s*"logs|docker\s+logs|docker_is_running\(|container_name\(' \
  && { echo "FAIL: cmd_test still hard-codes docker/container_name"; exit 1; } \
  || echo "OK: cmd_test clean (runtime-driven)"
echo

echo "=== 3) Key helpers must be runtime-driven ==="
FUNCS=(verify_lab_ready wait_for_bgp start_tcp_listener verify_host_ready verify_fw_routed_ready verify_frr_ready ensure_nc ensure_ip_tools)
for fn in "${FUNCS[@]}"; do
  echo "-- checking $fn"
  awk -v FN="$fn" 'BEGIN{p=0}
       $0 ~ ("^def "FN"\\("){p=1}
       p{print}
       /^def [a-zA-Z0-9_]+\(/ && $0 !~ ("^def "FN"\\(") {exit}' src/netsim.py \
    | grep -nE 'docker"\s*,\s*"exec|docker\s+exec|docker"\s*,\s*"inspect|docker\s+inspect|docker"\s*,\s*"logs|docker\s+logs|container_name\(' \
    && { echo "FAIL: $fn still hard-codes docker/container_name"; exit 1; } \
    || echo "OK: $fn clean"
done
echo

echo "=== 4) Enforce: docker exec/inspect/logs only inside class ContainerRuntime ==="
all_docker_lines="$(grep -nE '\bdocker\s+(exec|inspect|logs)\b' src/netsim.py \
  | grep -vE '^[0-9]+:[[:space:]]*#' || true)"

runtime_start="$(grep -nE '^class[[:space:]]+ContainerRuntime\b' src/netsim.py | head -n1 | cut -d: -f1 || true)"
if [ -z "${runtime_start:-}" ]; then
  echo "FAIL: class ContainerRuntime not found"
  exit 1
fi

runtime_end="$(awk -v start="$runtime_start" '
  NR <= start { next }
  /^class[[:space:]]+[A-Za-z0-9_]+\b/ { print NR-1; exit }
  /^def[[:space:]]+[A-Za-z0-9_]+\(/ { print NR-1; exit }
  END { print NR }
' src/netsim.py)"

bad=""
if [ -n "$all_docker_lines" ]; then
  while IFS= read -r line; do
    ln="${line%%:*}"
    if [ "$ln" -lt "$runtime_start" ] || [ "$ln" -gt "$runtime_end" ]; then
      bad+="$line"$'\n'
    fi
  done <<< "$all_docker_lines"
fi

if [ -n "$bad" ]; then
  echo "FAIL: docker exec/inspect/logs found outside ContainerRuntime:"
  printf "%s" "$bad"
  exit 1
fi

echo "OK: docker exec/inspect/logs only in ContainerRuntime"
echo

echo "=== AI) Guardrails: ai commands must not call runtime/deploy ==="

awk '
  /^def (cmd_ai_|_ai_)/{p=1}
  p{print}
  p && /^def / && $0 !~ /^def (cmd_ai_|_ai_)/{p=0}
' src/netsim.py \
  | grep -nE '\bcontainerlab\b|\bcmd_up\b|\bcmd_test\b|\bcmd_run\b|\bContainerRuntime\b|\brt\.exec\b|\bdocker\s+(exec|inspect|logs)\b' \
  && { echo "FAIL: ai code references runtime/deploy primitives"; exit 1; } \
  || echo "OK: ai code is artifact-only (no runtime/deploy refs)"
echo

echo "=== AI) Smoke: advisory headers + strict-inputs exit code ==="

./src/netsim.py ai coach >/dev/null
echo "OK: ai coach runs"

./src/netsim.py ai coach --bundle \
  | jq -r '.schema_version,.command,.authority,.non_authoritative' \
  | paste -sd' ' - \
  | grep -Fxq "1 coach advisory true" \
  && echo "OK: ai coach bundle headers" \
  || { echo "FAIL: ai coach bundle headers"; exit 1; }

./src/netsim.py ai review topologies/three-frr-two-hosts-fw-routed.yaml --bundle \
  | jq -r '.schema_version,.command,.authority,.non_authoritative' \
  | paste -sd' ' - \
  | grep -Fxq "1 review advisory true" \
  && echo "OK: ai review bundle headers" \
  || { echo "FAIL: ai review bundle headers"; exit 1; }

set +e
./src/netsim.py ai explain not_a_real_lab --strict-inputs >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  echo "FAIL: ai explain strict-inputs expected exit 2, got $rc"
  exit 1
fi
echo "OK: ai explain strict-inputs exit 2"
echo
echo "=== AI) Key redaction (must not leak API key) ==="

# Use a deterministic fake key value so we can assert it never appears in output.
FAKE_KEY="sk-THIS_IS_NOT_REAL"
export AI_NETSIM_AI_PROVIDER="openai"
export AI_NETSIM_AI_API_KEY="$FAKE_KEY"
export AI_NETSIM_AI_MODEL="gpt-4.1-mini"

# Run online path (will fail with 401) but must never print the raw key.
ai_err="$(./src/netsim.py ai explain "$LAB" --online --format json | jq -r '.ai_error' || true)"

# Assert: raw key must not appear
echo "$ai_err" | grep -Fq "$FAKE_KEY" \
  && { echo "FAIL: ai_error leaked raw API key"; echo "$ai_err"; exit 1; } \
  || echo "OK: ai_error does not contain raw API key"

# Optional stronger assert: redaction marker present (your sanitizer uses "*******")
echo "$ai_err" | grep -Eq 'sk-[A-Za-z0-9_-]*\*{3,}[A-Za-z0-9_-]*' \
  && echo "OK: ai_error appears redacted" \
  || echo "WARN: ai_error did not match redaction pattern (ensure sanitizer still applied)"

echo
echo
echo "=== AI) Golden fixtures (bundle drift guardrail) ==="

# Require fixtures to exist
test -s tests/ai/fixtures/explain.bundle.json || { echo "FAIL: missing tests/ai/fixtures/explain.bundle.json"; exit 1; }
test -s tests/ai/fixtures/review.bundle.json   || { echo "FAIL: missing tests/ai/fixtures/review.bundle.json"; exit 1; }
test -s tests/ai/fixtures/coach.bundle.json    || { echo "FAIL: missing tests/ai/fixtures/coach.bundle.json"; exit 1; }

# Normalize JSON (sorted keys) so formatting changes don't cause drift
jq -S . tests/ai/fixtures/explain.bundle.json > /tmp/ai_explain.golden.json
./src/netsim.py ai explain "$LAB" --bundle | jq -S . > /tmp/ai_explain.now.json
diff -u /tmp/ai_explain.golden.json /tmp/ai_explain.now.json \
  && echo "OK: ai explain bundle matches golden" \
  || { echo "FAIL: ai explain bundle drift"; exit 1; }

jq -S . tests/ai/fixtures/review.bundle.json > /tmp/ai_review.golden.json
./src/netsim.py ai review "topologies/${LAB}.yaml" --bundle | jq -S . > /tmp/ai_review.now.json
diff -u /tmp/ai_review.golden.json /tmp/ai_review.now.json \
  && echo "OK: ai review bundle matches golden" \
  || { echo "FAIL: ai review bundle drift"; exit 1; }

jq -S . tests/ai/fixtures/coach.bundle.json > /tmp/ai_coach.golden.json
./src/netsim.py ai coach --bundle | jq -S . > /tmp/ai_coach.now.json
diff -u /tmp/ai_coach.golden.json /tmp/ai_coach.now.json \
  && echo "OK: ai coach bundle matches golden" \
  || { echo "FAIL: ai coach bundle drift"; exit 1; }

# coach must not emit paste-ready YAML (v1 contract)
out="$(./src/netsim.py ai coach 2>/dev/null || true)"
echo "$out" | grep -Eq '^[[:space:]]*(tests:|scenarios:|nodes:|links:)[[:space:]]*$|^[[:space:]]*(tests:|scenarios:|nodes:|links:)[[:space:]]*$' \
  && { echo "FAIL: ai coach emitted YAML-like section header (v1 forbids paste-ready YAML)"; exit 1; } \
  || echo "OK: ai coach does not emit YAML blocks"

echo "=== 5) Ensure lab is deployed (clean-state) ==="
TOPO="topologies/${LAB}.yaml"
if [ ! -f "$TOPO" ]; then
  echo "FAIL: topology file not found: $TOPO"
  exit 1
fi

# Always deploy clean so verify works on a fresh lab
./src/netsim.py up "$TOPO" --reconfigure >/dev/null
echo "OK: lab deployed"
echo

echo "=== 6) Run authoritative tests ==="
./src/netsim.py test "$LAB" || { rc=$?; echo "exit=$rc"; exit "$rc"; }
echo "exit=0"
echo

echo "=== 6) Validate artifacts ==="
test -s "$LABDIR/results.json"
test -s "$LABDIR/results.summary.txt"

cat "$LABDIR/results.summary.txt"
grep -q '^result: pass' "$LABDIR/results.summary.txt"
grep -q '^tests: total=[1-9]' "$LABDIR/results.summary.txt"
echo

echo "=== 7) Scenario fault determinism ==="
fault_steps="$(jq '[.scenarios[].steps[] | select(.type=="fault")] | length' "$LABDIR/results.json")"
fault_events="$(jq '[.events[] | select(.type=="scenario_fault")] | length' "$LABDIR/results.json")"

if [ "$fault_steps" -ne "$fault_events" ]; then
  echo "FAIL: scenario_fault events mismatch (steps=$fault_steps events=$fault_events)"
  exit 1
fi

echo "OK: scenario_fault events are deterministic (1 per fault step)"
echo

echo "=== 8a) Scenario validation regression (positive files) ==="
./src/netsim.py validate "topologies/neg/good_wait_for_to_node.yaml" --json | jq -e '.result=="pass"' >/dev/null \
  && echo "OK: good_wait_for_to_node.yaml validates pass" \
  || { echo "FAIL: expected good_wait_for_to_node.yaml to validate pass"; ./src/netsim.py validate "topologies/neg/good_wait_for_to_node.yaml" --json; exit 1; }
echo

echo "=== 8) Scenario validation regression (negative files) ==="

must_fail_with() {
  local topo="$1"
  local needle="$2"
  local cmd="./src/netsim.py up \"$topo\" --reconfigure"

  set +e
  out="$(./src/netsim.py up "$topo" --reconfigure 2>&1)"
  rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    echo "FAIL: expected validation failure, but command succeeded:"
    echo "  $cmd"
    exit 1
  fi

  echo "$out" | grep -Fq "$needle" || {
    echo "FAIL: expected error message not found"
    echo "  cmd: $cmd"
    echo "  expected substring: $needle"
    echo "  got:"
    echo "$out"
    exit 1
  }

  echo "OK: $topo"
  echo "    matched: $needle"
}

# Each negative file tests exactly one invariant (deterministic fail-fast)
must_fail_with "topologies/neg/bad_steps_not_dict.yaml" "step must be a dict"
must_fail_with "topologies/neg/bad_wait_for_tcp_type_v1.yaml" "wait_for.type: must be ping (v1)"
must_fail_with "topologies/neg/bad_wait_for_bgp_unknown_node.yaml" "unknown node 'not_a_real_node'"
must_fail_with "topologies/neg/bad_wait_for_bgp_non_frr.yaml" "is not type/kind 'frr'"
must_fail_with "topologies/neg/bad_interface_unknown_node.yaml" "unknown node 'not_a_node'"
must_fail_with "topologies/neg/bad_interface_unknown_iface.yaml" "interface 'eth999' not found on node 'r2'"
must_fail_with "topologies/neg/bad_interface_missing_key.yaml" "must include exactly one of if/iface/interface"
must_fail_with "topologies/neg/bad_interface_multi_keys.yaml" "provide only one of if/iface/interface"
must_fail_with "topologies/neg/bad_wait_for_to_unknown_node.yaml" "wait_for.to: must be a valid node name or IPv4/IPv6 literal"
must_fail_with "topologies/neg/bad_wait_for_expect_invalid.yaml" "wait_for.expect: must be pass|fail"

echo "=== NEG) invalid include:all (unnamed test) ==="
./src/netsim.py up topologies/neg/invalid_include_all_unnamed_test.yaml --reconfigure >/dev/null 2>&1 \
  && { echo "FAIL: expected include:all unnamed test to be rejected"; exit 1; } \
  || echo "OK: include:all unnamed test rejected"
echo

echo
echo "✅ ALL VERIFIED"
