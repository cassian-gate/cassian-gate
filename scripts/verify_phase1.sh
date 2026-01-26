#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/verify_phase1.sh [lab-name]
#
# Notes:
# - Phase-1 verification is deterministic + offline-first.
# - AI verification lives in ./scripts/verify_ai.sh (kept separate on purpose).
#
LAB="${1:-three-frr-two-hosts-fw-routed}"
LABDIR="labs/clab-$LAB"
TOPO="topologies/${LAB}.yaml"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing required command: $1"; exit 1; }
}

need_cmd awk
need_cmd grep
need_cmd jq
need_cmd mktemp

echo "=== 0) py_compile ==="
python -m py_compile src/netsim.py
echo "OK: py_compile"
echo

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

caller_line="$(grep -RInE '\bwait_for_condition\s*\(' src/netsim.py | tail -n1)"
echo "OK: wait_for_condition wiring appears stable:"
echo "  $caller_line"
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

echo "=== 3) Key helpers must be runtime-driven (no docker/container_name) ==="
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

echo "=== 5) Ensure lab is deployed (clean-state) ==="
if [ ! -f "$TOPO" ]; then
  echo "FAIL: topology file not found: $TOPO"
  exit 1
fi

./src/netsim.py up "$TOPO" --reconfigure >/dev/null
echo "OK: lab deployed"
echo

echo "=== 6) Run authoritative tests ==="
./src/netsim.py test "$LAB" || { rc=$?; echo "exit=$rc"; exit "$rc"; }
echo "exit=0"
echo

echo "=== 6b) UX guardrail: netsim test rejects topology paths (friendly fail-fast) ==="
set +e
out="$(./src/netsim.py test "topologies/foo.yaml" 2>&1)"
rc=$?
set -e

if [ $rc -ne 2 ]; then
  echo "FAIL: expected exit code 2 for topology-path misuse, got rc=$rc"
  echo "$out"
  exit 1
fi

echo "$out" | grep -Fq "expects a LAB NAME, not a topology file path" || {
  echo "FAIL: expected friendly topology-path error message not found"
  echo "$out"
  exit 1
}

echo "OK: topology-path misuse rejected with friendly message (rc=2)"
echo

echo "=== 7) Validate artifacts ==="
test -s "$LABDIR/results.json"
test -s "$LABDIR/results.summary.txt"

# NEW: Coverage artifact must exist and be advisory-only.
test -s "$LABDIR/artifacts/coverage/coverage.json"
jq -e '.authority=="advisory"' "$LABDIR/artifacts/coverage/coverage.json" >/dev/null
jq -e '.schema_version=="coverage.v1"' "$LABDIR/artifacts/coverage/coverage.json" >/dev/null
echo "OK: coverage artifact present (advisory-only)"

cat "$LABDIR/results.summary.txt"
grep -q '^result: pass' "$LABDIR/results.summary.txt"
# tests total can be 0 in scenario-only mode; accept either:
#  - steady-state run: tests total >= 1
#  - scenario-only run: tests total == 0 and scenarios present
if grep -qE '^tests: total=[1-9]' "$LABDIR/results.summary.txt"; then
  echo "OK: summary shows steady-state tests executed"
elif grep -q '^tests: total=0 ' "$LABDIR/results.summary.txt" && grep -q '^scenarios: total=[1-9]' "$LABDIR/results.summary.txt"; then
  echo "OK: summary shows scenario-only mode (tests=0, scenarios present)"
else
  echo "FAIL: unexpected summary mode (neither steady-state tests nor scenario-only scenarios detected)"
  cat "$LABDIR/results.summary.txt"
  exit 1
fi
echo "OK: artifacts present and summary indicates pass"

echo
echo "=== 7b) Scenario summary rendering (results.summary.txt) ==="
# Run a deterministic scenario if available, then assert summary contains the scenario section.
# (This does not change authority; it is a human-only artifact check.)

scen_id="ping_test"

set +e
list_out="$(./src/netsim.py test --list-scenarios "$LAB" 2>&1)"
rc=$?
set -e

if [ $rc -ne 0 ]; then
  echo "FAIL: --list-scenarios failed (rc=$rc)"
  echo "$list_out"
  exit 1
fi

if echo "$list_out" | grep -Fq -- "- ${scen_id}:"; then
  ./src/netsim.py test --scenario "$scen_id" "$LAB" >/dev/null
  test -s "$LABDIR/results.summary.txt"

  grep -q '^=== Scenarios ===' "$LABDIR/results.summary.txt" || {
    echo "FAIL: expected scenario section header not found in results.summary.txt"
    cat "$LABDIR/results.summary.txt"
    exit 1
  }

  grep -qE "^scenario ${scen_id}:" "$LABDIR/results.summary.txt" || {
    echo "FAIL: expected scenario id '${scen_id}' not found in scenario summary"
    cat "$LABDIR/results.summary.txt"
    exit 1
  }

  echo "OK: scenario summary renders in results.summary.txt"
else
  echo "SKIP: lab '$LAB' has no '${scen_id}' scenario; scenario summary rendering not verified here"
fi
echo

echo "=== 8) Scenario fault determinism ==="
fault_steps="$(jq '[.scenarios[].steps[] | select(.type=="fault")] | length' "$LABDIR/results.json")"
fault_events="$(jq '[.events[] | select(.type=="scenario_fault")] | length' "$LABDIR/results.json")"

if [ "$fault_steps" -ne "$fault_events" ]; then
  echo "FAIL: scenario_fault events mismatch (steps=$fault_steps events=$fault_events)"
  exit 1
fi
echo "OK: scenario_fault events are deterministic (1 per fault step)"
echo

echo "=== 9a) Scenario validation regression (positive files) ==="
./src/netsim.py validate "topologies/neg/good_wait_for_to_node.yaml" --json | jq -e '.result=="pass"' >/dev/null \
  && echo "OK: good_wait_for_to_node.yaml validates pass" \
  || { echo "FAIL: expected good_wait_for_to_node.yaml to validate pass"; ./src/netsim.py validate "topologies/neg/good_wait_for_to_node.yaml" --json; exit 1; }
echo

echo "=== 9b) Scenario validation regression (negative files) ==="

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
must_fail_with_re() {
  local topo="$1"
  local pattern="$2"
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

  echo "$out" | grep -Eq "$pattern" || {
    echo "FAIL: expected error pattern not found"
    echo "  cmd: $cmd"
    echo "  expected regex: $pattern"
    echo "  got:"
    echo "$out"
    exit 1
  }

  echo "OK: $topo"
  echo "    matched regex: $pattern"
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
must_fail_with "topologies/neg/bad_wait_for_to_unknown_node.yaml" "wait_for.to: invalid destination 'not_a_node'"
must_fail_with "topologies/neg/bad_wait_for_expect_invalid.yaml" "wait_for.expect: must be pass|fail"
must_fail_with "topologies/neg/bad_candidate_changes_dup_id.yaml" "duplicate id 'change1'"
must_fail_with "topologies/neg/bad_candidate_changes_both_sources.yaml" "choose only one of 'file' or 'inline'"
must_fail_with_re "topologies/neg/bad_static_routes_rejected.yaml" "static_routes|static route|routing.*topology|not supported"
must_fail_with "topologies/neg/bad_wait_for_to_hostname.yaml" "Hostnames/DNS are not supported"
must_fail_with "topologies/neg/bad_wait_for_to_cidr.yaml" "CIDR"
must_fail_with "topologies/neg/bad_wait_for_to_ip_port.yaml" "IP:port"
must_fail_with "topologies/neg/bad_wait_for_to_ipv6.yaml" "IPv6"

echo
echo "=== NEG) invalid include:all (unnamed test) ==="
./src/netsim.py up topologies/neg/invalid_include_all_unnamed_test.yaml --reconfigure >/dev/null 2>&1 \
  && { echo "FAIL: expected include:all unnamed test to be rejected"; exit 1; } \
  || echo "OK: include:all unnamed test rejected"
echo

# NEW: Coverage negative invariants
must_fail_with "topologies/neg/bad_coverage_unnamed_test.yaml" "coverage: tests[1] is unnamed"
must_fail_with "topologies/neg/bad_coverage_run_dict.yaml" "unsupported keys ['test']"
echo

echo
echo "=== 10) Optional: examples smoke (quickstart) ==="
if [ "${AI_NETSIM_VERIFY_EXAMPLES:-0}" = "1" ]; then
  # ex01 should PASS (connected reachability)
  ./src/netsim.py up examples/01_connected_smoke.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex01-connected-smoke

  # ex03 should PASS (static demo images prove multi-hop)
  ./src/netsim.py up examples/03_static_multihop_ping.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex03-static-multihop

  # ex02 should PASS (BGP demo images prove multi-hop + tcp)
  ./src/netsim.py up examples/02_bgp_multihop_tcp.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex02-bgp-multihop-tcp

  echo "OK: examples smoke pass"
else
  echo "SKIP: set AI_NETSIM_VERIFY_EXAMPLES=1 to run examples smoke"
fi
echo

echo "✅ PHASE1 VERIFIED"
