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

echo "=== 4b) Advisory-only: preflight generates deterministic JSON (no runtime) ==="
rm -f artifacts/preflight/preflight.json 2>/dev/null || true
./src/netsim.py preflight "$TOPO" --format json >/dev/null
test -s artifacts/preflight/preflight.json
jq -e '.authority=="advisory" and .schema_version=="preflight.v1" and .command=="preflight"' artifacts/preflight/preflight.json >/dev/null
echo "OK: preflight.json present and schema looks sane (advisory-only)"
echo

echo "=== 4c) Advisory-only: preflight invalid input must exit 2 ==="
set +e
out="$(./src/netsim.py preflight topologies/neg/bad_steps_not_dict.yaml --format json 2>&1)"
rc=$?
set -e
if [ $rc -ne 2 ]; then
  echo "FAIL: expected rc=2 for invalid preflight input, got rc=$rc"
  echo "$out"
  exit 1
fi
echo "OK: preflight rejects invalid inputs with rc=2"
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

echo "$out" | grep -Fq -- "expects a LAB NAME, not a topology file path" || {
  echo "FAIL: expected friendly topology-path error message not found"
  echo "$out"
  exit 1
}

echo "OK: topology-path misuse rejected with friendly message (rc=2)"
echo

echo "=== 6c) UX guardrail: scenario/all-scenarios rejects --name/--kind filters ==="
set +e
out="$(./src/netsim.py test "$LAB" --scenario ping_test --name bar 2>&1)"
rc=$?
set -e

# We WANT this to be a usage error (rc=2). If it's rc=1, it means cmd_test is calling die() without code=2.
if [ $rc -ne 2 ]; then
  echo "FAIL: expected rc=2 for scenario+filter guardrail, got rc=$rc"
  echo "$out"
  echo
  echo "HINT: in cmd_test(), change:"
  echo "  die(\"ERROR: --name/--kind filters are not supported ...\")"
  echo "to:"
  echo "  die(\"ERROR: --name/--kind filters are not supported ...\", code=2)"
  exit 1
fi

needle="ERROR: --name/--kind filters are not supported with --scenario/--all-scenarios"
echo "$out" | grep -Fq -- "$needle" || {
  echo "FAIL: expected scenario+filter guardrail message not found"
  echo "$out"
  exit 1
}
echo "OK: scenario+filter guardrail rejects with rc=2 + message"
echo
echo "=== 6c2) UX guardrail: --capture-config forbidden in netsim test (rc=2 + message) ==="
set +e
out="$(./src/netsim.py test "$LAB" --capture-config 2>&1)"
rc=$?
set -e

if [ $rc -ne 2 ]; then
  echo "FAIL: expected rc=2 for --capture-config misuse in test, got rc=$rc"
  echo "$out"
  exit 1
fi

echo "$out" | grep -Fq -- "--capture-config is exploration evidence only and is not allowed in netsim test" || {
  echo "FAIL: expected capture-config misuse message not found"
  echo "$out"
  exit 1
}

echo "OK: capture-config misuse rejected with rc=2 + message"
echo "=== 6d) Candidate Config Apply (v1.5) verification ==="

# Candidate fixture locations (kept deterministic + repo-local)
NEG_UNKNOWN="topologies/neg/candidate-unknown-node"
NEG_EMPTY="topologies/neg/candidate-empty"
NEG_BAD_EXT="topologies/neg/candidate-bad-ext"

CAND_OK="tests/fixtures/candidate-ok"
CAND_BAD_NFT="tests/fixtures/candidate-bad-nft"

# Ensure deterministic negative fixtures exist (create if missing)
mkdir -p "$NEG_UNKNOWN/frr"
test -s "$NEG_UNKNOWN/frr/ghost.conf" || printf '!\n' > "$NEG_UNKNOWN/frr/ghost.conf"

mkdir -p "$NEG_EMPTY/frr"
# Must be empty (size 0)
: > "$NEG_EMPTY/frr/r1.conf"

mkdir -p "$NEG_BAD_EXT/frr"
test -s "$NEG_BAD_EXT/frr/r1.conf.bak" || printf '!\n' > "$NEG_BAD_EXT/frr/r1.conf.bak"

# 6c.1) Negative: unknown node rejected (fail-fast)
set +e
out="$(./src/netsim.py test "$LAB" --candidate-config "$NEG_UNKNOWN" 2>&1)"
rc=$?
set -e
if [ $rc -eq 0 ]; then
  echo "FAIL: expected candidate unknown-node to fail, but it succeeded"
  echo "$out"
  exit 1
fi
echo "$out" | grep -Fq "targets unknown node 'ghost'" || {
  echo "FAIL: expected unknown-node error not found"
  echo "$out"
  exit 1
}
echo "OK: candidate unknown node rejected"

# 6c.2) Negative: empty file rejected (fail-fast)
set +e
out="$(./src/netsim.py test "$LAB" --candidate-config "$NEG_EMPTY" 2>&1)"
rc=$?
set -e
if [ $rc -eq 0 ]; then
  echo "FAIL: expected candidate empty-file to fail, but it succeeded"
  echo "$out"
  exit 1
fi
echo "$out" | grep -Fq "empty candidate file" || {
  echo "FAIL: expected empty-file error not found"
  echo "$out"
  exit 1
}
echo "OK: candidate empty file rejected"

# 6c.3) Negative: bad extension rejected
set +e
out="$(./src/netsim.py test "$LAB" --candidate-config "$NEG_BAD_EXT" 2>&1)"
rc=$?
set -e
if [ $rc -eq 0 ]; then
  echo "FAIL: expected candidate bad-extension to fail, but it succeeded"
  echo "$out"
  exit 1
fi
echo "$out" | grep -Fq "unsupported file under frr/" || {
  echo "FAIL: expected bad-extension error not found"
  echo "$out"
  exit 1
}
echo "OK: candidate bad extension rejected"

# Ensure deterministic OK fixtures exist
mkdir -p "$CAND_OK/frr" "$CAND_OK/nft"
test -s "$CAND_OK/frr/r1.conf" || cat > "$CAND_OK/frr/r1.conf" <<'EOF'
!
! v1.5 candidate apply smoke (r1)
!
EOF

test -s "$CAND_OK/nft/fw1.nft" || cat > "$CAND_OK/nft/fw1.nft" <<'EOF'
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy accept;
  }
  chain forward {
    type filter hook forward priority 0;
    policy accept;
  }
  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

# 6c.4) Positive: candidate apply OK -> artifacts + results.json section
./src/netsim.py test "$LAB" --candidate-config "$CAND_OK" >/dev/null

test -s "$LABDIR/results.json" || { echo "FAIL: missing results.json after candidate apply OK"; exit 1; }

test -f "$LABDIR/artifacts/apply/r1.apply.json" || { echo "FAIL: missing apply artifact for r1"; exit 1; }
test -f "$LABDIR/artifacts/apply/fw1.apply.json" || { echo "FAIL: missing apply artifact for fw1"; exit 1; }

jq -e '.candidate_apply.enabled == true' "$LABDIR/results.json" >/dev/null || { echo "FAIL: candidate_apply.enabled not true"; exit 1; }
jq -e '.candidate_apply.verdict == "pass"' "$LABDIR/results.json" >/dev/null || { echo "FAIL: candidate_apply.verdict not pass"; exit 1; }
echo "OK: candidate apply pass recorded + artifacts present"

# Ensure deterministic BAD-NFT fixture exists
mkdir -p "$CAND_BAD_NFT/nft"
test -s "$CAND_BAD_NFT/nft/fw1.nft" || cat > "$CAND_BAD_NFT/nft/fw1.nft" <<'EOF'
this is not valid nft syntax
EOF

# 6c.5) Negative runtime-backed: apply fails -> no tests run
set +e
./src/netsim.py test "$LAB" --candidate-config "$CAND_BAD_NFT" >/dev/null 2>&1
rc=$?
set -e

if [ $rc -eq 0 ]; then
  echo "FAIL: expected candidate bad-nft apply to fail, but it succeeded"
  exit 1
fi

test -s "$LABDIR/results.json" || { echo "FAIL: missing results.json after candidate apply FAIL"; exit 1; }
jq -e '.candidate_apply.enabled == true and .candidate_apply.verdict == "fail"' "$LABDIR/results.json" >/dev/null \
  || { echo "FAIL: candidate_apply fail not recorded"; exit 1; }

# Assert tests did not execute
jq -e '(.summary.tests_executed // 0) == 0' "$LABDIR/results.json" >/dev/null \
  || { echo "FAIL: tests executed despite candidate apply failure"; exit 1; }

echo "OK: candidate apply failure is atomic (no tests executed)"
echo

# Restore a PASS run for downstream artifact checks (step 7 expects result: pass).
# We intentionally ran a failing candidate apply above; now reset to a clean passing summary.
./src/netsim.py test "$LAB" >/dev/null
echo "OK: restored PASS run after candidate-apply negative test"
echo

echo "=== 7) Validate artifacts ==="
test -s "$LABDIR/results.json"
test -s "$LABDIR/results.summary.txt"

echo
echo "=== 7c) Supporting evidence: state capture (non-authoritative) ==="

# Negative: unknown profile must exit 2 (fail-fast config validation)
set +e
out="$(./src/netsim.py test "$LAB" --state-capture pre --state-profile does-not-exist 2>&1)"
rc=$?
set -e
if [ $rc -ne 2 ]; then
  echo "FAIL: expected rc=2 for unknown state profile, got rc=$rc"
  echo "$out"
  exit 1
fi
echo "OK: unknown state profile rejected with rc=2"

# Positive: run with state capture (both) using built-in profiles
./src/netsim.py test "$LAB" --state-capture both --state-profile frr-routing-basic --state-profile linux-net-basic --state-profile nft-ruleset-basic >/dev/null

# Artifacts exist
test -s "$LABDIR/artifacts/state_capture/plan.json" || { echo "FAIL: missing state_capture plan.json"; exit 1; }
test -d "$LABDIR/artifacts/state_capture/pre" || { echo "FAIL: missing state_capture/pre"; exit 1; }
test -d "$LABDIR/artifacts/state_capture/post" || { echo "FAIL: missing state_capture/post"; exit 1; }

# results.json additive pointers exist (non-authoritative)
jq -e '.state_capture.enabled == true and (.state_capture.mode=="both") and (.state_capture.plan_path|type)=="string"' "$LABDIR/results.json" >/dev/null \
  || { echo "FAIL: results.json missing state_capture block"; exit 1; }

jq -e '.authority.supporting_evidence | any(.type=="state_capture")' "$LABDIR/results.json" >/dev/null \
  || { echo "FAIL: results.json missing authority.supporting_evidence state_capture pointer"; exit 1; }

echo "OK: state capture artifacts present + results.json pointers (evidence-only)"
echo

echo
echo "=== 7) results.json schema guarantee (stable headers + authority boundary) ==="
jq -e '
  .results_schema=="results.v1"
  and .results_schema_version=="1.0.0"
  and .tool=="ai-netsim"
  and .command=="test"
  and (.topology.name|type)=="string"
  and (.lab_obj.name|type)=="string"
  and .authority.verdict_source=="tests"
  and (.authority.supporting_evidence|type)=="array"
  and (.overall.observed|type)=="string"
  and (.overall.verdict=="pass" or .overall.verdict=="fail")
  and (.overall.exit_code|type)=="number"
  and (.overall.phase|type)=="string"
  and (has("hard_failure"))
  and (has("tests"))
  and (has("scenarios"))
  and (has("events"))
' "$LABDIR/results.json" >/dev/null || {
  echo "FAIL: results.json missing stable schema headers / authority boundary / overall envelope"
  head -80 "$LABDIR/results.json" || true
  exit 1
}
echo "OK: results.json schema headers + authority boundary present"
echo

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
echo "=== 7a) Advisory-only: coverage artifact present + schema sanity ==="
test -s "$LABDIR/artifacts/coverage/coverage.json"
jq -e '.authority=="advisory" and (.schema_version=="coverage.v1" or (.schema_version|type)=="string")' "$LABDIR/artifacts/coverage/coverage.json" >/dev/null || {
  echo "FAIL: coverage.json missing advisory authority or schema_version"
  head -50 "$LABDIR/artifacts/coverage/coverage.json" || true
  exit 1
}
echo "OK: coverage artifact present (advisory-only)"
echo

echo
echo "=== 7b) Scenario summary rendering (results.summary.txt) ==="
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
  ./src/netsim.py test "$LAB" --scenario "$scen_id" >/dev/null
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

  echo "$out" | grep -Fq -- "$needle" || {
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

  echo "$out" | grep -Eq -- "$pattern" || {
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

# Coverage model negatives (declared-only, advisory artifact generation is part of validate)
echo
echo "=== NEG) coverage model (unnamed tests rejected) ==="
./src/netsim.py validate topologies/neg/bad_coverage_unnamed_test.yaml >/dev/null 2>&1 \
  && { echo "FAIL: expected coverage unnamed-test rejection"; exit 1; } \
  || echo "OK: bad_coverage_unnamed_test rejected"
echo

echo "=== NEG) coverage model (run dict rejected by schema; keep aligned) ==="
./src/netsim.py validate topologies/neg/bad_coverage_run_dict.yaml >/dev/null 2>&1 \
  && { echo "FAIL: expected coverage run-dict topology to be rejected"; exit 1; } \
  || echo "OK: bad_coverage_run_dict rejected"
echo

echo
echo "=== 10) Optional: examples smoke (quickstart) ==="
if [ "${AI_NETSIM_VERIFY_EXAMPLES:-0}" = "1" ]; then
  ./src/netsim.py up examples/01_connected_smoke.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex01-connected-smoke

  ./src/netsim.py up examples/03_static_multihop_ping.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex03-static-multihop

  ./src/netsim.py up examples/02_bgp_multihop_tcp.yaml --reconfigure >/dev/null
  ./src/netsim.py test ex02-bgp-multihop-tcp

  echo "OK: examples smoke pass"
else
  echo "SKIP: set AI_NETSIM_VERIFY_EXAMPLES=1 to run examples smoke"
fi
echo

echo "✅ PHASE1 VERIFIED"