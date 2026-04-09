#!/usr/bin/env bash
set -euo pipefail

NS="./src/cassian.py"

LAB="ex-evpn-outcome-only"

REAL_CAND="tests/fixtures/evpn-real-cand"
NEG_INVALID="tests/fixtures/evpn-cand-neg-invalid"
NEG_WRAPPER="tests/fixtures/evpn-cand-neg-wrapper-only"

ART="labs/clab-${LAB}/artifacts/apply"
LEAF1_JSON="${ART}/leaf1.apply.json"

echo "=== [RESET LAB] ==="
python3 $NS down "${LAB}" || true
python3 $NS up "topologies/${LAB}.yaml"

# Per-case evidence capture (prevents later runs overwriting labs/clab-${LAB}/results.json)
EVID_DIR="artifacts/verify_candidate_apply_v1_5"
mkdir -p "${EVID_DIR}"

save_case_artifacts() {
  local label="$1"
  local r="labs/clab-${LAB}/results.json"
  local s="labs/clab-${LAB}/results.summary.txt"

  test -f "${r}" || { echo "ERROR: missing ${r}"; exit 1; }

  cp -f "${r}" "${EVID_DIR}/${label}.results.json"
  if test -f "${s}"; then
    cp -f "${s}" "${EVID_DIR}/${label}.results.summary.txt"
  fi
  # Keep leaf1 apply artifact too (used in all negative cases; also present in Case 1)
  if test -f "${LEAF1_JSON}"; then
    cp -f "${LEAF1_JSON}" "${EVID_DIR}/${label}.leaf1.apply.json"
  fi
}

assert_hard_gate_fail() {
  local rfile="$1"

  jq -e '
    (.overall.exit_code != 0)
    and (.overall.verdict == "fail")
    and (.candidate_apply.verdict == "fail")
    and (
      ((.summary.tests_executed // 0) == 0)
      or
      ([.tests[] | select(.kind!="candidate_apply" and .name!="candidate_apply:verdict")] | length == 0)
    )
  ' "${rfile}" >/dev/null
}

echo "=== [BASELINE MUST PASS] ==="
python3 $NS test "${LAB}"
save_case_artifacts "baseline_pass"
echo "OK: baseline artifacts archived to ${EVID_DIR}/baseline_pass.*"

###############################################################################
echo "=== [CASE 1: VALID CANDIDATE MUST PASS] ==="
###############################################################################
python3 $NS test "${LAB}" --candidate-config "${REAL_CAND}"

# Valid candidate: vtysh path succeeds end-to-end
jq -e '
  .apply_method == "vtysh"
  and .sanitize.exit_code == 0
  and .sanitize_nonempty.exit_code == 0
  and .vtysh_apply.exit_code == 0
  and .result.applied_ok == true
' "${LEAF1_JSON}" >/dev/null

docker exec "clab-${LAB}-leaf1" vtysh -c "show run" | grep -q "10.255.255.11/32"
echo "OK: valid candidate applied successfully"
save_case_artifacts "case1_valid_candidate"
echo "OK: case1 artifacts archived to ${EVID_DIR}/case1_valid_candidate.*"

###############################################################################
echo "=== [CASE 2: INVALID COMMAND MUST FAIL] ==="
###############################################################################
set +e
python3 $NS test "${LAB}" --candidate-config "${NEG_INVALID}"
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  echo "ERROR: invalid candidate unexpectedly passed"
  exit 1
fi

# Invalid command: sanitize typically succeeds + nonempty ok, but vtysh_apply fails
jq -e '
  .apply_method == "vtysh"
  and .result.applied_ok == false
  and (.sanitize_nonempty.exit_code // 0) == 0
  and .vtysh_apply.exit_code != 0
' "${LEAF1_JSON}" >/dev/null

echo "OK: invalid command correctly rejected"

# Archive + prove hard-gate after CASE 2 (invalid command)
save_case_artifacts "case2_invalid_command"
assert_hard_gate_fail "${EVID_DIR}/case2_invalid_command.results.json"
echo "OK: CASE 2 hard-gate proven in ${EVID_DIR}/case2_invalid_command.results.json"

###############################################################################
echo "=== [CASE 3: WRAPPER-ONLY CONFIG MUST FAIL] ==="
###############################################################################
set +e
python3 $NS test "${LAB}" --candidate-config "${NEG_WRAPPER}"
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  echo "ERROR: wrapper-only candidate unexpectedly passed"
  exit 1
fi

# Wrapper-only: must fail. Current artifacts can show either:
# - sanitize succeeds but sanitized file is empty (nonempty check fails), OR
# - sanitize itself fails and sanitize_nonempty is null.
jq -e '
  .apply_method == "vtysh"
  and .result.applied_ok == false
  and (
    (.sanitize.exit_code != 0)
    or ((.sanitize_nonempty.exit_code // 1) != 0)
  )
  and .vtysh_apply.exit_code != 0
  and (
    (.stderr | tostring | test("sanitized candidate is empty"))
    or (.stderr | tostring | test("sanitize failed"))
    or (.stderr | tostring | test("sanitized file empty"))
    or (.vtysh_apply.stderr | tostring | test("sanitize failed"))
  )
' "${LEAF1_JSON}" >/dev/null

echo "OK: wrapper-only candidate correctly rejected"

# Archive + prove hard-gate after CASE 3 (wrapper-only)
save_case_artifacts "case3_wrapper_only"
assert_hard_gate_fail "${EVID_DIR}/case3_wrapper_only.results.json"
echo "OK: CASE 3 hard-gate proven in ${EVID_DIR}/case3_wrapper_only.results.json"

###############################################################################
echo "✅ ALL v1.5 candidate apply guardrails VERIFIED"
###############################################################################
