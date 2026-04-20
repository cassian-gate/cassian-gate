#!/usr/bin/env bash
# Cold Sim v2 — shipped-path release smoke for Cassian Gate v2.
# Usage: run from the repo root or from a subdirectory inside the repo checkout.
# This script exercises only the shipped first-contact local path:
#   python3 src/cassian.py doctor
#   python3 src/cassian.py validate topologies/first-run-proof-minimal.yaml
#   python3 src/cassian.py test topologies/first-run-proof-minimal.yaml
#   python3 src/cassian.py test topologies/first-run-proof-fail-catching.yaml

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLI=(python3 src/cassian.py)

MIN_TOPO="topologies/first-run-proof-minimal.yaml"
FAIL_TOPO="topologies/first-run-proof-fail-catching.yaml"
MIN_LAB="first-run-proof-minimal"
FAIL_LAB="first-run-proof-fail-catching"
MIN_DIR="labs/clab-${MIN_LAB}"
FAIL_DIR="labs/clab-${FAIL_LAB}"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t cassian-cold-sim-v2)"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

say() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'COLD SIM v2: FAIL: %s\n' "$*" >&2
  exit 1
}

require_repo_surface() {
  command -v python3 >/dev/null 2>&1 || fail "python3 not found"
  [[ -f "${REPO_ROOT}/src/cassian.py" ]] || fail "broken shipped command path: missing src/cassian.py"
  [[ -f "${REPO_ROOT}/${MIN_TOPO}" ]] || fail "missing shipped topology: ${MIN_TOPO}"
  [[ -f "${REPO_ROOT}/${FAIL_TOPO}" ]] || fail "missing shipped topology: ${FAIL_TOPO}"
}

require_docker_leak_check_surface() {
  command -v docker >/dev/null 2>&1 || fail "docker not found: cannot perform required clab leak check"
  if ! (cd "${REPO_ROOT}" && docker ps -a --format '{{.Names}}' >/dev/null 2>&1); then
    fail "docker unavailable or not queryable: cannot perform required clab leak check"
  fi
}

run_cli_expect_rc() {
  local label="$1"
  local expected_rc="$2"
  shift 2

  local out_file="${TMP_DIR}/$(printf '%s' "${label}" | tr ' /' '__').log"
  local rc=0

  say "${CLI[*]} $*"
  set +e
  (
    cd "${REPO_ROOT}" &&
    "${CLI[@]}" "$@"
  ) >"${out_file}" 2>&1
  rc=$?
  set -e

  if [[ "${rc}" -ne "${expected_rc}" ]]; then
    printf -- '--- command output (%s) ---\n' "${label}" >&2
    cat "${out_file}" >&2
    printf -- '--- end command output (%s) ---\n' "${label}" >&2
    fail "${label}: expected exit ${expected_rc}, got ${rc}"
  fi
}

clear_stale_artifacts() {
  say "clearing stale generated artifacts for shipped proof labs"
  rm -rf "${REPO_ROOT}/${MIN_DIR}" "${REPO_ROOT}/${FAIL_DIR}"
}

snapshot_clab_names() {
  (
    cd "${REPO_ROOT}" &&
    docker ps -a --format '{{.Names}}' | grep '^clab-' | sort -u
  ) || true
}

check_artifact_trio() {
  local label="$1"
  local lab_dir="$2"
  local path="${REPO_ROOT}/${lab_dir}"

  [[ -f "${path}/topology.resolved.yaml" ]] || fail "${label}: missing ${lab_dir}/topology.resolved.yaml"
  [[ -f "${path}/results.json" ]] || fail "${label}: missing ${lab_dir}/results.json"
  [[ -f "${path}/results.summary.txt" ]] || fail "${label}: missing ${lab_dir}/results.summary.txt"
}

results_json_result() {
  local json_path="$1"
  python3 - "${json_path}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as fh:
    data = json.load(fh)
value = str(data.get('result', '')).strip()
if not value:
    raise SystemExit(3)
print(value)
PY
}

check_result_matches() {
  local label="$1"
  local lab_dir="$2"
  local expected_result="$3"
  local actual_result=""

  if ! actual_result="$(results_json_result "${REPO_ROOT}/${lab_dir}/results.json")"; then
    fail "${label}: unable to read authoritative result from ${lab_dir}/results.json"
  fi

  if [[ "${actual_result}" != "${expected_result}" ]]; then
    fail "${label}: contradictory exit/result behavior (expected results.json result '${expected_result}', got '${actual_result}')"
  fi
}

check_final_clab_leaks() {
  local before_snapshot="$1"
  local after_snapshot
  local target_leaks
  local new_leaks

  after_snapshot="$(snapshot_clab_names)"
  target_leaks="$(printf '%s\n' "${after_snapshot}" | grep -E '^clab-(first-run-proof-minimal|first-run-proof-fail-catching)(-|$)' || true)"
  new_leaks="$(comm -13 <(printf '%s\n' "${before_snapshot}" | sed '/^$/d' | sort -u) <(printf '%s\n' "${after_snapshot}" | sed '/^$/d' | sort -u) || true)"

  if [[ -n "${target_leaks}" ]]; then
    printf 'Leaked shipped-path containers:\n%s\n' "${target_leaks}" >&2
    fail "final clab leak check failed"
  fi

  if [[ -n "${new_leaks}" ]]; then
    printf 'Unexpected new clab containers remain after smoke run:\n%s\n' "${new_leaks}" >&2
    fail "final clab leak check failed"
  fi
}

main() {
  local before_clab=""

  require_repo_surface
  require_docker_leak_check_surface

  run_cli_expect_rc "doctor" 0 doctor

  before_clab="$(snapshot_clab_names)"
  clear_stale_artifacts

  run_cli_expect_rc "validate first-run-proof-minimal" 0 validate "${MIN_TOPO}"

  run_cli_expect_rc "test first-run-proof-minimal" 0 test "${MIN_TOPO}"
  check_artifact_trio "first-run-proof-minimal" "${MIN_DIR}"
  check_result_matches "first-run-proof-minimal" "${MIN_DIR}" "pass"

  run_cli_expect_rc "test first-run-proof-fail-catching" 1 test "${FAIL_TOPO}"
  check_artifact_trio "first-run-proof-fail-catching" "${FAIL_DIR}"
  check_result_matches "first-run-proof-fail-catching" "${FAIL_DIR}" "fail"

  check_final_clab_leaks "${before_clab}"

  printf '\nCold Sim v2: PASS\n'
  printf '  - doctor: ok\n'
  printf '  - validate first-run-proof-minimal: exit 0\n'
  printf '  - test first-run-proof-minimal: exit 0, artifacts ok, results.json=pass\n'
  printf '  - test first-run-proof-fail-catching: exit 1, artifacts ok, results.json=fail\n'
  printf '  - final clab leak check: clean\n'
  printf '  - artifacts: %s and %s\n' "${MIN_DIR}" "${FAIL_DIR}"
}

main "$@"

