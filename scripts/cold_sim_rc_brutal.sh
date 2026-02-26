#!/usr/bin/env bash
# scripts/cold_sim_rc_brutal.sh
#
# ai-netsim Release-Candidate Brutal Mode
# - Runs cold-sim phases + enforces trust/UX/determinism invariants.
# - Fails the script (non-zero) if contract/UX contradictions are detected.
#
# Usage:
#   bash scripts/cold_sim_rc_brutal.sh
#
# Overrides:
#   OUT_DIR=artifacts/cold_sim NETSIM=./src/netsim.py TOPO_MIN=examples/demo-lab.yaml bash scripts/cold_sim_rc_brutal.sh
#
# Notes:
# - This script is intentionally strict. It is intended for RC validation.
# - It does NOT assume sudo; it will record failures and enforce messaging integrity.
# - Container leak checks require docker CLI + permission to list containers.

set -u

OUT_DIR="${OUT_DIR:-artifacts/cold_sim_rc_brutal}"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/rc_brutal_${TS}.log"
JSONL="$OUT_DIR/rc_brutal_${TS}.jsonl"
REPORT="$OUT_DIR/rc_brutal_${TS}.report.txt"
mkdir -p "$OUT_DIR"

NETSIM_RAW="${NETSIM:-./src/netsim.py}"
TOPO_MIN="${TOPO_MIN:-examples/demo-lab.yaml}"

# ---------- helpers ----------
now_iso() { date -Is; }

die () {
  echo "FATAL: $*" | tee -a "$LOG" "$REPORT" >&2
  exit 2
}

note () {
  echo "$*" | tee -a "$LOG"
}

warn () {
  echo "WARN: $*" | tee -a "$LOG" >&2
}

# Normalize netsim invocation:
# - if NETSIM points to a .py and isn't executable -> run via python
declare -a NETSIM_CMD
if [[ "$NETSIM_RAW" == *.py && ! -x "$NETSIM_RAW" ]]; then
  NETSIM_CMD=(python "$NETSIM_RAW")
else
  NETSIM_CMD=("$NETSIM_RAW")
fi

# Cheap YAML name extraction (best-effort; no hard dependency on python packages beyond stdlib+pyyaml)
topo_name () {
  local topo="$1"
  python - <<'PY' "$topo" 2>/dev/null || true
import sys
try:
  import yaml
except Exception:
  sys.exit(0)
p=sys.argv[1]
try:
  with open(p,'r',encoding='utf-8') as f:
    d=yaml.safe_load(f) or {}
  name=str((d.get('name') or '')).strip()
  print(name)
except Exception:
  pass
PY
}

lab_dir () {
  local lab="$1"
  echo "labs/clab-${lab}"
}

sha256_file () {
  local f="$1"
  if [[ -f "$f" ]]; then
    sha256sum "$f" | awk '{print $1}'
  else
    echo ""
  fi
}

size_bytes () {
  local f="$1"
  if [[ -f "$f" ]]; then
    wc -c <"$f" | tr -d ' '
  else
    echo "0"
  fi
}

# Docker leak checks (best-effort)
docker_list_clab () {
  # Matches container names that start with "clab-"
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^clab-' || true
}

docker_leak_check () {
  local when="$1"
  local leaked
  leaked="$(docker_list_clab || true)"
  if [[ -n "$leaked" ]]; then
    echo "LEAK(${when}): clab containers still present:" | tee -a "$LOG" "$REPORT"
    echo "$leaked" | sed 's/^/  - /' | tee -a "$LOG" "$REPORT"
    return 1
  fi
  note "OK: no clab container leak (${when})"
  return 0
}

# Common contradiction checks
extract_summary_fields () {
  local summary="$1"
  local result tests scenarios
  result="$(grep -E '^RESULT:' "$summary" 2>/dev/null | head -n1 | sed 's/^RESULT:[[:space:]]*//')"
  tests="$(grep -E '^Tests executed:' "$summary" 2>/dev/null | head -n1 | sed 's/^Tests executed:[[:space:]]*//')"
  scenarios="$(grep -E '^Scenarios executed:' "$summary" 2>/dev/null | head -n1 | sed 's/^Scenarios executed:[[:space:]]*//')"
  echo "${result:-}|${tests:-}|${scenarios:-}"
}

# Best-effort heuristic for raw daemon leakage (tune if too noisy)
looks_like_raw_docker_error () {
  local out="$1"
  echo "$out" | grep -Eqi '(docker:|no such container|Error response from daemon|OCI runtime|container .* not found|Got permission denied while trying to connect)' && return 0
  return 1
}

# Step runner: capture output+rc; also write JSONL record
run_step () {
  local label="$1"; shift
  local cmd=("$@")

  local start_epoch end_epoch rc output
  start_epoch="$(date +%s)"

  {
    echo "================================================================"
    echo "STEP: $label"
    echo "TIME: $(now_iso)"
    echo -n "CMD :"
    printf " %q" "${cmd[@]}"
    echo
    echo "----------------------------------------------------------------"
  } | tee -a "$LOG"

  set +e
  output="$("${cmd[@]}" 2>&1)"
  rc=$?
  set -e

  end_epoch="$(date +%s)"

  {
    echo "$output"
    echo "----------------------------------------------------------------"
    echo "EXIT: $rc"
    echo "DUR : $((end_epoch - start_epoch))s"
    echo
  } | tee -a "$LOG"

  python - <<PY >>"$JSONL" || true
import json, time
rec = {
  "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
  "label": ${label!r},
  "cmd": ${cmd[@]@Q},
  "exit": $rc,
  "output": ${output!r},
}
print(json.dumps(rec, ensure_ascii=False))
PY

  # return output+rc via globals (bash-friendly)
  STEP_RC="$rc"
  STEP_OUT="$output"
}

# Assertions tracking
FAIL_COUNT=0
fail () {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL: $*" | tee -a "$LOG" "$REPORT"
}

ok () {
  echo "OK: $*" | tee -a "$LOG"
}

# ---------- setup bad inputs ----------
make_bad_inputs () {
  mkdir -p "$OUT_DIR/tmp"

  cat >"$OUT_DIR/tmp/bad_yaml.yaml" <<'YAML'
name: bad-yaml
nodes: [ this is: not valid
YAML

  cat >"$OUT_DIR/tmp/missing_required.yaml" <<'YAML'
foo: bar
YAML

  mkdir -p "$OUT_DIR/tmp/cand_bad_root"
  echo "oops" >"$OUT_DIR/tmp/cand_bad_root/not_allowed.txt"

  mkdir -p "$OUT_DIR/tmp/cand_empty_frr/frr"
  : >"$OUT_DIR/tmp/cand_empty_frr/frr/r1.conf"

  mkdir -p "$OUT_DIR/tmp/cand_unknown_subdir/banana"
  echo "x" >"$OUT_DIR/tmp/cand_unknown_subdir/banana/r1.conf"
}

# ---------- brutal checks for a gate run ----------
check_gate_artifacts_and_consistency () {
  local topo="$1"
  local label="$2"
  local lab
  lab="$(topo_name "$topo")"
  if [[ -z "$lab" ]]; then
    fail "${label}: could not extract lab name from topology: $topo (cannot validate artifacts)"
    return 0
  fi

  local dir
  dir="$(lab_dir "$lab")"

  local resolved="$dir/topology.resolved.yaml"
  local results="$dir/results.json"
  local summary="$dir/results.summary.txt"

  # Existence checks (contract: artifacts must exist after gate, even if failure happened late)
  [[ -f "$resolved" ]] || fail "${label}: missing $resolved"
  [[ -f "$results" ]] || fail "${label}: missing $results"
  [[ -f "$summary" ]] || fail "${label}: missing $summary"

  # Summary format: must contain key lines (stable parsing)
  if [[ -f "$summary" ]]; then
    grep -qE '^RESULT:' "$summary" || fail "${label}: summary missing 'RESULT:' line"
    grep -qE '^Tests executed:' "$summary" || fail "${label}: summary missing 'Tests executed:' line"
    grep -qE '^Scenarios executed:' "$summary" || fail "${label}: summary missing 'Scenarios executed:' line"
  fi

  # Exit/result contradiction checks (if summary exists)
  if [[ -f "$summary" ]]; then
    local fields result
    fields="$(extract_summary_fields "$summary")"
    result="${fields%%|*}"

    # If RESULT says PASS, exit should be 0. If RESULT says FAIL, exit should be non-zero.
    # (If your contract uses different mapping, this will catch it.)
    if [[ "$result" == "PASS" && "$STEP_RC" -ne 0 ]]; then
      fail "${label}: CONTRADICTION: summary RESULT=PASS but exit=$STEP_RC"
    elif [[ "$result" == "FAIL" && "$STEP_RC" -eq 0 ]]; then
      fail "${label}: CONTRADICTION: summary RESULT=FAIL but exit=0"
    else
      ok "${label}: exit/result relationship looks consistent (RESULT=${result:-?}, exit=$STEP_RC)"
    fi
  fi

  # Raw daemon error leakage heuristic:
  # If we see raw daemon text, we expect netsim to own messaging; this flags potential UX regression.
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "${label}: possible raw Docker/daemon error leakage in output (should be netsim-owned or behind --verbose)"
  fi

  # PASS with 0 tests is allowed, but must be clearly communicated in summary.
  # We validate that the counts are present; we don't fail on 0.
  if [[ -f "$summary" ]]; then
    local fields tests scenarios
    fields="$(extract_summary_fields "$summary")"
    tests="$(echo "$fields" | cut -d'|' -f2)"
    scenarios="$(echo "$fields" | cut -d'|' -f3)"
    ok "${label}: summary counts present (tests=${tests:-?}, scenarios=${scenarios:-?})"
  fi
}

# Compare determinism between two identical gate runs
compare_gate_determinism () {
  local topo="$1"
  local label_a="$2"
  local label_b="$3"

  local lab
  lab="$(topo_name "$topo")"
  if [[ -z "$lab" ]]; then
    fail "determinism: cannot extract lab name from $topo"
    return 0
  fi

  local dir
  dir="$(lab_dir "$lab")"

  local resolved="$dir/topology.resolved.yaml"
  local results="$dir/results.json"
  local summary="$dir/results.summary.txt"

  local h_resolved h_results h_summary
  h_resolved="$(sha256_file "$resolved")"
  h_results="$(sha256_file "$results")"
  h_summary="$(sha256_file "$summary")"

  # Store first-run hashes in files keyed by TS+lab
  local base="$OUT_DIR/${lab}_${TS}"
  echo "$h_resolved" >"${base}.resolved.sha"
  echo "$h_results"  >"${base}.results.sha"
  echo "$h_summary"  >"${base}.summary.sha"

  ok "determinism: captured hashes for ${label_b} (lab=$lab)"
}

# ---------- phases ----------
phase0 () {
  run_step "00_help" "${NETSIM_CMD[@]}" --help
  ok "help executed (exit=$STEP_RC)"

  run_step "01_doctor" "${NETSIM_CMD[@]}" doctor
  [[ "$STEP_RC" -eq 0 ]] || fail "doctor non-zero exit=$STEP_RC"
  ok "doctor executed (exit=$STEP_RC)"

  run_step "02_doctor_repeat" "${NETSIM_CMD[@]}" doctor
  [[ "$STEP_RC" -eq 0 ]] || fail "doctor repeat non-zero exit=$STEP_RC"
  ok "doctor repeat executed (exit=$STEP_RC)"
}

phaseA () {
  [[ -f "$TOPO_MIN" ]] || fail "missing TOPO_MIN topology: $TOPO_MIN"

  # Leak check before anything (hidden state detection)
  docker_leak_check "pre" || fail "pre: container leak detected"

  # A1 gate
  if [[ -f "$TOPO_MIN" ]]; then
    run_step "A1_gate_test_topology" "${NETSIM_CMD[@]}" test "$TOPO_MIN"
    check_gate_artifacts_and_consistency "$TOPO_MIN" "A1_gate"
    docker_leak_check "post_A1_gate" || fail "post_A1_gate: container leak detected"
  fi

  # A2 identical gate (determinism)
  if [[ -f "$TOPO_MIN" ]]; then
    # Snapshot A1 hashes for comparison
    local lab dir resolved results summary
    lab="$(topo_name "$TOPO_MIN")"
    dir="$(lab_dir "$lab")"
    resolved="$dir/topology.resolved.yaml"
    results="$dir/results.json"
    summary="$dir/results.summary.txt"

    local a_res a_results a_sum
    a_res="$(sha256_file "$resolved")"
    a_results="$(sha256_file "$results")"
    a_sum="$(sha256_file "$summary")"

    run_step "A2_gate_test_topology_repeat" "${NETSIM_CMD[@]}" test "$TOPO_MIN"
    check_gate_artifacts_and_consistency "$TOPO_MIN" "A2_gate"
    docker_leak_check "post_A2_gate" || fail "post_A2_gate: container leak detected"

    # Compare hashes
    local b_res b_results b_sum
    b_res="$(sha256_file "$resolved")"
    b_results="$(sha256_file "$results")"
    b_sum="$(sha256_file "$summary")"

    if [[ -n "$a_res" && -n "$b_res" && "$a_res" != "$b_res" ]]; then
      fail "DETERMINISM: topology.resolved.yaml hash changed between identical gate runs (A1 vs A2)"
    else
      ok "determinism: topology.resolved.yaml stable (A1 vs A2)"
    fi

    if [[ -n "$a_results" && -n "$b_results" && "$a_results" != "$b_results" ]]; then
      fail "DETERMINISM: results.json hash changed between identical gate runs (A1 vs A2)"
    else
      ok "determinism: results.json stable (A1 vs A2)"
    fi

    if [[ -n "$a_sum" && -n "$b_sum" && "$a_sum" != "$b_sum" ]]; then
      fail "DETERMINISM: results.summary.txt hash changed between identical gate runs (A1 vs A2)"
    else
      ok "determinism: results.summary.txt stable (A1 vs A2)"
    fi
  fi

  # A3 explore: up -> status -> test lab -> collect -> down
  if [[ -f "$TOPO_MIN" ]]; then
    run_step "A3_up_reconfigure" "${NETSIM_CMD[@]}" up "$TOPO_MIN" --reconfigure
    # up may fail in environments lacking permissions; we log but do not auto-fail the whole RC.
    [[ "$STEP_RC" -eq 0 ]] || warn "up returned non-zero (exit=$STEP_RC) - continuing to observe UX"

    local lab
    lab="$(topo_name "$TOPO_MIN")"
    if [[ -n "$lab" ]]; then
      run_step "A3_status_summary" "${NETSIM_CMD[@]}" status "$lab" --summary
      run_step "A3_status_json" "${NETSIM_CMD[@]}" status "$lab" --json

      run_step "A3_test_lab_name" "${NETSIM_CMD[@]}" test "$lab"
      # Test-lab-mode should never silently behave like gate-topology-mode.
      # We can’t enforce semantics here, but we can flag contradictions/leaks.
      if looks_like_raw_docker_error "$STEP_OUT"; then
        fail "A3_test_lab_name: possible raw daemon leakage (should be netsim-owned)"
      fi

      run_step "A3_collect" "${NETSIM_CMD[@]}" collect "$lab"
      run_step "A3_down" "${NETSIM_CMD[@]}" down "$lab"

      # Idempotency: down twice should be clear and safe (either “already down” or clear not-found)
      run_step "A3_down_idempotent" "${NETSIM_CMD[@]}" down "$lab"
      if [[ "$STEP_RC" -eq 0 ]]; then
        ok "down idempotent returned exit=0 (acceptable if messaging is explicit)"
      else
        ok "down idempotent non-zero exit=$STEP_RC (acceptable if messaging is explicit and not raw-daemon)"
      fi

      docker_leak_check "post_A3_down" || fail "post_A3_down: container leak detected"
    else
      fail "A3: could not derive lab name; cannot continue explore checks"
    fi
  fi
}

phaseB () {
  make_bad_inputs

  run_step "B1_validate_bad_yaml" "${NETSIM_CMD[@]}" validate "$OUT_DIR/tmp/bad_yaml.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B1_validate_bad_yaml: expected non-zero exit, got 0"

  run_step "B2_validate_missing_required" "${NETSIM_CMD[@]}" validate "$OUT_DIR/tmp/missing_required.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B2_validate_missing_required: expected non-zero exit, got 0"

  run_step "B3_gate_test_bad_yaml" "${NETSIM_CMD[@]}" test "$OUT_DIR/tmp/bad_yaml.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B3_gate_test_bad_yaml: expected non-zero exit, got 0"

  run_step "B4_gate_test_missing_required" "${NETSIM_CMD[@]}" test "$OUT_DIR/tmp/missing_required.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B4_gate_test_missing_required: expected non-zero exit, got 0"

  # Destructive misuse: down with topology path must not silently no-op
  run_step "B5_down_with_topology_path" "${NETSIM_CMD[@]}" down "$TOPO_MIN"
  [[ "$STEP_RC" -ne 0 ]] || warn "B5_down_with_topology_path returned 0; ensure messaging explicitly describes behavior"

  run_step "B6_down_unknown_lab" "${NETSIM_CMD[@]}" down "no-such-lab-xyz"
  # Acceptable either way, but must be explicit and owned
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "B6_down_unknown_lab: raw daemon leakage"
  fi

  run_step "B7_destroy_unknown_lab" "${NETSIM_CMD[@]}" destroy "no-such-lab-xyz"
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "B7_destroy_unknown_lab: raw daemon leakage"
  fi

  # Candidate-config misuse (gate-only): should fail-fast
  run_step "B8_candidate_missing_dir" "${NETSIM_CMD[@]}" test "$TOPO_MIN" --candidate-config "$OUT_DIR/tmp/does_not_exist"
  [[ "$STEP_RC" -ne 0 ]] || fail "B8_candidate_missing_dir: expected non-zero exit, got 0"

  run_step "B9_candidate_wrong_root_file" "${NETSIM_CMD[@]}" test "$TOPO_MIN" --candidate-config "$OUT_DIR/tmp/cand_bad_root"
  [[ "$STEP_RC" -ne 0 ]] || fail "B9_candidate_wrong_root_file: expected non-zero exit, got 0"

  run_step "B10_candidate_empty_file" "${NETSIM_CMD[@]}" test "$TOPO_MIN" --candidate-config "$OUT_DIR/tmp/cand_empty_frr"
  [[ "$STEP_RC" -ne 0 ]] || fail "B10_candidate_empty_file: expected non-zero exit, got 0"

  run_step "B11_candidate_unknown_subdir" "${NETSIM_CMD[@]}" test "$TOPO_MIN" --candidate-config "$OUT_DIR/tmp/cand_unknown_subdir"
  [[ "$STEP_RC" -ne 0 ]] || fail "B11_candidate_unknown_subdir: expected non-zero exit, got 0"
}

phaseC () {
  # Missing args should be owned and clear
  run_step "C1_test_no_args" "${NETSIM_CMD[@]}" test
  [[ "$STEP_RC" -ne 0 ]] || warn "C1_test_no_args returned 0; ensure it prints help + non-zero"

  run_step "C2_status_no_args" "${NETSIM_CMD[@]}" status
  [[ "$STEP_RC" -ne 0 ]] || warn "C2_status_no_args returned 0; ensure it prints help + non-zero"

  run_step "C3_exec_no_args" "${NETSIM_CMD[@]}" exec
  [[ "$STEP_RC" -ne 0 ]] || warn "C3_exec_no_args returned 0; ensure it prints help + non-zero"

  run_step "C4_vty_no_args" "${NETSIM_CMD[@]}" vty
  [[ "$STEP_RC" -ne 0 ]] || warn "C4_vty_no_args returned 0; ensure it prints help + non-zero"

  # Path-like ambiguity: must not be misinterpreted as lab
  run_step "C5_test_pathlike_labname" "${NETSIM_CMD[@]}" test "topologies/not-real.yaml"
  [[ "$STEP_RC" -ne 0 ]] || warn "C5: returned 0; ensure it didn't treat missing file as lab or silently succeed"

  run_step "C6_test_dot_slash_yaml" "${NETSIM_CMD[@]}" test "./not-real.yaml"
  [[ "$STEP_RC" -ne 0 ]] || warn "C6: returned 0; ensure it didn't silently succeed"

  # Rapid-fire gate repeats (noise regression + stability)
  if [[ -f "$TOPO_MIN" ]]; then
    for i in 1 2 3; do
      run_step "C7_gate_repeat_${i}" "${NETSIM_CMD[@]}" test "$TOPO_MIN"
      check_gate_artifacts_and_consistency "$TOPO_MIN" "C7_gate_repeat_${i}"
      docker_leak_check "post_C7_${i}" || fail "post_C7_${i}: container leak detected"
    done
  fi

  # Exec guardrails: invalid lab should not leak raw docker by default
  run_step "C8_exec_unknown_lab" "${NETSIM_CMD[@]}" exec "no-such-lab-xyz" "r1" -- ip addr
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "C8_exec_unknown_lab: raw daemon leakage"
  fi
}

phaseD () {
  # CI: exit code capture and summary parsing stability
  if [[ -f "$TOPO_MIN" ]]; then
    set +e
    "${NETSIM_CMD[@]}" test "$TOPO_MIN" >/dev/null 2>&1
    local rc=$?
    set -e

    echo "CI_CAPTURE: gate_exit=${rc}" | tee -a "$LOG" "$REPORT"

    # Basic expectation: rc is 0 on PASS; non-zero on FAIL.
    # We validate by reading summary if present.
    local lab dir summary fields result
    lab="$(topo_name "$TOPO_MIN")"
    dir="$(lab_dir "$lab")"
    summary="$dir/results.summary.txt"
    if [[ -f "$summary" ]]; then
      fields="$(extract_summary_fields "$summary")"
      result="${fields%%|*}"

      if [[ "$result" == "PASS" && "$rc" -ne 0 ]]; then
        fail "CI: CONTRADICTION: RESULT=PASS but rc=${rc}"
      elif [[ "$result" == "FAIL" && "$rc" -eq 0 ]]; then
        fail "CI: CONTRADICTION: RESULT=FAIL but rc=0"
      else
        ok "CI: exit/result consistent (RESULT=${result:-?}, rc=${rc})"
      fi

      # Parse stability grep
      grep -E '^(RESULT:|Tests executed:|Scenarios executed:)' "$summary" >/dev/null 2>&1 \
        || fail "CI: summary parsing grep failed (format drift?)"
      ok "CI: summary parsing grep OK"
    else
      warn "CI: summary missing at expected path: $summary"
    fi
  fi
}

main () {
  {
    echo "================================================================"
    echo "ai-netsim RC Brutal Cold Simulation"
    echo "TIME : $(now_iso)"
    echo "OUT  : $OUT_DIR"
    echo "LOG  : $LOG"
    echo "JSONL: $JSONL"
    echo "REPORT: $REPORT"
    echo "NETSIM: ${NETSIM_CMD[*]}"
    echo "TOPO_MIN: $TOPO_MIN"
    echo "================================================================"
    echo
  } | tee -a "$LOG" "$REPORT"

  # Sanity: docker must exist for leak checks; if not, we still run but flag
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker CLI missing; cannot run leak checks (doctor should have caught this)"
  fi

  phase0
  phaseA
  phaseB
  phaseC
  phaseD

  {
    echo
    echo "================================================================"
    echo "DONE"
    echo "FAIL_COUNT: $FAIL_COUNT"
    echo "LOG   : $LOG"
    echo "JSONL : $JSONL"
    echo "REPORT: $REPORT"
    echo "================================================================"
  } | tee -a "$LOG" "$REPORT"

  # Brutal mode: any failure => non-zero exit
  if [[ "$FAIL_COUNT" -ne 0 ]]; then
    exit 1
  fi
  exit 0
}

set -e
main
