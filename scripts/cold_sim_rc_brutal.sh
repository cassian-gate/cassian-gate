#!/usr/bin/env bash
# scripts/cold_sim_rc_brutal.sh
#
# ai-netsim Release-Candidate Brutal Cold Simulation (v2-compatible)
# One-shot: run a fixed battery of commands and enforce trust/UX/determinism invariants.
# Exits 1 if any invariant is violated.
#
# Usage:
#   bash scripts/cold_sim_rc_brutal.sh
#
# Recommended:
#   LEAK_SCOPE=topo TOPO_MIN=topologies/rc_cold_baseline.yaml bash scripts/cold_sim_rc_brutal.sh
#
# Optional overrides:
#   OUT_DIR=artifacts/cold_sim_rc_brutal \
#   NETSIM=./src/netsim.py \
#   TOPO_MIN=examples/01_connected_smoke.yaml \
#   LEAK_SCOPE=topo \
#   bash scripts/cold_sim_rc_brutal.sh
#
set -euo pipefail

OUT_DIR="${OUT_DIR:-artifacts/cold_sim_rc_brutal}"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/rc_brutal_${TS}.log"
JSONL="$OUT_DIR/rc_brutal_${TS}.jsonl"
REPORT="$OUT_DIR/rc_brutal_${TS}.report.txt"
mkdir -p "$OUT_DIR"

# Deterministic single-run artifacts (truncate at start)
: >"$LOG"
: >"$JSONL"
: >"$REPORT"

NETSIM_RAW="${NETSIM:-./src/netsim.py}"
TOPO_MIN="${TOPO_MIN:-}"

# Leak check scope:
# - all  : fail if ANY clab-* containers exist (brutal; assumes clean host)
# - topo : only check containers for the topo-derived lab name
LEAK_SCOPE="${LEAK_SCOPE:-all}"

# ---------- helpers ----------
now_iso() { date -Is; }

note () { echo "$*" | tee -a "$LOG"; }
warn () { echo "WARN: $*" | tee -a "$LOG" >&2; }

FAIL_COUNT=0
fail () {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL: $*" | tee -a "$LOG" "$REPORT" >&2
}
ok () { echo "OK: $*" | tee -a "$LOG"; }

# Normalize netsim invocation (supports NETSIM=./src/netsim.py)
declare -a NETSIM_CMD
if [[ "$NETSIM_RAW" == *.py && ! -x "$NETSIM_RAW" ]]; then
  NETSIM_CMD=(python "$NETSIM_RAW")
else
  NETSIM_CMD=("$NETSIM_RAW")
fi

pick_topo_min () {
  if [[ -n "${TOPO_MIN:-}" && -f "$TOPO_MIN" ]]; then
    echo "$TOPO_MIN"; return 0
  fi
  if [[ -f "examples/01_connected_smoke.yaml" ]]; then
    echo "examples/01_connected_smoke.yaml"; return 0
  fi
  local c
  c="$(ls -1 examples/*.yaml 2>/dev/null | head -n 1 || true)"
  if [[ -n "$c" && -f "$c" ]]; then
    echo "$c"; return 0
  fi
  c="$(ls -1 topologies/*.yaml 2>/dev/null | head -n 1 || true)"
  if [[ -n "$c" && -f "$c" ]]; then
    echo "$c"; return 0
  fi
  echo ""
  return 1
}

# Extract lab name from YAML (best-effort):
# 1) Try PyYAML (preferred)
# 2) Fallback: grep first top-level "name:" key
topo_name () {
  local topo="$1"

  local py=""
  py="$(python - <<'PY' "$topo" 2>/dev/null || true
import sys
p=sys.argv[1]
try:
  import yaml
except Exception:
  sys.exit(0)
try:
  with open(p,'r',encoding='utf-8') as f:
    d=yaml.safe_load(f) or {}
  name=str((d.get('name') or '')).strip()
  if name:
    print(name)
except Exception:
  pass
PY
)"
  if [[ -n "$py" ]]; then
    echo "$py"
    return 0
  fi

  local g=""
  g="$(grep -E '^[[:space:]]*name:[[:space:]]*' "$topo" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*name:[[:space:]]*//')"
  g="$(echo "$g" | tr -d '"' | tr -d "'" | xargs || true)"
  echo "$g"
}

lab_dir () {
  local lab="$1"
  echo "labs/clab-${lab}"
}

# Stable-slice hash for results.json (exclude volatile metadata)
stable_results_sha () {
  local results_json="$1"
  [[ -f "$results_json" ]] || { echo ""; return 0; }
  python - <<'PY' "$results_json" 2>/dev/null || true
import sys, json, hashlib
p=sys.argv[1]
obj=json.load(open(p,'r',encoding='utf-8'))

stable = {
  "authority": obj.get("authority"),
  "lab": obj.get("lab"),
  "result": obj.get("result"),
  "overall": obj.get("overall"),
  "tests": obj.get("tests"),
  "scenarios": obj.get("scenarios"),
  "hard_failure": obj.get("hard_failure"),
  "summary": obj.get("summary"),
  "results_schema_version": obj.get("results_schema_version"),
  "results_schema": obj.get("results_schema"),
  "schema_version": obj.get("schema_version"),
  "tool": obj.get("tool"),
  "topology": obj.get("topology"),
}

DROP_KEYS = set([
  "timing","timestamps","time","duration","duration_s","duration_ms",
  "started_at","ended_at","finished_at","created_at","generated_at",
  "wall_s","cpu_s",
  "resolved_topology_mtime",
  "resolved_topology_path","artifacts_dir","lab_dir","work_dir",
])

def scrub(x):
  if isinstance(x, dict):
    return {k: scrub(v) for k,v in x.items() if k not in DROP_KEYS}
  if isinstance(x, list):
    return [scrub(v) for v in x]
  return x

stable = scrub(stable)
canon = json.dumps(stable, sort_keys=True, separators=(",",":")).encode("utf-8")
print(hashlib.sha256(canon).hexdigest())
PY
}

# Docker leak checks
docker_list_clab_all () {
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^clab-' || true
}
docker_list_clab_for_lab () {
  local lab="$1"
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E "^clab-${lab}-" || true
}

docker_leak_check () {
  local when="$1"
  local lab="${2:-}"
  local leaked=""

  if ! command -v docker >/dev/null 2>&1; then
    warn "docker CLI missing; skipping leak check (${when})"
    return 0
  fi

  if [[ "$LEAK_SCOPE" == "topo" ]]; then
    if [[ -z "$lab" ]]; then
      warn "leak check (${when}): LEAK_SCOPE=topo but lab name unknown; skipping"
      return 0
    fi
    leaked="$(docker_list_clab_for_lab "$lab" || true)"
  else
    leaked="$(docker_list_clab_all || true)"
  fi

  if [[ -n "$leaked" ]]; then
    echo "FAIL: LEAK(${when}): clab containers still present:" | tee -a "$LOG" "$REPORT" >&2
    echo "$leaked" | sed 's/^/  - /' | tee -a "$LOG" "$REPORT" >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
  fi
  ok "no clab container leak (${when}, scope=${LEAK_SCOPE})"
  return 0
}

looks_like_raw_docker_error () {
  local out="$1"
  echo "$out" | grep -Eqi '(Error response from daemon|OCI runtime|no such container|Got permission denied while trying to connect|docker:)' && return 0
  return 1
}

looks_like_missing_nc () {
  local out="$1"
  echo "$out" | grep -Eqi '(^|[[:space:]])nc not found([[:space:]]|$)' && return 0
  echo "$out" | grep -Eqi 'Use wbitt/network-multitool' && return 0
  return 1
}

# Step runner: capture output+rc; append JSONL record safely
STEP_RC=0
STEP_OUT=""
run_step () {
  local label="$1"; shift
  local cmd=("$@")

  local started_at ended_at start_epoch end_epoch dur_s rc
  started_at="$(now_iso)"
  start_epoch="$(date +%s)"

  {
    echo "================================================================"
    echo "STEP: $label"
    echo "TIME: $started_at"
    echo -n "CMD :"
    printf " %q" "${cmd[@]}"
    echo
    echo "----------------------------------------------------------------"
  } | tee -a "$LOG"

  set +e
  STEP_OUT="$("${cmd[@]}" 2>&1)"
  rc=$?
  set -e

  ended_at="$(now_iso)"
  end_epoch="$(date +%s)"
  if [[ "$end_epoch" -ge "$start_epoch" ]]; then
    dur_s="$((end_epoch - start_epoch))"
  else
    dur_s="0"
  fi

  {
    echo "$STEP_OUT"
    echo "----------------------------------------------------------------"
    echo "EXIT: $rc"
    echo "DUR : ${dur_s}s"
    echo
  } | tee -a "$LOG"

  # Important: program via -c, and STEP_OUT via stdin.
  python -c '
import sys, json
jsonl_path = sys.argv[1]
label = sys.argv[2]
rc = int(sys.argv[3])
started_at = sys.argv[4]
ended_at = sys.argv[5]
dur_s = int(sys.argv[6])
cmd = sys.argv[7:]
output = sys.stdin.read()

rec = {
  "label": label,
  "exit": rc,
  "started_at": started_at,
  "ended_at": ended_at,
  "duration_s": dur_s,
  "cmd": cmd,
  "output": output,
}
with open(jsonl_path, "a", encoding="utf-8") as f:
  f.write(json.dumps(rec, ensure_ascii=False) + "\n")
' "$JSONL" "$label" "$rc" "$started_at" "$ended_at" "$dur_s" "${cmd[@]}" <<<"$STEP_OUT" || true

  STEP_RC="$rc"
}

# Accept both summary formats (old + new)
summary_has_required_keys () {
  local summary="$1"
  [[ -f "$summary" ]] || return 1

  if grep -qiE '^[[:space:]]*verdict:[[:space:]]*(PASS|FAIL)' "$summary" \
     && grep -qiE '^[[:space:]]*tests:[[:space:]]*total=' "$summary"; then
    return 0
  fi

  if grep -qE '^RESULT:' "$summary" \
     && grep -qE '^Tests executed:' "$summary" \
     && grep -qE '^Scenarios executed:' "$summary"; then
    return 0
  fi

  return 1
}

extract_summary_verdict () {
  local summary="$1"
  [[ -f "$summary" ]] || { echo ""; return 0; }

  local v=""
  v="$(grep -iE '^[[:space:]]*verdict:' "$summary" | head -n1 | awk -F: '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print toupper($2)}')"
  if [[ "$v" == "PASS" || "$v" == "FAIL" ]]; then
    echo "$v"; return 0
  fi

  v="$(grep -E '^RESULT:' "$summary" | head -n1 | sed 's/^RESULT:[[:space:]]*//')"
  v="$(echo "$v" | tr -d '\r' | xargs || true)"
  echo "${v:-}"
}

# Brutal checks for a gate run
check_gate_artifacts_and_consistency () {
  local topo="$1"
  local label="$2"

  local lab dir resolved results summary
  lab="$(topo_name "$topo")"
  if [[ -z "$lab" ]]; then
    fail "${label}: could not extract lab name from topology: $topo"
    return 0
  fi

  dir="$(lab_dir "$lab")"
  resolved="$dir/topology.resolved.yaml"
  results="$dir/results.json"
  summary="$dir/results.summary.txt"

  [[ -f "$resolved" ]] || fail "${label}: missing $resolved"
  [[ -f "$results"  ]] || fail "${label}: missing $results (RC-grade: gate must emit results.json even on prereq failures)"
  [[ -f "$summary"  ]] || fail "${label}: missing $summary (RC-grade: gate must emit summary even on prereq failures)"

  if [[ -f "$summary" ]]; then
    if summary_has_required_keys "$summary"; then
      ok "${label}: summary contains required keys (format ok)"
    else
      fail "${label}: summary missing required keys (format drift or wrong file)"
    fi

    local verdict
    verdict="$(extract_summary_verdict "$summary")"
    if [[ "$verdict" == "PASS" && "$STEP_RC" -ne 0 ]]; then
      fail "${label}: CONTRADICTION: verdict=PASS but exit=$STEP_RC"
    elif [[ "$verdict" == "FAIL" && "$STEP_RC" -eq 0 ]]; then
      fail "${label}: CONTRADICTION: verdict=FAIL but exit=0"
    else
      ok "${label}: exit/verdict consistent (verdict=${verdict:-?}, exit=$STEP_RC)"
    fi
  fi

  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "${label}: raw Docker/daemon error leakage (should be netsim-owned or behind --verbose)"
  fi

  if looks_like_missing_nc "$STEP_OUT"; then
    fail "${label}: prereq/tooling mismatch detected (nc missing). RC expectation: fail clearly BUT still write authoritative artifacts."
  fi
}

make_bad_inputs () {
  mkdir -p "$OUT_DIR/tmp"
  cat >"$OUT_DIR/tmp/bad_yaml.yaml" <<'YAML'
name: bad-yaml
nodes: [ this is: not valid
YAML
  cat >"$OUT_DIR/tmp/missing_required.yaml" <<'YAML'
foo: bar
YAML
}

# ---------- phases ----------
phase0 () {
  run_step "00_help" "${NETSIM_CMD[@]}" --help
  [[ "$STEP_RC" -eq 0 ]] || fail "help returned non-zero exit=$STEP_RC"
  ok "help executed (exit=$STEP_RC)"

  run_step "01_doctor" "${NETSIM_CMD[@]}" doctor
  [[ "$STEP_RC" -eq 0 ]] || fail "doctor non-zero exit=$STEP_RC"
  ok "doctor executed (exit=$STEP_RC)"

  run_step "02_doctor_repeat" "${NETSIM_CMD[@]}" doctor
  [[ "$STEP_RC" -eq 0 ]] || fail "doctor repeat non-zero exit=$STEP_RC"
  ok "doctor repeat executed (exit=$STEP_RC)"
}

phaseA () {
  local topo="$1"
  [[ -f "$topo" ]] || { fail "missing TOPO_MIN topology: $topo"; return 0; }

  local lab=""
  lab="$(topo_name "$topo" || true)"

  docker_leak_check "pre" "$lab" || true

  run_step "A1_gate_test_topology" "${NETSIM_CMD[@]}" test "$topo"
  check_gate_artifacts_and_consistency "$topo" "A1_gate"
  docker_leak_check "post_A1_gate" "$lab" || true

  # A2 identical gate -> stable-slice determinism check (only if results exist)
  if [[ -n "$lab" ]]; then
    local dir results a_stable b_stable
    dir="$(lab_dir "$lab")"
    results="$dir/results.json"
    a_stable="$(stable_results_sha "$results")"

    run_step "A2_gate_test_topology_repeat" "${NETSIM_CMD[@]}" test "$topo"
    check_gate_artifacts_and_consistency "$topo" "A2_gate"
    docker_leak_check "post_A2_gate" "$lab" || true

    b_stable="$(stable_results_sha "$results")"

    if [[ -n "$a_stable" && -n "$b_stable" && "$a_stable" != "$b_stable" ]]; then
      fail "DETERMINISM: stable results slice hash changed between identical gate runs (A1 vs A2)"
    else
      ok "determinism: stable results slice hash stable (A1 vs A2)"
    fi
  else
    fail "A2: could not derive lab name; cannot determinism-check results.json"
  fi
}

phaseB () {
  local topo="$1"
  make_bad_inputs

  run_step "B1_validate_bad_yaml" "${NETSIM_CMD[@]}" validate "$OUT_DIR/tmp/bad_yaml.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B1_validate_bad_yaml: expected non-zero exit, got 0"

  run_step "B2_validate_missing_required" "${NETSIM_CMD[@]}" validate "$OUT_DIR/tmp/missing_required.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B2_validate_missing_required: expected non-zero exit, got 0"

  run_step "B3_gate_test_bad_yaml" "${NETSIM_CMD[@]}" test "$OUT_DIR/tmp/bad_yaml.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B3_gate_test_bad_yaml: expected non-zero exit, got 0"
  if echo "$STEP_OUT" | grep -qE 'Traceback \(most recent call last\):'; then
    fail "B3_gate_test_bad_yaml: traceback leaked (should be netsim-owned error unless --verbose)"
  fi

  run_step "B4_gate_test_missing_required" "${NETSIM_CMD[@]}" test "$OUT_DIR/tmp/missing_required.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B4_gate_test_missing_required: expected non-zero exit, got 0"

  run_step "B5_down_with_missing_topology_path" "${NETSIM_CMD[@]}" down "examples/does-not-exist.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "B5_down_with_missing_topology_path: expected non-zero exit"

  # Record behavior; do not fail by default.
  run_step "B6_down_unknown_lab" "${NETSIM_CMD[@]}" down "no-such-lab-xyz"
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "B6_down_unknown_lab: raw daemon leakage"
  fi

  run_step "B7_destroy_unknown_lab" "${NETSIM_CMD[@]}" destroy "no-such-lab-xyz"
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "B7_destroy_unknown_lab: raw daemon leakage"
  fi

  if [[ -f "$topo" ]]; then
    run_step "B8_candidate_missing_dir" "${NETSIM_CMD[@]}" test "$topo" --candidate-config "$OUT_DIR/tmp/does_not_exist"
    [[ "$STEP_RC" -ne 0 ]] || fail "B8_candidate_missing_dir: expected non-zero exit, got 0"
  fi
}

phaseC () {
  local topo="$1"

  run_step "C1_test_no_args" "${NETSIM_CMD[@]}" test
  [[ "$STEP_RC" -ne 0 ]] || fail "C1_test_no_args: expected non-zero exit"

  run_step "C2_status_no_args" "${NETSIM_CMD[@]}" status
  [[ "$STEP_RC" -ne 0 ]] || fail "C2_status_no_args: expected non-zero exit"

  run_step "C3_exec_no_args" "${NETSIM_CMD[@]}" exec
  [[ "$STEP_RC" -ne 0 ]] || fail "C3_exec_no_args: expected non-zero exit"

  run_step "C4_vty_no_args" "${NETSIM_CMD[@]}" vty
  [[ "$STEP_RC" -ne 0 ]] || fail "C4_vty_no_args: expected non-zero exit"

  run_step "C5_test_pathlike_missing" "${NETSIM_CMD[@]}" test "topologies/not-real.yaml"
  [[ "$STEP_RC" -ne 0 ]] || fail "C5_test_pathlike_missing: expected non-zero exit"

  if [[ -f "$topo" ]]; then
    local lab
    lab="$(topo_name "$topo" || true)"
    for i in 1 2 3; do
      run_step "C7_gate_repeat_${i}" "${NETSIM_CMD[@]}" test "$topo"
      check_gate_artifacts_and_consistency "$topo" "C7_gate_repeat_${i}"
      docker_leak_check "post_C7_${i}" "$lab" || true
    done
  fi

  run_step "C8_exec_unknown_lab" "${NETSIM_CMD[@]}" exec "no-such-lab-xyz" "r1" -- ip addr
  [[ "$STEP_RC" -ne 0 ]] || fail "C8_exec_unknown_lab: expected non-zero exit"
  if looks_like_raw_docker_error "$STEP_OUT"; then
    fail "C8_exec_unknown_lab: raw daemon leakage"
  fi
}

phaseD () {
  local topo="$1"
  if [[ -f "$topo" ]]; then
    set +e
    "${NETSIM_CMD[@]}" test "$topo" >/dev/null 2>&1
    local rc=$?
    set -e
    echo "CI_CAPTURE: gate_exit=${rc}" | tee -a "$LOG" "$REPORT"

    local lab dir summary verdict
    lab="$(topo_name "$topo" || true)"
    dir="$(lab_dir "$lab")"
    summary="$dir/results.summary.txt"

    if [[ -f "$summary" ]]; then
      verdict="$(extract_summary_verdict "$summary")"
      if [[ "$verdict" == "PASS" && "$rc" -ne 0 ]]; then
        fail "CI: CONTRADICTION: verdict=PASS but rc=${rc}"
      elif [[ "$verdict" == "FAIL" && "$rc" -eq 0 ]]; then
        fail "CI: CONTRADICTION: verdict=FAIL but rc=0"
      else
        ok "CI: exit/verdict consistent (verdict=${verdict:-?}, rc=${rc})"
      fi

      if ! summary_has_required_keys "$summary"; then
        fail "CI: summary parsing failed (format drift?)"
      else
        ok "CI: summary parsing ok"
      fi
    else
      fail "CI: missing summary at expected path: $summary"
    fi
  fi
}

finalize () {
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

  if [[ "$FAIL_COUNT" -ne 0 ]]; then
    exit 1
  fi
  exit 0
}
trap finalize EXIT

main () {
  local topo
  topo="$(pick_topo_min || true)"
  if [[ -z "$topo" ]]; then
    fail "no usable topology found; set TOPO_MIN=... to a real YAML"
    topo="(none)"
  fi

  {
    echo "================================================================"
    echo "ai-netsim RC Brutal Cold Simulation"
    echo "TIME : $(now_iso)"
    echo "OUT  : $OUT_DIR"
    echo "LOG  : $LOG"
    echo "JSONL: $JSONL"
    echo "REPORT: $REPORT"
    echo "NETSIM: ${NETSIM_CMD[*]}"
    echo "TOPO_MIN: $topo"
    echo "LEAK_SCOPE: $LEAK_SCOPE"
    echo "================================================================"
    echo
  } | tee -a "$LOG" "$REPORT"

  phase0
  phaseA "$topo"
  phaseB "$topo"
  phaseC "$topo"
  phaseD "$topo"
}

main