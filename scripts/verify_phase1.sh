#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Deterministic module resolution (local src/ only)
# ------------------------------------------------------------------------------
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"

# Always invoke cassian through this wrapper (no direct ./src/cassian.py calls)
NS="./src/cassian.py"

# ------------------------------------------------------------------------------
# Usage:
#   ./scripts/verify_phase1.sh [lab-name]
#
# Notes:
# - Phase-1 verification is deterministic + offline-first.
# - AI verification lives in ./scripts/verify_ai.sh (kept separate on purpose).
# ------------------------------------------------------------------------------
LAB="${1:-three-frr-two-hosts-fw-routed}"
LABDIR="labs/clab-$LAB"
TOPO="topologies/${LAB}.yaml"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing required command: $1"
    exit 1
  }
}

need_cmd awk
need_cmd grep
need_cmd jq
need_cmd mktemp
need_cmd wc
need_cmd diff
need_cmd tr
need_cmd docker

TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT

fail() {
  echo "FAIL: $*"
  exit 1
}

dump_file_if_nonempty() {
  local f="$1"
  [ -s "$f" ] && cat "$f"
}

dump_pair_if_nonempty() {
  dump_file_if_nonempty "$1"
  dump_file_if_nonempty "$2"
}


# ------------------------------------------------------------------------------
echo "=== 0) py_compile ==="
python -m py_compile src/cassian.py src/cassian_tests.py src/cassian_artifacts.py
echo "OK: py_compile"
echo

# ------------------------------------------------------------------------------
echo "=== 0b) Guardrail: wait_for_condition wiring invariant ==="
# Invariant:
#  - defined exactly once in cassian_tests.py
#  - exactly one call site there (def + call = 2)
#  - zero occurrences in cassian.py
wf_defs="$({ grep -nE '^[[:space:]]*def[[:space:]]+wait_for_condition[[:space:]]*\(' src/cassian_tests.py || true; } | wc -l | tr -d ' ')"
wf_all="$({ grep -nE '\bwait_for_condition[[:space:]]*\(' src/cassian_tests.py || true; } | wc -l | tr -d ' ')"
wf_py="$({ grep -nE '\bwait_for_condition[[:space:]]*\(' src/cassian.py || true; } | wc -l | tr -d ' ')"
echo "wait_for_condition defs in cassian_tests.py = $wf_defs"
echo "wait_for_condition total refs in cassian_tests.py = $wf_all"
echo "wait_for_condition refs in cassian.py = $wf_py"
if [ "$wf_defs" -ne 1 ] || [ "$wf_all" -ne 2 ] || [ "$wf_py" -ne 0 ]; then
  echo "FAIL: wait_for_condition wiring invariant broken"
  exit 1
fi

echo "=== 0b) Guardrail: validate-contrib structural verification ==="
# Invariant:
#  - validate-contrib command exists as an explicit surface
#  - model exposes validate_contrib_path
#  - supported contrib roots are enforced in deterministic code
if ! grep -q 'add_parser("validate-contrib"' src/cassian.py; then
  echo "FAIL: missing validate-contrib parser in src/cassian.py"
  exit 1
fi
if ! grep -q 'validate_contrib_path' src/cassian.py; then
  echo "FAIL: src/cassian.py does not reference validate_contrib_path"
  exit 1
fi
if ! grep -q 'def validate_contrib_path(' src/cassian_model.py; then
  echo "FAIL: missing validate_contrib_path in src/cassian_model.py"
  exit 1
fi
for sym in '"topologies"' '"packs"' '"state-profiles"'; do
  if ! grep -q "$sym" src/cassian_model.py; then
    echo "FAIL: missing supported contrib root $sym in src/cassian_model.py"
    exit 1
  fi
done

echo "=== 0c) Guardrail: grey-failure scenario invariant ==="
# Invariant:
#  - schema validator knows the four grey-failure actions
#  - runtime coverage knows the four grey-failure actions
#  - runtime exposes scenario_apply_fault + scenario_clear_fault_state
#  - scenario executor uses scenario_apply_fault and cleanup
for sym in '"packet_loss"' '"latency"' '"bandwidth_cap"' '"prefix_blackhole"'; do
  if ! grep -q "$sym" src/cassian_tests.py; then
    echo "FAIL: missing grey-failure action $sym in src/cassian_tests.py"
    exit 1
  fi
  if ! grep -q "$sym" src/cassian_runtime_container.py; then
    echo "FAIL: missing grey-failure action $sym in src/cassian_runtime_container.py"
    exit 1
  fi
done

if ! grep -q 'def scenario_apply_fault(' src/cassian_runtime_container.py; then
  echo "FAIL: missing scenario_apply_fault in src/cassian_runtime_container.py"
  exit 1
fi
if ! grep -q 'def scenario_clear_fault_state(' src/cassian_runtime_container.py; then
  echo "FAIL: missing scenario_clear_fault_state in src/cassian_runtime_container.py"
  exit 1
fi
if ! grep -q 'scenario_apply_fault' src/cassian_tests.py; then
  echo "FAIL: src/cassian_tests.py does not reference scenario_apply_fault"
  exit 1
fi
if ! grep -q 'scenario_clear_fault_state' src/cassian_tests.py; then
  echo "FAIL: src/cassian_tests.py does not reference scenario_clear_fault_state"
  exit 1
fi
if ! grep -q 'active_fault_states' src/cassian_tests.py; then
  echo "FAIL: src/cassian_tests.py missing active_fault_states tracking"
  exit 1
fi

echo "=== 0d) Guardrail: invariant pack resolve expansion ==="
rm -rf \
  labs/clab-pack-resolve-expansion \
  labs/clab-pack-local-compatibility-ok \
  labs/clab-pack-invalid-reference \
  labs/clab-pack-unknown-reference \
  labs/clab-pack-incompatible-contents

$NS validate topologies/pack_resolve_expansion.yaml >"${TMPROOT}/verify_pack_validate.out" 2>"${TMPROOT}/verify_pack_validate.err"
rc=$?
if [ "$rc" -ne 0 ]; then
  dump_pair_if_nonempty "${TMPROOT}/verify_pack_validate.out" "${TMPROOT}/verify_pack_validate.err"
  fail "pack_resolve_expansion validate exited $rc"
fi

$NS validate topologies/pack_local_compatibility_ok.yaml >"${TMPROOT}/verify_pack_local_ok.out" 2>"${TMPROOT}/verify_pack_local_ok.err"
rc=$?
if [ "$rc" -ne 0 ]; then
  dump_pair_if_nonempty "${TMPROOT}/verify_pack_local_ok.out" "${TMPROOT}/verify_pack_local_ok.err"
  fail "pack_local_compatibility_ok validate exited $rc"
fi

set +e
$NS validate topologies/neg/pack_unknown_reference.yaml >"${TMPROOT}/verify_pack_neg.out" 2>"${TMPROOT}/verify_pack_neg.err"
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  dump_pair_if_nonempty "${TMPROOT}/verify_pack_neg.out" "${TMPROOT}/verify_pack_neg.err"
  fail "pack_unknown_reference validate exited $rc (expected 2)"
fi

set +e
$NS validate topologies/neg/pack_incompatible_contents.yaml >"${TMPROOT}/verify_pack_incompat.out" 2>"${TMPROOT}/verify_pack_incompat.err"
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  dump_pair_if_nonempty "${TMPROOT}/verify_pack_incompat.out" "${TMPROOT}/verify_pack_incompat.err"
  fail "pack_incompatible_contents validate exited $rc (expected 2)"
fi
echo "OK: pack compatibility negative validation failed as expected (exit 2)"

rm -rf labs/clab-pack-resolve-expansion
set +e
$NS test topologies/pack_resolve_expansion.yaml >"${TMPROOT}/verify_pack_test.out" 2>"${TMPROOT}/verify_pack_test.err"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  dump_pair_if_nonempty "${TMPROOT}/verify_pack_test.out" "${TMPROOT}/verify_pack_test.err"
  fail "pack_resolve_expansion test exited $rc"
fi

if [ ! -f labs/clab-pack-resolve-expansion/topology.resolved.yaml ]; then
  echo "FAIL: pack_resolve_expansion resolved artifact missing after test"
  exit 1
fi

if ! grep -q '^tests:' labs/clab-pack-resolve-expansion/topology.resolved.yaml; then
  echo "FAIL: resolved artifact missing tests section"
  exit 1
fi

if ! grep -q 'leaf1_evpn_session_to_spine1_up' labs/clab-pack-resolve-expansion/topology.resolved.yaml; then
  echo "FAIL: resolved artifact missing expanded invariant leaf1_evpn_session_to_spine1_up"
  exit 1
fi

if ! grep -q 'leaf2_evpn_session_to_spine1_up' labs/clab-pack-resolve-expansion/topology.resolved.yaml; then
  echo "FAIL: resolved artifact missing expanded invariant leaf2_evpn_session_to_spine1_up"
  exit 1
fi

echo "OK: invariant pack loading and compatibility guardrails"

echo "=== 0e) Guardrail: blast radius awareness ==="
python3 $NS test topologies/blast_radius_ok.yaml >${TMPROOT}/blast_radius_ok.out 2>&1
br_exit=$?
if [ "$br_exit" -ne 0 ]; then
  cat ${TMPROOT}/blast_radius_ok.out
  echo "FAIL: blast_radius_ok gate run failed"
  exit 1
fi

if [ ! -f labs/clab-blast-radius-ok/artifacts/blast-radius/blast_radius.json ]; then
  echo "FAIL: missing blast radius artifact"
  exit 1
fi

python - <<'PY'
import json
from pathlib import Path

results = json.loads(Path("labs/clab-blast-radius-ok/results.json").read_text(encoding="utf-8"))
artifact = json.loads(Path("labs/clab-blast-radius-ok/artifacts/blast-radius/blast_radius.json").read_text(encoding="utf-8"))

assert isinstance(results.get("authority"), dict), "results.authority missing"
se = results["authority"].get("supporting_evidence")
assert isinstance(se, list), "results.authority.supporting_evidence missing"
assert any(
    isinstance(x, dict)
    and x.get("type") == "blast_radius"
    and x.get("authority") == "supporting_evidence"
    for x in se
), "blast_radius supporting evidence entry missing"

br = results.get("blast_radius")
assert isinstance(br, dict), "results.blast_radius missing"
assert br.get("authority") == "supporting_evidence", "results.blast_radius authority mismatch"

assert artifact.get("authority") == "supporting_evidence", "artifact authority mismatch"
assert artifact.get("schema") == "blast_radius.v1", "artifact schema mismatch"
assert isinstance(artifact.get("coverage_basis"), list), "artifact coverage_basis missing"
assert isinstance(artifact.get("counts"), dict), "artifact counts missing"
PY
if [ "$?" -ne 0 ]; then
  echo "FAIL: blast radius artifact/results validation failed"
  exit 1
fi
echo "OK: blast radius artifact + results surfaces valid"

$NS replay labs/clab-blast-radius-ok --gate --verify-results >${TMPROOT}/blast_radius_replay.out 2>&1
replay_exit=$?
if [ "$replay_exit" -ne 0 ]; then
  cat ${TMPROOT}/blast_radius_replay.out
  echo "FAIL: blast radius replay verification failed"
  exit 1
fi
echo "OK: blast radius replay verification passed"

set +e
python3 $NS test topologies/neg/blast_radius_ambiguous_fault_target.yaml >${TMPROOT}/blast_radius_ambiguous_fault_target.out 2>&1
neg_exit=$?
set -e
if [ "$neg_exit" -ne 2 ]; then
  cat ${TMPROOT}/blast_radius_ambiguous_fault_target.out
  echo "FAIL: blast radius ambiguous fault misuse expected exit 2"
  exit 1
fi
if ! grep -q "choose node+if OR a/b link form, not both" ${TMPROOT}/blast_radius_ambiguous_fault_target.out; then
  cat ${TMPROOT}/blast_radius_ambiguous_fault_target.out
  echo "FAIL: blast radius ambiguous fault misuse missing expected error text"
  exit 1
fi
echo "OK: blast radius ambiguous fault misuse failed as expected (exit 2)"
echo

echo "=== 1) Guardrails: no package installs in engine ==="
grep -RInE '\bapk\s+(add|update)\b' src && { echo "FAIL: apk usage found"; exit 1; } || echo "OK: no apk installs"
grep -RInE '\bapt(-get)?\s+(install|update)\b' src && { echo "FAIL: apt usage found"; exit 1; } || echo "OK: no apt installs"
grep -RInE '\b(yum|dnf)\s+install\b' src && { echo "FAIL: yum/dnf usage found"; exit 1; } || echo "OK: no yum/dnf installs"
echo

# ------------------------------------------------------------------------------
echo "=== 2) cmd_test must be runtime-driven ==="
awk '
  BEGIN{p=0}
  /^def cmd_test\(/{p=1}
  p{print}
  /^def [a-zA-Z0-9_]+\(/ && $0 !~ /^def cmd_test/{exit}
' src/cassian.py \
| grep -nE 'docker\s+(exec|inspect|logs)|container_name\(' \
&& { echo "FAIL: cmd_test hard-codes docker/container_name"; exit 1; } \
|| echo "OK: cmd_test clean"
echo

# ------------------------------------------------------------------------------
echo "=== 3) Key helpers must be runtime-driven ==="
FUNCS=(verify_lab_ready wait_for_bgp start_tcp_listener verify_host_ready verify_fw_routed_ready verify_frr_ready ensure_nc ensure_ip_tools)
for fn in "${FUNCS[@]}"; do
  echo "-- checking $fn"
  awk -v FN="$fn" '
    BEGIN{p=0}
    $0 ~ ("^def "FN"\\("){p=1}
    p{print}
    /^def [a-zA-Z0-9_]+\(/ && $0 !~ ("^def "FN"\\(") {exit}
  ' src/cassian.py \
  | grep -nE 'docker\s+(exec|inspect|logs)|container_name\(' \
  && { echo "FAIL: $fn hard-codes docker/container_name"; exit 1; } \
  || echo "OK: $fn clean"
done
echo

# ------------------------------------------------------------------------------
echo "=== 4) docker exec/inspect/logs only inside ContainerRuntime ==="
all_docker_lines="$(grep -nE '\bdocker\s+(exec|inspect|logs)\b' src/cassian.py | grep -vE '^[0-9]+:[[:space:]]*#' || true)"

runtime_start="$(grep -nE '^class[[:space:]]+ContainerRuntime\b' src/cassian.py | head -n1 | cut -d: -f1 || true)"
[ -n "$runtime_start" ] || { echo "FAIL: ContainerRuntime not found"; exit 1; }

runtime_end="$(awk -v start="$runtime_start" '
  NR<=start{next}
  /^class /{print NR-1; exit}
  /^def /{print NR-1; exit}
  END{print NR}
' src/cassian.py)"

bad=""
if [ -n "$all_docker_lines" ]; then
  while read -r line; do
    ln="${line%%:*}"
    if [ "$ln" -lt "$runtime_start" ] || [ "$ln" -gt "$runtime_end" ]; then
      bad+="$line"$'\n'
    fi
  done <<< "$all_docker_lines"
fi

[ -z "$bad" ] || { echo "FAIL: docker usage outside ContainerRuntime"; printf "%s" "$bad"; exit 1; }
echo "OK: docker usage constrained to ContainerRuntime"
echo

# ------------------------------------------------------------------------------
echo "=== 4b) Advisory-only: preflight JSON ==="
rm -f artifacts/preflight/preflight.json 2>/dev/null || true
$NS preflight "$TOPO" --format json >/dev/null
test -s artifacts/preflight/preflight.json
jq -e '.authority=="advisory" and .schema_version=="preflight.v1"' artifacts/preflight/preflight.json >/dev/null
echo "OK: preflight.json valid"
# Determinism proof (WI-1):
# Run the same JSON write twice and require byte-identical output.
cp -f artifacts/preflight/preflight.json ${TMPROOT}/preflight.json.run1

rm -f artifacts/preflight/preflight.json 2>/dev/null || true
$NS preflight "$TOPO" --format json >/dev/null
test -s artifacts/preflight/preflight.json
cp -f artifacts/preflight/preflight.json ${TMPROOT}/preflight.json.run2

diff -u ${TMPROOT}/preflight.json.run1 ${TMPROOT}/preflight.json.run2 >/dev/null \
  && echo "OK: preflight.json deterministic (byte-identical across runs)" \
  || { echo "FAIL: preflight.json not deterministic across runs"; diff -u ${TMPROOT}/preflight.json.run1 ${TMPROOT}/preflight.json.run2 || true; exit 1; }
echo
# ------------------------------------------------------------------------------
echo "=== 4bb) Advisory-only: adapters (fixtures + golden drift guard) ==="

# Ensure fixtures + goldens exist
test -s tests/adapters/fixtures/terraform.plan.json || { echo "FAIL: missing terraform fixture"; exit 1; }
test -d tests/adapters/fixtures/ansible_rendered     || { echo "FAIL: missing ansible rendered fixture dir"; exit 1; }
test -s tests/adapters/goldens/terraform.plan.adapter.golden.json || { echo "FAIL: missing terraform adapter golden"; exit 1; }
test -s tests/adapters/goldens/ansible.rendered.adapter.golden.json || { echo "FAIL: missing ansible adapter golden"; exit 1; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' EXIT

# 1) Terraform adapter output must match golden (stable ordering + schema)
$NS adapt terraform --plan tests/adapters/fixtures/terraform.plan.json --out "$tmpdir" >/dev/null
test -s "$tmpdir/terraform.plan.adapter.json" || { echo "FAIL: missing terraform adapter output"; exit 1; }

jq -S . "$tmpdir/terraform.plan.adapter.json" > "$tmpdir/terraform.now.json"
jq -S . tests/adapters/goldens/terraform.plan.adapter.golden.json > "$tmpdir/terraform.golden.json"

diff -u "$tmpdir/terraform.golden.json" "$tmpdir/terraform.now.json" \
  && echo "OK: terraform adapter matches golden" \
  || { echo "FAIL: terraform adapter drift"; exit 1; }

# 2) Ansible adapter output must match golden (allowlist excludes binary.bin)
$NS adapt ansible --dir tests/adapters/fixtures/ansible_rendered --out "$tmpdir" >/dev/null
test -s "$tmpdir/ansible.rendered.adapter.json" || { echo "FAIL: missing ansible adapter output"; exit 1; }

jq -S . "$tmpdir/ansible.rendered.adapter.json" > "$tmpdir/ansible.now.json"
jq -S . tests/adapters/goldens/ansible.rendered.adapter.golden.json > "$tmpdir/ansible.golden.json"

diff -u "$tmpdir/ansible.golden.json" "$tmpdir/ansible.now.json" \
  && echo "OK: ansible adapter matches golden" \
  || { echo "FAIL: ansible adapter drift"; exit 1; }

echo "OK: adapters fixture + golden verification"
echo

# ------------------------------------------------------------------------------
echo "=== 4c) VM runtime precondition gate (env-aware) ==="
# Active handover contract:
# - validate must remain environment-agnostic
# - unsupported VM environments must be rejected at deploy/up/test
# - supported hosts must still validate+gen successfully

# Detect WSL2 deterministically (common signals)
is_wsl2=0
if [ -n "${WSL_INTEROP:-}" ] || [ -n "${WSL_DISTRO_NAME:-}" ]; then
  is_wsl2=1
else
  if [ -r /proc/version ] && grep -qiE '(microsoft|wsl)' /proc/version; then
    is_wsl2=1
  fi
fi

# Detect KVM deterministically (must exist + be accessible)
has_kvm=0
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  has_kvm=1
fi

# validate must pass regardless of host VM support
$NS validate topologies/vm-smoke.yaml >/dev/null

if [ "$is_wsl2" -eq 1 ]; then
  set +e
  vm_up_out="$($NS up topologies/vm-smoke.yaml 2>&1)"
  vm_up_rc=$?
  vm_test_out="$($NS test topologies/vm-smoke.yaml 2>&1)"
  vm_test_rc=$?
  set -e

  if [ "$vm_up_rc" -ne 1 ]; then
    echo "FAIL: expected VM up to fail with exit 1 on WSL2"
    echo "$vm_up_out"
    exit 1
  fi
  echo "$vm_up_out" | grep -Fq "VM runtime is not supported on WSL2." || {
    echo "FAIL: expected WSL2 VM runtime gate message during up"
    echo "$vm_up_out"
    exit 1
  }

  if [ "$vm_test_rc" -ne 2 ]; then
    echo "FAIL: expected VM test to fail with exit 2 on WSL2 (zero-assertion gate rejection)"
    echo "$vm_test_out"
    exit 1
  fi
  echo "$vm_test_out" | grep -Fq "ERROR: no assertions defined" || {
    echo "FAIL: expected zero-assertion gate rejection during VM test on WSL2"
    echo "$vm_test_out"
    exit 1
  }
  echo "$vm_test_out" | grep -Fq "A validation gate must include at least one test or scenario." || {
    echo "FAIL: expected zero-assertion gate guidance during VM test on WSL2"
    echo "$vm_test_out"
    exit 1
  }
  echo "OK: VM up gate triggers at deploy on WSL2"
  echo "OK: VM test path is rejected earlier by zero-assertion gate guardrail on WSL2"
elif [ "$has_kvm" -eq 0 ]; then
  set +e
  vm_up_out="$($NS up topologies/vm-smoke.yaml 2>&1)"
  vm_up_rc=$?
  set -e

  if [ "$vm_up_rc" -ne 1 ]; then
    echo "FAIL: expected VM up to fail with exit 1 without /dev/kvm"
    echo "$vm_up_out"
    exit 1
  fi
  echo "$vm_up_out" | grep -Fq "VM runtime requires KVM (/dev/kvm)." || {
    echo "FAIL: expected /dev/kvm VM runtime gate message during up"
    echo "$vm_up_out"
    exit 1
  }
  echo "OK: VM runtime gate triggers at deploy without /dev/kvm"
else
  $NS gen topologies/vm-smoke.yaml >/dev/null
  test -f labs/vm-smoke.clab.yaml
  grep -nE 'kind:[[:space:]]*sonic-vm|image:' labs/vm-smoke.clab.yaml >/dev/null
  echo "OK: VM validate + gen succeed on supported host"
fi

  echo "=== 4d) VM SONiC outcomes scenario smoke (supported hosts only) ==="

  # Single strong proof on supported VM Linux hosts:
  # - Brings up the outcomes topology (SONiC VM present)
  # - Proves VM runtime is active (qemu process inside s1 container)
  # - Proves image is local/sonic-vm (not a FRR/alpine container)
  # - Runs declared tests + scenario enumeration + all scenarios
  OUT_TOPO="topologies/vm-three-nodes-two-hosts-fw-outcomes.yaml"
  OUT_LAB="vm-three-nodes-two-hosts-fw-outcomes"

  if [ "$is_wsl2" -eq 1 ] || [ "$has_kvm" -eq 0 ]; then
    echo "SKIP: VM SONiC outcomes scenario smoke requires supported VM host"
  else
    $NS validate "$OUT_TOPO" >/dev/null
    $NS up "$OUT_TOPO" --reconfigure >/dev/null

    # Prove the s1 node is using the SONiC VM image.
    if ! docker inspect -f '{{.Config.Image}}' clab-${OUT_LAB}-s1 2>/dev/null | grep -Fq "local/sonic-vm"; then
      echo "FAIL: outcomes lab s1 is not using local/sonic-vm image"
      docker inspect -f '{{.Name}} {{.Config.Image}}' clab-${OUT_LAB}-s1 2>/dev/null || true
      exit 1
    fi

    # Prove VM runtime is active (qemu or SONiC launch process running inside the container).
    docker exec clab-${OUT_LAB}-s1 sh -lc 'ps -eo comm,args | grep -E "[q]emu-system|[q]emu-kvm|/launch\.py" >/dev/null' \
      && echo "OK: outcomes s1 has a VM runtime process (SONiC runtime active)" \
      || { echo "FAIL: outcomes s1 has no VM runtime process (expected SONiC VM runtime)"; docker exec clab-${OUT_LAB}-s1 sh -lc 'ps -eo comm,args | head -n 80 || true'; exit 1; }

    $NS test "$OUT_LAB" >/dev/null

    scen_list="$($NS test "$OUT_LAB" --list-scenarios 2>/dev/null || true)"
    echo "$scen_list" | grep -Fq "vm_bounce_interface_s1_eth1_recover" || { echo "FAIL: missing expected scenario vm_bounce_interface_s1_eth1_recover"; echo "$scen_list"; exit 1; }
    echo "$scen_list" | grep -Fq "vm_bounce_link_fw1_s1_recover"     || { echo "FAIL: missing expected scenario vm_bounce_link_fw1_s1_recover";     echo "$scen_list"; exit 1; }

    $NS test "$OUT_LAB" --all-scenarios >/dev/null
    $NS down "$OUT_LAB" >/dev/null

    echo "OK: VM SONiC outcomes scenario smoke passed"
  fi
echo

# ------------------------------------------------------------------------------
echo "=== 5) Deploy lab (clean-state) ==="
$NS up "$TOPO" --reconfigure >/dev/null
echo "OK: lab deployed"
echo

# ------------------------------------------------------------------------------
echo "=== 6) Run authoritative tests ==="
test_out="${TMPROOT}/authoritative_lab_test.out"
test_err="${TMPROOT}/authoritative_lab_test.err"
set +e
$NS test "$LAB" >"$test_out" 2>"$test_err"
test_rc=$?
set -e
if [ "$test_rc" -ne 0 ]; then
  dump_pair_if_nonempty "$test_out" "$test_err"
  fail "tests failed (rc=$test_rc)"
fi
echo "OK: tests passed"
echo
# ------------------------------------------------------------------------------
echo "=== 6a) results.summary.txt header (deterministic, non-authoritative) ==="
summary_txt="${LABDIR}/results.summary.txt"
test -s "$summary_txt" || { echo "FAIL: missing $summary_txt"; exit 1; }

# PASS path (the run above must be PASS for the default LAB)
# CI header must be line-1, fixed order, stable fields only, then the authoritative header.
head -n 10 "$summary_txt" | awk -v LABDIR_EXPECT="${LABDIR}/" '
  NR==1{ok1=($0=="=== CI SUMMARY ===")}
  NR==2{ok2=($0=="verdict: PASS")}
  NR==3{ok3=($0=="failed_tests: []")}
  NR==4{ok4=($0=="failed_scenarios: []")}
  NR==5{ok5=($0==("artifact_root: " LABDIR_EXPECT))}
  NR==6{ok6=($0=="")}
  NR==7{ok7=($0=="=== AUTHORITATIVE TEST VERDICT ===")}
  NR==8{ok8=($0=="verdict: PASS")}
  NR==9{ok9=($0 ~ /^scope: topology=[^ ]+ tests=[^ ]+ scenarios=[^ ]+$/)}
  NR==10{ok10=($0=="")}
  END{exit !(ok1&&ok2&&ok3&&ok4&&ok5&&ok6&&ok7&&ok8&&ok9&&ok10)}
' || { echo "FAIL: summary header malformed (PASS)"; head -n 16 "$summary_txt"; exit 1; }
echo "OK: summary header PASS format"

# FAIL path: force a deterministic fail via filter no-match
set +e
fail_out="$($NS test "$LAB" --name DOES_NOT_EXIST 2>&1)"
fail_rc=$?
set -e
if [ "$fail_rc" -eq 0 ]; then
  echo "FAIL: expected --name DOES_NOT_EXIST run to fail (rc!=0), but rc=0"
  echo "$fail_out"
  exit 1
fi

test -s "$summary_txt" || { echo "FAIL: missing $summary_txt after FAIL run"; exit 1; }
head -n 10 "$summary_txt" | awk -v LABDIR_EXPECT="${LABDIR}/" '
  NR==1{ok1=($0=="=== CI SUMMARY ===")}
  NR==2{ok2=($0=="verdict: FAIL")}
  NR==3{ok3=($0=="failed_tests: [\"filter:no-match\"]")}
  NR==4{ok4=($0=="failed_scenarios: []")}
  NR==5{ok5=($0==("artifact_root: " LABDIR_EXPECT))}
  NR==6{ok6=($0=="")}
  NR==7{ok7=($0=="=== AUTHORITATIVE TEST VERDICT ===")}
  NR==8{ok8=($0=="verdict: FAIL")}
  NR==9{ok9=($0 ~ /^scope: topology=[^ ]+ tests=filtered:name:DOES_NOT_EXIST scenarios=[^ ]+$/)}
  NR==10{ok10=($0=="")}
  END{exit !(ok1&&ok2&&ok3&&ok4&&ok5&&ok6&&ok7&&ok8&&ok9&&ok10)}
' || { echo "FAIL: summary header malformed (FAIL)"; head -n 16 "$summary_txt"; exit 1; }
echo "OK: summary header FAIL format"
echo

# Gate-failure messaging normalization (summary):
# Deterministic gate FAIL must not emit any human-facing ERROR: prefix lines.
if grep -q '^ERROR:' "$summary_txt"; then
  echo "FAIL: found ERROR: prefix in results.summary.txt on gate FAIL run"
  grep -n '^ERROR:' "$summary_txt" || true
  exit 1
fi
echo "OK: summary contains no ERROR: prefix lines on gate FAIL"
echo
# ------------------------------------------------------------------------------
echo "=== 6b) Optional: PCAP schema sanity (non-gating; schema-only) ==="
# This is intentionally NON-GATING in terms of tool success/failure:
# - We only validate schema/shape if evidence exists.
# - We do NOT require .pcap file presence or tool_status == ok.
# - If no PCAP evidence exists, we skip cleanly.

pcap_root="${LABDIR}/artifacts/pcap"
results_json="${LABDIR}/results.json"

if [ -d "$pcap_root" ] || [ -f "$results_json" ]; then
  # 1) Validate any *.meta.json files under artifacts/pcap (if present)
  if [ -d "$pcap_root" ]; then
    meta_count="$(find "$pcap_root" -type f -name '*.meta.json' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${meta_count:-0}" -gt 0 ]; then
      bad_meta=0
      while IFS= read -r mf; do
        # Must be valid JSON and contain required keys for supporting-evidence meta
        jq -e '
          .authority=="supporting_evidence"
          and (.scenario_id|type=="string" and length>0)
          and (.step_seq_start|type=="number")
          and (.step_seq_stop|type=="number")
          and (.target|type=="object" and (.node|type=="string" and length>0) and (.iface|type=="string" and length>0))
          and (.tool|type=="string" and length>0)
          and (.tool_status|type=="string" and length>0)
          and (.bytes_written|type=="number")
          and (.pcap_file|type=="string" and length>0)
        ' "$mf" >/dev/null || { echo "WARN: invalid pcap meta schema: $mf"; bad_meta=1; }
      done < <(find "$pcap_root" -type f -name '*.meta.json' 2>/dev/null | sort)
      if [ "$bad_meta" -ne 0 ]; then
        echo "FAIL: pcap meta schema sanity failed"
        exit 1
      fi
      echo "OK: pcap meta schema sanity (${meta_count} files)"
    else
      echo "OK: pcap meta schema sanity (no meta files present)"
    fi
  fi

  # 2) Validate results.json supporting_evidence pcap entries (if present)
  if [ -f "$results_json" ]; then
    pcap_ev_count="$(jq -r '.authority.supporting_evidence[]? | select(.type=="pcap") | 1' "$results_json" 2>/dev/null | wc -l | tr -d ' ' || true)"
    if [ "${pcap_ev_count:-0}" -gt 0 ]; then
      jq -e '
        [ .authority.supporting_evidence[]? | select(.type=="pcap") ] as $xs
        | ($xs | length) > 0
        and ( all($xs[];
            (.scenario_id|type=="string" and length>0)
            and (.step|type=="number")
            and (.tool_status|type=="string" and length>0)
            and (.pcap_file|type=="string" and length>0)
          ))
      ' "$results_json" >/dev/null || { echo "FAIL: results.json pcap supporting_evidence schema invalid"; exit 1; }
      echo "OK: results.json pcap supporting_evidence schema sanity (${pcap_ev_count} entries)"
    else
      echo "OK: results.json pcap supporting_evidence schema sanity (no pcap entries present)"
    fi

    state_diff_ev_count="$(jq -r '.authority.supporting_evidence[]? | select(.type=="state_diff") | 1' "$results_json" 2>/dev/null | wc -l | tr -d ' ' || true)"
    if [ "${state_diff_ev_count:-0}" -gt 0 ]; then
      jq -e '
        [ .authority.supporting_evidence[]? | select(.type=="state_diff") ] as $xs
        | ($xs | length) > 0
        and ( all($xs[];
            (.authority=="supporting_evidence")
            and (.path|type=="string" and length>0)
            and (.profiles|type=="array")
          ))
      ' "$results_json" >/dev/null || { echo "FAIL: results.json state_diff supporting_evidence schema invalid"; exit 1; }
      echo "OK: results.json state_diff supporting_evidence schema sanity (${state_diff_ev_count} entries)"
    else
      echo "OK: results.json state_diff supporting_evidence schema sanity (no state_diff entries present)"
    fi
  fi
else
  echo "OK: PCAP/state_diff schema sanity skipped (no artifacts/results present)"
fi
echo
# ------------------------------------------------------------------------------
echo "=== 6c) wait_for step shape consistency (authoritative artifact shape) ==="
# Invariant (representation-only):
# - wait_for steps must have a stable key-set across paths (present-with-null).
# Proof:
# - run a scenario containing wait_for (ping_test)
# - assert at least one wait_for step exists
# - assert every wait_for step has the canonical key-set

set +e
wf_out="$($NS test "$LAB" --scenario ping_test 2>&1)"
wf_rc=$?
set -e
if [ "$wf_rc" -ne 0 ]; then
  echo "FAIL: expected --scenario ping_test run to pass (rc=0), but rc=$wf_rc"
  echo "$wf_out"
  exit 1
fi

test -s "${LABDIR}/results.json" || { echo "FAIL: missing ${LABDIR}/results.json after scenario run"; exit 1; }

wf_count="$(jq -r '
  [ .scenarios[]?.steps[]?
    | select(.type=="wait_for")
  ] | length
' "${LABDIR}/results.json" 2>/dev/null || echo 0)"

if [ "${wf_count:-0}" -le 0 ]; then
  echo "FAIL: expected at least one wait_for step in results.json for ping_test scenario"
  exit 1
fi

expected_keys="attempts,duration_ms,error,expected,interval_s,meta,observed,step,succeeded,time_to_first_success_ms,time_to_success_ms,timeout_s,type,verdict,wait_for,wait_type"

bad_keys="$(jq -r '
  .scenarios[]?.steps[]?
  | select(.type=="wait_for")
  | (keys_unsorted | sort | join(","))
' "${LABDIR}/results.json" 2>/dev/null | sort -u | grep -vxF "$expected_keys" || true)"

if [ -n "$bad_keys" ]; then
  echo "FAIL: wait_for step key-set mismatch (expected exact canonical set):"
  echo "expected: $expected_keys"
  echo "observed unique:"
  echo "$bad_keys"
  exit 1
fi

echo "OK: wait_for step shape stable (${wf_count} steps; canonical key-set)"
echo

echo "=== 6d) Invariant gate + replay determinism ==="

INV_TOPO="route_present_missing.yaml"
INV_LAB="route-present-missing"
INV_LABDIR="labs/clab-${INV_LAB}"

# Clean any prior artifacts for deterministic comparison
rm -rf "${INV_LABDIR}" 2>/dev/null || true

# 1) Authoritative gate run must PASS without external candidate-config context
set +e
inv_out="$($NS test "$INV_TOPO" 2>&1)"
inv_rc=$?
set -e
if [ "$inv_rc" -ne 0 ]; then
  echo "FAIL: expected invariant gate run to pass (rc=0), but rc=$inv_rc"
  echo "$inv_out"
  exit 1
fi

test -s "${INV_LABDIR}/results.json" || { echo "FAIL: missing ${INV_LABDIR}/results.json after invariant gate run"; exit 1; }
test -s "${INV_LABDIR}/topology.resolved.yaml" || { echo "FAIL: missing ${INV_LABDIR}/topology.resolved.yaml after invariant gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="inv_route_present_r1_10_10_10_0_24" and .kind=="invariant" and .verdict=="pass")] | length) == 1
  and ([.tests[]? | select(.name=="inv_route_absent_r1_10_20_20_0_24" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${INV_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: invariant gate results.json missing expected invariant PASS entries"
  jq '.tests' "${INV_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: invariant gate PASS recorded"

cp -f "${INV_LABDIR}/results.json" ${TMPROOT}/route_present_missing.results.run1.json

# 2) Replay must PASS and --verify-results must confirm deterministic equality
set +e
replay_out="$($NS replay "${INV_LABDIR}" --gate --verify-results 2>&1)"
replay_rc=$?
set -e
if [ "$replay_rc" -ne 0 ]; then
  echo "FAIL: expected invariant replay to pass with --verify-results (rc=0), but rc=$replay_rc"
  echo "$replay_out"
  exit 1
fi

test -s "${INV_LABDIR}/results.json" || { echo "FAIL: missing ${INV_LABDIR}/results.json after replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="inv_route_present_r1_10_10_10_0_24" and .kind=="invariant" and .verdict=="pass")] | length) == 1
  and ([.tests[]? | select(.name=="inv_route_absent_r1_10_20_20_0_24" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${INV_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: replay results.json missing expected invariant PASS entries"
  jq '.tests' "${INV_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: invariant replay PASS recorded"

cp -f "${INV_LABDIR}/results.json" ${TMPROOT}/route_present_missing.results.replay.json

diff -u ${TMPROOT}/route_present_missing.results.run1.json ${TMPROOT}/route_present_missing.results.replay.json >/dev/null \
  && echo "OK: invariant replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: invariant replay results.json drift"; diff -u ${TMPROOT}/route_present_missing.results.run1.json ${TMPROOT}/route_present_missing.results.replay.json || true; exit 1; }

EVPN_VNI_TOPO="topologies/evpn_vni_route_present.yaml"
EVPN_VNI_LAB="evpn-vni-route-present"
EVPN_VNI_LABDIR="labs/clab-${EVPN_VNI_LAB}"
EVPN_VNI_NEG_TOPO="topologies/evpn_vni_route_absent_expected_present.yaml"
EVPN_VNI_NEG_LAB="evpn-vni-route-absent-expected-present"
EVPN_VNI_NEG_LABDIR="labs/clab-${EVPN_VNI_NEG_LAB}"
EVPN_VNI_MISUSE_TOPO="topologies/neg/evpn_invalid_vni_invariant.yaml"

rm -rf "${EVPN_VNI_LABDIR}" "${EVPN_VNI_NEG_LABDIR}" 2>/dev/null || true

set +e
evpn_vni_out="$($NS test "$EVPN_VNI_TOPO" 2>&1)"
evpn_vni_rc=$?
set -e
if [ "$evpn_vni_rc" -ne 0 ]; then
  echo "FAIL: expected EVPN VNI invariant gate run to pass (rc=0), but rc=$evpn_vni_rc"
  echo "$evpn_vni_out"
  exit 1
fi

test -s "${EVPN_VNI_LABDIR}/results.json" || { echo "FAIL: missing ${EVPN_VNI_LABDIR}/results.json after EVPN VNI gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="leaf2_sees_vni_10100" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${EVPN_VNI_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: EVPN VNI gate results.json missing expected invariant PASS entry"
  jq '.tests' "${EVPN_VNI_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: EVPN VNI invariant gate PASS recorded"

set +e
evpn_vni_neg_out="$($NS test "$EVPN_VNI_NEG_TOPO" 2>&1)"
evpn_vni_neg_rc=$?
set -e
if [ "$evpn_vni_neg_rc" -ne 1 ]; then
  echo "FAIL: expected EVPN VNI negative validation run to fail with rc=1, but rc=$evpn_vni_neg_rc"
  echo "$evpn_vni_neg_out"
  exit 1
fi

test -s "${EVPN_VNI_NEG_LABDIR}/results.json" || { echo "FAIL: missing ${EVPN_VNI_NEG_LABDIR}/results.json after EVPN VNI negative run"; exit 1; }

jq -e '
  .result=="fail"
  and ([.tests[]? | select(.name=="leaf2_sees_absent_vni_10101" and .kind=="invariant" and .verdict=="fail")] | length) == 1
' "${EVPN_VNI_NEG_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: EVPN VNI negative results.json missing expected invariant FAIL entry"
  jq '.tests' "${EVPN_VNI_NEG_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: EVPN VNI invariant negative validation recorded"

set +e
evpn_vni_misuse_out="$($NS test "$EVPN_VNI_MISUSE_TOPO" 2>&1)"
evpn_vni_misuse_rc=$?
set -e
if [ "$evpn_vni_misuse_rc" -ne 2 ]; then
  echo "FAIL: expected EVPN VNI misuse run to fail with rc=2, but rc=$evpn_vni_misuse_rc"
  echo "$evpn_vni_misuse_out"
  exit 1
fi
echo "OK: EVPN VNI invariant misuse recorded"

cp -f "${EVPN_VNI_LABDIR}/results.json" ${TMPROOT}/evpn_vni_route_present.results.run1.json

set +e
evpn_vni_replay_out="$($NS replay "${EVPN_VNI_LABDIR}" --gate --verify-results 2>&1)"
evpn_vni_replay_rc=$?
set -e
if [ "$evpn_vni_replay_rc" -ne 0 ]; then
  echo "FAIL: expected EVPN VNI replay to pass with --verify-results (rc=0), but rc=$evpn_vni_replay_rc"
  echo "$evpn_vni_replay_out"
  exit 1
fi

test -s "${EVPN_VNI_LABDIR}/results.json" || { echo "FAIL: missing ${EVPN_VNI_LABDIR}/results.json after EVPN VNI replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="leaf2_sees_vni_10100" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${EVPN_VNI_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: EVPN VNI replay results.json missing expected invariant PASS entry"
  jq '.tests' "${EVPN_VNI_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: EVPN VNI invariant replay PASS recorded"

cp -f "${EVPN_VNI_LABDIR}/results.json" ${TMPROOT}/evpn_vni_route_present.results.replay.json

diff -u ${TMPROOT}/evpn_vni_route_present.results.run1.json ${TMPROOT}/evpn_vni_route_present.results.replay.json >/dev/null \
  && echo "OK: EVPN VNI replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: EVPN VNI replay results.json drift"; diff -u ${TMPROOT}/evpn_vni_route_present.results.run1.json ${TMPROOT}/evpn_vni_route_present.results.replay.json || true; exit 1; }

EVPN_BGP_TOPO="topologies/evpn_bgp_session_up.yaml"
EVPN_BGP_LAB="evpn-bgp-session-up"
EVPN_BGP_LABDIR="labs/clab-${EVPN_BGP_LAB}"
EVPN_BGP_MISUSE_TOPO="topologies/neg/evpn_invalid_bgp_session_invariant.yaml"

rm -rf "${EVPN_BGP_LABDIR}" 2>/dev/null || true

set +e
evpn_bgp_out="$($NS test "$EVPN_BGP_TOPO" 2>&1)"
evpn_bgp_rc=$?
set -e
if [ "$evpn_bgp_rc" -ne 0 ]; then
  echo "FAIL: expected EVPN BGP-session invariant gate run to pass (rc=0), but rc=$evpn_bgp_rc"
  echo "$evpn_bgp_out"
  exit 1
fi

test -s "${EVPN_BGP_LABDIR}/results.json" || { echo "FAIL: missing ${EVPN_BGP_LABDIR}/results.json after EVPN BGP-session gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="leaf1_evpn_session_to_spine1_up" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${EVPN_BGP_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: EVPN BGP-session gate results.json missing expected invariant PASS entry"
  jq '.tests' "${EVPN_BGP_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: EVPN BGP-session invariant gate PASS recorded"

set +e
evpn_bgp_misuse_out="$($NS test "$EVPN_BGP_MISUSE_TOPO" 2>&1)"
evpn_bgp_misuse_rc=$?
set -e
if [ "$evpn_bgp_misuse_rc" -ne 2 ]; then
  echo "FAIL: expected EVPN BGP-session misuse run to fail with rc=2, but rc=$evpn_bgp_misuse_rc"
  echo "$evpn_bgp_misuse_out"
  exit 1
fi
echo "OK: EVPN BGP-session invariant misuse recorded"

cp -f "${EVPN_BGP_LABDIR}/results.json" ${TMPROOT}/evpn_bgp_session_up.results.run1.json

set +e
evpn_bgp_replay_out="$($NS replay "${EVPN_BGP_LABDIR}" --gate --verify-results 2>&1)"
evpn_bgp_replay_rc=$?
set -e
if [ "$evpn_bgp_replay_rc" -ne 0 ]; then
  echo "FAIL: expected EVPN BGP-session replay to pass with --verify-results (rc=0), but rc=$evpn_bgp_replay_rc"
  echo "$evpn_bgp_replay_out"
  exit 1
fi

test -s "${EVPN_BGP_LABDIR}/results.json" || { echo "FAIL: missing ${EVPN_BGP_LABDIR}/results.json after EVPN BGP-session replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="leaf1_evpn_session_to_spine1_up" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${EVPN_BGP_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: EVPN BGP-session replay results.json missing expected invariant PASS entry"
  jq '.tests' "${EVPN_BGP_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: EVPN BGP-session invariant replay PASS recorded"

cp -f "${EVPN_BGP_LABDIR}/results.json" ${TMPROOT}/evpn_bgp_session_up.results.replay.json

diff -u ${TMPROOT}/evpn_bgp_session_up.results.run1.json ${TMPROOT}/evpn_bgp_session_up.results.replay.json >/dev/null \
  && echo "OK: EVPN BGP-session replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: EVPN BGP-session replay results.json drift"; diff -u ${TMPROOT}/evpn_bgp_session_up.results.run1.json ${TMPROOT}/evpn_bgp_session_up.results.replay.json || true; exit 1; }

echo

echo "=== 6e) BGP localpref invariant gate + replay determinism ==="

LP_TOPO="topologies/bgp_localpref_equals.yaml"
LP_LAB="bgp-localpref-equals"
LP_LABDIR="labs/clab-${LP_LAB}"
LP_NEG_TOPO="topologies/bgp_localpref_not_equal_expected_equal.yaml"
LP_NEG_LAB="bgp-localpref-not-equal-expected-equal"
LP_NEG_LABDIR="labs/clab-${LP_NEG_LAB}"
LP_MISUSE_TOPO="topologies/neg/bgp_invalid_localpref_invariant.yaml"

rm -rf "${LP_LABDIR}" "${LP_NEG_LABDIR}" 2>/dev/null || true

set +e
lp_out="$($NS test "$LP_TOPO" 2>&1)"
lp_rc=$?
set -e
if [ "$lp_rc" -ne 0 ]; then
  echo "FAIL: expected BGP localpref invariant gate run to pass (rc=0), but rc=$lp_rc"
  echo "$lp_out"
  exit 1
fi

test -s "${LP_LABDIR}/results.json" || { echo "FAIL: missing ${LP_LABDIR}/results.json after BGP localpref gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r2_sees_1_1_1_1_32_with_localpref_200" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${LP_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: BGP localpref gate results.json missing expected invariant PASS entry"
  jq '.tests' "${LP_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: BGP localpref invariant gate PASS recorded"

set +e
lp_neg_out="$($NS test "$LP_NEG_TOPO" 2>&1)"
lp_neg_rc=$?
set -e
if [ "$lp_neg_rc" -ne 1 ]; then
  echo "FAIL: expected BGP localpref negative validation run to fail with rc=1, but rc=$lp_neg_rc"
  echo "$lp_neg_out"
  exit 1
fi

test -s "${LP_NEG_LABDIR}/results.json" || { echo "FAIL: missing ${LP_NEG_LABDIR}/results.json after BGP localpref negative run"; exit 1; }

jq -e '
  .result=="fail"
  and ([.tests[]? | select(.name=="r2_sees_1_1_1_1_32_with_localpref_150" and .kind=="invariant" and .verdict=="fail")] | length) == 1
' "${LP_NEG_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: BGP localpref negative results.json missing expected invariant FAIL entry"
  jq '.tests' "${LP_NEG_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: BGP localpref invariant negative validation recorded"

set +e
lp_misuse_out="$($NS test "$LP_MISUSE_TOPO" 2>&1)"
lp_misuse_rc=$?
set -e
if [ "$lp_misuse_rc" -ne 2 ]; then
  echo "FAIL: expected BGP localpref misuse run to fail with rc=2, but rc=$lp_misuse_rc"
  echo "$lp_misuse_out"
  exit 1
fi
echo "OK: BGP localpref invariant misuse recorded"

cp -f "${LP_LABDIR}/results.json" ${TMPROOT}/bgp_localpref_equals.results.run1.json

set +e
lp_replay_out="$($NS replay "${LP_LABDIR}" --gate --verify-results 2>&1)"
lp_replay_rc=$?
set -e
if [ "$lp_replay_rc" -ne 0 ]; then
  echo "FAIL: expected BGP localpref replay to pass with --verify-results (rc=0), but rc=$lp_replay_rc"
  echo "$lp_replay_out"
  exit 1
fi

test -s "${LP_LABDIR}/results.json" || { echo "FAIL: missing ${LP_LABDIR}/results.json after BGP localpref replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r2_sees_1_1_1_1_32_with_localpref_200" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${LP_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: BGP localpref replay results.json missing expected invariant PASS entry"
  jq '.tests' "${LP_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: BGP localpref invariant replay PASS recorded"

cp -f "${LP_LABDIR}/results.json" ${TMPROOT}/bgp_localpref_equals.results.replay.json

diff -u ${TMPROOT}/bgp_localpref_equals.results.run1.json ${TMPROOT}/bgp_localpref_equals.results.replay.json >/dev/null \
  && echo "OK: BGP localpref replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: BGP localpref replay results.json drift"; diff -u ${TMPROOT}/bgp_localpref_equals.results.run1.json ${TMPROOT}/bgp_localpref_equals.results.replay.json || true; exit 1; }

echo
echo "=== 6f) Route advertisement invariants gate + replay determinism ==="

RA_TOPO="topologies/route_advertised_to.yaml"
RA_LAB="route-advertised-to"
RA_LABDIR="labs/clab-${RA_LAB}"
RA_NEG_TOPO="topologies/route_advertised_to_expected_not_advertised.yaml"
RA_NEG_LAB="route-advertised-to-expected-not-advertised"
RA_NEG_LABDIR="labs/clab-${RA_NEG_LAB}"
RA_MISUSE_TOPO="topologies/neg/route_invalid_advertisement_invariant.yaml"

RNA_TOPO="topologies/route_not_advertised_to.yaml"
RNA_LAB="route-not-advertised-to"
RNA_LABDIR="labs/clab-${RNA_LAB}"

rm -rf "${RA_LABDIR}" "${RA_NEG_LABDIR}" "${RNA_LABDIR}" 2>/dev/null || true

set +e
ra_out="$($NS test "$RA_TOPO" 2>&1)"
ra_rc=$?
set -e
if [ "$ra_rc" -ne 0 ]; then
  echo "FAIL: expected route_advertised_to gate run to pass (rc=0), but rc=$ra_rc"
  echo "$ra_out"
  exit 1
fi

test -s "${RA_LABDIR}/results.json" || { echo "FAIL: missing ${RA_LABDIR}/results.json after route_advertised_to gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r1_advertises_10_10_10_0_24_to_r2" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${RA_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: route_advertised_to gate results.json missing expected invariant PASS entry"
  jq '.tests' "${RA_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: route_advertised_to invariant gate PASS recorded"

cp -f "${RA_LABDIR}/results.json" ${TMPROOT}/route_advertised_to.results.run1.json

rm -rf "${RA_NEG_LABDIR}"

set +e
ra_neg_out="$($NS test "$RA_NEG_TOPO" 2>&1)"
ra_neg_rc=$?
set -e
if [ "$ra_neg_rc" -ne 1 ]; then
  echo "FAIL: expected route_advertised_to negative validation run to fail with rc=1, but rc=$ra_neg_rc"
  echo "$ra_neg_out"
  exit 1
fi

test -s "${RA_NEG_LABDIR}/results.json" || { echo "FAIL: missing ${RA_NEG_LABDIR}/results.json after route_advertised_to negative run"; echo "$ra_neg_out"; exit 1; }

jq -e '
  .result=="fail"
  and (.hard_failure.occurred==false)
  and ([.tests[]? | select(.name=="r1_advertises_10_10_10_0_24_to_r2_but_it_should_not" and .kind=="invariant" and .verdict=="fail")] | length) == 1
' "${RA_NEG_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: route_advertised_to negative results.json missing expected invariant FAIL entry"
  echo "$ra_neg_out"
  jq '.' "${RA_NEG_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: route_advertised_to invariant negative validation recorded"

set +e
ra_misuse_out="$($NS test "$RA_MISUSE_TOPO" 2>&1)"
ra_misuse_rc=$?
set -e
if [ "$ra_misuse_rc" -ne 2 ]; then
  echo "FAIL: expected route_advertised_to misuse run to fail with rc=2, but rc=$ra_misuse_rc"
  echo "$ra_misuse_out"
  exit 1
fi
echo "OK: route_advertised_to invariant misuse recorded"

set +e
ra_replay_out="$($NS replay "${RA_LABDIR}" --gate --verify-results 2>&1)"
ra_replay_rc=$?
set -e
if [ "$ra_replay_rc" -ne 0 ]; then
  echo "FAIL: expected route_advertised_to replay to pass with --verify-results (rc=0), but rc=$ra_replay_rc"
  echo "$ra_replay_out"
  exit 1
fi

test -s "${RA_LABDIR}/results.json" || { echo "FAIL: missing ${RA_LABDIR}/results.json after route_advertised_to replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r1_advertises_10_10_10_0_24_to_r2" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${RA_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: route_advertised_to replay results.json missing expected invariant PASS entry"
  jq '.tests' "${RA_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: route_advertised_to invariant replay PASS recorded"

cp -f "${RA_LABDIR}/results.json" ${TMPROOT}/route_advertised_to.results.replay.json

diff -u ${TMPROOT}/route_advertised_to.results.run1.json ${TMPROOT}/route_advertised_to.results.replay.json >/dev/null \
  && echo "OK: route_advertised_to replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: route_advertised_to replay results.json drift"; diff -u ${TMPROOT}/route_advertised_to.results.run1.json ${TMPROOT}/route_advertised_to.results.replay.json || true; exit 1; }

set +e
rna_out="$($NS test "$RNA_TOPO" 2>&1)"
rna_rc=$?
set -e
if [ "$rna_rc" -ne 0 ]; then
  echo "FAIL: expected route_not_advertised_to gate run to pass (rc=0), but rc=$rna_rc"
  echo "$rna_out"
  exit 1
fi

test -s "${RNA_LABDIR}/results.json" || { echo "FAIL: missing ${RNA_LABDIR}/results.json after route_not_advertised_to gate run"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r1_does_not_advertise_10_10_10_0_24_to_r2" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${RNA_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: route_not_advertised_to gate results.json missing expected invariant PASS entry"
  jq '.tests' "${RNA_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: route_not_advertised_to invariant gate PASS recorded"

cp -f "${RNA_LABDIR}/results.json" ${TMPROOT}/route_not_advertised_to.results.run1.json

set +e
rna_replay_out="$($NS replay "${RNA_LABDIR}" --gate --verify-results 2>&1)"
rna_replay_rc=$?
set -e
if [ "$rna_replay_rc" -ne 0 ]; then
  echo "FAIL: expected route_not_advertised_to replay to pass with --verify-results (rc=0), but rc=$rna_replay_rc"
  echo "$rna_replay_out"
  exit 1
fi

test -s "${RNA_LABDIR}/results.json" || { echo "FAIL: missing ${RNA_LABDIR}/results.json after route_not_advertised_to replay"; exit 1; }

jq -e '
  .result=="pass"
  and ([.tests[]? | select(.name=="r1_does_not_advertise_10_10_10_0_24_to_r2" and .kind=="invariant" and .verdict=="pass")] | length) == 1
' "${RNA_LABDIR}/results.json" >/dev/null || {
  echo "FAIL: route_not_advertised_to replay results.json missing expected invariant PASS entry"
  jq '.tests' "${RNA_LABDIR}/results.json" 2>/dev/null || true
  exit 1
}
echo "OK: route_not_advertised_to invariant replay PASS recorded"

cp -f "${RNA_LABDIR}/results.json" ${TMPROOT}/route_not_advertised_to.results.replay.json

diff -u ${TMPROOT}/route_not_advertised_to.results.run1.json ${TMPROOT}/route_not_advertised_to.results.replay.json >/dev/null \
  && echo "OK: route_not_advertised_to replay results.json deterministic (byte-identical)" \
  || { echo "FAIL: route_not_advertised_to replay results.json drift"; diff -u ${TMPROOT}/route_not_advertised_to.results.run1.json ${TMPROOT}/route_not_advertised_to.results.replay.json || true; exit 1; }

echo
echo "=== 7) Cleanup smoke (cassian cleanup --all) ==="

# 7a) Dry-run must show a plan and exit 0
cleanup_out="$($NS cleanup --all 2>&1)"
cleanup_rc=$?
if [ "$cleanup_rc" -ne 0 ]; then
  echo "FAIL: cleanup --all dry-run exited non-zero: rc=$cleanup_rc"
  echo "$cleanup_out"
  exit 1
fi
echo "$cleanup_out" | grep -Fq "Cleanup plan (dry-run):" || {
  echo "FAIL: cleanup --all dry-run did not print expected header"
  echo "$cleanup_out"
  exit 1
}
echo "OK: cleanup --all dry-run produced a plan"

# 7b) Execute must write cleanup report and leave no clab-* containers running
$NS cleanup --all --yes >/dev/null
test -f labs/_cleanup/cleanup.json && echo "OK: cleanup report present" || { echo "FAIL: cleanup report missing"; exit 1; }

if docker ps --format '{{.Names}}' | grep -qE '^clab-'; then
  echo "FAIL: expected no clab-* containers after cleanup --all --yes"
  docker ps --format '{{.Names}}' | grep -E '^clab-' || true
  exit 1
fi
echo "OK: cleanup removed all clab-* containers"
echo

echo "✅ PHASE1 VERIFIED"
