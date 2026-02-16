#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Deterministic module resolution (local src/ only)
# ------------------------------------------------------------------------------
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"

# Always invoke netsim through this wrapper (no direct ./src/netsim.py calls)
NS="./src/netsim.py"

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

# ------------------------------------------------------------------------------
echo "=== 0) py_compile ==="
python -m py_compile src/netsim.py src/netsim_tests.py
echo "OK: py_compile"
echo

# ------------------------------------------------------------------------------
echo "=== 0b) Guardrail: wait_for_condition wiring invariant ==="
# Invariant:
#  - defined exactly once in netsim_tests.py
#  - exactly one call site there (def + call = 2)
#  - zero occurrences in netsim.py

wfc_def_count="$({ grep -nE '^[[:space:]]*def[[:space:]]+wait_for_condition[[:space:]]*\(' src/netsim_tests.py || true; } | wc -l | tr -d ' ')"
if [ "$wfc_def_count" -ne 1 ]; then
  echo "FAIL: expected exactly one wait_for_condition() definition, found $wfc_def_count"
  grep -nE '^[[:space:]]*def[[:space:]]+wait_for_condition[[:space:]]*\(' src/netsim_tests.py || true
  exit 1
fi

wfc_call_count="$({ grep -nE '\bwait_for_condition[[:space:]]*\(' src/netsim_tests.py || true; } | wc -l | tr -d ' ')"
if [ "$wfc_call_count" -ne 2 ]; then
  echo "FAIL: expected wait_for_condition() to appear exactly twice (def + call), found $wfc_call_count"
  grep -nE '\bwait_for_condition[[:space:]]*\(' src/netsim_tests.py || true
  exit 1
fi

wfc_py_count="$({ grep -nE '\bwait_for_condition[[:space:]]*\(' src/netsim.py || true; } | wc -l | tr -d ' ')"
if [ "$wfc_py_count" -ne 0 ]; then
  echo "FAIL: wait_for_condition() must not appear in netsim.py"
  grep -nE '\bwait_for_condition[[:space:]]*\(' src/netsim.py || true
  exit 1
fi

caller_line="$({ grep -nE '\bwait_for_condition[[:space:]]*\(' src/netsim_tests.py || true; } | tail -n1)"
echo "OK: wait_for_condition wiring appears stable:"
echo "  $caller_line"
echo

# ------------------------------------------------------------------------------
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
' src/netsim.py \
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
  ' src/netsim.py \
  | grep -nE 'docker\s+(exec|inspect|logs)|container_name\(' \
  && { echo "FAIL: $fn hard-codes docker/container_name"; exit 1; } \
  || echo "OK: $fn clean"
done
echo

# ------------------------------------------------------------------------------
echo "=== 4) docker exec/inspect/logs only inside ContainerRuntime ==="
all_docker_lines="$(grep -nE '\bdocker\s+(exec|inspect|logs)\b' src/netsim.py | grep -vE '^[0-9]+:[[:space:]]*#' || true)"

runtime_start="$(grep -nE '^class[[:space:]]+ContainerRuntime\b' src/netsim.py | head -n1 | cut -d: -f1 || true)"
[ -n "$runtime_start" ] || { echo "FAIL: ContainerRuntime not found"; exit 1; }

runtime_end="$(awk -v start="$runtime_start" '
  NR<=start{next}
  /^class /{print NR-1; exit}
  /^def /{print NR-1; exit}
  END{print NR}
' src/netsim.py)"

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
# This is a deterministic PRECONDITION gate:
# - If VM runtime is requested and the host is unsupported, validate must fail fast
# - Container-only topologies must remain unaffected

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

# Capture validate output *and* true exit code (must not be masked by "|| true")
set +e
vm_out="$($NS validate topologies/vm-smoke.yaml 2>&1)"
vm_rc=$?
set -e

if [ "$is_wsl2" -eq 1 ]; then
  if [ "$vm_rc" -eq 0 ]; then
    echo "FAIL: expected VM validate to fail on WSL2, but it succeeded"
    exit 1
  fi
  echo "$vm_out" | grep -Fq "VM runtime is not supported on WSL2." || {
    echo "FAIL: expected WSL2 VM runtime gate message"
    echo "$vm_out"
    exit 1
  }
  echo "OK: VM runtime gate triggers on WSL2"
elif [ "$has_kvm" -eq 0 ]; then
  if [ "$vm_rc" -eq 0 ]; then
    echo "FAIL: expected VM validate to fail without /dev/kvm, but it succeeded"
    exit 1
  fi
  echo "$vm_out" | grep -Fq "VM runtime requires KVM (/dev/kvm)." || {
    echo "FAIL: expected /dev/kvm VM runtime gate message"
    echo "$vm_out"
    exit 1
  }
  echo "OK: VM runtime gate triggers without /dev/kvm"
else
  if [ "$vm_rc" -ne 0 ]; then
    echo "FAIL: expected VM validate to pass on supported host, but it failed"
    echo "$vm_out"
    exit 1
  fi
  $NS gen topologies/vm-smoke.yaml >/dev/null
  test -f labs/vm-smoke.clab.yaml
  grep -nE 'kind:[[:space:]]*sonic-vm|image:' labs/vm-smoke.clab.yaml >/dev/null
  echo "OK: VM validate + gen succeed on supported host"

  echo "=== 4d) VM runtime smoke (deploy+test+cleanup; supported hosts only) ==="
  $NS up topologies/vm-smoke.yaml --reconfigure >/dev/null
  $NS test vm-smoke >/dev/null
  $NS down vm-smoke >/dev/null
  echo "OK: VM runtime smoke passed (deploy+test+cleanup)"
fi
echo

# ------------------------------------------------------------------------------
echo "=== 5) Deploy lab (clean-state) ==="
$NS up "$TOPO" --reconfigure >/dev/null
echo "OK: lab deployed"
echo

# ------------------------------------------------------------------------------
echo "=== 6) Run authoritative tests ==="
$NS test "$LAB"
echo "OK: tests passed"
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
  fi
else
  echo "OK: PCAP schema sanity skipped (no artifacts/results present)"
fi
echo
echo "=== 7) Cleanup smoke (netsim cleanup --all) ==="

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
