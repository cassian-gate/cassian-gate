#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/verify_ai.sh [lab-name]
#
# Notes:
# - AI-only verification (no runtime/deploy checks beyond grep guardrails).
# - CI-safe by default: does NOT require a valid API key unless explicitly enabled.
#
# Optional modes / checks (explicit opt-in):
#
#   1) Live online schema check (non-fatal on invalid key unless strict):
#      AI_NETSIM_VERIFY_ONLINE_OK=1 OPENAI_API_KEY=... ./scripts/verify_ai.sh
#
#   2) Emit sanitized (shape-only) online ai_output and exit:
#      AI_NETSIM_VERIFY_SANITIZE=1 AI_NETSIM_VERIFY_ONLINE_OK=1 OPENAI_API_KEY=... ./scripts/verify_ai.sh
#
#   3) Sanitized fixture check (shape-only, guards schema expansion):
#      AI_NETSIM_VERIFY_ONLINE_OK=1 AI_NETSIM_VERIFY_SANITIZED_FIXTURE=1 OPENAI_API_KEY=... ./scripts/verify_ai.sh
#
# Strict mode (make invalid key a hard FAIL instead of SKIP):
#      AI_NETSIM_VERIFY_ONLINE_STRICT=1
#
# Fixture location:
#   tests/ai/fixtures/explain.online.sanitized.json
#
LAB="${1:-three-frr-two-hosts-fw-routed}"
LABDIR="labs/clab-$LAB"
TOPO="topologies/${LAB}.yaml"
# Optional: regenerate golden bundle fixtures (explicit opt-in)
# Use when you intentionally changed topology/tests/scenarios or bundle fields.
#   AI_NETSIM_UPDATE_GOLDENS=1 ./scripts/verify_ai.sh
AI_NETSIM_UPDATE_GOLDENS="${AI_NETSIM_UPDATE_GOLDENS:-0}"


need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing required command: $1"; exit 1; }
}

need_cmd awk
need_cmd grep
need_cmd jq
need_cmd diff
need_cmd mktemp

# Temp files we may create
tmps=()
cleanup() {
  for f in "${tmps[@]:-}"; do
    rm -f "$f" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# jq sanitizer: turn ai_output into stable, content-free shape:
# - strings -> "<string>"
# - arrays of strings -> ["<string>", ...] (preserve length)
# - findings array -> objects with placeholder strings
# - include _extra_keys to guard schema expansion (must be [])
sanitize_ai_output_jq='
  .ai_output
  | {
      summary: (if (.summary|type)=="string" then "<string>" else "<missing>" end),
      findings: (
        if (.findings|type)=="array" then
          [ .findings[]
            | {
                title: (if (.title|type)=="string" then "<string>" else "<missing>" end),
                evidence: (if (.evidence|type)=="string" then "<string>" else "<missing>" end),
                suggestion: (if (.suggestion|type)=="string" then "<string>" else "<missing>" end)
              }
          ]
        else
          []
        end
      ),
      suggested_next_tests: (
        if (.suggested_next_tests|type)=="array" then
          [ .suggested_next_tests[] | "<string>" ]
        else
          []
        end
      ),
      _extra_keys: (keys - ["summary","findings","suggested_next_tests"] | sort)
    }
'

skip_or_fail_invalid_key() {
  local ctx="$1"  # e.g. "online check" / "fixture check"
  local json="$2"

  local err
  err="$(echo "$json" | jq -r '.ai_error // ""')"

  if echo "$err" | grep -q "invalid_api_key" || echo "$err" | grep -q "Incorrect API key"; then
    if [ "${AI_NETSIM_VERIFY_ONLINE_STRICT:-0}" = "1" ]; then
      echo "FAIL: $ctx requested but API key is invalid"
      echo "$json" | jq .
      exit 1
    fi
    echo "SKIP: $ctx could not run (invalid API key)"
    echo "Hint: ensure OPENAI_API_KEY is set to a valid key (not a placeholder) and not revoked."
    exit 0
  fi
}

if [ "$AI_NETSIM_UPDATE_GOLDENS" = "1" ]; then
  echo "=== AI) Update golden fixtures (explicit opt-in) ==="

  mkdir -p tests/ai/fixtures

  echo "Updating: tests/ai/fixtures/explain.bundle.json"
  ./src/netsim.py ai explain "$LAB" --bundle | jq -S . > tests/ai/fixtures/explain.bundle.json

  if [ -f "$TOPO" ]; then
    echo "Updating: tests/ai/fixtures/review.bundle.json"
    ./src/netsim.py ai review "$TOPO" --bundle | jq -S . > tests/ai/fixtures/review.bundle.json
  else
    echo "WARN: skipping review golden update (missing $TOPO)"
  fi

  echo "Updating: tests/ai/fixtures/coach.bundle.json"
  ./src/netsim.py ai coach --bundle | jq -S . > tests/ai/fixtures/coach.bundle.json

  echo "OK: golden fixtures updated"
  echo "Next:"
  echo "  git add tests/ai/fixtures/*.bundle.json"
  echo "  git commit -m \"tests(ai): refresh golden bundles\""
  exit 0
fi

echo "=== AI) Guardrails: ai code must not call runtime/deploy primitives ==="

awk '
  BEGIN {p=0}
  /^def (cmd_ai_|_ai_)/ {p=1}
  p {print}
  p && /^def / && $0 !~ /^def (cmd_ai_|_ai_)/ {p=0}
' src/netsim.py \
  | grep -nE '\bcontainerlab\b|\bcmd_up\b|\bcmd_test\b|\bcmd_run\b|\bContainerRuntime\b|\brt\.exec\b|\bdocker\s+(exec|inspect|logs)\b' \
  && { echo "FAIL: ai code references runtime/deploy primitives"; exit 1; } \
  || echo "OK: ai code is artifact-only (no runtime/deploy refs)"

echo

echo "=== AI) Smoke: unified netsim ai surface ==="

echo "INFO: produce deterministic artifact context"
if ! python3 src/netsim.py test topologies/three-frr-two-hosts-fw-routed.yaml >/dev/null; then
  echo "FAIL: prerequisite test run for ai verification failed"
  exit 1
fi

tmp="$(mktemp)"
if ! python3 src/netsim.py ai --artifacts labs/clab-three-frr-two-hosts-fw-routed "why did this fail" >"$tmp"; then
  echo "FAIL: unified ai --artifacts command failed"
  rm -f "$tmp"
  exit 1
fi
if ! grep -q '^Authority: Advisory Only$' "$tmp"; then
  echo "FAIL: unified ai --artifacts missing advisory authority line"
  rm -f "$tmp"
  exit 1
fi
if ! grep -q '^Execution Impact: None$' "$tmp"; then
  echo "FAIL: unified ai --artifacts missing execution impact line"
  rm -f "$tmp"
  exit 1
fi
if ! grep -q '^Context Source: explicit_artifacts$' "$tmp"; then
  echo "FAIL: unified ai --artifacts missing explicit_artifacts context"
  rm -f "$tmp"
  exit 1
fi
echo "OK: unified ai --artifacts advisory/context lines"
rm -f "$tmp"

tmp="$(mktemp)"
if ! python3 src/netsim.py ai --lab three-frr-two-hosts-fw-routed "why did this fail" >"$tmp"; then
  echo "FAIL: unified ai --lab command failed"
  rm -f "$tmp"
  exit 1
fi
if ! grep -q '^Context Source: explicit_lab$' "$tmp"; then
  echo "FAIL: unified ai --lab missing explicit_lab context"
  rm -f "$tmp"
  exit 1
fi
echo "OK: unified ai --lab context line"
rm -f "$tmp"

tmp="$(mktemp)"
if ! python3 src/netsim.py ai "why did this fail" >"$tmp"; then
  echo "FAIL: unified ai common path failed"
  rm -f "$tmp"
  exit 1
fi
if ! grep -q '^Context Source: most_recent_run$' "$tmp"; then
  echo "FAIL: unified ai common path missing most_recent_run context"
  rm -f "$tmp"
  exit 1
fi
echo "OK: unified ai common path context line"
rm -f "$tmp"

set +e
python3 src/netsim.py ai "modify this topology to fix the problem" >/tmp/verify_ai_blocked.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  echo "FAIL: blocked out-of-scope request expected exit 2, got $rc"
  rm -f /tmp/verify_ai_blocked.out
  exit 1
fi
if ! grep -q 'AI request blocked (advisory scope exceeded)' /tmp/verify_ai_blocked.out; then
  echo "FAIL: blocked out-of-scope request missing scope-block message"
  rm -f /tmp/verify_ai_blocked.out
  exit 1
fi
rm -f /tmp/verify_ai_blocked.out
echo "OK: blocked out-of-scope request"

set +e
python3 src/netsim.py ai --artifacts labs/does-not-exist "why did this fail" >/tmp/verify_ai_missing.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
  echo "FAIL: missing-artifact refusal expected exit 2, got $rc"
  rm -f /tmp/verify_ai_missing.out
  exit 1
fi
if ! grep -q 'Required artifacts:' /tmp/verify_ai_missing.out; then
  echo "FAIL: missing-artifact refusal missing required artifacts text"
  rm -f /tmp/verify_ai_missing.out
  exit 1
fi
if ! grep -q 'results.json' /tmp/verify_ai_missing.out; then
  echo "FAIL: missing-artifact refusal missing results.json reference"
  rm -f /tmp/verify_ai_missing.out
  exit 1
fi
rm -f /tmp/verify_ai_missing.out
echo "OK: deterministic missing-artifact refusal"
echo

echo "=== AI) Key redaction (must not leak API key) ==="

# IMPORTANT: Run redaction check in a subshell so fake exports do not leak
(
  set -euo pipefail
  FAKE_KEY="sk-THIS_IS_NOT_REAL"
  export AI_NETSIM_AI_PROVIDER="openai"
  export AI_NETSIM_AI_API_KEY="$FAKE_KEY"
  export AI_NETSIM_AI_MODEL="${AI_NETSIM_AI_MODEL:-gpt-4.1-mini}"

  ai_err="$(./src/netsim.py ai --lab "$LAB" "why did this fail" --format json | jq -r '.ai_error' || true)"

  echo "$ai_err" | grep -Fq "$FAKE_KEY" \
    && { echo "FAIL: ai_error leaked raw API key"; echo "$ai_err"; exit 1; } \
    || echo "OK: ai_error does not contain raw API key"

  if echo "$ai_err" | grep -Eq 'sk-[A-Za-z0-9_-]{10,}'; then
    echo "$ai_err" | grep -Eq 'sk-[A-Za-z0-9_-]*REDACTED|sk-[A-Za-z0-9_-]*\*{3,}[A-Za-z0-9_-]*' \
      && echo "OK: ai_error appears redacted" \
      || { echo "FAIL: ai_error contained key-like text but did not look redacted"; echo "$ai_err"; exit 1; }
  else
    echo "WARN: ai_error had no key-like substring (cannot assert redaction pattern)"
  fi
)

echo
echo "=== AI) Unified surface stability + non-AI non-regression ==="

tmp1="$(mktemp)"
tmp2="$(mktemp)"
if ! python3 src/netsim.py ai --artifacts labs/clab-three-frr-two-hosts-fw-routed "why did this fail" >"$tmp1"; then
  echo "FAIL: first unified ai stability run failed"
  rm -f "$tmp1" "$tmp2"
  exit 1
fi
if ! python3 src/netsim.py ai --artifacts labs/clab-three-frr-two-hosts-fw-routed "why did this fail" >"$tmp2"; then
  echo "FAIL: second unified ai stability run failed"
  rm -f "$tmp1" "$tmp2"
  exit 1
fi
if ! diff -u "$tmp1" "$tmp2" >/dev/null; then
  echo "FAIL: unified ai output drift across identical invocations"
  rm -f "$tmp1" "$tmp2"
  exit 1
fi
rm -f "$tmp1" "$tmp2"
echo "OK: unified ai stable across repeated identical invocations"

echo "=== AI) Non-AI command non-regression smoke ==="
set +e
python3 src/netsim.py validate topologies/three-frr-two-hosts-fw-routed.yaml >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "FAIL: validate non-regression expected exit 0, got $rc"
  exit 1
fi
echo "OK: validate non-regression"
echo "=== AI) Optional: online structured-output schema (explicit opt-in) ==="

if [ "${AI_NETSIM_VERIFY_ONLINE_OK:-0}" = "1" ]; then
  # Ensure fake key from redaction test does not interfere with live online checks.
  unset AI_NETSIM_AI_API_KEY
  unset AI_NETSIM_AI_PROVIDER

  if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${AI_NETSIM_AI_API_KEY:-}" ]; then
    echo "FAIL: AI_NETSIM_VERIFY_ONLINE_OK=1 but no OPENAI_API_KEY/AI_NETSIM_AI_API_KEY set"
    exit 1
  fi

  j="$(AI_NETSIM_AI_PROVIDER=openai ./src/netsim.py ai --lab "$LAB" "why did this fail" --format json)"
  status="$(echo "$j" | jq -r '.ai_status')"
  if [ "$status" != "ok" ]; then
    skip_or_fail_invalid_key "online check" "$j"
    echo "FAIL: expected ai_status ok for optional online check; got $status"
    echo "$j" | jq .
    exit 1
  fi

  echo "$j" | jq -e '
    .ai_output.summary and
    (.ai_output.summary|type=="string") and
    (.ai_output.findings|type=="array") and
    (.ai_output.suggested_next_tests|type=="array")
  ' >/dev/null \
    && echo "OK: online ai_output schema present" \
    || { echo "FAIL: online ai_output schema missing/invalid"; echo "$j" | jq .; exit 1; }

  # B) Output mode: emit sanitized shape-only output for fixture generation
  if [ "${AI_NETSIM_VERIFY_SANITIZE:-0}" = "1" ]; then
    echo "$j" | jq -S "$sanitize_ai_output_jq"
    exit 0
  fi

else
  echo "SKIP: set AI_NETSIM_VERIFY_ONLINE_OK=1 to run the live online schema check"
fi

echo
echo "=== AI) Optional: online sanitized output fixture (explicit opt-in) ==="

if [ "${AI_NETSIM_VERIFY_ONLINE_OK:-0}" = "1" ] && [ "${AI_NETSIM_VERIFY_SANITIZED_FIXTURE:-0}" = "1" ]; then
  unset AI_NETSIM_AI_API_KEY
  unset AI_NETSIM_AI_PROVIDER

  if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${AI_NETSIM_AI_API_KEY:-}" ]; then
    echo "FAIL: AI_NETSIM_VERIFY_SANITIZED_FIXTURE=1 but no OPENAI_API_KEY/AI_NETSIM_AI_API_KEY set"
    exit 1
  fi

  FIX="tests/ai/fixtures/explain.online.sanitized.json"
  if [ ! -s "$FIX" ]; then
    echo "FAIL: missing sanitized fixture: $FIX"
    echo "To generate it (shape-only), run:"
    echo "  AI_NETSIM_VERIFY_ONLINE_OK=1 AI_NETSIM_VERIFY_SANITIZE=1 OPENAI_API_KEY=... ./scripts/verify_ai.sh > $FIX"
    exit 1
  fi

  j2="$(AI_NETSIM_AI_PROVIDER=openai ./src/netsim.py ai --lab "$LAB" "why did this fail" --format json)"
  status2="$(echo "$j2" | jq -r '.ai_status')"
  if [ "$status2" != "ok" ]; then
    skip_or_fail_invalid_key "fixture check" "$j2"
    echo "FAIL: expected ai_status ok for sanitized fixture check; got $status2"
    echo "$j2" | jq .
    exit 1
  fi

  now="$(mktemp)"; tmps+=("$now")
  echo "$j2" | jq -S "$sanitize_ai_output_jq" > "$now"

  diff -u <(jq -S . "$FIX") <(cat "$now") \
    && echo "OK: online sanitized ai_output matches fixture (shape-only)" \
    || { echo "FAIL: sanitized fixture drift (shape-only)"; exit 1; }

  if ! jq -e '._extra_keys == []' "$now" >/dev/null; then
    echo "FAIL: ai_output contained unexpected extra keys:"
    cat "$now" | jq -r '._extra_keys'
    exit 1
  fi
  echo "OK: no extra keys (schema expansion guard)"
else
  echo "SKIP: set AI_NETSIM_VERIFY_ONLINE_OK=1 and AI_NETSIM_VERIFY_SANITIZED_FIXTURE=1 to run sanitized fixture check"
fi

echo
echo "✅ AI VERIFIED"