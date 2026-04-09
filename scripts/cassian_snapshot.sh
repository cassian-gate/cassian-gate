#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Snapshot destination (WSL path with spaces must stay quoted)
# ------------------------------------------------------------------------------
SNAP="/mnt/c/Users/acast/Documents/Ai Sim/snapshot"
mkdir -p "$SNAP"

# ------------------------------------------------------------------------------
# Always run relative to the Cassian Gate repo root (so src/ resolves correctly)
# ------------------------------------------------------------------------------
if command -v git >/dev/null 2>&1 && git rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
  cd "$REPO_ROOT"
fi

# Fail fast if we still don't see src/
if [[ ! -d "src" ]]; then
  echo "FAIL: cannot find ./src directory."
  echo "Run this from the Cassian Gate repo root, or ensure git is available so the script can auto-cd."
  exit 1
fi

if [[ ! -f "src/cassian.py" ]]; then
  echo "FAIL: missing src/cassian.py (expected authoritative entrypoint)."
  exit 1
fi

# ------------------------------------------------------------------------------
# Determine next version number (vNN)
# Strictly look at snapshot files that end in vNN.py
# ------------------------------------------------------------------------------
LAST="$(
  find "$SNAP" -maxdepth 1 -type f -name '*v[0-9]*.py' -print 2>/dev/null \
    | sed -n 's/.*v\([0-9]\+\)\.py$/\1/p' \
    | sort -n \
    | tail -1
)"
LAST="${LAST:-0}"

NN=$((LAST + 1))
VER="v${NN}"

# ------------------------------------------------------------------------------
# Copy authoritative modules
# ------------------------------------------------------------------------------
for f in src/cassian.py src/cassian_*.py; do
  [[ -f "$f" ]] || continue
  base="$(basename "$f" .py)"
  cp -f "$f" "$SNAP/${base}${VER}.py"
done

echo "Snapshot saved as version $VER"
echo

# ------------------------------------------------------------------------------
# Emit copy/paste-ready authoritative mapping block
# Notes:
# - The text keeps the placeholder 'vNN' (generic), while the mapping uses $VER.
# - Deterministic ordering:
#   1) src/cassian.py
#   2) src/cassian_*.py sorted
# ------------------------------------------------------------------------------
echo "Snapshot mapping (authoritative)"
echo
echo "The following uploaded files are snapshots of the current authoritative code."
echo "Version suffixes (vNN) are for tracking only."
echo
echo "Mapping:"

files=()
files+=("src/cassian.py")

while IFS= read -r -d '' f; do
  files+=("$f")
done < <(find src -maxdepth 1 -type f -name 'cassian_*.py' -print0 | sort -z)

for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue
  src_base="$(basename "$f")"
  snap_base="${src_base%.py}${VER}.py"
  echo "- ${snap_base} → ${f}"
done

cat <<'EOT'

Treat these as the current authoritative versions of the above modules.
Ignore any earlier snapshots or prior context.

Do not assume the existence of any other files or versions beyond this mapping.
EOT
