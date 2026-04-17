#!/usr/bin/env bash
set -euo pipefail

SNAP="/mnt/c/Users/acast/Documents/Ai Sim/snapshot"
BASE="cassian-implementation-surface"
COUNTER="$SNAP/.${BASE}.counter"

mkdir -p "$SNAP"

LAST=0
if [[ -f "$COUNTER" ]]; then
  LAST=$(cat "$COUNTER")
fi

NEXT=$((LAST + 1))
echo "$NEXT" > "$COUNTER"

OUT="$SNAP/${BASE}.${NEXT}.tar"

tar -cf "$OUT" \
  topologies \
  docs \
  tests \
  examples \
  contrib \
  candidate

mapfile -t SNAPSHOTS < <(
  find "$SNAP" -maxdepth 1 -type f -name "${BASE}.*.tar" \
    | sed -E 's|.*/'"${BASE}"'\.([0-9]+)\.tar$|\1 &|' \
    | sort -n \
    | awk '{print $2}'
)

if (( ${#SNAPSHOTS[@]} > 2 )); then
  for old in "${SNAPSHOTS[@]:0:${#SNAPSHOTS[@]}-2}"; do
    rm -f "$old"
  done
fi

echo
echo "Implementation surface snapshot saved as version ${NEXT}: $(basename "$OUT")"
echo
echo "Paste this into the implementation chat:"
echo "Treat the uploaded tar as the active implementation surface. Do not assume changes outside this uploaded set unless explicitly requested."