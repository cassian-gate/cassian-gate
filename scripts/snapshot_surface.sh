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

find "$SNAP" -maxdepth 1 -type f -name "${BASE}.*.tar" \
  | sed -n 's|.*/'"${BASE}"'\.\([0-9]\+\)\.tar|\1 &|p' \
  | sort -n \
  | head -n -2 \
  | cut -d' ' -f2- \
  | xargs -r rm -f

echo
echo "Implementation surface snapshot saved as version ${NEXT}: $OUT"
echo
echo "Paste this into the implementation chat:"
echo "Treat the uploaded tar as the active implementation surface. Do not assume changes outside this uploaded set unless explicitly requested."