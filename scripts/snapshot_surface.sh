#!/usr/bin/env bash
set -euo pipefail

SNAP="/mnt/c/Users/acast/Documents/Ai Sim/snapshot"
BASE="cassian-implementation-surface"
COUNTER="$SNAP/.${BASE}.counter"

mkdir -p "$SNAP"

LAST=0
if [[ -f "$COUNTER" ]]; then
  LAST=$(<"$COUNTER")
fi

NEXT=$((LAST + 1))
printf '%s\n' "$NEXT" > "$COUNTER"

OUT="$SNAP/${BASE}.${NEXT}.tar"

tar -cf "$OUT" \
  topologies \
  docs \
  tests \
  examples \
  contrib \
  candidate

shopt -s nullglob
files=( "$SNAP"/${BASE}.*.tar )

if (( ${#files[@]} > 2 )); then
  versions=()

  for f in "${files[@]}"; do
    name=$(basename "$f")
    ver=${name#${BASE}.}
    ver=${ver%.tar}
    versions+=( "$ver:$f" )
  done

  IFS=$'\n' sorted=($(printf '%s\n' "${versions[@]}" | sort -t: -k1,1n))
  unset IFS

  keep_from=$(( ${#sorted[@]} - 2 ))
  for ((i=0; i<keep_from; i++)); do
    old=${sorted[$i]#*:}
    rm -f -- "$old"
  done
fi

echo
echo "Implementation surface snapshot saved as version ${NEXT}: $(basename "$OUT")"
echo
echo "Paste this into the implementation chat:"
echo "Treat the uploaded tar as the active implementation surface. Do not assume changes outside this uploaded set unless explicitly requested."