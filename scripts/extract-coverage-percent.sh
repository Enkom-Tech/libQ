#!/usr/bin/env bash
# Read aggregate line coverage (0-100) from cargo-tarpaulin output in OUTPUT_DIR.
# Prefers cobertura.xml; falls back to HTML. Prints percentage; exit 0 if ok.

set -euo pipefail

DIR="${1:-coverage}"
pct=""

if [[ -f "$DIR/cobertura.xml" ]]; then
  rate=""
  rate=$(grep -m1 -oE 'line-rate="[0-9.]+"' "$DIR/cobertura.xml" | sed -E 's/^line-rate="//;s/"$//' || true)
  if [[ -n "${rate}" ]]; then
    pct=$(awk -v r="$rate" 'BEGIN { printf "%.4g", r * 100 }')
  fi
fi

if [[ -z "${pct}" ]]; then
  for f in "$DIR/tarpaulin-report.html" "$DIR/index.html"; do
    [[ -f "$f" ]] || continue
    found=$(awk '
      {
        if (match($0, /[0-9]+(\.[0-9]+)?[[:space:]]*%/)) {
          s = substr($0, RSTART, RLENGTH)
          gsub(/[[:space:]]|%/, "", s)
          print s
          exit
        }
      }
    ' "$f" || true)
    if [[ -n "${found}" ]]; then
      pct=$(awk -v x="$found" 'BEGIN { printf "%.4g", x+0 }')
      break
    fi
  done
fi

if [[ -n "${pct}" ]] && [[ "${pct}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "${pct}"
  exit 0
fi

exit 1
