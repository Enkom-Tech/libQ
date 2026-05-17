#!/usr/bin/env bash
# Read aggregate line or branch coverage (0-100) from cargo-tarpaulin output in OUTPUT_DIR.
# Prefers cobertura.xml; falls back to HTML for line only. Prints percentage; exit 0 if ok.
# Usage: extract-coverage-percent.sh [DIR] [line|branch]
# For branch: exit 2 if Cobertura has branches-valid=0 (no branch data to enforce).

set -euo pipefail

DIR="${1:-coverage}"
METRIC="${2:-line}"
pct=""

if [[ "$METRIC" != "line" && "$METRIC" != "branch" ]]; then
  echo "Second argument must be 'line' or 'branch'" >&2
  exit 2
fi

if [[ -f "$DIR/cobertura.xml" ]]; then
  xml="$DIR/cobertura.xml"
  if [[ "$METRIC" == "branch" ]]; then
    bv=""
    bv=$(grep -m1 -oE 'branches-valid="[0-9]+"' "$xml" | sed -E 's/^branches-valid="//;s/"$//' || true)
    if [[ -z "${bv}" ]] || [[ "${bv}" -eq 0 ]]; then
      exit 2
    fi
    rate=""
    rate=$(grep -m1 -oE 'branch-rate="[0-9.]+"' "$xml" | sed -E 's/^branch-rate="//;s/"$//' || true)
    if [[ -n "${rate}" ]]; then
      pct=$(awk -v r="$rate" 'BEGIN { printf "%.4g", r * 100 }')
    fi
  else
    rate=""
    rate=$(grep -m1 -oE 'line-rate="[0-9.]+"' "$xml" | sed -E 's/^line-rate="//;s/"$//' || true)
    if [[ -n "${rate}" ]]; then
      pct=$(awk -v r="$rate" 'BEGIN { printf "%.4g", r * 100 }')
    fi
  fi
fi

if [[ -z "${pct}" && "$METRIC" == "line" ]]; then
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

if [[ "$METRIC" == "branch" ]]; then
  exit 2
fi

exit 1
