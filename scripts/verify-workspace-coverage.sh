#!/usr/bin/env bash
# Run scripts/run-coverage.sh for every workspace package (local / CI parity check).
# Requires: cargo, cargo-tarpaulin, jq. Run from repository root or any directory (script cds to root).
#
# Usage:
#   ./scripts/verify-workspace-coverage.sh [LINE_THRESHOLD]
# Env:
#   VERIFY_COVERAGE_SKIP  optional extended-regex (grep -E); matching package names are skipped (default: skip none).

set -uo pipefail

THRESH="${1:-70}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SKIP_RE="${VERIFY_COVERAGE_SKIP:-^$}"

# CI gates on Linux. On this repo the same commit measures up to 29 points differently between
# Windows and Linux, with different denominators, so a clean sweep here is not evidence about CI.
if [[ "$(uname -s 2>/dev/null)" != Linux* ]]; then
  echo "WARNING: not Linux. CI gates on Linux and the two disagree materially on this repo;" >&2
  echo "         treat these numbers as describing THIS machine only (WSL works)." >&2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required" >&2
  exit 1
fi

# Guard: optional deps enabled only via `dep:` do not get implicit workspace feature names.
# `cargo-tarpaulin` / `cargo metadata --features zeroize` must resolve for every workspace member.
if ! cargo metadata --format-version 1 --features zeroize -q >/dev/null; then
  echo "ERROR: cargo metadata --features zeroize failed (see messages above)." >&2
  exit 1
fi

mapfile -t NAMES < <(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | .name' | sort -u)

# Per-crate floors are READ FROM THE WORKFLOWS, not restated here.
#
# This function used to hardcode its own copy of the table. That made three copies -- pr.yml,
# coverage.yml and this script -- and copies drift. It already had: when 23 previously ungated
# crates were given measured floors in coverage.yml on 2026-08-08, this list was not updated, so
# a local sweep would have applied the generic 70% default to crates whose real floors run from
# 3% to 92% and reported failures that CI does not have.
#
# coverage.yml wins where both define a crate: it is the fuller table (pr.yml has no
# lib-q-fn-dsa branch, so that crate would otherwise silently take pr.yml's 70% default rather
# than its calibrated 68%). ci_guard_coverage_floors.py enforces that the two agree wherever
# both do define a crate, so "coverage.yml wins" is not papering over a conflict.
load_floors() {
  local py=""
  for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
      py="$candidate"; break
    fi
  done
  if [[ -z "$py" ]]; then
    echo "WARNING: no python3; falling back to the requested threshold for every crate." >&2
    return 0
  fi
  "$py" - <<'PY'
import re
floors = {}
try:
    pr = open(".github/workflows/pr.yml", encoding="utf-8").read()
    for m in re.finditer(r'^\s*(lib-q[\w-]*)\)\s*echo "coverage-threshold=(\d+)"', pr, re.M):
        floors[m.group(1)] = m.group(2)
except OSError:
    pass
try:
    cov = open(".github/workflows/coverage.yml", encoding="utf-8").read()
    # `CRATE) THRESH=NN` (extended-coverage) and `CRATE) CRATE_THRESH="NN"` / UTIL_THRESH.
    for m in re.finditer(r'^\s*(lib-q[\w-]*)\)\s*(?:CRATE_|UTIL_)?THRESH="?(\d+)"?', cov, re.M):
        floors[m.group(1)] = m.group(2)
except OSError:
    pass
for crate, floor in sorted(floors.items()):
    print(f"{crate}={floor}")
PY
}

declare -A FLOORS=()
while IFS='=' read -r _crate _floor; do
  [[ -n "$_crate" ]] && FLOORS["$_crate"]="$_floor"
done < <(load_floors)

if ((${#FLOORS[@]} == 0)); then
  echo "WARNING: read no per-crate floors from .github/workflows; using ${THRESH}% for all." >&2
else
  echo "Loaded ${#FLOORS[@]} per-crate floors from .github/workflows (default ${THRESH}% elsewhere)."
fi

effective_threshold_for() {
  local pkg="$1"
  local t="$2"
  echo "${FLOORS[$pkg]:-$t}"
}

failed=()
skipped=()
margins=()
for n in "${NAMES[@]}"; do
  if echo "$n" | grep -qE "$SKIP_RE"; then
    skipped+=("$n")
    continue
  fi
  eff="$(effective_threshold_for "$n" "$THRESH")"
  echo ""
  echo "======== coverage: $n (min ${eff}%) ========"
  out="$(bash scripts/run-coverage.sh --crate "$n" --threshold "$eff" --output-dir "coverage-verify-${n}" --no-report 2>&1)"
  rc=$?
  printf '%s\n' "$out"
  if [[ $rc -eq 0 ]]; then
    echo "OK  $n"
  else
    echo "FAIL  $n" >&2
    failed+=("$n")
  fi
  # Record the MARGIN, not just the verdict. A floor far below the real number passes while
  # protecting nothing -- which is how a gate quietly stops being a gate. Quote tarpaulin's own
  # reported total; never re-derive a percentage from its per-file lines.
  measured="$(printf '%s' "$out" | grep -oE '[0-9]+\.[0-9]+% coverage' | tail -1 | sed 's/% coverage//')"
  if [[ -n "$measured" ]]; then
    margins+=("$(printf '%s|%s|%s' "$n" "$eff" "$measured")")
  fi
done

# --- margin report -----------------------------------------------------------------------
# The reason this exists: the floors were originally calibrated on Windows while CI gates on
# Linux, and the two disagreed by up to 29 points on this repo (lib-q-mayo 65.56% -> 94.83%),
# with the DENOMINATOR differing on 17 of 23 crates because Linux compiles more code. Every
# floor still "passed". A floor with 35 points of slack is not a gate.
if ((${#margins[@]} > 0)); then
  echo ""
  echo "Floor margins (measured - floor):"
  printf '  %-26s %6s %10s %9s\n' CRATE FLOOR MEASURED MARGIN
  tight=""; loose=""
  for row in "${margins[@]}"; do
    IFS='|' read -r mc mf mm <<< "$row"
    delta="$(awk -v a="$mm" -v b="$mf" 'BEGIN{printf "%+.2f", a-b}')"
    printf '  %-26s %6s %9s%% %9s\n' "$mc" "$mf" "$mm" "$delta"
    band="$(awk -v a="$mm" -v b="$mf" 'BEGIN{d=a-b; print (d<2)?"tight":((d>12)?"loose":"")}')"
    [[ "$band" == tight ]] && tight+=" $mc"
    [[ "$band" == loose ]] && loose+=" $mc"
  done
  [[ -n "$tight" ]] && echo "  TIGHT (<2 points; likely to flake on unrelated changes):$tight"
  [[ -n "$loose" ]] && echo "  LOOSE (>12 points; the floor is not protecting much -- consider raising):$loose"
fi

if ((${#skipped[@]} > 0)); then
  echo ""
  echo "Skipped (${#skipped[@]}): ${skipped[*]}"
fi

if ((${#failed[@]} > 0)); then
  echo "" >&2
  echo "FAILED (${#failed[@]}): ${failed[*]}" >&2
  exit 1
fi

passed=$(( ${#NAMES[@]} - ${#skipped[@]} - ${#failed[@]} ))
echo ""
echo "OK: ${passed} package(s) met per-crate line floors (default request ${THRESH}%; skipped: ${#skipped[@]})."
exit 0
