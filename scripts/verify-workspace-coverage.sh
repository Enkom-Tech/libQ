#!/usr/bin/env bash
# Run scripts/run-coverage.sh for every workspace package (local / CI parity check).
# Requires: cargo, cargo-tarpaulin, jq. Run from repository root or any directory (script cds to root).
#
# Usage:
#   ./scripts/verify-workspace-coverage.sh [LINE_THRESHOLD]
# Env:
#   VERIFY_COVERAGE_SKIP  optional extended-regex (grep -E); matching package names are skipped (default: skip none).

set -uo pipefail

THRESH="${1:-65}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SKIP_RE="${VERIFY_COVERAGE_SKIP:-^$}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required" >&2
  exit 1
fi

mapfile -t NAMES < <(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | .name' | sort -u)

failed=()
skipped=()
for n in "${NAMES[@]}"; do
  if echo "$n" | grep -qE "$SKIP_RE"; then
    skipped+=("$n")
    continue
  fi
  echo ""
  echo "======== coverage: $n (min ${THRESH}%) ========"
  if bash scripts/run-coverage.sh --crate "$n" --threshold "$THRESH" --output-dir "coverage-verify-${n}" --no-report; then
    echo "OK  $n"
  else
    echo "FAIL  $n" >&2
    failed+=("$n")
  fi
done

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
echo "OK: ${passed} package(s) met ${THRESH}% line coverage (skipped: ${#skipped[@]})."
exit 0
