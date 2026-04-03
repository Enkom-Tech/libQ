#!/usr/bin/env bash
# Enforce line (and optionally branch) coverage from cargo-tarpaulin cobertura.xml.
# Branch enforcement is skipped when the report has branches-valid=0 (common for LLVM tarpaulin).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINE_MIN=""
BRANCH_MIN=""
OUTPUT_DIR="coverage"

usage() {
  echo "Usage: $0 [--dir DIR] --line-min N [--branch-min N]" >&2
  echo "  --dir DIR       Directory containing cobertura.xml (default: coverage)" >&2
  echo "  --line-min N    Minimum line coverage percent (required)" >&2
  echo "  --branch-min N  Minimum branch coverage when Cobertura includes branch data" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --line-min)
      LINE_MIN="$2"
      shift 2
      ;;
    --branch-min)
      BRANCH_MIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "${LINE_MIN}" ]]; then
  echo "ERROR: --line-min is required" >&2
  usage
fi

EXTRACT="${SCRIPT_DIR}/extract-coverage-percent.sh"
if [[ ! -f "${EXTRACT}" ]]; then
  echo "ERROR: Missing ${EXTRACT}" >&2
  exit 1
fi

if ! LINE_PCT="$("${EXTRACT}" "${OUTPUT_DIR}" line)"; then
  echo "ERROR: Could not read line coverage from ${OUTPUT_DIR}" >&2
  exit 1
fi

echo "Line coverage: ${LINE_PCT}% (minimum ${LINE_MIN}%)"
if awk -v c="${LINE_PCT}" -v t="${LINE_MIN}" 'BEGIN { exit !(c + 0 < t) }'; then
  echo "ERROR: Line coverage below threshold" >&2
  exit 1
fi

if [[ -n "${BRANCH_MIN}" ]]; then
  set +e
  BR_OUT="$("${EXTRACT}" "${OUTPUT_DIR}" branch 2>/dev/null)"
  BR_EC=$?
  set -e
  if [[ "${BR_EC}" -eq 2 ]]; then
    echo "Branch coverage: not emitted in Cobertura (branches-valid=0); skipping branch gate"
  elif [[ "${BR_EC}" -ne 0 ]] || [[ -z "${BR_OUT}" ]]; then
    echo "ERROR: Could not read branch coverage from ${OUTPUT_DIR}" >&2
    exit 1
  else
    echo "Branch coverage: ${BR_OUT}% (minimum ${BRANCH_MIN}%)"
    if awk -v c="${BR_OUT}" -v t="${BRANCH_MIN}" 'BEGIN { exit !(c + 0 < t) }'; then
      echo "ERROR: Branch coverage below threshold" >&2
      exit 1
    fi
  fi
fi

echo "Coverage metric checks passed"
exit 0
