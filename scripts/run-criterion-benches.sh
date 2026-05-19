#!/usr/bin/env bash
# Run Criterion benches for one workspace package (skips libtest lib/autobench targets).
#
# Usage (repo root):
#   ./scripts/run-criterion-benches.sh -p lib-q-sha3
#   ./scripts/run-criterion-benches.sh -p lib-q-zkp -f zkp,std -b zkp_benchmarks
#   PERF_NO_RUN=1 ./scripts/run-criterion-benches.sh -p lib-q-sha3   # compile only
#
# Environment:
#   BENCH_CRITERION_FLAGS  Args after `--` (default: --quick --warm-up-time 1)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export BENCH_CRITERION_FLAGS="${BENCH_CRITERION_FLAGS:---quick --warm-up-time 1}"
# shellcheck disable=SC2206
BENCH_EXTRA=( ${BENCH_CRITERION_FLAGS} )

PACKAGE=""
FEATURES=""
BENCH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--package) PACKAGE="$2"; shift 2 ;;
    -f|--features) FEATURES="$2"; shift 2 ;;
    -b|--bench) BENCH="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,12p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PACKAGE" ]]; then
  echo "ERROR: -p/--package is required" >&2
  exit 2
fi

PYTHON=()
for py in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c "import tomllib" 2>/dev/null; then
    PYTHON=("$py")
    break
  fi
done
if [[ ${#PYTHON[@]} -eq 0 ]]; then
  echo "ERROR: need Python 3.11+ (stdlib tomllib)" >&2
  exit 1
fi

BENCHES=()
if [[ -n "$BENCH" ]]; then
  BENCHES=("$BENCH")
else
  mapfile -t BENCHES < <("${PYTHON[@]}" scripts/bench_shards_lib.py criterion-benches "$PACKAGE" "$FEATURES")
  if [[ ${#BENCHES[@]} -eq 0 ]]; then
    echo "ERROR: no Criterion bench targets for $PACKAGE" >&2
    exit 1
  fi
fi

for target in "${BENCHES[@]}"; do
  CMD=(cargo bench -p "$PACKAGE" --bench "$target")
  if [[ -n "$FEATURES" ]]; then
    CMD+=(--features "$FEATURES")
  fi
  if [[ "${PERF_NO_RUN:-}" == "1" ]]; then
    CMD+=(--no-run)
  fi
  CMD+=(--verbose -- "${BENCH_EXTRA[@]}")
  echo ">>> cargo bench -p $PACKAGE --bench $target"
  "${CMD[@]}"
done
