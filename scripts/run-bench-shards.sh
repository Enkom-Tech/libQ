#!/usr/bin/env bash
# Run CI benchmark shards from .github/benchmark-shards.toml
#
# Usage (from repo root):
#   ./scripts/run-bench-shards.sh              # sequential
#   PERF_PARALLEL=1 ./scripts/run-bench-shards.sh
#   PERF_NO_RUN=1 ./scripts/run-bench-shards.sh   # compile only (validate)
#   SHARD_ID=lib-q-zkp ./scripts/run-bench-shards.sh
#
# Environment:
#   BENCH_CRITERION_FLAGS  Passed after `--` to each Criterion bench (default: --quick --warm-up-time 1)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export BENCH_CRITERION_FLAGS="${BENCH_CRITERION_FLAGS:---quick --warm-up-time 1}"

PYTHON=()
for py in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c "import tomllib" 2>/dev/null; then
    PYTHON=("$py")
    break
  fi
done
if [[ ${#PYTHON[@]} -eq 0 ]] && command -v py >/dev/null 2>&1 && py -3 -c "import tomllib" 2>/dev/null; then
  PYTHON=(py -3)
fi
if [[ ${#PYTHON[@]} -eq 0 ]]; then
  echo "ERROR: need Python 3.11+ (stdlib tomllib); install python3.11 or newer" >&2
  exit 1
fi

bench_shard() {
  local id="$1"
  local package="$2"
  local features="$3"
  local bench="$4"

  echo ">>> Benchmark shard: $id"
  local -a args=(-p "$package")
  if [[ -n "$features" ]]; then
    args+=(-f "$features")
  fi
  if [[ -n "$bench" ]]; then
    args+=(-b "$bench")
  fi
  ./scripts/run-criterion-benches.sh "${args[@]}"
}

run_shard_from_line() {
  local line="$1"
  eval "$line"
  if [[ -n "${SHARD_ID:-}" && "$ID" != "$SHARD_ID" ]]; then
    return 0
  fi
  bench_shard "$ID" "$PACKAGE" "${FEATURES:-}" "${BENCH:-}"
}

SHARD_LINES="$("${PYTHON[@]}" -c "
import tomllib
from pathlib import Path
for s in tomllib.loads(Path('.github/benchmark-shards.toml').read_text(encoding='utf-8')).get('shard', []):
    if s.get('enabled', True) is False:
        continue
    f = s.get('features', '')
    b = s.get('bench', '')
    print(f\"ID={s['id']!r} PACKAGE={s['package']!r} FEATURES={f!r} BENCH={b!r}\")
")"

if [[ "${PERF_NO_RUN:-}" == "1" && -z "${SHARD_ID:-}" ]]; then
  echo "PERF_NO_RUN=1: compile-check all manifest shards"
fi

if [[ "${PERF_PARALLEL:-}" == "1" && -z "${SHARD_ID:-}" ]]; then
  echo "PERF_PARALLEL=1: running shards in background"
  PIDS=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ( run_shard_from_line "$line" ) &
    PIDS+=($!)
  done <<<"$SHARD_LINES"
  FAIL=0
  for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
      FAIL=1
    fi
  done
  exit "$FAIL"
fi

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  run_shard_from_line "$line"
done <<<"$SHARD_LINES"
