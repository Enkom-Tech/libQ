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
# shellcheck disable=SC2206
BENCH_EXTRA=( ${BENCH_CRITERION_FLAGS} )

if command -v python3 >/dev/null 2>&1; then
  PYTHON=(python3)
elif command -v py >/dev/null 2>&1; then
  PYTHON=(py -3)
else
  echo "ERROR: python3 or py not found" >&2
  exit 1
fi

bench_shard() {
  local id="$1"
  local package="$2"
  local features="$3"
  local bench="$4"

  local -a cmd=(cargo bench -p "$package")
  if [[ -n "$features" ]]; then
    cmd+=(--features "$features")
  fi
  if [[ -n "$bench" ]]; then
    cmd+=(--bench "$bench")
  fi
  if [[ "${PERF_NO_RUN:-}" == "1" ]]; then
    cmd+=(--no-run)
  fi
  cmd+=(--verbose -- "${BENCH_EXTRA[@]}")

  echo ">>> Benchmark shard: $id"
  "${cmd[@]}"
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
for s in tomllib.loads(Path('.github/benchmark-shards.toml').read_bytes()).get('shard', []):
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
