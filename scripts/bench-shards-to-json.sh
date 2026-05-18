#!/usr/bin/env bash
# Emit GitHub Actions matrix JSON from .github/benchmark-shards.toml
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PYTHON=(python3)
elif command -v py >/dev/null 2>&1; then
  PYTHON=(py -3)
else
  echo "ERROR: python3 or py not found" >&2
  exit 1
fi

JSON="$("${PYTHON[@]}" scripts/bench_shards_lib.py matrix)"
echo "$JSON" | "${PYTHON[@]}" scripts/bench_shards_lib.py verify-matrix

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "matrix<<EOF"
    echo "$JSON"
    echo "EOF"
  } >>"$GITHUB_OUTPUT"
else
  echo "$JSON"
fi
