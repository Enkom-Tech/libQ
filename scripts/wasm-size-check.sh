#!/usr/bin/env bash
# Advisory WASM binary size check for selected libQ crates.
# Requires wasm-pack and rust wasm32-unknown-unknown target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'

MAX_SIZE_KB="${MAX_SIZE_KB:-2048}"
FAIL_ON_OVERSIZE="${FAIL_ON_OVERSIZE:-0}"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found; skip wasm-size-check (install: cargo install wasm-pack)" >&2
  exit 0
fi

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

check_one() {
  local dir="$1"
  local features="$2"
  echo "==> wasm-pack: $dir (features: ${features:-none})"
  (
    cd "$ROOT/$dir"
    if [[ -n "$features" ]]; then
      wasm-pack build --target web --out-dir pkg-size-check --release -- --features "$features" --lib
    else
      wasm-pack build --target web --out-dir pkg-size-check --release -- --lib
    fi
    local wasm_file
    wasm_file=$(ls pkg-size-check/*.wasm 2>/dev/null | head -1 || true)
    if [[ -z "$wasm_file" ]]; then
      echo "No .wasm produced in $dir" >&2
      exit 1
    fi
    local size_kb
    size_kb=$(du -k "$wasm_file" | cut -f1)
    echo "    $dir: ${size_kb} KB ($(basename "$wasm_file"))"
    if [[ "$size_kb" -gt "$MAX_SIZE_KB" ]]; then
      echo "    WARNING: exceeds advisory limit ${MAX_SIZE_KB} KB (set MAX_SIZE_KB to tune)" >&2
      if [[ "$FAIL_ON_OVERSIZE" == "1" ]]; then
        exit 2
      fi
    fi
    rm -rf pkg-size-check
  )
}

# Crates that ship wasm-pack-friendly cdylib + wasm features
check_one "lib-q-core" "wasm,ml-kem,rand"
check_one "lib-q" "wasm,ml-kem"

echo "wasm-size-check: done"
