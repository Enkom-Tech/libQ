#!/usr/bin/env bash
# WASM binary size gate for libQ crates that ship wasm-pack artifacts (`cdylib` + `rlib`).
# Requires wasm-pack and rust wasm32-unknown-unknown target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "::error::wasm-pack not found; install it before running wasm-size-check" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

check_one() {
  local dir="$1"
  local features="$2"
  local max_kb="$3"
  echo "==> wasm-pack size: $dir (features: ${features:-none}, max ${max_kb} KB)"
  (
    cd "$ROOT/$dir"
    if [[ -n "$features" ]]; then
      wasm-pack build --target web --out-dir pkg-size-check --release -- --features "$features"
    else
      wasm-pack build --target web --out-dir pkg-size-check --release
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
    if [[ "$size_kb" -gt "$max_kb" ]]; then
      echo "::error::WASM size ${size_kb} KB exceeds budget ${max_kb} KB for $dir (features: ${features:-none})" >&2
      exit 2
    fi
    rm -rf pkg-size-check
  )
}

# (directory, features, max_size_kb) — release + wasm-opt (`-Oz`); re-run locally after large dependency changes.
check_one "lib-q-ml-kem" "wasm" 4000
check_one "lib-q-core" "wasm,ml-kem,rand" 3500
check_one "lib-q" "wasm,ml-kem" 10400
check_one "lib-q-zkp" "wasm,zkp" 13900
check_one "lib-q-hpke" "wasm,alloc,ml-kem,saturnin,shake256" 10400
check_one "lib-q-aead" "wasm,saturnin,alloc" 10400
check_one "lib-q-hqc" "wasm,hqc,random,serialization" 10400
check_one "lib-q-cb-kem" "wasm,cbkem348864,wasm_getrandom,alloc,zeroize" 13900
check_one "lib-q-slh-dsa" "wasm" 13900
check_one "lib-q-ring-sig" "wasm" 7000
check_one "lib-q-prf" "wasm" 3500
check_one "lib-q-random" "wasm" 1750
check_one "lib-q-stark" "wasm" 3500
check_one "lib-q-plonky" "wasm" 3500
check_one "lib-q-poseidon" "wasm,alloc" 7000
check_one "lib-q-lattice-zkp" "wasm,random" 10400
check_one "lib-q-ring" "wasm,alloc" 7000

echo "wasm-size-check: OK"
