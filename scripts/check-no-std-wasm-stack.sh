#!/usr/bin/env bash
# no_std + wasm32 gate for STARK stack and research pilot crates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'

rustup target add wasm32-unknown-unknown thumbv7em-none-eabi >/dev/null 2>&1 || true

echo "==> dev-no-std (thumbv7em; native host skips cdylib allocator requirement)"
cargo check -p lib-q-ring --profile dev-no-std --no-default-features --features no_std --target thumbv7em-none-eabi
cargo check -p lib-q-lattice-zkp --profile dev-no-std --no-default-features --features no_std --target thumbv7em-none-eabi
cargo check -p lib-q-stark-dft --profile dev-no-std --no-default-features --features alloc

echo "==> wasm32-unknown-unknown (npm / wasm-pack features)"
cargo check -p lib-q-ring --no-default-features --features alloc,wasm --target wasm32-unknown-unknown
cargo check -p lib-q-lattice-zkp --no-default-features --features alloc,wasm,random --target wasm32-unknown-unknown
cargo check -p lib-q-stark --no-default-features --features alloc,wasm --target wasm32-unknown-unknown
cargo check -p lib-q-plonky --no-default-features --features alloc,wasm --target wasm32-unknown-unknown
cargo check -p lib-q-poseidon --no-default-features --features alloc,wasm --target wasm32-unknown-unknown

echo "check-no-std-wasm-stack: OK"
