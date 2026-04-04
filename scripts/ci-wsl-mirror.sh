#!/usr/bin/env bash
# Deeper CI-style checks under Linux/WSL (SLH-DSA all parameter sets, ZKP recursive, docs, …).
# For a fast PR-style gate use: ./scripts/simulate-ci-wsl.sh
# For full feature matrix + builds use: ./scripts/simulate-ci-wsl.sh full
# Prefer a native WSL filesystem clone for speed: ~/libQ instead of /mnt/c/...
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'

rustup target add wasm32-unknown-unknown 2>/dev/null || true

echo "== Core: fmt + clippy (root lib-q, matches CI clippy job) =="
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

echo "== SLH-DSA unit tests (smoke parameter sets; default) =="
cargo test -p lib-q-slh-dsa --features alloc --verbose

echo "== SLH-DSA: all 12 parameter sets (unit macros + known_answer_tests KATs; slow) =="
cargo test -p lib-q-slh-dsa --profile release-ci --features "alloc,all-parameter-set-tests" --verbose

echo "== HQC SIMD (simd-debug-tests job) =="
(
  cd lib-q-hqc
  RUST_SIMD_DEBUG=1 cargo test --features "simd-avx2,alloc,hqc128" simd_unit_tests --verbose
  cargo test --features "simd-avx2,alloc,hqc128" cross_implementation --verbose
)

echo "== Linux x86_64 release build (cross-platform Ubuntu job) =="
RUSTFLAGS='-C target-cpu=generic -C opt-level=3 -C overflow-checks=on' \
  cargo build --target x86_64-unknown-linux-gnu --features all-algorithms --release

echo "== WASM cargo check (wasm-validation matrix, check-only style) =="
cargo check --target wasm32-unknown-unknown --features "wasm,all-algorithms,ml-kem" --lib
( cd lib-q-kem && cargo check --target wasm32-unknown-unknown --features "wasm,ml-kem" --lib )
( cd lib-q-core && cargo check --target wasm32-unknown-unknown --features "wasm,ml-kem,rand" --lib )
( cd lib-q-zkp && cargo check --target wasm32-unknown-unknown --features "wasm,zkp" --lib )

echo "== ZKP recursive aggregation (release, slow) =="
cargo test -p lib-q-zkp --release --features "zkp,recursive-proofs-experimental,std" \
  --test aggregation_tests test_recursive_verifier_trace_satisfies_constraints_then_prove_verify \
  -- --test-threads=1

echo "== Documentation job =="
cargo doc --all-features --no-deps
cargo doc --all-features --no-deps --document-private-items

echo "== Integration tests job =="
cargo test -p lib-q --test hash_integration_tests --features "all-algorithms" --verbose
cargo test --package lib-q --features "all-algorithms" --verbose

echo "== ci-wsl-mirror.sh: finished OK =="
