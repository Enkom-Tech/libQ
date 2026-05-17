#!/usr/bin/env bash
# Mirror the GitHub CI jobs gated with `if: github.event_name != 'pull_request'`
# (.github/workflows/ci.yml): ZKP Recursive Aggregation, Cross-Platform Builds (Linux
# matrix only in WSL), Performance & Benchmarks, SIMD Debug Verification, Constant-Time
# Verification.
#
# From WSL, at repo root:
#   chmod +x scripts/run-non-pr-ci-jobs-wsl.sh
#   ./scripts/run-non-pr-ci-jobs-wsl.sh
#
# Cross-compilation (aarch64, armv7) needs Ubuntu packages:
#   sudo apt-get update
#   sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
#     gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-dev-armhf-cross file
#
# macOS / Windows MSVC targets from the CI matrix cannot be built from WSL; run those on
# the native runners or a matching host.
#
# Environment:
#   CARGO_TARGET_DIR   If unset and the repo lives under /mnt/, defaults to
#                      $HOME/.cache/libq-wsl-ci-target so `cargo clean` / `rm -rf target/release`
#                      patterns do not hit drvfs I/O errors.
#   PERF_NO_RUN=1      Only compile workspace benches (`cargo bench --no-run`); skip the
#                      long `cargo bench --features all-algorithms` execution (CI runs it).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "${HOME:-}/.cargo/env" ]]; then
  set +u
  # shellcheck source=/dev/null
  source "${HOME}/.cargo/env"
  set -u
fi

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

if [[ -z "${CARGO_TARGET_DIR:-}" ]] && [[ "${ROOT}" == /mnt/* ]]; then
  export CARGO_TARGET_DIR="${HOME}/.cache/libq-wsl-ci-target"
  mkdir -p "${CARGO_TARGET_DIR}"
  echo "== Using CARGO_TARGET_DIR=${CARGO_TARGET_DIR} (repo on /mnt/ avoids drvfs target/ I/O issues) =="
fi

# Artifacts land under CARGO_TARGET_DIR when set, otherwise under repo target/.
TGT_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"

echo "== 1/5 ZKP Recursive Aggregation (release-ci, matches CI) =="
rm -rf "${TGT_DIR}/release-ci"
cargo test -p lib-q-zkp --profile release-ci --features "zkp,recursive-proofs-experimental,std" \
  --test aggregation_tests test_recursive_verifier_trace_satisfies_constraints_then_prove_verify \
  -- --test-threads=1

echo "== 2/5 Cross-Platform Builds: Linux x86_64 + aarch64 + armv7 (CI Ubuntu rows) =="
rustup target add aarch64-unknown-linux-gnu armv7-unknown-linux-gnueabihf 2>/dev/null || true
if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || ! command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1; then
  echo "ERROR: cross GCC not found. Install the packages listed in the header of this script." >&2
  exit 1
fi

RUSTFLAGS="-C target-cpu=generic -C opt-level=3 -C overflow-checks=on" \
  cargo build --target x86_64-unknown-linux-gnu --features "all-algorithms" --release
RUSTFLAGS="-C target-cpu=generic -C opt-level=3 -C overflow-checks=on" \
  cargo build --target aarch64-unknown-linux-gnu --features "all-algorithms" --release
RUSTFLAGS="-C target-cpu=generic -C opt-level=3 -C overflow-checks=on" \
  cargo build --target armv7-unknown-linux-gnueabihf --features "all-algorithms" --release

file "${TGT_DIR}/aarch64-unknown-linux-gnu/release/liblibq.so" | grep -q "ARM aarch64"
file "${TGT_DIR}/armv7-unknown-linux-gnueabihf/release/liblibq.so" | grep -q "ARM"

rm -rf "${TGT_DIR}/release-ci"
cargo test -p lib-q-keccak --target aarch64-unknown-linux-gnu --features std --profile release-ci --no-run
rm -rf "${TGT_DIR}/release-ci"
cargo test -p lib-q-keccak --target armv7-unknown-linux-gnueabihf --features std --profile release-ci --no-run

echo "== 3/5 Performance & Benchmarks (matches ci.yml performance job) =="
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  rm -rf "${CARGO_TARGET_DIR}/release"
else
  rm -rf "${ROOT}/target/release"
fi

if [[ "${PERF_NO_RUN:-}" == "1" ]]; then
  cargo bench --features "all-algorithms" --no-run --verbose
else
  cargo bench --features "all-algorithms" --verbose
fi

cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream,simd-avx2" --bench saturnin_criterion_benches --verbose
(
  cd lib-q-random
  cargo bench --features "std,secure,zeroize" --verbose
)
(
  cd lib-q-hqc
  cargo bench --features "alloc,hqc128,simd-avx2" --bench simd_benchmarks --verbose
)
cargo bench -p lib-q-zkp --features "zkp,std" --bench stark_arithmetic_bench --verbose

echo "== 4/5 SIMD Debug Verification (HQC) =="
(
  cd lib-q-hqc
  RUST_SIMD_DEBUG=1 cargo test --features "simd-avx2,alloc,hqc128" simd_unit_tests --verbose
  cargo test --features "simd-avx2,alloc,hqc128" cross_implementation --verbose
)

echo "== 5/5 Constant-Time Verification (same cargo tests as CI constant-time job) =="
cargo test --test constant_time -p lib-q-sha3
cargo test --test constant_time -p lib-q-k12

echo "== run-non-pr-ci-jobs-wsl.sh: all steps finished OK =="
