#!/usr/bin/env bash
# Mirrors .github/workflows/ci.yml test-matrix + critical follow-on jobs (local Linux).
# Not invoked by CI; for developer parity checks.
#
# Windows: use Git Bash so `cargo` resolves to the Windows rustup install (prepend
# %USERPROFILE%\.cargo\bin to PATH). Avoid `bash` from System32 if it launches WSL,
# which may use a separate rustup tree or fail mid-update.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
export CARGO_INCREMENTAL=0
export CARGO_TERM_COLOR=always

nuke_release_ci() {
  rm -rf "${ROOT}/target/release-ci"
}

echo "========== crate/npm CI guards =========="
bash "$ROOT/scripts/ci-guard-new-crates-and-npm.sh" "$ROOT"

run_packages_matrix() {
  local features="$1"
  shift
  local packages_line="$1"
  local SHARED_FLAGS=""
  for item in $packages_line; do
    if [[ "$item" == *"@"* ]]; then
      local pkg="${item%%@*}"
      local pfeats="${item#*@}"
      echo ">>> cargo test -p $pkg --features $pfeats"
      cargo test -p "$pkg" --features "$pfeats" --verbose
    else
      if [[ -z "$SHARED_FLAGS" ]]; then
        SHARED_FLAGS="-p $item"
      else
        SHARED_FLAGS="$SHARED_FLAGS -p $item"
      fi
    fi
  done
  if [[ -n "$SHARED_FLAGS" ]]; then
    echo ">>> cargo test $SHARED_FLAGS --features $features"
    cargo test $SHARED_FLAGS --features "$features" --verbose
  fi
}

run_packages_matrix_release() {
  local features="$1"
  shift
  local packages_line="$1"
  local SHARED_FLAGS=""
  for item in $packages_line; do
    if [[ "$item" == *"@"* ]]; then
      local pkg="${item%%@*}"
      local pfeats="${item#*@}"
      echo ">>> cargo test -p $pkg --features $pfeats --profile release-ci"
      cargo test -p "$pkg" --features "$pfeats" --profile release-ci --verbose
    else
      if [[ -z "$SHARED_FLAGS" ]]; then
        SHARED_FLAGS="-p $item"
      else
        SHARED_FLAGS="$SHARED_FLAGS -p $item"
      fi
    fi
  done
  if [[ -n "$SHARED_FLAGS" ]]; then
    echo ">>> cargo test $SHARED_FLAGS --features $features --profile release-ci"
    cargo test $SHARED_FLAGS --features "$features" --profile release-ci --verbose
  fi
}

echo "========== CI matrix: std =========="
nuke_release_ci
cargo test --features std --verbose
nuke_release_ci
cargo test --features std --profile release-ci --verbose

echo "========== CI matrix: all-algorithms =========="
nuke_release_ci
cargo test --features std,all-algorithms --verbose
nuke_release_ci
cargo test --features std,all-algorithms --profile release-ci --verbose

echo "========== CI matrix: ml-kem (split packages) =========="
nuke_release_ci
run_packages_matrix "std,ml-kem,rand" "lib-q lib-q-kem lib-q-core lib-q-ml-kem@std,random"
nuke_release_ci
run_packages_matrix_release "std,ml-kem,rand" "lib-q lib-q-kem lib-q-core lib-q-ml-kem@std,random"

echo "========== CI matrix: no_std lib-q-core =========="
nuke_release_ci
cargo check -p lib-q-core --profile dev-no-std --no-default-features --features "no_std,getrandom" --verbose
nuke_release_ci
cargo check -p lib-q-core --profile release-security --no-default-features --features "no_std,getrandom" --verbose

echo "========== CI matrix: wasm lib-q + lib-q-core =========="
nuke_release_ci
run_packages_matrix "std,wasm" "lib-q lib-q-core"
nuke_release_ci
run_packages_matrix_release "std,wasm" "lib-q lib-q-core"

echo "========== CI matrix: zkp lib-q + lib-q-zkp =========="
nuke_release_ci
run_packages_matrix "std,zkp" "lib-q lib-q-zkp"
nuke_release_ci
run_packages_matrix_release "std,zkp" "lib-q lib-q-zkp"

echo "========== CI matrix: lib-q-kem =========="
nuke_release_ci
cargo test -p lib-q-kem --features ml-kem --verbose
nuke_release_ci
cargo test -p lib-q-kem --features ml-kem --profile release-ci --verbose

echo "========== CI matrix: lib-q-ml-kem =========="
nuke_release_ci
cargo test -p lib-q-ml-kem --features std --verbose
nuke_release_ci
cargo test -p lib-q-ml-kem --features std --profile release-ci --verbose

echo "========== CI matrix: ml-dsa-fips =========="
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,fips-mode,mldsa44,mldsa65,mldsa87,acvp --verbose
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,fips-mode,mldsa44,mldsa65,mldsa87,acvp --profile release-ci --verbose

echo "========== CI matrix: ml-dsa-hardened =========="
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,hardened,mldsa44,mldsa65,mldsa87 --verbose
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,hardened,mldsa44,mldsa65,mldsa87 --profile release-ci --verbose

echo "========== CI matrix: ml-dsa-cross-mode =========="
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,random,acvp,mldsa44,mldsa65,mldsa87 --verbose
nuke_release_ci
cargo test -p lib-q-ml-dsa --features std,random,acvp,mldsa44,mldsa65,mldsa87 --profile release-ci --verbose

echo "========== CI matrix: lib-q-keccak no_std =========="
nuke_release_ci
cargo check -p lib-q-keccak --profile dev-no-std --no-default-features --features "alloc" --verbose
nuke_release_ci
cargo check -p lib-q-keccak --profile release --no-default-features --features "alloc" --verbose

echo "========== CI matrix: lib-q-random std =========="
nuke_release_ci
cargo test -p lib-q-random --features std,secure,zeroize --verbose
nuke_release_ci
cargo test -p lib-q-random --features std,secure,zeroize --profile release-ci --verbose

echo "========== CI matrix: lib-q-random no_std =========="
nuke_release_ci
cargo check -p lib-q-random --profile dev-no-std --no-default-features --features "no_std,getrandom" --verbose
nuke_release_ci
cargo check -p lib-q-random --profile release-security --no-default-features --features "no_std,getrandom" --verbose

echo "========== CI matrix: lib-q-random wasm =========="
nuke_release_ci
cargo test -p lib-q-random --features wasm --verbose
nuke_release_ci
cargo test -p lib-q-random --features wasm --profile release-ci --verbose

echo "========== CI matrix: lib-q-stark-rayon =========="
nuke_release_ci
cargo test -p lib-q-stark-rayon --features parallel --verbose
nuke_release_ci
cargo test -p lib-q-stark-rayon --features parallel --profile release-ci --verbose

echo "========== CI matrix: lib-q-stark-dft alloc =========="
nuke_release_ci
cargo test -p lib-q-stark-dft --features alloc --verbose
nuke_release_ci
cargo test -p lib-q-stark-dft --features alloc --profile release-ci --verbose

echo "========== CI matrix: lib-q-stark-dft parallel =========="
nuke_release_ci
cargo test -p lib-q-stark-dft --features alloc,parallel --verbose
nuke_release_ci
cargo test -p lib-q-stark-dft --features alloc,parallel --profile release-ci --verbose

echo "========== CI matrix: lib-q-ring =========="
nuke_release_ci
cargo test -p lib-q-ring --features alloc --verbose
nuke_release_ci
cargo test -p lib-q-ring --features alloc --profile release-ci --verbose

echo "========== CI matrix: lib-q-prf =========="
echo "Running: cargo test -p lib-q-prf --features alloc --verbose"
cargo test -p lib-q-prf --features alloc --verbose
echo "Running: cargo test -p lib-q-prf --features alloc --profile release-ci --verbose"
cargo test -p lib-q-prf --features alloc --profile release-ci --verbose

echo "========== CI matrix: lib-q-ring-sig (dualring-prf) =========="
echo "Running: cargo test -p lib-q-ring-sig --features dualring-prf --verbose"
cargo test -p lib-q-ring-sig --features dualring-prf --verbose
echo "Running: cargo test -p lib-q-ring-sig --features dualring-prf --profile release-ci --verbose"
cargo test -p lib-q-ring-sig --features dualring-prf --profile release-ci --verbose

echo "========== CI matrix: lib-q-lattice-zkp =========="
nuke_release_ci
cargo test -p lib-q-lattice-zkp --features alloc --verbose
nuke_release_ci
cargo test -p lib-q-lattice-zkp --features alloc --profile release-ci --verbose

echo "========== CI matrix: lib-q-ring-sig default =========="
nuke_release_ci
cargo test -p lib-q-ring-sig --verbose
nuke_release_ci
cargo test -p lib-q-ring-sig --profile release-ci --verbose

echo "========== CI matrix: lib-q privacy_protocol_integration_tests =========="
nuke_release_ci
cargo test -p lib-q --test privacy_protocol_integration_tests --verbose
nuke_release_ci
cargo test -p lib-q --test privacy_protocol_integration_tests --profile release-ci --verbose

echo "========== test-matrix: OK =========="

# --- wasm-validation (ci.yml): compile for wasm32; same RUSTFLAGS as wasm-build action ---
echo "========== wasm-validation (cargo check --lib) =========="
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
rustup target add wasm32-unknown-unknown
wasm_check() {
  local dir="$1"
  local feats="$2"
  echo ">>> wasm check in $dir features=${feats:-<none>}"
  ( cd "$dir" && if [ -n "$feats" ]; then
      cargo check --target wasm32-unknown-unknown --features "$feats" --lib
    else
      cargo check --target wasm32-unknown-unknown --lib
    fi )
}
wasm_check lib-q "wasm,all-algorithms,ml-kem"
wasm_check lib-q-kem "wasm,ml-kem"
wasm_check lib-q-core "wasm,ml-kem,rand"
wasm_check lib-q-zkp "wasm,zkp"
wasm_check lib-q-romulus ""
wasm_check lib-q-prf ""
wasm_check lib-q-lattice-zkp ""
wasm_check lib-q-ring-sig ""
wasm_check lib-q-sca-test ""
wasm_check lib-q-plonky ""
unset CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS

echo "========== wasm-workspace-gate (ci.yml) =========="
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
cargo check --workspace --exclude lib-q-examples --target wasm32-unknown-unknown
unset CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS

# --- romulus-no-std-wasm (ci.yml) ---
echo "========== romulus-no-std-wasm =========="
cargo check -p lib-q-romulus --no-default-features
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
cargo check -p lib-q-romulus --no-default-features --target wasm32-unknown-unknown
cargo check -p lib-q-aead --no-default-features --features alloc,romulus
cargo check -p lib-q-aead --no-default-features --features alloc,romulus --target wasm32-unknown-unknown
unset CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS

# --- ml-dsa-compliance (PR subset from ci.yml) ---
echo "========== ml-dsa-compliance (PR-focused) =========="
(
  cd lib-q-ml-dsa
  cargo test --features "fips-mode,acvp" --test nistkats
  cargo test --features "simd256,random,acvp" --test determinism
  cargo test --no-default-features --features "std,mldsa44" --test interoperability_tests --test wire_format_tests
  cargo test --features "random,mldsa44" --test interoperability_tests --test wire_format_tests
  cargo test --features "hardened,mldsa44" --test interoperability_tests --test wire_format_tests
  cargo test --test wire_format_tests test_against_saved_interop_vectors
)

# --- ml-kem-tests (ci.yml) ---
echo "========== ml-kem-tests =========="
( cd lib-q-ml-kem && cargo test --verbose )
( cd lib-q-ml-kem && cargo test --features "hardened,random" --lib --verbose )
( cd lib-q-core && cargo test --features "ml-kem,rand" --verbose && rm -rf target/dev-no-std && cargo build --profile dev-no-std --no-default-features --features "no_std,getrandom" )
( cd lib-q-kem && cargo test --features "ml-kem" --verbose )
( cargo test -p lib-q-sca-test --verbose )

# --- integration-tests (ci.yml) ---
echo "========== integration-tests =========="
cargo test -p lib-q --test hash_integration_tests --features "all-algorithms" --verbose
cargo test --package lib-q --features "all-algorithms" --verbose

# --- documentation (ci.yml) ---
echo "========== documentation =========="
cargo doc --all-features --no-deps
cargo doc --all-features --no-deps --document-private-items

# --- core-validation parity ---
echo "========== fmt + clippy + audit + duplicate check =========="
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo audit --deny warnings
bash "$ROOT/scripts/check-integration-test-duplicates.sh"

echo "========== FULL LOCAL CI PARITY: OK =========="
