#!/usr/bin/env bash
# Build libq in WSL and run all tests (CI-parity script).
# Usage: from repo root: ./scripts/wsl-build-and-test.sh
# Or: bash scripts/wsl-build-and-test.sh
# Prerequisites: rustup (cargo), jq. Optional: cargo-audit.

set -euo pipefail

# Ensure cargo is on PATH (e.g. when WSL shell has not sourced ~/.cargo/env)
if [[ -f "${HOME:-}/.cargo/env" ]]; then
  set +u
  source "${HOME:-}/.cargo/env"
  set -u
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

run() {
  echo "==> $*"
  "$@"
}

run_or_fail() {
  echo "==> $*"
  if ! "$@"; then
    echo "FAILED: $*"
    exit 1
  fi
}

# --- Prereq checks ---
echo "Checking prerequisites..."
command -v cargo >/dev/null 2>&1 || { echo "cargo not found. Install rustup and ensure cargo is on PATH."; exit 1; }
# jq is optional; we use a fixed package list for no-default-features build when jq is missing
HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1
[[ "$HAVE_JQ" -eq 0 ]] && echo "jq not found; using fixed package list for no-default-features build."
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit not found. Install with: cargo install cargo-audit"
  echo "Skipping security audit step."
  SKIP_AUDIT=1
else
  SKIP_AUDIT=0
fi

# --- Format ---
run_or_fail cargo fmt --all -- --check

# --- Security audit ---
if [[ "$SKIP_AUDIT" -eq 0 ]]; then
  run_or_fail cargo audit --deny warnings
else
  run cargo audit --deny warnings || true
fi

# --- Clippy ---
run_or_fail cargo clippy --all-targets --all-features -- -D warnings

# --- Build with no default features (workspace at .) ---
echo "Building with no default features..."
if [[ "$HAVE_JQ" -eq 1 ]]; then
  NO_DF_PKGS=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name' | grep -E '^(lib-q-core|lib-q-kem|lib-q-ml-kem)$' || true)
else
  NO_DF_PKGS="lib-q-core lib-q-kem lib-q-ml-kem"
fi
for pkg in $NO_DF_PKGS; do
  echo "Building $pkg with no default features..."
  cargo build -p "$pkg" --no-default-features || echo "Package $pkg failed with no default features - expected"
done
echo "Building lib-q-keccak (no_std)..."
rm -rf target/dev-no-std
run_or_fail cargo build -p lib-q-keccak --profile dev-no-std --no-default-features --features "alloc,no_std_panic_handler"

# --- Build with features ---
run_or_fail cargo build --features "all-algorithms"

# --- Build all features ---
run_or_fail cargo build --all-features

# --- Test matrix (debug + release); no_std / lib-q-keccak use cargo check ---
run_test_or_check() {
  local features="$1"
  local package="$2"
  local use_check=0
  if [[ "$features" == *"no_std"* ]] || [[ "$package" == "lib-q-keccak" ]]; then
    use_check=1
  fi

  if [[ "$use_check" -eq 1 ]]; then
    if [[ -n "$package" ]]; then
      if [[ "$package" == "lib-q-keccak" ]]; then
        run_or_fail cargo check -p "$package" --profile dev-no-std --no-default-features --features "${features},no_std_panic_handler" --verbose
        run_or_fail cargo check -p "$package" --profile release --no-default-features --features "${features},no_std_panic_handler" --verbose
      elif [[ "$package" == "lib-q-core" ]]; then
        run_or_fail cargo check -p "$package" --profile dev-no-std --no-default-features --features "${features},no_std_panic_handler" --verbose
        run_or_fail cargo check -p "$package" --profile release-security --no-default-features --features "${features},no_std_panic_handler" --verbose
      else
        run_or_fail cargo check -p "$package" --profile dev-no-std --no-default-features --features "$features" --verbose
        run_or_fail cargo check -p "$package" --profile release-security --no-default-features --features "$features" --verbose
      fi
    else
      run_or_fail cargo check --profile dev-no-std --no-default-features --features "$features" --verbose
      run_or_fail cargo check --profile release-security --no-default-features --features "$features" --verbose
    fi
  else
    if [[ -n "$package" ]]; then
      run_or_fail cargo test -p "$package" --features "$features" --verbose
      run_or_fail cargo test -p "$package" --features "$features" --release --verbose
    else
      run_or_fail cargo test --features "$features" --verbose
      run_or_fail cargo test --features "$features" --release --verbose
    fi
  fi
}

echo "Running test matrix (CI feature/package combinations)..."
# name, features, package
run_test_or_check "std" ""
run_test_or_check "std,all-algorithms" ""
run_test_or_check "std,ml-kem,rand" ""
run_test_or_check "no_std,getrandom" "lib-q-core"
run_test_or_check "std,wasm" ""
run_test_or_check "std,zkp" ""
run_test_or_check "ml-kem" "lib-q-kem"
run_test_or_check "std" "lib-q-ml-kem"
run_test_or_check "std,fips-mode,mldsa44,mldsa65,mldsa87,acvp" "lib-q-ml-dsa"
run_test_or_check "std,hardened,mldsa44,mldsa65,mldsa87" "lib-q-ml-dsa"
run_test_or_check "std,random,acvp,mldsa44,mldsa65,mldsa87" "lib-q-ml-dsa"
run_test_or_check "alloc" "lib-q-keccak"
run_test_or_check "std,secure,zeroize" "lib-q-random"
run_test_or_check "no_std,getrandom" "lib-q-random"
run_test_or_check "wasm" "lib-q-random"
run_test_or_check "parallel" "lib-q-stark-rayon"
run_test_or_check "alloc" "lib-q-stark-dft"
run_test_or_check "alloc,parallel" "lib-q-stark-dft"
run_test_or_check "alloc" "lib-q-ring"
run_test_or_check "alloc" "lib-q-lattice-zkp"

echo "All steps completed successfully."
