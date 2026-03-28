#!/usr/bin/env bash
# Local mirror of GitHub CI for WSL/Linux (run from repo root).
#
# Usage:
#   ./scripts/simulate-ci-wsl.sh           # default: pr (fast PR-style gate)
#   ./scripts/simulate-ci-wsl.sh pr        # same: audit, fmt, clippy, lib-q tests + wasm check
#   ./scripts/simulate-ci-wsl.sh full      # full matrix + builds (~matches push CI test matrix)
#   ./scripts/simulate-ci-wsl.sh mirror    # deep checks: SLH-12-param, ZKP recursive, docs, integration
#
# Prefer a clone on the WSL native filesystem (e.g. ~/libQ) for speed; /mnt/c/... is much slower.
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

run_pr_gate() {
  echo "== simulate-ci-wsl: PR-style gate (fmt, clippy, audit, smoke tests) =="

  if command -v cargo-audit >/dev/null 2>&1; then
    cargo install cargo-audit --locked 2>/dev/null || true
    cargo audit --deny warnings
  else
    echo "cargo-audit not installed; skip audit (install: cargo install cargo-audit --locked)"
  fi

  cargo fmt --all -- --check

  # Matches merged CI: workspace clippy with all features (one compile, all optional code paths).
  cargo clippy --all-targets --all-features -- -D warnings

  # Core library smoke (same feature set as rust-build in CI).
  cargo test -p lib-q --features "all-algorithms" --verbose

  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'
  rustup target add wasm32-unknown-unknown 2>/dev/null || true
  echo "== WASM compile smoke (cargo check, root crate) =="
  cargo check --target wasm32-unknown-unknown --features "wasm,all-algorithms,ml-kem" --lib

  echo "== simulate-ci-wsl pr: OK =="
}

mode="${1:-pr}"
case "$mode" in
  pr | quick)
    run_pr_gate
    ;;
  full)
    exec "$ROOT/scripts/wsl-build-and-test.sh"
    ;;
  mirror)
    exec "$ROOT/scripts/ci-wsl-mirror.sh"
    ;;
  help | -h | --help)
    head -n 18 "$0"
    exit 0
    ;;
  *)
    echo "Unknown mode: $mode (use pr, full, mirror, or help)" >&2
    exit 2
    ;;
esac
