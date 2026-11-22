#!/usr/bin/env bash
# Guard: no production build of lib-q-hpke (or of lib-q with the hpke feature) may expose a
# deterministic test RNG.
#
# WHY THIS EXISTS
# ================
# `lib-q-hpke::security::test_rng::TestRng` is a fixed-seed (12345) deterministic RNG that
# implements the real `CryptoRng` trait consumed by `HpkeContext::set_rng`. It used to be gated
# `#[cfg(any(test, feature = "std"))]`. `std` is an ordinary PRODUCTION feature -- lib-q's own
# `hpke` feature turns it on (`hpke = ["dep:lib-q-hpke", "lib-q-hpke/std"]`) with no `cfg(test)`
# anywhere in the chain -- so a plain `cargo build -p lib-q --features hpke` (no test harness
# involved at all) compiled `TestRng` in as a `pub`, globally-exported type. Confirmed by symbol
# inspection before the fix: `nm target/debug/liblib_q_hpke.rlib` showed 6 `TestRng` symbols
# (`new`, `with_seed`, `Default::default`, and the three `CryptoRng` trait methods) when built
# with `--features std,alloc,ml-kem,saturnin,shake256,hash,secure-rng` and no `cfg(test)`. Same
# defect class as the previously-removed `SimpleRng` (see lib-q-hpke/src/security/prng.rs).
#
# The fix moves the gate to a dedicated, non-default `test-utils` feature that is NOT implied by
# `std` or by any other production feature, and that lib-q-hpke enables for its own tests only via
# a self-referencing `[dev-dependencies]` entry (`[dev-dependencies]` is never consulted by
# `cargo build`/`cargo build --release`).
#
# WHAT IT CHECKS
# ===============
# Builds lib-q-hpke with (a) bare default features and (b) the exact `std`-enabled feature set
# lib-q's production `hpke` feature turns on, neither of which may ever enable `test-utils`, then
# a direct build of lib-q itself with `--features hpke` (the real downstream production path).
# Each build's compiled `.rlib` SYMBOL TABLE (via `nm`, not the whole binary) is scanned for any
# defined `TestRng`/`SimpleRng` symbol. Zero matches in all three is the only pass.
#
# Deliberately `nm`-based rather than a whole-file `strings`/`grep`: a doc comment mentioning
# "`crate::security::test_rng::TestRng`" (the `set_rng` doc warning telling callers not to use it
# in production) is embedded in the crate's metadata/debug info regardless of whether the
# `test_rng` module itself compiled, and a whole-file text scan flags that mention as a false
# positive. The symbol table only contains a `TestRng`-named entry when the type's code actually
# got compiled in.
#
# WHAT IT DELIBERATELY DOES NOT DO
# =================================
# It does not attempt to enumerate every possible deterministic-RNG type name that could be added
# in the future -- it is a regression guard for this specific, previously-shipped defect (and its
# `SimpleRng` predecessor), not a general static analyzer. If a new deterministic RNG type is
# added under a different name, extend the `NAMES` list below.
#
# Usage:
#   bash scripts/ci-guard-no-test-rng-in-release.sh
#   bash scripts/ci-guard-no-test-rng-in-release.sh --self-test
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

# Deterministic RNG type names that must never appear in a production artifact's symbol table.
NAMES=("TestRng" "SimpleRng")

NM_BIN="${NM_BIN:-nm}"
if ! command -v "$NM_BIN" >/dev/null 2>&1; then
  echo "ci-guard-no-test-rng-in-release: '$NM_BIN' not found on PATH" >&2
  exit 1
fi

# check_no_symbol <label> <rlib-path> -> prints OK/FAIL, returns 0/1
check_no_symbol() {
  local label="$1" artifact="$2"
  if [[ ! -f "$artifact" ]]; then
    echo "ci-guard-no-test-rng-in-release: FAIL ($label) -- expected build artifact not found: $artifact" >&2
    return 1
  fi
  local name hits total=0
  local table
  table="$("$NM_BIN" "$artifact" 2>/dev/null || true)"
  for name in "${NAMES[@]}"; do
    hits="$(printf '%s\n' "$table" | grep -c "$name" || true)"
    if [[ "$hits" -ne 0 ]]; then
      echo "ci-guard-no-test-rng-in-release: FAIL ($label) -- $hits symbol(s) referencing '$name' in $artifact" >&2
      printf '%s\n' "$table" | grep "$name" | head -5 >&2 || true
      total=$((total + hits))
    fi
  done
  if [[ "$total" -ne 0 ]]; then
    return 1
  fi
  echo "ci-guard-no-test-rng-in-release: OK ($label) -- 0 deterministic-RNG symbols in $artifact"
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"

  cat >"$tmp/clean.rs" <<'RUST'
pub struct RealRng;
impl RealRng {
    pub fn new() -> Self { RealRng }
    pub fn fill(&self, dest: &mut [u8]) { for b in dest { *b = 0; } }
}
RUST

  cat >"$tmp/dirty.rs" <<'RUST'
pub struct TestRng { seed: u64 }
impl TestRng {
    pub fn new() -> Self { TestRng { seed: 12345 } }
    pub fn fill(&self, dest: &mut [u8]) { for b in dest { *b = self.seed as u8; } }
}
RUST

  if ! rustc --crate-type lib --edition 2021 -o "$tmp/clean.rlib" "$tmp/clean.rs" >/dev/null 2>"$tmp/clean.err"; then
    echo "ci-guard-no-test-rng-in-release: self-test setup FAILED -- could not compile clean fixture:" >&2
    cat "$tmp/clean.err" >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! rustc --crate-type lib --edition 2021 -o "$tmp/dirty.rlib" "$tmp/dirty.rs" >/dev/null 2>"$tmp/dirty.err"; then
    echo "ci-guard-no-test-rng-in-release: self-test setup FAILED -- could not compile dirty fixture:" >&2
    cat "$tmp/dirty.err" >&2
    rm -rf "$tmp"
    return 1
  fi

  local ok=0
  if ! check_no_symbol "self-test clean (RealRng only)" "$tmp/clean.rlib" >/dev/null 2>&1; then
    echo "ci-guard-no-test-rng-in-release: self-test FAILED -- a clean rlib with no TestRng/SimpleRng symbol was flagged" >&2
    ok=1
  fi
  if check_no_symbol "self-test dirty (TestRng)" "$tmp/dirty.rlib" >/dev/null 2>&1; then
    echo "ci-guard-no-test-rng-in-release: self-test FAILED -- a dirty rlib containing a real TestRng symbol was NOT flagged" >&2
    ok=1
  fi
  if check_no_symbol "self-test missing" "$tmp/does-not-exist.rlib" >/dev/null 2>&1; then
    echo "ci-guard-no-test-rng-in-release: self-test FAILED -- a missing artifact was not flagged" >&2
    ok=1
  fi

  rm -rf "$tmp"
  return "$ok"
}

if [[ "${1:-}" == "--self-test" ]]; then
  if self_test; then
    echo "ci-guard-no-test-rng-in-release: self-test OK"
    exit 0
  else
    exit 1
  fi
fi

# Re-prove detection before trusting a clean result on real builds below.
if ! self_test; then
  exit 1
fi

FAIL=0

echo "ci-guard-no-test-rng-in-release: building lib-q-hpke with bare default features..."
(cd lib-q-hpke && cargo build --lib --quiet)
check_no_symbol "lib-q-hpke, default features" "target/debug/liblib_q_hpke.rlib" || FAIL=1

echo "ci-guard-no-test-rng-in-release: building lib-q-hpke with std and no test-utils (the set lib-q's production 'hpke' feature turns on)..."
(cd lib-q-hpke && cargo build --lib --quiet --no-default-features --features "std,alloc,ml-kem,saturnin,shake256,hash,secure-rng")
check_no_symbol "lib-q-hpke, std (no test-utils)" "target/debug/liblib_q_hpke.rlib" || FAIL=1

echo "ci-guard-no-test-rng-in-release: building lib-q with --features hpke (the real downstream production path)..."
(cd lib-q && cargo build --lib --quiet --features hpke)
LIBQ_RLIB="$(find target/debug -maxdepth 1 -iname 'liblibq*.rlib' | head -1)"
check_no_symbol "lib-q, --features hpke" "${LIBQ_RLIB:-target/debug/liblibq.rlib}" || FAIL=1

if [[ $FAIL -ne 0 ]]; then
  echo "ci-guard-no-test-rng-in-release: FAIL -- a production build exposed a deterministic RNG type" >&2
  exit 1
fi

echo "ci-guard-no-test-rng-in-release: OK -- no deterministic RNG type in any production build checked"
