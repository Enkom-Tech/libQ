#!/usr/bin/env bash
# Guard: no tracked `.rs` file may gate an item behind `#[cfg(any())]` / `#![cfg(any())]` without
# a KNOWN-DEBT allowlist entry.
#
# WHY THIS EXISTS
# ----------------
# `any()` with zero arguments is never true -- `cfg(any())` is the "always-disabled" idiom, most
# often reached for as a quick way to comment out a test module without deleting it. The item it
# guards still parses (so the surrounding file stays valid Rust) but never compiles into any
# build, in any configuration, ever -- unlike a normal `#[cfg(feature = "x")]` gate, there is no
# feature flag that re-enables it.
#
# This is the same defect class the runtime vacuity guard (ci-guard-no-vacuous-tests.sh) and
# ci-guard-vacuous-test-shapes.sh cover in CI *workflow* YAML, but neither of those looks inside
# Rust source: a `cargo test -p <crate>` step that runs cleanly and reports "N passed" looks
# completely healthy even when an entire `mod tests { ... }` block never got compiled into that
# N. OBSERVED 2026-08: nine files across four published STARK crates carry this shape --
# lib-q-stark-dft/src/{naive.rs,util.rs}, lib-q-stark-interpolation/src/lib.rs,
# lib-q-stark-matrix/src/{dense.rs,extension.rs,lib.rs,row_index_mapped.rs},
# lib-q-stark-mds/src/{coset_mds.rs,integrated_coset_mds.rs} -- and `cargo test -p <crate>`
# reports **literally 0 executed tests** for two of those four crates (lib-q-stark-dft,
# lib-q-stark-interpolation), both of which are published to crates.io.
#
# WHAT THIS GUARD DOES
# ---------------------
# Every file matched by `git ls-files '*.rs'` is scanned (whitespace-normalized) for
# `cfg(any())` / `cfg (any ())` etc. A match in a file NOT on the KNOWN_DEBT allowlist below is a
# hard failure. This is DEBT ACCEPTANCE, not approval: the allowlist exists so the nine files
# already in this state do not retroactively block CI the day this guard lands, but it may only
# SHRINK -- adding a new file to it requires a card, the same discipline
# ci-guard-no-disabled-test-modules's sibling guards use for their own escape hatches.
#
# WHAT THIS GUARD DOES NOT COVER
# --------------------------------
#   * It is a textual grep for one specific idiom (`cfg(any())`). A functionally-equivalent
#     always-false gate spelled a different way (e.g. a custom `cfg(feature = "never-enabled")`
#     that genuinely no Cargo.toml ever defines) is invisible to this guard -- that is a
#     different, harder-to-detect shape and not what this guard claims to catch.
#   * It does not itself prove the STARK crates' zero-executed-test state is fixed -- fixing
#     lib-q-stark-dft / lib-q-stark-interpolation (both published, both currently at 0 executed
#     tests) is out of scope for the guard itself; see the allowlist comment below for the
#     tracking status.
#   * A file that legitimately needs an always-false cfg for some other reason (not observed in
#     this repo today) would need an allowlist entry too -- this guard cannot distinguish "a test
#     module someone commented out" from any other use of the same syntax.
#
# Usage: bash scripts/ci-guard-no-disabled-test-modules.sh [REPO_ROOT]

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

# KNOWN-DEBT allowlist (may only shrink; growing it requires a card). Every entry here compiles
# to literally nothing in any configuration -- `lib-q-stark-dft` and `lib-q-stark-interpolation`
# currently run 0 tests total (`cargo test -q -p <crate>` -> 0 passed, both crates, OBSERVED
# 2026-08), and both are published to crates.io.
KNOWN_DEBT=(
  "lib-q-stark-dft/src/naive.rs"
  "lib-q-stark-dft/src/util.rs"
  "lib-q-stark-interpolation/src/lib.rs"
  "lib-q-stark-matrix/src/dense.rs"
  "lib-q-stark-matrix/src/extension.rs"
  "lib-q-stark-matrix/src/lib.rs"
  "lib-q-stark-matrix/src/row_index_mapped.rs"
  "lib-q-stark-mds/src/coset_mds.rs"
  "lib-q-stark-mds/src/integrated_coset_mds.rs"
)

is_known_debt() {
  local f="$1"
  for entry in "${KNOWN_DEBT[@]}"; do
    [[ "$f" == "$entry" ]] && return 0
  done
  return 1
}

# Whitespace-normalized match: `cfg(any())`, `cfg( any() )`, `cfg (any ())`, etc. all reduce to
# the same check. `git grep -P` needs a UTF-8 locale on some runners (same trap
# ci-guard-standards-claims.sh documents); force it here too.
export LC_ALL=C.UTF-8

findings=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  if is_known_debt "$file"; then
    continue
  fi
  echo "$line"
  findings=$((findings + 1))
done < <(git grep -nP '#!?\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]' -- '*.rs' || true)

if [[ "$findings" -gt 0 ]]; then
  echo "ci-guard-no-disabled-test-modules: FAIL -- $findings new #[cfg(any())] disabled item(s) found outside the KNOWN_DEBT allowlist" >&2
  exit 1
fi
echo "ci-guard-no-disabled-test-modules: OK -- no #[cfg(any())] disabled items outside the KNOWN_DEBT allowlist"
