#!/usr/bin/env bash
# Guard: no tracked Rust source may gate an item on a Cargo feature its own crate does not define.
#
# WHY THIS EXISTS
# ----------------
# `#[cfg(feature = "X")]` where the crate's manifest never defines `X` is ALWAYS FALSE. Whatever
# it guards compiles to nothing in every configuration, in every feature combination, forever --
# exactly like `#[cfg(any())]`, but without looking like a disabled item to a reader or to grep.
#
# This is the blind spot `scripts/ci-guard-no-disabled-test-modules.sh` names in its own
# "WHAT THIS GUARD DOES NOT COVER" section, verbatim:
#
#     "A functionally-equivalent always-false gate spelled a different way (e.g. a custom
#      cfg(feature = "never-enabled") that genuinely no Cargo.toml ever defines) is invisible to
#      this guard -- that is a different, harder-to-detect shape and not what this guard claims
#      to catch."
#
# It is the same family as the two vacuity guards, one level further in: `ci-guard-no-vacuous-
# tests.sh` catches "the step ran but 0 tests executed" at run time, `ci-guard-vacuous-test-
# shapes.sh` catches a CI call site that cannot fail, `ci-guard-no-disabled-test-modules.sh`
# catches `cfg(any())` in source -- and this one catches the always-false gate that none of them
# can see, because a crate with a dead gate still compiles clean and still reports "N passed".
#
# WHAT IT SCANS
# --------------
# Every crate whose `Cargo.toml` is TRACKED BY GIT and not under `reference/` (vendored upstream
# copies -- blake2 and libcrux, which are not workspace members and whose nightly `simd` gates
# this repo can neither fix nor should block on). Within each: `src/`, `tests/`, `benches/`,
# `examples/` and `build.rs`. Tracked-only is what keeps a developer's git-ignored `scratchpad/`
# and the build `target/` out of scope.
#
# It recognises the attribute (`#[cfg(`), the inner attribute (`#![cfg(`), the macro (`cfg!(`)
# and `cfg_attr` -- across line breaks, since the condition of a multi-line attribute is one
# parenthesis group, not one line.
#
# THIS GUARD HAS BEEN SEEN TO FAIL
# ---------------------------------
# Landing it green would prove nothing (see the card contract's register rule: "a check you have
# not seen fail is not evidence"). It was developed against an adversarial fixture carrying seven
# planted always-false gates -- multi-line attribute, `cfg!` macro, nested `all(unix, feature=)`,
# an optional dependency suppressed by `dep:` syntax, a gate under `tests/`, one in `build.rs`,
# and a crate outside the `lib-q-*` naming convention -- alongside controls that must NOT trip
# (`target_feature`, a real feature, an implicit optional-dep feature, and the exemption comment).
# OBSERVED: the guard reports all 7 and none of the controls. Two of the seven -- both `cfg!`
# macro spellings -- passed clean on the first implementation and were the reason the token regex
# gained its `!?`; the fixture is what caught that, not review.
#
# Reproduce with any tree of your own:  bash scripts/ci-guard-nonexistent-feature-gates.sh /path/to/fixture
#
# SCOPE CORRECTION THIS REPLACES
# -------------------------------
# The scratch probe this grew from globbed `lib-q-*/Cargo.toml` and read only `src/`. OBSERVED
# 2026-08-08: that reached 70 of the 79 workspace members, silently skipping `lib-q` itself (the
# primary published facade crate), the five nested `lib-q-fn-dsa/*` crates, `lib-q-hqc/traits`
# and both `examples/` crates. This guard reaches 79 of 79 (measured against `cargo metadata
# --no-deps`), plus 11 tracked non-member crates.
#
# WHAT IT DOES NOT COVER
# -----------------------
#   * A feature name assembled by a macro rather than written as a string literal.
#   * `cfg_attr`'s second argument (the attribute, not the condition) is deliberately not scanned.
#   * A feature that is DEFINED but unreachable -- no dependency path can ever turn it on -- is a
#     harder question this guard does not attempt. It answers only "is it defined at all".
#
# Escape hatch: an inline `// feature-gate-ok: <reason>` on any line the cfg group spans. It shows
# up in `git blame`, unlike a separate allowlist file that drifts from the tree.
#
# Static and stdlib-only: a `git ls-files`, a repo walk and a TOML read per crate. No cargo, no
# build, no network. ~1.5s measured on this tree (90 crates, 1236 files).
#
# Usage: bash scripts/ci-guard-nonexistent-feature-gates.sh [REPO_ROOT]

set -euo pipefail

# The python implementation lives next to THIS script, which is not necessarily inside the tree
# being scanned: the documented `[REPO_ROOT]` argument exists precisely so a reviewer can point
# the guard at a synthetic fixture tree elsewhere on disk and watch it fail. Resolve from
# BASH_SOURCE, the convention every other multi-file script in scripts/ already uses.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(git rev-parse --show-toplevel)}"

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same trap ci-guard-coverage-honesty.sh,
# ci-guard-kat-provenance.sh and ci-guard-vacuous-test-shapes.sh work around).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-nonexistent-feature-gates: a working python3 interpreter is required" >&2
  exit 1
fi

# Re-prove that this guard can fail, BEFORE trusting the clean result of the real scan below.
# scripts/fixtures/nonexistent-feature-gates/ carries eight planted always-false gates and a set
# of controls that must not trip; every one of them is load-bearing against a specific mutation
# of the guard (the table in that fixture's README records which). Skipped when the fixture is
# absent, which is the case only if someone points $ROOT at a foreign tree AND the scripts
# directory travelled without it.
if [[ -d "$SCRIPT_DIR/fixtures/nonexistent-feature-gates" ]]; then
  "$PY_BIN" "$SCRIPT_DIR/ci_guard_nonexistent_feature_gates.py" --self-test
fi

"$PY_BIN" "$SCRIPT_DIR/ci_guard_nonexistent_feature_gates.py" "$ROOT"
