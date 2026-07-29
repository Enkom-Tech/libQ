#!/usr/bin/env bash
# Guard: the coverage gate must measure what it claims to measure.
#
# WHY THIS EXISTS
# ---------------
# A coverage percentage is a fraction. Both halves can be quietly corrupted, and when they are
# the gate keeps going green/red for reasons that have nothing to do with the code:
#
#   * NUMERATOR   -- a test-NAME filter appended after libtest's `--` separator shrinks the set
#                    of tests that runs, while --include-files (the denominator) stays put.
#                    lib-q-fn-dsa carried `-- keypair_generation test_basic_fn_dsa_functionality
#                    sign_and_verify seeded_sign`, which ran 6 of the crate's 34 tests and scored
#                    69/161 = 42.86% against a 68% floor. Removing the filter: 129/161 = 80.12%.
#                    The crate never changed. Only the filter did.
#   * SELECTION   -- a package silently routed to the "skip coverage" branch is never measured at
#                    all. `*"lib-q-keccak"*` is a substring pattern, so it also swallowed the
#                    unrelated sibling crate lib-q-keccak-digest.
#   * DENOMINATOR -- --include-files scoped to `<crate>/src/**` misses source that lives in a
#                    NESTED cargo package under that crate. lib-q-fn-dsa/src/lib.rs is 834 lines;
#                    lib-q-fn-dsa/fn-dsa-*/src is ~37k lines and is not in the denominator. The
#                    two-month FN-DSA portable-keygen livelock lived in that excluded tree.
#                    The same half can also be narrowed head-on, by pointing --include-files at a
#                    single file or by adding an --exclude-files for source that merely lacks
#                    tests. Both raise the percentage without a line of new test code.
#
# Each check below corresponds to one of those failure modes, and to a defect that was actually
# found in this repository. Every check fails CLOSED: if it cannot locate what it is supposed to
# inspect, it errors rather than silently passing.
#
# WHAT THIS GUARD DOES *NOT* COVER
# --------------------------------
# Stated so the next reader does not mistake a green run for a proof of correctness:
#
#   * It is STATIC. It reads the command lines CI would build; it never runs tarpaulin and cannot
#     tell you that a percentage is right -- only that the fraction was not rescoped behind your
#     back.
#   * CHECK 1 reaches command text by tainting variables that flow into a `cargo tarpaulin`
#     invocation *within one file*. A command assembled across two files (a helper that echoes a
#     filter which the caller interpolates) is not modelled.
#   * CHECK 4 only requires an allowlist entry for an --exclude-files that reaches inside a
#     workspace member's own `src/`. A coarse `<crate>/*` exclusion -- the idiom lib-q-core uses to
#     keep sibling-crate lines out of its Cobertura -- is NOT allowlisted, because 15 entries whose
#     only failure mode is excluding the crate you are measuring is friction that buys little. If
#     you ever see a `<crate>/*` exclusion naming the crate under `--packages`, that is the gap.
#   * Discovery is by file suffix (.sh/.ps1/.yml/...) plus the literal string "tarpaulin". A
#     tarpaulin command reached through a wrapper that never spells the tool's name is unseen.
#
# Usage: bash scripts/ci-guard-coverage-honesty.sh [REPO_ROOT]

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute.
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-coverage-honesty: a working python3 interpreter is required" >&2
  exit 1
fi

"$PY_BIN" scripts/ci_guard_coverage_honesty.py "$ROOT"
