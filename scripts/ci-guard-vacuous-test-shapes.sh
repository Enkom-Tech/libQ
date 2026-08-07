#!/usr/bin/env bash
# Guard: a NEW `cargo test`/`bench`/`build`/`check`/`run` call site in .github/**/*.yml may not
# land in one of the three shapes proven in this repository to make a CI step report green
# without doing what its name claims.
#
# WHY THIS EXISTS
# ----------------
# `scripts/ci-guard-no-vacuous-tests.sh` (already wired at several call sites) catches this
# CLASS at RUN time: it fails a step whose wrapped command exits 0 but reports 0 tests passed.
# That is necessary but not sufficient on its own -- every one of the incidents below shipped
# green for months because nothing forced the *next* call site to be wrapped:
#
#   * t_9f13e8e5 -- lib-q-hpke's constant-time / RFC-9180 / security-validation / mode-test CI
#     steps compiled six `#![cfg(feature = "std")]`-gated test files to empty binaries because
#     the CI matrix omitted `std`; each reported "0 passed" and exit 0.
#   * t_9d1766f3 / test-fn-dsa's old "Memory safety validation" step filtered on `-- memory_safety`,
#     which matched none of the crate's real test names -- 0 of 7 tests ran.
#   * test-k12/action.yml carried FOUR dead name filters (`test_k12_implementations` and
#     `test_create_hash_by_name` exist nowhere in this repository; `test_length_encode` exists in
#     a different crate than the one the step ran in) plus TWO `cargo test ... | grep ... ||
#     true` pipelines, where the pipe hides the summary line from any guard and `|| true` masks a
#     real cargo failure outright.
#
# See scripts/ci_guard_vacuous_test_shapes.py for the three rules (R1 piped output, R2 unguarded
# name filter, R3 `|| true`/`|| echo` masking a cargo command) and this guard's own documented
# scanning limits (it only reads `run:` block-scalar shell steps, not the whole YAML file, so
# prose in `description:` fields that happens to mention "cargo test" is never scanned as if it
# were shell).
#
# A call site guarded at run time by `ci-guard-no-vacuous-tests.sh` ($GUARD) is exempted from R2
# (a dead filter there becomes a hard CI failure the day it goes dead, which is the point) but
# NOT from R1/R3 (piping the guarded command's output, or `|| true`-ing it, still defeats the
# runtime check). An inline `# vacuity-ok: <reason>` comment exempts a line from every rule,
# mirroring the runtime guard's `--allow "reason"` (shows up in `git blame`, no separate
# allowlist file to fall out of sync).
#
# Usage: bash scripts/ci-guard-vacuous-test-shapes.sh [REPO_ROOT]

set -euo pipefail

# The python implementation lives next to THIS script, which is not necessarily inside the tree
# being scanned: the documented `[REPO_ROOT]` argument exists precisely so a reviewer can point
# the guard at a synthetic fixture tree elsewhere on disk and watch it fail. Resolving the
# implementation relative to $ROOT (after `cd`) broke exactly that use -- it died with python's
# "can't open file" and exit 2 for any ROOT that is not this repo. Resolve from BASH_SOURCE, the
# convention every other multi-file script in scripts/ already uses.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same trap ci-guard-coverage-honesty.sh and
# ci-guard-kat-provenance.sh work around).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-vacuous-test-shapes: a working python3 interpreter is required" >&2
  exit 1
fi

"$PY_BIN" "$SCRIPT_DIR/ci_guard_vacuous_test_shapes.py" "$ROOT"
