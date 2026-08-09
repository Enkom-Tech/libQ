#!/usr/bin/env bash
# Guard: a `#[test]` fn with no failure mechanism (assert/panic/unwrap/expect/`?`/should_panic)
# reports "ok" no matter what it computes. See scripts/ci_guard_no_assert_tests.py for the full
# rationale (card t_f0d676d1) and the incident that motivated it: all three #[test] fns in
# lib-q-hqc/tests/kat_with_aes_drbg_test.rs could not fail, and one was a KEM round-trip that
# printed a cross mark on mismatch instead of asserting -- fixed at 766cb0c.
#
# Usage:
#   bash scripts/ci-guard-no-assert-tests.sh [REPO_ROOT]
#   bash scripts/ci-guard-no-assert-tests.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  ROOT_ARG="--self-test"
else
  ROOT_ARG="${1:-$(git rev-parse --show-toplevel)}"
fi

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same trap several sibling guards work around;
# `python`, not `python3`, is the one that actually runs on this box).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-no-assert-tests: a working python3 interpreter is required" >&2
  exit 1
fi

"$PY_BIN" "$SCRIPT_DIR/ci_guard_no_assert_tests.py" "$ROOT_ARG"
