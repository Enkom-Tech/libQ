#!/usr/bin/env bash
# Guard: a `cargo test` / `cargo nextest` step that reports 0 tests passed must FAIL the step.
#
# WHY THIS EXISTS
# ----------------
# `cargo test` exits 0 whenever the test *harness* ran cleanly, regardless of whether it executed
# zero assertions. Every one of these produces exit code 0 with "0 passed" in the summary:
#
#   * A `-- some_filter` name filter that matches nothing:
#       cargo test -q -p lib-q-fn-dsa-comm zzz_no_such_test_name
#       -> "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out"
#     (proven in this repo: test-fn-dsa/action.yml's "Memory safety validation" step filtered on
#     `-- memory_safety`, which matches neither `test_memory_optimization_security` nor
#     `test_memory_zeroization` -- 0 of 7 tests ran, every release shipped believing it had.)
#   * A whole-file `#![cfg(feature = "x")]` (or `#[cfg(test)] mod tests` under a feature) that is
#     never actually enabled by the features the CI step passes -- the file compiles to nothing,
#     "running 0 tests", same "0 passed" summary.
#   * A `--bench`/test body wrapped in a `#[cfg(...)]` that is dead for the invoked feature set.
#
# All three land on the exact same observable: exit 0, "0 passed" in the `test result:` line. One
# check on that line catches all three failure modes at once, independent of *why* nothing ran.
#
# WHAT THIS GUARD DOES
# ---------------------
# Runs the given command, streams its combined stdout+stderr live (so the CI log is unchanged),
# and afterwards:
#   1. If the command itself exited non-zero, propagates that exit code as-is -- a real failure is
#      already a failure; this guard only adds a check for the *silent* case.
#   2. Otherwise, sums the "N passed" figure across every `test result: ...` summary line cargo
#      test printed (a single invocation can cover several test binaries: lib unit tests, an
#      integration `--test` target, doctests, ...). If that total is 0, or no such summary line
#      was printed at all, the step is treated as vacuous and this script exits 1.
#   3. Best-effort: also recognises `cargo nextest`'s "Summary [...] N tests run: M passed" trailer.
#      Not exercised anywhere in this repo today (no `cargo nextest` call exists yet) -- kept
#      forward-compatible rather than proven.
#
# Pass `--allow "reason"` before `--` to accept a genuine 0-tests invocation (e.g. a crate that
# legitimately has no tests yet under some feature combination). The reason is printed so it shows
# up in the CI log and in `git blame` on the workflow file -- there is no separate allowlist file to
# fall out of sync.
#
# Usage:
#   scripts/ci-guard-no-vacuous-tests.sh [--allow "reason"] -- <command...>
#
# WHAT THIS GUARD DOES *NOT* COVER
# ---------------------------------
#   * It sums passed counts ACROSS all `test result:` lines in one invocation. A multi-binary
#     invocation where one binary is vacuous but another passes will not be flagged (not a pattern
#     this repo's guarded call sites hit -- each wraps exactly one `-p`/`--test`/`--` combination).
#   * It parses the exact libtest/nextest summary line text. A test harness that changes that
#     format, or a wrapper that reformats its output before this script sees it, is unseen.
#   * It is a runtime check, not static analysis: it proves nothing about a call site until that
#     call site actually runs in CI.

set -uo pipefail

ALLOW_REASON=""
if [[ "${1:-}" == "--allow" ]]; then
  ALLOW_REASON="${2:-}"
  if [[ -z "$ALLOW_REASON" ]]; then
    echo "ci-guard-no-vacuous-tests: --allow requires a reason string" >&2
    exit 2
  fi
  shift 2
fi

if [[ "${1:-}" != "--" ]]; then
  echo "ci-guard-no-vacuous-tests: usage: $0 [--allow \"reason\"] -- <command...>" >&2
  exit 2
fi
shift

if [[ $# -eq 0 ]]; then
  echo "ci-guard-no-vacuous-tests: no command given after --" >&2
  exit 2
fi

LOGFILE="$(mktemp)"
trap 'rm -f "$LOGFILE"' EXIT

# Stream live to the CI log via `tee` while also capturing it for parsing. `${PIPESTATUS[0]}`
# recovers the wrapped command's own exit code (the pipeline's own status would be `tee`'s).
"$@" 2>&1 | tee "$LOGFILE"
CMD_STATUS="${PIPESTATUS[0]}"

if [[ "$CMD_STATUS" -ne 0 ]]; then
  echo "ci-guard-no-vacuous-tests: wrapped command exited $CMD_STATUS -- propagating (not a vacuity check)" >&2
  exit "$CMD_STATUS"
fi

# libtest: "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ..."
# Truncate each matching line at "<N> passed" and pull the number out of that -- the only digits
# left are the passed count, so this needs no capture-group support (portable to plain grep -E).
libtest_lines="$(grep -cE '^test result: ' "$LOGFILE" || true)"
libtest_passed_list="$(grep -oE '^test result: [A-Za-z]+\. [0-9]+ passed' "$LOGFILE" | grep -oE '[0-9]+' || true)"

# nextest (best-effort, unexercised in this repo): "Summary [   0.083s] 7 tests run: 7 passed, ..."
nextest_lines="$(grep -cE 'tests? run: [0-9]+ passed' "$LOGFILE" || true)"
nextest_passed_list="$(grep -oE 'tests? run: [0-9]+ passed' "$LOGFILE" | grep -oE '[0-9]+' || true)"

total_passed=0
summary_lines=$((libtest_lines + nextest_lines))
for n in $libtest_passed_list $nextest_passed_list; do
  total_passed=$((total_passed + n))
done

if [[ -n "$ALLOW_REASON" ]]; then
  echo "ci-guard-no-vacuous-tests: vacuity check skipped (--allow: $ALLOW_REASON); summary_lines=$summary_lines total_passed=$total_passed" >&2
  exit 0
fi

if [[ "$summary_lines" -eq 0 ]]; then
  echo "ci-guard-no-vacuous-tests: FAIL -- command exited 0 but printed no 'test result:' (or nextest summary) line at all; cannot confirm any test ran. If this is expected, rerun with --allow \"reason\"." >&2
  exit 1
fi

if [[ "$total_passed" -eq 0 ]]; then
  echo "ci-guard-no-vacuous-tests: FAIL -- command exited 0 but 0 tests passed across $summary_lines summary line(s) (dead name filter, a feature-gated file that compiled to nothing, or similar). If this is expected, rerun with --allow \"reason\"." >&2
  exit 1
fi

echo "ci-guard-no-vacuous-tests: OK -- $total_passed test(s) passed across $summary_lines summary line(s)" >&2
exit 0
