#!/usr/bin/env bash
# Reproducible checks for CI failure triage (HQC feature graph, E0460-related builds, coverage hints).
# Run from repo root: bash scripts/verify-ci-failure-assumptions.sh
#
# Coverage workflow (verified against GitHub run 24593929379, 2026-04-18):
# - Wall time ~1h17m; failed step: "Run coverage for entire workspace" on both stable and nightly matrix legs.
# - Root symptom: cargo-tarpaulin (Linux default ptrace engine) can report Error: "Test failed during run"
#   even when libtest prints all tests passed (e.g. after fn_dsa_comm or lib_q_core). Mitigation: run with
#   `--engine llvm` (see scripts/run-coverage.sh, rust-test action, coverage.yml llvm-tools-preview).
# - If triaging an older log: the failing child may not emit a further "running …deps" line; use
#   `gh api …/jobs/<id>/logs` and search for the last test binary before the error.
# - Historically, per-crate tarpaulin sometimes passed while the final workspace-wide invocation failed;
#   LLVM engine reduces ptrace/signal false failures on the full workspace run.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== 1. lib-q-hqc feature set under lib-q --features all-algorithms =="
echo "(integration-tests / test-matrix use this; simd-avx2 is NOT enabled unless added explicitly.)"
echo ""
if ! command -v cargo >/dev/null 2>&1; then
  echo "SKIP: cargo not in PATH (use a shell where rustup/cargo is configured, e.g. CI or same terminal as rustc)."
else
  if ! OUT="$(cargo tree -p lib-q --features all-algorithms -e features -f "{p} features=[{f}]")"; then
    echo "ERROR: cargo tree failed (need Rust toolchain and valid workspace)." >&2
    exit 1
  fi
  echo "$OUT" | grep "lib-q-hqc" || true
  echo ""
  if echo "$OUT" | grep -q "lib-q-hqc.*simd-avx2"; then
    echo "UNEXPECTED: simd-avx2 appears on lib-q-hqc with only all-algorithms." >&2
    exit 1
  else
    echo "OK: no simd-avx2 on lib-q-hqc in the all-algorithms resolution."
  fi
fi
echo ""

echo "== 2. Where examples (e.g. lib-q-tweak-aead dump_tweak_kat) get compiled =="
echo "Workspace Clippy in CI uses --all-targets (builds examples/benches):"
grep -n "clippy.*all-targets" .github/workflows/ci.yml 2>/dev/null | tr -d '\r' || true
echo ""
echo "rust-test composite action (test-matrix) uses cargo test without --all-targets:"
grep -n "cargo test" .github/actions/rust-test/action.yml | tr -d '\r' | head -n 8
echo ""
echo "To correlate an E0460 line mentioning examples/dump_tweak_kat.rs with a job,"
echo "match the surrounding cargo subcommand in the log (clippy --all-targets vs cargo test)."
echo ""

echo "== 3. Coverage workflow (optional, needs gh + auth) =="
if command -v gh >/dev/null 2>&1; then
  echo "Latest Test Coverage workflow runs:"
  gh run list --workflow coverage.yml --limit 3 --json databaseId,conclusion,name,displayTitle,updatedAt \
    --jq '.[] | "\(.databaseId) \(.conclusion) \(.displayTitle) \(.updatedAt)"' 2>/dev/null || echo "(gh run list failed)"
  echo ""
  echo "To inspect a failed workspace step:"
  echo "  gh run view <run-id> --json jobs --jq '.jobs[] | {name: .name, conclusion: .conclusion, failed: [.steps[]|select(.conclusion==\"failure\")|.name]}'"
  echo "  gh api repos/<org>/<repo>/actions/jobs/<job-databaseId>/logs | less"
else
  echo "Skipping (install GitHub CLI 'gh' to list runs)."
fi

echo ""
echo "Done."
