#!/usr/bin/env bash
# Guard: every committed KAT (Known-Answer-Test) vector file must disclose where it came from.
#
# WHY THIS EXISTS
# ---------------
# lib-q-hqc shipped a KAT tree at `kats/official/` whose every `.rsp` response value was written
# by the code under test (`write_official_rsp_file`, fed from NIST's `.req` seed chain via
# `nist_kem_kat.rs`) -- so the module doc's "byte-exact vs authoritative `.rsp` vectors" was
# byte-exact against itself. Nine KAT tests, CI-gated, permanently green, proved only that the
# crate agreed with a prior run of the same crate (card t_71d4f79a). The same failure shape is
# live elsewhere in this tree: `reference/classic-mceliece`'s own `test_katkem.rs::katkem()`
# dispatches on `env::args().len()`, and its no-args arm literally contains
# `// assert!(false); comment out temporary` -- a plain `cargo test` passes it doing nothing.
#
# This guard does not decide whether any given vector file's origin claim is TRUE -- it cannot,
# it has no external ground truth to check against. What it makes impossible is the specific gap
# card t_71d4f79a found: a self-generated (or otherwise non-upstream) vector file sitting at a
# path or under a name that says "official"/"nist"/"rfc", with no machine-checked record anywhere
# of what the file actually is. Every committed KAT file now needs a manifest entry AND a header
# comment that agree with each other, and the two are cross-checked by hash so neither can drift
# from the file silently.
#
# See scripts/ci_guard_kat_provenance.py for the five checks (discovery, manifest coverage in
# both directions, content hash, the official/nist/rfc naming ban, and the header/manifest
# cross-check) and kats-manifest.toml for the manifest itself and its current, deliberately
# narrow, rollout scope.
#
# WHAT THIS GUARD DOES NOT COVER
# --------------------------------
#   * Discovery is scoped to `[scan].roots` in kats-manifest.toml, not the whole repository.
#     Widening that scope requires the same per-file provenance investigation this lane did for
#     lib-q-hqc -- see the manifest's own comment before adding a root.
#   * It is static: a repo walk, a small TOML read, and a SHA-256 per file. No cargo, no network.
#     It never runs the code under test and so cannot itself detect a *value* divergence from a
#     real upstream reference (that is `tests/nist_kem_kat.rs` / a future upstream-conformance
#     test's job) -- only whether the file's claimed origin is declared, consistent, and not
#     wearing an "official" name it has not earned.
#
# Usage: bash scripts/ci-guard-kat-provenance.sh [REPO_ROOT]

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same trap ci-guard-coverage-honesty.sh works
# around).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-kat-provenance: a working python3 interpreter is required" >&2
  exit 1
fi

"$PY_BIN" scripts/ci_guard_kat_provenance.py "$ROOT"
