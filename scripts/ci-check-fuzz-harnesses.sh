#!/usr/bin/env bash
# Builds every standalone cargo-fuzz harness in the repo (the ones excluded from the main
# workspace via root Cargo.toml's `workspace.exclude`, e.g. lib-q-zkp/fuzz,
# lib-q-lattice-zkp/fuzz, ...). This does NOT run fuzzing -- it only checks that each harness
# still compiles against current library APIs. `cargo-fuzz`-generated crates build fine under
# plain `cargo check`/`cargo build` on the pinned toolchain; only actually *fuzzing* needs the
# cargo-fuzz subcommand.
#
# Harnesses are discovered by walking the tree for `*/fuzz/Cargo.toml` (git-tracked files only)
# rather than hardcoding a list, so a new harness is covered automatically and a deleted one
# can't leave a stale, always-skipped entry behind.
#
# Card: L7/L8 audit findings -- lib-q-lattice-zkp/fuzz silently stopped compiling (E0308 API
# drift) because no CI job built it; only lib-q-zkp/fuzz targets were ever exercised in CI
# (zkp-fuzz-scheduled.yml). This script closes that blind spot for ALL harnesses.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

mapfile -t fuzz_manifests < <(git ls-files -- '*/fuzz/Cargo.toml' | sort)

if [ "${#fuzz_manifests[@]}" -eq 0 ]; then
  echo "::error::ci-check-fuzz-harnesses.sh found zero '*/fuzz/Cargo.toml' files -- guard is now vacuous, investigate before trusting this job" >&2
  exit 1
fi

echo "Discovered ${#fuzz_manifests[@]} fuzz harness manifest(s):"
printf '  %s\n' "${fuzz_manifests[@]}"

fail=0
for manifest in "${fuzz_manifests[@]}"; do
  echo "=== cargo check --manifest-path ${manifest} ==="
  if ! cargo check --manifest-path "${manifest}"; then
    echo "::error::fuzz harness failed to compile: ${manifest}" >&2
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "::error::one or more cargo-fuzz harnesses do not compile" >&2
  exit 1
fi

echo "All ${#fuzz_manifests[@]} fuzz harness manifest(s) compiled cleanly."
