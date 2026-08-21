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


# A MISSING TOOL IS NOT A COMPILE FAILURE, AND THIS SCRIPT SAID IT WAS.
#
# On 2026-08-21 (task 4924) the fuzz-harnesses-build job ran with no Rust toolchain installed --
# its only step before this script was actions/checkout. Every `cargo check` below hit
#
#     ./scripts/ci-check-fuzz-harnesses.sh: line 33: cargo: command not found
#
# and the loop reported, six times, once per crate:
#
#     ::error::fuzz harness failed to compile: lib-q-dkg/fuzz/Cargo.toml
#     ::error::fuzz harness failed to compile: lib-q-lattice-zkp/fuzz/Cargo.toml
#     ...
#     ::error::one or more cargo-fuzz harnesses do not compile
#
# Nothing was compiled, so nothing failed to compile. Six red lines each naming a crate that was
# fine, on a check that never ran. That is worse than no check: it is a check that manufactures
# evidence against innocent code, and a reviewer who chases one of those crates finds nothing and
# learns to distrust this job's output permanently.
#
# The workflow now installs a toolchain, which is the actual repair. This preamble is the part
# that survives the next time someone edits that job: the script refuses to render a verdict on
# code it never compiled.
#
# EXIT CODES:
#   0  every harness compiled
#   1  at least one harness genuinely does not compile -- a statement about the code
#   2  could not tell: no cargo, or cargo vanished mid-run. NEVER collapsed into 0 or 1.
if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::ci-check-fuzz-harnesses.sh: no 'cargo' on PATH. This job did not install a Rust toolchain." >&2
  echo "  NOTHING WAS COMPILED, so nothing failed to compile. Exiting 2 (could not tell), not 1," >&2
  echo "  so this red cannot be mistaken for a verdict on any harness. Add a toolchain step" >&2
  echo "  (dtolnay/rust-toolchain, as .github/actions/rust-build does) to the calling job." >&2
  exit 2
fi
fail=0
fail=0
missing_tool=0
for manifest in "${fuzz_manifests[@]}"; do
  echo "=== cargo check --manifest-path ${manifest} ==="
  rc=0
  cargo check --manifest-path "${manifest}" || rc=$?
  case "${rc}" in
    0) ;;
    127)
      # 127 is the shell's "I could not find that program", not the compiler's verdict.
      echo "::error::ci-check-fuzz-harnesses.sh: cargo disappeared from PATH partway through (exit 127) at ${manifest}." >&2
      missing_tool=1
      break
      ;;
    *)
      echo "::error::fuzz harness failed to compile: ${manifest} (cargo check exit ${rc})" >&2
      fail=1
      ;;
  esac
done

if [ "${missing_tool}" -ne 0 ]; then
  echo "::error::ci-check-fuzz-harnesses.sh COULD NOT TELL whether the harnesses compile -- the toolchain went away mid-run." >&2
  exit 2
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::one or more cargo-fuzz harnesses do not compile" >&2
  exit 1
fi

echo "All ${#fuzz_manifests[@]} fuzz harness manifest(s) compiled cleanly."
