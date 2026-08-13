#!/usr/bin/env bash
# Guard: a publishable cdylib crate must link with BARE DEFAULT FEATURES on the host -- the one
# combination `cargo publish --verify` builds and CI never does.
#
# WHY THIS EXISTS
# ---------------
# v0.0.11 published 35 crates and then died at tier 3 with
#
#     error: unwinding panics are not supported without std
#     error: could not compile `lib-q-core` (lib) due to 1 previous error
#
# because `lib-q-kem` (crate-type = ["cdylib", "rlib"]) had `default = []` while its `lib-q-core`
# dependency was tightened to `default-features = false`. Every CI job was green: `--all-features`
# structurally cannot see this (it turns `std` on), and the `thumbv7em-none-eabi` no_std build is a
# different target with no cdylib to link. crates.io versions are immutable, so the half-release
# could only be completed, never rolled back.
#
# See scripts/ci_guard_cdylib_default_link.py for the two modes (`--static` on every PR,
# `--build` on the release path) and why the static shape alone is necessary but not sufficient.
#
# Usage:
#   bash scripts/ci-guard-cdylib-default-link.sh            # static shape check (every PR)
#   bash scripts/ci-guard-cdylib-default-link.sh --build    # really link them (release path)
#   bash scripts/ci-guard-cdylib-default-link.sh --self-test
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
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
  echo "ci-guard-cdylib-default-link: a working python3 interpreter is required" >&2
  exit 1
fi

# No pipe here: the guard's own exit code must be what this script reports. `cmd | tail` would
# report tail's status and turn a real violation into a green step.
"$PY_BIN" scripts/ci_guard_cdylib_default_link.py "$@"
