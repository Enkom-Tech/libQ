#!/usr/bin/env bash
# Emit cargo-tarpaulin --include-files arguments scoped to one workspace package so
# Cobertura line-rate is not dominated by dependencies.
#
# Usage: print-tarpaulin-include-args.sh <crate-directory-or-package-name>
# Run from any directory inside the workspace; paths are resolved against
# `cargo metadata` workspace_root when jq is available.
#
# Requires jq when <ident> is a Cargo package name that is not a repo-relative path with src/.

set -euo pipefail

ident="${1:?package name or path under repo root}"

if command -v jq >/dev/null 2>&1; then
  ws_raw="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.workspace_root // empty')"
  if [[ -n "$ws_raw" ]]; then
    ws="$(cd "$ws_raw" && pwd -P)"
  else
    ws="$(pwd -P)"
  fi
else
  ws="$(pwd -P)"
fi

prel=""

# Example-only workspace member (no src/lib); sources live next to its manifest.
if [[ "$ident" == "lib-q-examples" && -f "$ws/examples/Cargo.toml" ]]; then
  prel="examples"
elif [[ -d "$ws/${ident}/src" ]]; then
  prel="${ident#./}"
  prel="${prel//\\//}"
elif command -v jq >/dev/null 2>&1; then
  man="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r --arg n "$ident" '.packages[] | select(.name == $n) | .manifest_path' | head -1)"
  if [[ -z "$man" || "$man" == "null" ]]; then
    echo "print-tarpaulin-include-args: unknown Cargo package '${ident}'" >&2
    exit 1
  fi
  adir="$(cd "$(dirname "$man")" && pwd -P)"
  if [[ "$adir" == "${ws}" ]]; then
    echo "print-tarpaulin-include-args: package manifest at workspace root" >&2
    exit 1
  fi
  if [[ "$adir" != "${ws}"/* ]]; then
    echo "print-tarpaulin-include-args: package outside workspace" >&2
    exit 1
  fi
  prel="${adir#"${ws}/"}"
else
  echo "print-tarpaulin-include-args: jq not found; cannot resolve '${ident}'" >&2
  exit 1
fi

prel="${prel//\\//}"
bs="${prel//\//\\\\}"

if [[ -d "$ws/${prel}/src" ]]; then
  printf '%s' " --include-files '${prel}/src/*' --include-files '${prel}/src/**' --include-files '${bs}\\\\src\\\\*'"
else
  printf '%s' " --include-files '${prel}/*.rs' --include-files '${prel}/**/*.rs' --include-files '${bs}\\\\*.rs'"
fi
