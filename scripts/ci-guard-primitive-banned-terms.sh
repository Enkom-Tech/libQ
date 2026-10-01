#!/usr/bin/env bash
# Reject forbidden consumer-specific strings in new primitive crate sources.
#
# The search runs through GNU `grep -P`, which every Linux runner ships. It used to run through
# `rg ... 2>/dev/null` inside an `if`. Neither the GitHub-hosted nor the forge runner image has
# ripgrep, so `rg` exited 127, the `if` read that as "no match", and the guard printed OK on every
# run without searching anything. A hit had been sitting in lib-q-dkg/tests for a month. Now a
# search that cannot run is an error (exit 2), never a pass, and `--self-test` proves the
# search finds a planted term before the real scan runs.
set -euo pipefail

PATTERN='(?i:gip|sybil|vault)|PoP'

# search <paths...>: 0 = hit (printed), 1 = clean, anything else = could not search.
search() {
  local rc=0
  grep -rnP -- "$PATTERN" "$@" || rc=$?
  return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "${tmp:?}"' EXIT
  mkdir -p "$tmp/src"
  printf '// a vault lookup\n' > "$tmp/src/hit.rs"
  printf '// nothing to see\n' > "$tmp/src/clean.rs"
  rc=0; search "$tmp/src/hit.rs" >/dev/null || rc=$?
  [[ "$rc" -eq 0 ]] || { echo "SELF-TEST FAILED: a planted term was not found (rc=$rc)" >&2; exit 2; }
  rc=0; search "$tmp/src/clean.rs" >/dev/null || rc=$?
  [[ "$rc" -eq 1 ]] || { echo "SELF-TEST FAILED: a clean file did not read as clean (rc=$rc)" >&2; exit 2; }
  rc=0; search "$tmp/src/does-not-exist.rs" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -ge 2 ]] || { echo "SELF-TEST FAILED: a search that cannot run did not report it (rc=$rc)" >&2; exit 2; }
  echo "Banned-term guard self-test: OK"
  exit 0
fi

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

CRATES=(
  lib-q-mac
  lib-q-blind-pcs
  lib-q-dkg
  lib-q-threshold-raccoon
  lib-q-threshold-kem-lattice
  lib-q-blind-token
  lib-q-mve
  lib-q-transcript
  lib-q-stark-baby-bear
  lib-q-zk-encryption-proof
)

failed=0
for crate in "${CRATES[@]}"; do
  [[ -d "$crate" ]] || { echo "ERROR: listed crate $crate does not exist (update CRATES)" >&2; exit 2; }
  paths=()
  for p in "$crate/src" "$crate/tests" "$crate/README.md"; do
    [[ -e "$p" ]] && paths+=("$p")
  done
  [[ ${#paths[@]} -gt 0 ]] || continue
  rc=0
  search "${paths[@]}" || rc=$?
  case "$rc" in
    0) echo "ERROR: forbidden term in $crate" >&2; failed=1 ;;
    1) ;;
    *) echo "ERROR: could not search $crate (grep exit $rc) -- not a pass" >&2; exit 2 ;;
  esac
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Banned-term guard: OK"
