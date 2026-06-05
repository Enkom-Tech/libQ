#!/usr/bin/env bash
# Reject forbidden consumer-specific strings in new primitive crate sources.
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

CRATES=(
  lib-q-mac
  lib-q-threshold-sig
  lib-q-threshold-kem
  lib-q-double-kem
  lib-q-fhe
  lib-q-blind-pcs
)

PATTERN='(gip|GIP|sybil|PoP|vault)'

failed=0
for crate in "${CRATES[@]}"; do
  if rg -n -i "$PATTERN" "$crate/src" "$crate/tests" "$crate/README.md" 2>/dev/null; then
    echo "ERROR: forbidden term in $crate" >&2
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Banned-term guard: OK"
