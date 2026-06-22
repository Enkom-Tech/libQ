#!/usr/bin/env bash
# Copy KAT JSON fixtures to export/ for handoff to the downstream SDK vectors/security/.
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

DEST="$ROOT/export/kat-vectors"
mkdir -p "$DEST"

cp lib-q-mac/tests/vectors/qcw-mac-v1.json "$DEST/qcw-mac-v1.json"
cp lib-q-threshold-sig/tests/vectors/threshold-sig-pop-v1.json "$DEST/threshold-sig-pop-v1.json"
cp lib-q-double-kem/tests/vectors/double-kem-v1.json "$DEST/double-kem-v1.json"
cp lib-q-threshold-kem/tests/vectors/threshold-kem-v1.json "$DEST/threshold-kem-v1.json"

echo "Exported KAT vectors to $DEST"
echo "Copy into the consumer repo: sdk/vectors/security/"
