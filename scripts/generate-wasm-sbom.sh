#!/usr/bin/env bash
# Generate a CycloneDX JSON SBOM for the @lib-q/core wasm dependency graph (wasm32 + ML-KEM).
# `cargo-cyclonedx` emits one file per workspace member when resolving the graph; we keep
# lib-q's BOM under sbom/ and delete the transient copies elsewhere.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NAME="lib-q-wasm-wasm32"
DEST_DIR="$ROOT/sbom"
mkdir -p "$DEST_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found" >&2
  exit 1
fi

if ! cargo cyclonedx --help >/dev/null 2>&1; then
  echo "Installing cargo-cyclonedx (pinned) for reproducible SBOM output..."
  cargo install cargo-cyclonedx --version 0.5.9 --locked
fi

(
  cd "$ROOT/lib-q"
  cargo cyclonedx \
    -F wasm,ml-kem \
    --target wasm32-unknown-unknown \
    -f json \
    --override-filename "$NAME" \
    -q
)

SRC="$ROOT/lib-q/${NAME}.json"
if [[ ! -f "$SRC" ]]; then
  echo "::error::expected SBOM at $SRC" >&2
  exit 1
fi

mv "$SRC" "$DEST_DIR/${NAME}.cdx.json"

# Remove duplicate BOMs cargo-cyclonedx writes next to other workspace manifests.
while IFS= read -r -d '' f; do
  rm -f "$f"
done < <(find "$ROOT" -name "${NAME}.json" -type f -print0 2>/dev/null || true)

echo "SBOM: $DEST_DIR/${NAME}.cdx.json"
