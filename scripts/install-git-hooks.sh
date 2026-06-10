#!/usr/bin/env bash
# Install tracked git hooks (pre-push health gate).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

HOOKS_DIR="$ROOT/.githooks"
chmod +x "$HOOKS_DIR/pre-push" \
  "$ROOT/scripts/pre-git-push.sh" \
  "$ROOT/scripts/rust-pre-push-health.sh"

git config core.hooksPath .githooks

echo "Installed git hooks:"
echo "  core.hooksPath = .githooks"
echo "  pre-push       → scripts/pre-git-push.sh → rust-pre-push-health (when Cargo.toml present)"
echo ""
echo "Optional tools (install as needed):"
echo "  cargo install cargo-audit --locked"
echo "  cargo install cargo-machete"
echo "  cargo install warnalyzer"
echo "  cargo install code-dupes"
echo "  cargo install rust-code-analysis-cli"
