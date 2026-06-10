#!/usr/bin/env bash
# Pre-git-push orchestrator: delegates to language-specific health gates.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [[ -f "$ROOT/Cargo.toml" ]]; then
  exec bash "$ROOT/scripts/rust-pre-push-health.sh"
fi

# Not a Rust repo — no-op so other pre-push hooks/skills can run.
exit 0
