#!/usr/bin/env bash
# Guard: no internal work-tracker references or internal infrastructure details in the tree.
#
# This repository is published; tracker identifiers, internal task numbers, workstation paths,
# private addresses and names of private hosts and tools mean nothing to its readers. The check
# lives in scripts/ci_guard_internal_refs.py (stdlib-only Python, no network); its header documents
# every check, the optional INTERNAL_REFS_KEY variable that enables the internal-name check (the
# names are not stored in this repository), and the address-only exemption with its committed
# ceiling in scripts/internal-refs-exemptions-max.txt. The guard re-runs its self-test before every
# scan, so a guard that has stopped detecting anything fails instead of reporting a clean tree.
#
# Usage:
#   bash scripts/ci-guard-internal-refs.sh [REPO_ROOT]
#   bash scripts/ci-guard-internal-refs.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH and
# satisfies `command -v` while refusing to execute (same as ci-guard-kat-provenance.sh).
PY_BIN=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  echo "ci-guard-internal-refs: a working python3 interpreter is required" >&2
  exit 1
fi

exec "$PY_BIN" "$SCRIPT_DIR/ci_guard_internal_refs.py" "$@"
