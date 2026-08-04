#!/usr/bin/env bash
# Guard: cd.yml's publish tiers must be a valid topological order of the dependency graph.
#
# WHY THIS EXISTS
# ---------------
# The v0.0.10 release published 51 crates to crates.io and then failed at tier 7:
#
#     error: failed to prepare local package for uploading
#     Caused by:
#       failed to select a version for the requirement `lib-q-stark-challenger = "^0.0.10"`
#       candidate versions found which didn't match: 0.0.9
#
# lib-q-stark-commit declared an optional (runtime) dependency on lib-q-stark-challenger, which
# publishes three tiers later -- and could not be moved earlier, because it transitively needs
# lib-q-stark-mersenne31 and the SHAKE/SHA3 adapters. The ordering was not satisfiable at any
# position. Tiers 8-17 and every npm/wasm package were skipped, and because crates.io versions are
# immutable the half-release could only be completed, never undone.
#
# ci-guard-publish-order.sh reported PASS on that exact tree, minutes before the tag. It is not a
# bug in that guard: it checks the publish list's MEMBERSHIP and BUILD PARAMETERS against cd.yml,
# which is a different question from whether the ORDER is satisfiable. This guard answers that one.
#
# See scripts/ci_guard_publish_dependency_order.py for which dependency kinds are fatal and why
# dev-dependencies deliberately are not.
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
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
  echo "ci-guard-publish-dependency-order: a working python3 interpreter is required" >&2
  exit 1
fi

"$PY_BIN" scripts/ci_guard_publish_dependency_order.py "$ROOT"
