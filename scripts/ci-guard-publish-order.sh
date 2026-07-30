#!/usr/bin/env bash
# Guard: every restatement of "what libQ publishes" must still match cd.yml.
#
# WHY THIS EXISTS
# ---------------
# `.github/workflows/cd.yml` is the authority on which crates and npm packages ship and in what
# order. Three places restate that list by hand, and a restatement of a list that grows every
# release does not stay correct on its own:
#
#   * scripts/publish-crates-io-ordered.ps1 -- the crates.io fallback an operator reaches for when
#     the tag-triggered CD path is unavailable. At 0.0.10 its header claimed to mirror cd.yml while
#     listing 65 of cd.yml's 80 crates. The 15 it omitted (lib-q-rocca-s, lib-q-mayo, lib-q-mac,
#     lib-q-threshold-kem, lib-q-double-kem, lib-q-fhe, lib-q-blind-pcs, lib-q-dkg,
#     lib-q-blind-token, lib-q-threshold-raccoon, lib-q-threshold-kem-lattice,
#     lib-q-stark-baby-bear, lib-q-mve, lib-q-transcript, lib-q-zk-encryption-proof) would not
#     error -- they would simply never publish, under a closing banner that says the run succeeded.
#     crates.io versions are immutable, so an incomplete release is permanent.
#   * scripts/publish-npm-ordered.sh -- same failure mode on the npm side, and it can also drift on
#     BUILD PARAMETERS rather than membership: at 0.0.10 it built @lib-q/aead without the `rocca-s`
#     feature cd.yml builds it with, which ships a package that silently lacks a cipher.
#   * docs/npm-publish.md "Package list (CD order)" -- the table an operator reads to decide what
#     a release should contain. At 0.0.10 it claimed "Total: 22 packages" against cd.yml's 30.
#
# None of those is a compile error, a test failure, or a runtime fault. They are a config that
# quietly stopped matching reality -- the same shape as the coverage gate that kept scoring a
# crate after its test filter was narrowed (scripts/ci-guard-coverage-honesty.sh). So the fix is
# the same shape too: derive the truth from the authority, diff every restatement against it, and
# fail the pull request that introduces the divergence.
#
# The derivation lives in scripts/cd_publish_manifest.py (stdlib-only block-YAML parser, because
# ci.yml's core-validation job has no pip step and PyYAML is not a dependency of this repo). The
# checks live in scripts/ci_guard_publish_order.py.
#
# WHAT THIS GUARD DOES *NOT* COVER
# --------------------------------
#   * It is STATIC. It never publishes anything, and it cannot tell you that cd.yml's own order is
#     correct -- only that the fallback scripts do not contradict it.
#   * It does not check that a crate CAN be published (version pins, forward dev-deps, feature
#     resolution). scripts/publish-readiness-pr.sh and the CD tiers do that.
#   * It does not model `if:` conditions on publish jobs, matrix `exclude:`, or non-`include`
#     matrix axes; cd_publish_manifest.py raises on those rather than guessing.
#   * Ordering inside one cd.yml matrix job is deliberately unconstrained -- those entries publish
#     in parallel, so cd.yml asserts nothing about their relative order (see CHECK 2's rationale).
#
# Usage: bash scripts/ci-guard-publish-order.sh [REPO_ROOT]

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
  echo "ci-guard-publish-order: a working python3 interpreter is required" >&2
  exit 1
fi

# Cross-validates the stdlib block-YAML parser against PyYAML when PyYAML happens to be importable
# (dev boxes); a no-op that prints and returns 0 where it is not (CI runners without it).
"$PY_BIN" scripts/cd_publish_manifest.py --root "$ROOT" --self-check
"$PY_BIN" scripts/ci_guard_publish_order.py "$ROOT"
