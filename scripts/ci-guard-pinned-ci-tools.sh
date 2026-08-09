#!/usr/bin/env bash
# Guard: CI tools installed via taiki-e/install-action must be pinned to an exact version.
#
# WHY THIS EXISTS
# ================
# `tool: cargo-tarpaulin` (no version) resolves to @latest at job run time. That makes the build
# depend on a third party's release schedule: a tool release can turn CI red with no change on our
# side, and -- worse for a coverage job -- can silently change what a number MEANS. Measured in this
# repo: cargo-tarpaulin 0.35.2 and 0.37.0 disagree by up to 44 coverage points on the same crate.
# A floor tuned against one version is not a floor against the other.
#
# THIS IS NOT HYPOTHETICAL. The `Test Coverage (nightly)` job broke on 2026-08-06 with
# `parser failure: Nom(Satisfy)` on unchanged source. Three eliminations (stable passed; an
# unchanged Aug-5 commit re-run now failed; tarpaulin logged the same 0.37.0 both sides) put the
# only moving variable in the toolchain -- see card t_93dc6b27. The nightly toolchain is the half we
# cannot pin away forever, but the tool half we can, and two jobs in
# security-critical-coverage.yml were still installing tarpaulin unpinned at that time.
#
# WHAT IT CHECKS
# ===============
# Every `tool:` value under a taiki-e/install-action step in .github/workflows/*.yml carries an
# `@<version>`. Comma-separated tool lists are checked per entry.
#
# WHAT IT DELIBERATELY DOES NOT DO
# =================================
# It does not require the SAME version everywhere, and it does not judge whether a pin is current.
# Both are real concerns and neither is this guard's job -- a stale pin is visible and arguable, an
# absent pin is invisible. It also does not check actions themselves (those are already SHA-pinned
# by a separate convention) or tools installed by other means.
#
# Usage:
#   bash scripts/ci-guard-pinned-ci-tools.sh [REPO_ROOT]
#   bash scripts/ci-guard-pinned-ci-tools.sh --self-test

set -uo pipefail

check_tree() { # check_tree <workflow-dir> -> findings on stdout, count in $FOUND
  local dir="$1"
  FOUND=0
  local f line lineno tools tool
  shopt -s nullglob
  for f in "$dir"/*.yml "$dir"/*.yaml; do
    # Only `tool:` keys that belong to an install-action step. Rather than parse YAML, take every
    # `tool:` line in a file that uses install-action -- no other action in this repo uses that key.
    grep -q 'taiki-e/install-action' "$f" || continue
    while IFS=: read -r lineno line; do
      tools="${line#*tool:}"
      tools="$(printf '%s' "$tools" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      [[ -z "$tools" ]] && continue
      # a comma-separated list installs several tools; each needs its own pin
      local IFS_SAVE="$IFS"; IFS=','
      for tool in $tools; do
        IFS="$IFS_SAVE"
        tool="$(printf '%s' "$tool" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$tool" ]] && continue
        if [[ "$tool" != *@* ]]; then
          echo "  FAIL: $(basename "$f"):$lineno installs '$tool' unpinned (resolves to @latest)."
          echo "        Pin it: 'tool: $tool@<version>'. A tool that moves under us can turn CI red"
          echo "        with no change on our side -- and for a measurement tool it can change what"
          echo "        the number MEANS, not just whether the job passes."
          FOUND=$((FOUND + 1))
        fi
        IFS=','
      done
      IFS="$IFS_SAVE"
    done < <(grep -n '^[[:space:]]*tool:' "$f")
  done
  shopt -u nullglob
}

self_test() {
  # Prove the guard fires on an unpinned tool and stays quiet on a pinned one. Without this, a
  # broken guard and a healthy repo look identical -- both print OK.
  local tmp; tmp="$(mktemp -d)" problems=0
  mkdir -p "$tmp/good" "$tmp/bad" "$tmp/list"

  printf 'jobs:\n  a:\n    steps:\n      - uses: taiki-e/install-action@abc\n        with:\n          tool: cargo-tarpaulin@0.37.0\n' > "$tmp/good/w.yml"
  check_tree "$tmp/good" >/dev/null
  [[ $FOUND -ne 0 ]] && { echo "  - a pinned tool must NOT fire (got $FOUND)"; problems=1; }

  printf 'jobs:\n  a:\n    steps:\n      - uses: taiki-e/install-action@abc\n        with:\n          tool: cargo-tarpaulin\n' > "$tmp/bad/w.yml"
  check_tree "$tmp/bad" >/dev/null
  [[ $FOUND -eq 0 ]] && { echo "  - an unpinned tool MUST fire"; problems=1; }

  # a comma-separated list where only one entry is pinned
  printf 'jobs:\n  a:\n    steps:\n      - uses: taiki-e/install-action@abc\n        with:\n          tool: cargo-deny@0.16.1,cargo-audit\n' > "$tmp/list/w.yml"
  check_tree "$tmp/list" >/dev/null
  [[ $FOUND -ne 1 ]] && { echo "  - a partly-pinned list must fire exactly once (got $FOUND)"; problems=1; }

  rm -rf "$tmp"
  if [[ $problems -ne 0 ]]; then
    echo "SELF-TEST FAILED -- the pinned-CI-tools guard is not detecting what it claims."
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  if self_test; then echo "ci-guard-pinned-ci-tools: self-test OK"; exit 0; else exit 1; fi
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
WF="$ROOT/.github/workflows"
[[ -d "$WF" ]] || { echo "ci-guard-pinned-ci-tools: missing $WF" >&2; exit 1; }

# Re-prove detection before trusting a clean result: a clean tree is the normal state here.
if ! self_test; then exit 1; fi

check_tree "$WF"
TOTAL="$(grep -l 'taiki-e/install-action' "$WF"/*.yml "$WF"/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
if [[ $FOUND -ne 0 ]]; then
  echo "ci-guard-pinned-ci-tools: $FOUND unpinned tool install(s)"
  exit 1
fi
echo "ci-guard-pinned-ci-tools: OK -- all install-action tools pinned across $TOTAL workflow file(s)"
