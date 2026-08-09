#!/usr/bin/env bash
# Guard: a crate withdrawn for a soundness defect must not come back.
#
# WHY THIS EXISTS
# ================
# Deleting an unsound crate from `main` does not make it unreachable. `lib-q-threshold-kem` and
# `lib-q-fhe` were deleted at 401eb2e because they are broken, not untidy:
#   * lib-q-threshold-kem: `partial_decap` returns the party's raw Shamir share of the ML-KEM-768
#     decapsulation key. t of them reconstruct the key.
#   * lib-q-fhe: `decrypt` never reads the key. Anyone who can see the ciphertext can read the
#     plaintext.
# Both are still present on two branches (spike/anon-cred-oom-red, wip/pvtn-v1-construction7),
# which cannot simply be deleted -- wip/pvtn-v1-construction7 carries research work that is not on
# main. See card t_59609fc3.
#
# THIS IS NOT HYPOTHETICAL. On 2026-08-08 an agent hit GIP's stale path dependencies on these two
# crates -- GIP's sdk/Cargo.toml still declared them, and because cargo resolves every path dep at
# manifest load, before any feature gating, the ENTIRE GIP workspace failed to load for anyone
# cloning GIP and libQ at their default branches. The agent made resolution succeed by grafting the
# directories back out of the spike branch. It checked with `cargo tree` that nothing linked
# against them, so no result was corrupted -- but "restore the deleted crate until cargo is happy"
# is the reflex this guard exists to interrupt. The correct response to a missing dependency that
# someone deleted on purpose is to read the history, not to reach for a branch that still has it.
#
# WHAT IT CHECKS
# ===============
# For every crate named in scripts/withdrawn-crates.txt:
#   1. no tracked file lives under <crate>/            (it is back in the tree)
#   2. the directory does not exist in the working copy (it is back on disk, tracked or not --
#      this is the graft case, which leaves an UNTRACKED directory and so would pass check 1)
#   3. the root Cargo.toml does not list it as a workspace member
#
# Check 2 is the one that catches what actually happened, and it is why this guard does not simply
# grep `git ls-files`.
#
# WHAT IT DELIBERATELY DOES NOT DO
# =================================
# It does not inspect other branches. The withdrawn sources legitimately remain on the two branches
# above until someone decides how to preserve their unrelated work; failing on that would make the
# guard unpassable rather than useful. It guards the tree you are building.
#
# It also does not check other repositories. GIP declaring a path dep on a withdrawn crate is a GIP
# problem and cannot be seen from here.
#
# Usage:
#   bash scripts/ci-guard-withdrawn-crates.sh [REPO_ROOT]
#   bash scripts/ci-guard-withdrawn-crates.sh --self-test

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST_DEFAULT="$SCRIPT_DIR/withdrawn-crates.txt"

check_tree() { # check_tree <root> <list-file>  -> prints findings, returns count via $FOUND
  local root="$1" list="$2"
  FOUND=0
  local crate reason
  while IFS='|' read -r crate reason; do
    # Trim with sed, not `xargs`: xargs applies shell quoting rules, so an apostrophe in a
    # reason ("the party's raw Shamir share") makes it fail with "unmatched single quote".
    crate="$(printf '%s' "${crate:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    reason="$(printf '%s' "${reason:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$crate" || "$crate" == \#* ]] && continue

    # 1. tracked files under the crate directory
    if git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
      if git -C "$root" ls-files --error-unmatch "$crate" >/dev/null 2>&1 \
         || [[ -n "$(git -C "$root" ls-files "$crate/" 2>/dev/null)" ]]; then
        echo "  FAIL: $crate is TRACKED again. It was withdrawn: $reason"
        FOUND=$((FOUND + 1))
        continue
      fi
    fi

    # 2. present on disk at all (the graft case leaves it untracked)
    if [[ -d "$root/$crate" ]]; then
      echo "  FAIL: $root/$crate exists in the working copy (untracked). It was withdrawn: $reason"
      echo "        If a build is failing for want of it, fix the dependent's manifest --"
      echo "        restoring the crate reintroduces the defect."
      FOUND=$((FOUND + 1))
      continue
    fi

    # 3. named as a workspace member
    if [[ -f "$root/Cargo.toml" ]] && grep -qE "^\s*\"$crate\"\s*,?\s*$" "$root/Cargo.toml"; then
      echo "  FAIL: $crate is listed as a workspace member in Cargo.toml. It was withdrawn: $reason"
      FOUND=$((FOUND + 1))
    fi
  done < "$list"
}

self_test() {
  # Prove each of the three checks fires, and that a clean tree does not.
  local tmp; tmp="$(mktemp -d)"
  local list="$tmp/list.txt"
  printf 'gone-crate | fixture: unsound, deleted on purpose\n' > "$list"
  local problems=0

  # clean tree -> must NOT fire
  mkdir -p "$tmp/clean"; printf '[workspace]\nmembers = ["kept"]\n' > "$tmp/clean/Cargo.toml"
  check_tree "$tmp/clean" "$list" >/dev/null
  if [[ $FOUND -ne 0 ]]; then echo "  - clean tree must not fire (got $FOUND)"; problems=1; fi

  # untracked directory on disk -> MUST fire (this is the graft case)
  mkdir -p "$tmp/graft/gone-crate/src"; printf '[workspace]\n' > "$tmp/graft/Cargo.toml"
  check_tree "$tmp/graft" "$list" >/dev/null
  if [[ $FOUND -eq 0 ]]; then echo "  - an untracked resurrected directory must fire"; problems=1; fi

  # workspace member entry -> MUST fire
  mkdir -p "$tmp/member"; printf '[workspace]\nmembers = [\n    "gone-crate",\n]\n' > "$tmp/member/Cargo.toml"
  check_tree "$tmp/member" "$list" >/dev/null
  if [[ $FOUND -eq 0 ]]; then echo "  - a workspace member entry must fire"; problems=1; fi

  rm -rf "$tmp"
  if [[ $problems -ne 0 ]]; then
    echo "SELF-TEST FAILED -- the withdrawn-crate guard is not detecting what it claims."
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  if self_test; then echo "ci-guard-withdrawn-crates: self-test OK"; exit 0; else exit 1; fi
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
LIST="$LIST_DEFAULT"
[[ -f "$LIST" ]] || { echo "ci-guard-withdrawn-crates: missing $LIST" >&2; exit 1; }

# Re-prove detection before trusting a clean result -- this guard's whole point is that a clean
# tree is the normal state, so a broken guard would look identical to a healthy repo.
if ! self_test; then exit 1; fi

check_tree "$ROOT" "$LIST"
COUNT="$(grep -vcE '^\s*(#|$)' "$LIST")"
if [[ $FOUND -ne 0 ]]; then
  echo "ci-guard-withdrawn-crates: $FOUND withdrawn crate(s) have reappeared"
  exit 1
fi
echo "ci-guard-withdrawn-crates: OK -- $COUNT withdrawn crate(s) absent from the tree"
