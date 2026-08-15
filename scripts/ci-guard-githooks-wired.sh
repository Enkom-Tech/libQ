#!/usr/bin/env bash
# ci-guard-githooks-wired.sh — prove the pre-push health gate can actually run.
#
# WHY THIS EXISTS. On 2026-08-15 `core.hooksPath` in a working clone still pointed at
# `C:\Users\...\Transfer\...\libQ\.githooks` — the path the repo lived at *before* it was moved.
# That directory no longer existed, so Git found no hooks, and `scripts/rust-pre-push-health.sh`
# (fmt + clippy + cargo-audit) was silently skipped on every push. Nothing reported it. The gate
# looked installed and was not running: a control nobody had watched fire.
#
# WHAT CI CAN AND CANNOT PROVE — read this before "strengthening" the guard.
# A CI runner checks the repo out fresh and never sets `core.hooksPath`, so an assertion of the
# form "core.hooksPath resolves" is VACUOUS on CI: unset is the normal state there and the check
# would pass by construction on every run, forever, while proving nothing. That is precisely the
# unfailable-check class this repo keeps getting burned by. So the two properties are separated:
#
#   A. REPO-SIDE (enforced everywhere, including CI). The hook chain exists and is installable,
#      and the installer writes a RELATIVE core.hooksPath. An absolute path is the root cause of
#      the 2026-08-15 rot: it silently stops resolving the moment a clone moves.
#
#   B. DEVELOPER-SIDE (enforced off-CI only). In a real clone, core.hooksPath must be set AND
#      resolve to a directory containing pre-push. On CI this is reported as skipped, out loud —
#      never silently passed.
#
# Usage:
#   bash scripts/ci-guard-githooks-wired.sh
#   bash scripts/ci-guard-githooks-wired.sh --self-test
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

note() { echo "ci-guard-githooks-wired: $*" >&2; }

# ---------------------------------------------------------------- A. repo-side
# Prints one line per violation on stdout; returns 1 if any. Takes a root so the
# self-test can run the real logic against mutated fixtures rather than a copy of it.
validate_repo_side() {
  local r="$1" bad=0

  [[ -f "$r/.githooks/pre-push" ]] \
    || { echo "missing .githooks/pre-push"; bad=1; }
  [[ -f "$r/scripts/pre-git-push.sh" ]] \
    || { echo "missing scripts/pre-git-push.sh (.githooks/pre-push delegates to it)"; bad=1; }
  [[ -f "$r/scripts/rust-pre-push-health.sh" ]] \
    || { echo "missing scripts/rust-pre-push-health.sh (the gate itself)"; bad=1; }

  local inst="$r/scripts/install-git-hooks.sh"
  if [[ ! -f "$inst" ]]; then
    echo "missing scripts/install-git-hooks.sh (nothing wires core.hooksPath)"
    bad=1
  else
    local val
    val="$(grep -oE 'git config[[:space:]]+core\.hooksPath[[:space:]]+[^[:space:]]+' "$inst" \
           | head -1 | awk '{print $NF}' || true)"
    if [[ -z "$val" ]]; then
      echo "install-git-hooks.sh never sets core.hooksPath"
      bad=1
    elif [[ "$val" == /* || "$val" =~ ^[A-Za-z]: ]]; then
      echo "install-git-hooks.sh sets an ABSOLUTE core.hooksPath ('$val'); it must be relative"
      echo "  an absolute path stops resolving the moment the clone moves — the 2026-08-15 rot"
      bad=1
    fi
  fi

  return "$bad"
}

# ---------------------------------------------------------------- B. developer-side
validate_local_config() {
  local hp
  hp="$(git config --get core.hooksPath || true)"

  if [[ -z "$hp" ]]; then
    if [[ -n "${CI:-}" ]]; then
      echo "ci-guard-githooks-wired: core.hooksPath unset — expected on a CI runner, so the"
      echo "ci-guard-githooks-wired: developer-side check is SKIPPED (not passed). Repo-side checks ran."
      return 0
    fi
    # UNSET is a WARNING, not a failure, and the distinction is deliberate.
    # DEVELOPMENT.md documents the pre-push gate as *optional*, so an unset core.hooksPath may be
    # a considered choice and this guard must not quietly promote it to mandatory. What is never
    # a choice is core.hooksPath SET to something that does not resolve — that is always rot, and
    # that is the case below, which does fail.
    note "WARNING: core.hooksPath is unset in this clone."
    note "This repo keeps its hooks in .githooks/, not .git/hooks/, so Git finds no pre-push hook"
    note "and the Rust health gate (fmt + clippy + cargo-audit) will not run on your pushes."
    note "That is permitted — DEVELOPMENT.md calls the gate optional — but it is worth knowing."
    note "To enable it: bash scripts/install-git-hooks.sh"
    return 0
  fi

  local dir="$hp"
  [[ "$dir" == /* || "$dir" =~ ^[A-Za-z]: ]] || dir="$ROOT/$hp"

  if [[ ! -d "$dir" ]]; then
    note "core.hooksPath points at a directory that does not exist:"
    note "  configured: $hp"
    note "  resolved:   $dir"
    note "Git finds no hooks there, so the pre-push health gate is SILENTLY skipped on every push."
    note "This is what an absolute path baked in before the clone moved looks like."
    note "Fix: bash scripts/install-git-hooks.sh"
    return 1
  fi

  if [[ ! -f "$dir/pre-push" ]]; then
    note "core.hooksPath='$hp' resolves to '$dir', but that directory has no pre-push hook."
    note "Fix: bash scripts/install-git-hooks.sh"
    return 1
  fi

  return 0
}

# ---------------------------------------------------------------- self-test
# Every case must be OBSERVED to fail before the guard is trusted. A guard whose failure
# path has never executed is a claim, not a control.
self_test() {
  local tmp passed=0 failed=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  make_fixture() {
    local d="$1"
    mkdir -p "$d/.githooks" "$d/scripts"
    printf '#!/usr/bin/env bash\nexec bash scripts/pre-git-push.sh\n' > "$d/.githooks/pre-push"
    printf '#!/usr/bin/env bash\ntrue\n' > "$d/scripts/pre-git-push.sh"
    printf '#!/usr/bin/env bash\ntrue\n' > "$d/scripts/rust-pre-push-health.sh"
    printf '#!/usr/bin/env bash\ngit config core.hooksPath .githooks\n' > "$d/scripts/install-git-hooks.sh"
  }

  expect() {
    local label="$1" want="$2" dir="$3" got=0
    validate_repo_side "$dir" >/dev/null 2>&1 || got=1
    if [[ "$got" == "$want" ]]; then
      echo "  ok    $label (expected rc=$want)"
      passed=$((passed + 1))
    else
      echo "  FAIL  $label (expected rc=$want, got rc=$got)"
      failed=$((failed + 1))
    fi
  }

  # 1. intact fixture must PASS — proves the guard is not failing on everything
  make_fixture "$tmp/intact"
  expect "intact hook chain" 0 "$tmp/intact"

  # 2..6 each mutation must FAIL — proves each check actually fires
  make_fixture "$tmp/no-hook"          && rm "$tmp/no-hook/.githooks/pre-push"
  expect "missing .githooks/pre-push" 1 "$tmp/no-hook"

  make_fixture "$tmp/no-orchestrator"  && rm "$tmp/no-orchestrator/scripts/pre-git-push.sh"
  expect "missing pre-git-push.sh" 1 "$tmp/no-orchestrator"

  make_fixture "$tmp/no-gate"          && rm "$tmp/no-gate/scripts/rust-pre-push-health.sh"
  expect "missing rust-pre-push-health.sh" 1 "$tmp/no-gate"

  make_fixture "$tmp/abs-win"
  printf '#!/usr/bin/env bash\ngit config core.hooksPath C:/Users/someone/old/.githooks\n' \
    > "$tmp/abs-win/scripts/install-git-hooks.sh"
  expect "installer writes ABSOLUTE windows path (the 2026-08-15 rot)" 1 "$tmp/abs-win"

  make_fixture "$tmp/abs-posix"
  printf '#!/usr/bin/env bash\ngit config core.hooksPath /home/someone/old/.githooks\n' \
    > "$tmp/abs-posix/scripts/install-git-hooks.sh"
  expect "installer writes ABSOLUTE posix path" 1 "$tmp/abs-posix"

  make_fixture "$tmp/no-set"
  printf '#!/usr/bin/env bash\necho nothing\n' > "$tmp/no-set/scripts/install-git-hooks.sh"
  expect "installer never sets core.hooksPath" 1 "$tmp/no-set"

  echo
  if [[ "$failed" -gt 0 ]]; then
    echo "ci-guard-githooks-wired: self-test FAILED ($failed of $((passed + failed)) cases)" >&2
    return 1
  fi
  echo "ci-guard-githooks-wired: self-test OK ($passed mutation cases behaved as specified)"
  return 0
}

# ---------------------------------------------------------------- main
if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi

rc=0

violations="$(validate_repo_side "$ROOT" || true)"
if [[ -n "$violations" ]]; then
  note "the pre-push health gate is not installable from this tree:"
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "  $line" >&2
  done <<< "$violations"
  note "The gate runs fmt + clippy + cargo-audit before every push; a broken chain means it"
  note "cannot run at all. Repair the files above, then: bash scripts/install-git-hooks.sh"
  rc=1
fi

validate_local_config || rc=1

if [[ "$rc" -eq 0 ]]; then
  echo "ci-guard-githooks-wired: OK (hook chain intact; installer writes a relative core.hooksPath)"
fi
exit "$rc"
