#!/usr/bin/env bash
# Guard: every `lib-q-sca-test` dependency declaration must set `default-features = false`.
#
# WHY THIS EXISTS
# ================
# Cargo unifies features across a single invocation's dependency graph -- including a package's OWN
# dev-dependencies against its own lib target. `lib-q-sca-test`'s default features (`mlkem`, `mldsa`,
# `privacy`) pull in `lib-q-ml-kem` and `lib-q-ml-dsa` with their `hardened` feature turned on
# unconditionally. Because `lib-q-ml-kem` and `lib-q-ml-dsa` each take `lib-q-sca-test` as a
# dev-dependency WITH DEFAULT FEATURES, `cargo test -p lib-q-ml-kem` / `cargo test -p lib-q-ml-dsa`
# (and `cargo bench` for the same) resolve to a single instance of the crate under test that also
# satisfies sca-test's request -- so its own `hardened` feature gets turned on. That measures the
# side-channel-MASKED path, not the configuration users get with a plain `cargo build`.
#
# THIS IS NOT HYPOTHETICAL. It already produced a wrong published-sounding number: the "ML-DSA is
# ~7x slower" result was this trap (the real figure is ~1.7x on signing). Confirmed 2026-08-09 via
# captured rustc invocations (`cargo test -p <crate> -v --no-run`, grepped for
# `--crate-name lib_q_ml_kem`/`lib_q_ml_dsa` and `feature="hardened"`) -- see card t_42086971.
#
# Every consumer of `lib-q-sca-test`'s `dudect` module (the only thing any of these tests actually
# use) needs none of sca-test's optional features (`mlkem`, `mldsa`, `privacy`, `hqc-hardened`) --
# `dudect` is unconditional in lib-q-sca-test/src/lib.rs. So `default-features = false` with no
# replacement features is the correct fix, not a partial one.
#
# WHAT IT CHECKS
# ===============
# Every line in any `Cargo.toml` under the repo that declares `lib-q-sca-test = { ... }` as a
# dependency must contain `default-features = false` on that same line (all such declarations in
# this repo are single-line table syntax).
#
# WHAT IT DELIBERATELY DOES NOT DO
# =================================
# It does not check WHICH extra features (if any) a consumer re-enables -- a consumer needing an
# optional sca-test module (e.g. lib-q-lattice-zkp needs `privacy`) may re-enable it explicitly;
# that is fine and expected. It only guards against the DEFAULT-feature-unification trap. It also
# does not parse multi-line `[dependencies.lib-q-sca-test]` table syntax -- none exists in this repo
# today; if that style is introduced this guard must be extended.
#
# Usage:
#   bash scripts/ci-guard-sca-test-default-features.sh [REPO_ROOT]
#   bash scripts/ci-guard-sca-test-default-features.sh --self-test

set -uo pipefail

check_tree() { # check_tree <repo-root> -> findings on stdout, count in $FOUND
  local root="$1"
  FOUND=0
  local f
  while IFS= read -r -d '' f; do
    while IFS=: read -r lineno line; do
      # Skip lib-q-sca-test's own manifest (it doesn't depend on itself) and comments.
      case "$line" in
        *'#'*lib-q-sca-test*) ;;
      esac
      if [[ "$line" != *"default-features = false"* ]]; then
        echo "  FAIL: ${f#"$root"/}:$lineno declares lib-q-sca-test without 'default-features = false'."
        echo "        Cargo unifies a package's dev-dependency features with its own lib target --"
        echo "        sca-test's default features force 'hardened' on for lib-q-ml-kem/lib-q-ml-dsa"
        echo "        when they take it as a dev-dependency, silently measuring the masked path."
        FOUND=$((FOUND + 1))
      fi
    done < <(grep -n '^[[:space:]]*lib-q-sca-test[[:space:]]*=' "$f")
  done < <(find "$root" -name Cargo.toml -not -path '*/target/*' -not -path '*/lib-q-sca-test/Cargo.toml' -print0)
}

self_test() {
  # Prove the guard fires on a manifest missing the flag and stays quiet on one that has it.
  # Without this, a broken guard and a healthy repo look identical -- both print OK.
  local tmp; tmp="$(mktemp -d)" problems=0
  mkdir -p "$tmp/good/lib-q-fake-good" "$tmp/bad/lib-q-fake-bad"

  printf '[dev-dependencies]\nlib-q-sca-test = { path = "../lib-q-sca-test", version = "0.0.10", default-features = false }\n' \
    > "$tmp/good/lib-q-fake-good/Cargo.toml"
  check_tree "$tmp/good" >/dev/null
  [[ $FOUND -ne 0 ]] && { echo "  - a compliant declaration must NOT fire (got $FOUND)"; problems=1; }

  printf '[dev-dependencies]\nlib-q-sca-test = { path = "../lib-q-sca-test", version = "0.0.10" }\n' \
    > "$tmp/bad/lib-q-fake-bad/Cargo.toml"
  check_tree "$tmp/bad" >/dev/null
  [[ $FOUND -eq 0 ]] && { echo "  - a declaration missing default-features=false MUST fire"; problems=1; }

  rm -rf "$tmp"
  if [[ $problems -ne 0 ]]; then
    echo "SELF-TEST FAILED -- the sca-test default-features guard is not detecting what it claims."
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  if self_test; then echo "ci-guard-sca-test-default-features: self-test OK"; exit 0; else exit 1; fi
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
[[ -d "$ROOT" ]] || { echo "ci-guard-sca-test-default-features: missing $ROOT" >&2; exit 1; }

# Re-prove detection before trusting a clean result: a clean tree is the normal state here.
if ! self_test; then exit 1; fi

check_tree "$ROOT"
TOTAL="$(grep -rl '^[[:space:]]*lib-q-sca-test[[:space:]]*=' --include=Cargo.toml "$ROOT" 2>/dev/null | grep -v '/lib-q-sca-test/Cargo.toml$' | wc -l | tr -d ' ')"
if [[ $FOUND -ne 0 ]]; then
  echo "ci-guard-sca-test-default-features: $FOUND lib-q-sca-test dependency declaration(s) without default-features=false"
  exit 1
fi
echo "ci-guard-sca-test-default-features: OK -- all $TOTAL lib-q-sca-test dependency declaration(s) set default-features=false"
