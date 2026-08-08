#!/usr/bin/env bash
# lib-Q security check -- run from a pre-commit hook and by hand (see DEVELOPMENT.md).
#
# WHAT THIS SCRIPT USED TO BE, AND WHY IT WAS REPLACED
# =====================================================
# Every source-scanning check here was of the form
#
#     if grep -r "use.*aes\|use.*sha256\|use.*rsa\|use.*ecdsa" src/ 2>/dev/null; then
#         print_status "FAIL" ...; exit 1
#     else
#         print_status "PASS" "No classical cryptographic algorithms found"
#     fi
#
# and there were eight of them. They all scanned a repo-root `src/` directory, which
# stopped existing when libQ split into `lib-q-*` crates. `grep` matched nothing,
# `2>/dev/null` swallowed the "No such file or directory" that would have revealed it, and
# so five checks always printed PASS and three (written `if ! grep`) always printed WARN.
# The FAIL branch was unreachable on this layout: the script could not fail.
#
# It then printed a Summary section of PASS/WARN marks that were hardcoded string
# literals, unrelated to anything the run had observed. A green result from this script
# was evidence of nothing at all.
#
# WHAT REPLACED IT
# =================
# One check that can fail, plus the audit. The eight grep checks were not repointed,
# because most of them could not be made meaningful:
#
#   * "No classical cryptographic algorithms" -- premise is false. 21 tracked files use
#     one, nearly all because a standard says to (FIPS 205 SLH-DSA-SHA2, MAYO's AES-CTR
#     matrix expansion, NIST KAT AES-CTR-DRBGs). Repointed as written it would fail on
#     correct code. It is now a RATCHET over a reviewed allowlist -- see below.
#   * "SHA-3 family compliance" (`use.*sha[0-9]` minus shake/cshake) -- would match this
#     repo's own `use lib_q_sha3::...`, i.e. flag the compliant crate as a violation.
#   * unsafe / zeroize / "if.*secret" / unwrap / assert / rand presence greps -- each was
#     a WARN whichever way it went, on a codebase where every one of them is present in
#     quantity. A check with one possible outcome carries no information.
#   * `cargo doc` missing-docs count, tarpaulin coverage, and a full wasm-pack build --
#     minutes of work per commit, and CI already gates all three properly
#     (.github/workflows/ci.yml, coverage.yml, and the wasm-build action).
#
# Deleting a check that cannot fail is not a loss of coverage. It never had any.
#
# THE CHECK THAT REMAINS
# =======================
# A post-quantum library cannot ban classical crypto outright -- see above. What it can do
# is ensure no NEW classical dependency appears without someone looking at it. Every
# classical dependency declared by any tracked crate must appear in
# scripts/classical-crypto-allowlist.txt with a reason. A new one fails; an allowlist entry
# that no longer matches anything also fails, so the list cannot rot into a blanket permit.
#
# Implementation and full rationale: scripts/security_check_classical_crypto.py.
#
# THIS SCRIPT HAS BEEN SEEN TO FAIL
# ==================================
# The predecessor's whole problem was that it never could, so a clean run here is only
# meaningful if the check is known to reject something. `--self-test` runs first and
# replays a fixture covering a new shipped dependency, a new dev-only one, one hidden
# behind a `package = "..."` rename, one in a `[target.'cfg(...)'.dependencies]` table, and
# a stale allowlist entry -- plus controls that must NOT fire (a covered dependency, a
# clean crate, and workspace-root version pins).
#
# Usage: bash scripts/security-check.sh [REPO_ROOT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(git rev-parse --show-toplevel)}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Every check appends its outcome here, and the summary is printed FROM this array. The
# predecessor's summary was a block of hardcoded marks; deriving it is the whole point.
declare -a RESULTS=()
FAILED=0

record() { # record <PASS|WARN|FAIL> <name>
    RESULTS+=("$1|$2")
    [[ "$1" == "FAIL" ]] && FAILED=1
    return 0
}

echo "Running lib-Q security checks..."
echo ""

# Probe by RUNNING each candidate: on Windows a `python3` App Execution Alias sits on PATH
# and satisfies `command -v` while refusing to execute (the same trap the ci-guard-*
# scripts work around).
PY_BIN=""
for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
        PY_BIN="$candidate"
        break
    fi
done

RATCHET="$SCRIPT_DIR/security_check_classical_crypto.py"

if [[ -z "$PY_BIN" ]]; then
    # Do not silently skip: a missing interpreter must not read as a pass.
    echo -e "${RED}FAIL${NC}: no working python3 interpreter; cannot run the classical-crypto ratchet"
    record FAIL "classical-crypto ratchet (interpreter missing)"
elif [[ ! -f "$RATCHET" ]]; then
    echo -e "${RED}FAIL${NC}: $RATCHET is missing"
    record FAIL "classical-crypto ratchet (script missing)"
else
    echo "Proving the ratchet can fail (self-test)..."
    if "$PY_BIN" "$RATCHET" --self-test; then
        echo -e "${GREEN}PASS${NC}: ratchet self-test -- detection verified against known-bad input"
        record PASS "ratchet self-test"
    else
        echo -e "${RED}FAIL${NC}: ratchet self-test -- the check is not detecting what it claims"
        record FAIL "ratchet self-test"
    fi

    echo ""
    echo "Checking the classical-cryptography surface..."
    ratchet_out=""
    ratchet_rc=0
    ratchet_out="$("$PY_BIN" "$RATCHET" "$ROOT" 2>&1)" || ratchet_rc=$?
    echo "$ratchet_out"
    if [[ $ratchet_rc -eq 0 ]]; then
        if echo "$ratchet_out" | grep -q "WARN:"; then
            echo -e "${YELLOW}WARN${NC}: classical-crypto surface unchanged, with unjustified entries outstanding"
            record WARN "classical-crypto ratchet"
        else
            echo -e "${GREEN}PASS${NC}: classical-crypto surface matches the reviewed allowlist"
            record PASS "classical-crypto ratchet"
        fi
    else
        echo -e "${RED}FAIL${NC}: classical-crypto surface differs from the reviewed allowlist"
        record FAIL "classical-crypto ratchet"
    fi
fi

echo ""
echo "Running cargo audit..."
if command -v cargo-audit >/dev/null 2>&1; then
    if cargo audit --deny warnings; then
        echo -e "${GREEN}PASS${NC}: cargo audit"
        record PASS "cargo audit"
    else
        echo -e "${RED}FAIL${NC}: cargo audit reported advisories"
        record FAIL "cargo audit"
    fi
else
    echo -e "${YELLOW}WARN${NC}: cargo-audit not installed (cargo install cargo-audit); CI runs it regardless"
    record WARN "cargo audit (not installed)"
fi

echo ""
echo "Summary"
echo "--------------------------------------------------"
for entry in "${RESULTS[@]}"; do
    status="${entry%%|*}"
    name="${entry#*|}"
    case "$status" in
        PASS) echo -e "  ${GREEN}PASS${NC}  $name" ;;
        WARN) echo -e "  ${YELLOW}WARN${NC}  $name" ;;
        FAIL) echo -e "  ${RED}FAIL${NC}  $name" ;;
    esac
done
echo "--------------------------------------------------"

if [[ $FAILED -ne 0 ]]; then
    echo ""
    echo -e "${RED}Security check FAILED.${NC}"
    exit 1
fi

echo ""
echo "Security check passed."
echo "Note: this covers the classical-crypto surface and the advisory audit only."
echo "Coverage, docs, WASM and lints are gated in CI, not here."
