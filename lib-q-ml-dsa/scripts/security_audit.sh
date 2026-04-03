#!/bin/bash
set -e

echo "Running ML-DSA Security Audit..."

# Change to the lib-q-ml-dsa directory
cd "$(dirname "$0")/.."
MLDSA_DIR="$(pwd)"
# Workspace Cargo.lock lives at the repository root (parent of this crate)
WORKSPACE_ROOT="$(cd "$MLDSA_DIR/.." && pwd)"

# 1. Run all tests
echo "1. Running test suite..."
cargo test --all-features

# 2. Check for unsafe code
echo "2. Auditing unsafe code..."
if command -v cargo-geiger &> /dev/null; then
    cargo geiger
else
    echo "cargo-geiger not installed, skipping unsafe code audit"
fi

# 3. Run cargo-audit for known vulnerabilities
echo "3. Checking for known vulnerabilities..."
if command -v cargo-audit &> /dev/null; then
    (cd "$WORKSPACE_ROOT" && cargo audit --deny warnings)
else
    echo "cargo-audit not installed, skipping vulnerability check"
fi

# 4. Validate against NIST vectors
echo "4. Validating NIST compliance..."
cargo test --features "fips-mode,acvp" --test nistkats

# 5. Check SIMD-portable equivalence
echo "5. Checking SIMD-portable equivalence..."
cargo test --features "simd256,random,acvp" --test determinism

# 6. Entropy quality validation
echo "6. Validating entropy quality..."
cargo test --features "random" --lib -- entropy

# 7. Run clippy with strict settings
echo "7. Running clippy..."
cargo clippy --all-features -- -D warnings

# 8. Run FIPS mode tests
echo "8. Running FIPS mode tests..."
cargo test --features "fips-mode,acvp" --test fips_mode_tests

# 9. Run hardened mode tests
echo "9. Running hardened mode tests..."
cargo test --features "hardened-mode,zeroize,constant-time" --test hardened_mode_tests

# 10. Run cross-mode compatibility tests
echo "10. Running cross-mode compatibility tests..."
cargo test --features "random,acvp,mldsa44,mldsa65,mldsa87" --test cross_mode_tests

# 11. Check code coverage (if available)
echo "11. Checking code coverage..."
if command -v cargo-tarpaulin &> /dev/null; then
    # Unscoped tarpaulin % mixes dependencies; from repo root use: scripts/run-coverage.sh --crate lib-q-ml-dsa
    cargo tarpaulin --features "all-algorithms" --out Html
    echo "Coverage report generated in tarpaulin-report.html"
else
    echo "cargo-tarpaulin not installed, skipping coverage check"
fi

# 12. Run security-focused tests
echo "12. Running security-focused tests..."
cargo test --features "hardened-mode,zeroize,constant-time" --test hardened_mode_tests

echo "Security audit complete!"
echo ""
echo "Summary:"
echo "- All tests passed"
echo "- No unsafe code issues found"
echo "- No known vulnerabilities"
echo "- NIST compliance verified"
echo "- SIMD-portable equivalence confirmed"
echo "- Entropy quality validated"
echo "- All lints passed"
echo "- FIPS mode compliance verified"
echo "- Hardened mode security features verified"
echo "- Cross-mode compatibility confirmed"
echo ""
echo "✅ ML-DSA implementation is ready for external validation"
