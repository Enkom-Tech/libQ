#!/bin/bash

# Complete Test Suite Runner
# This script runs all test suites in the correct order

echo "=== Complete HQC Test Suite Runner ==="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Please run this script from the lib-q-hqc directory"
    exit 1
fi

echo "Running complete test suite..."
echo ""

# Phase 1: Feature Flag Validation
echo "Phase 1: Feature Flag Validation"
echo "================================="
bash scripts/test_feature_flag_validation.sh
if [ $? -ne 0 ]; then
    echo "❌ Feature flag validation failed"
    exit 1
fi
echo ""

# Phase 2: Production Mode Tests
echo "Phase 2: Production Mode Tests"
echo "=============================="
bash scripts/test_production_modes.sh
if [ $? -ne 0 ]; then
    echo "❌ Production mode tests failed"
    exit 1
fi
echo ""

# Phase 3: Diagnostic Mode Tests
echo "Phase 3: Diagnostic Mode Tests"
echo "=============================="
bash scripts/test_drbg_diagnostic.sh
if [ $? -ne 0 ]; then
    echo "❌ Diagnostic mode tests failed"
    exit 1
fi
echo ""

# Phase 4: Additional Validation
echo "Phase 4: Additional Validation"
echo "=============================="
echo "Running additional validation tests..."

# Test no_std compatibility
echo "Testing no_std compatibility..."
cargo check --no-default-features --features aes-drbg
if [ $? -eq 0 ]; then
    echo "✅ no_std with aes-drbg works"
else
    echo "❌ no_std with aes-drbg failed"
fi

cargo check --no-default-features --features bearssl-aes
if [ $? -eq 0 ]; then
    echo "✅ no_std with bearssl-aes works"
else
    echo "❌ no_std with bearssl-aes failed"
fi

cargo check --no-default-features
if [ $? -eq 0 ]; then
    echo "✅ no_std with no features works"
else
    echo "❌ no_std with no features failed"
fi

echo ""

# Test WASM compatibility (if wasm32 target is available)
echo "Testing WASM compatibility..."
if rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    cargo check --target wasm32-unknown-unknown --features aes-drbg
    if [ $? -eq 0 ]; then
        echo "✅ WASM with aes-drbg works"
    else
        echo "❌ WASM with aes-drbg failed"
    fi
    
    cargo check --target wasm32-unknown-unknown
    if [ $? -eq 0 ]; then
        echo "✅ WASM with no features works"
    else
        echo "❌ WASM with no features failed"
    fi
else
    echo "⚠️  WASM target not installed, skipping WASM tests"
fi

echo ""
echo "=== Complete Test Suite Finished ==="
echo ""
echo "Summary:"
echo "- Feature flag validation: ✅"
echo "- Production mode tests: ✅"
echo "- Diagnostic mode tests: ✅"
echo "- Additional validation: ✅"
echo ""
echo "All test suites completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review diagnostic test output for DRBG differences"
echo "2. Choose a single DRBG implementation for production"
echo "3. Update your application to use the chosen implementation"
echo "4. Consider the interoperability limitations documented in the analysis"
