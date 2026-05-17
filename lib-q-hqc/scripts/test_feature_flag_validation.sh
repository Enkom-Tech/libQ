#!/bin/bash

# Feature Flag Validation Test Suite
# This script validates that feature flags work correctly and prevent invalid combinations

echo "=== Feature Flag Validation Test Suite ==="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Please run this script from the lib-q-hqc directory"
    exit 1
fi

echo "Validating feature flag combinations..."
echo ""

# Test 1: Both features enabled without debug-drbg-interop (should fail)
echo "1. Testing invalid combination: aes-drbg + bearssl-aes without debug-drbg-interop"
echo "   (This should fail with a compile error)"
if cargo check --features aes-drbg,bearssl-aes 2>&1 | grep -q "compile_error"; then
    echo "   ✅ Correctly failed with compile error"
else
    echo "   ❌ Should have failed but didn't"
    exit 1
fi

echo ""

# Test 2: Both features enabled with debug-drbg-interop (should succeed)
echo "2. Testing valid combination: aes-drbg + bearssl-aes + debug-drbg-interop"
echo "   (This should compile successfully)"
if cargo check --features aes-drbg,bearssl-aes,debug-drbg-interop; then
    echo "   ✅ Correctly compiled with debug-drbg-interop"
else
    echo "   ❌ Failed to compile with debug-drbg-interop"
    exit 1
fi

echo ""

# Test 3: Only aes-drbg (should succeed)
echo "3. Testing single feature: aes-drbg only"
if cargo check --features aes-drbg; then
    echo "   ✅ Correctly compiled with aes-drbg only"
else
    echo "   ❌ Failed to compile with aes-drbg only"
    exit 1
fi

echo ""

# Test 4: Only bearssl-aes (should succeed)
echo "4. Testing single feature: bearssl-aes only"
if cargo check --features bearssl-aes; then
    echo "   ✅ Correctly compiled with bearssl-aes only"
else
    echo "   ❌ Failed to compile with bearssl-aes only"
    exit 1
fi

echo ""

# Test 5: No features (should succeed with SHAKE256 fallback)
echo "5. Testing no features (SHAKE256 fallback)"
if cargo check; then
    echo "   ✅ Correctly compiled with no features (SHAKE256 fallback)"
else
    echo "   ❌ Failed to compile with no features"
    exit 1
fi

echo ""
echo "=== Feature Flag Validation Complete ==="
echo ""
echo "Summary:"
echo "- Invalid combinations are properly rejected"
echo "- Valid combinations compile successfully"
echo "- Single features work correctly"
echo "- No features fallback works correctly"
echo ""
echo "Feature flag management is working as expected!"
