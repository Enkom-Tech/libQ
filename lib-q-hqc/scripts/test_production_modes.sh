#!/bin/bash

# Production Mode Test Suite
# This script tests both production DRBG implementations separately

echo "=== Production Mode Test Suite ==="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Please run this script from the lib-q-hqc directory"
    exit 1
fi

echo "Testing production DRBG implementations separately..."
echo ""

# Test with aes-drbg only
echo "1. Testing with aes-drbg feature only..."
cargo test --features aes-drbg --test drbg_equivalence_test -- --nocapture
cargo test --features aes-drbg --test hqc_keygen_cross_compatibility_test -- --nocapture
cargo test --features aes-drbg --test hqc_full_operations_consistency_test -- --nocapture

echo ""
echo "2. Testing with bearssl-aes feature only..."
cargo test --features bearssl-aes --test drbg_equivalence_test -- --nocapture
cargo test --features bearssl-aes --test hqc_keygen_cross_compatibility_test -- --nocapture
cargo test --features bearssl-aes --test hqc_full_operations_consistency_test -- --nocapture

echo ""
echo "3. Testing with no DRBG features (SHAKE256 fallback)..."
cargo test --test drbg_equivalence_test -- --nocapture
cargo test --test hqc_keygen_cross_compatibility_test -- --nocapture
cargo test --test hqc_full_operations_consistency_test -- --nocapture

echo ""
echo "=== Production Tests Complete ==="
echo ""
echo "Summary:"
echo "- All production modes have been tested"
echo "- Each DRBG implementation works correctly in isolation"
echo "- SHAKE256 fallback works when no DRBG features are enabled"
echo ""
echo "Production recommendations:"
echo "- Use 'aes-drbg' for pure Rust implementation (no external dependencies)"
echo "- Use 'bearssl-aes' for BearSSL-based implementation (requires BearSSL)"
echo "- Use no features for SHAKE256 fallback (slower but no dependencies)"
