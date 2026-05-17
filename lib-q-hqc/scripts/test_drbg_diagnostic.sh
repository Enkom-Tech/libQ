#!/bin/bash

# DRBG Diagnostic Mode Test Suite
# This script runs the diagnostic mode tests to analyze DRBG interoperability

echo "=== DRBG Diagnostic Mode Test Suite ==="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Please run this script from the lib-q-hqc directory"
    exit 1
fi

echo "Running with debug-drbg-interop feature enabled..."
echo ""

# Run the dedicated DRBG interoperability tests
echo "1. Running dedicated DRBG interoperability tests..."
cargo test --features aes-drbg,bearssl-aes,debug-drbg-interop --test drbg_interop_tests -- --nocapture

echo ""
echo "2. Running DRBG equivalence tests with diagnostic logging..."
cargo test --features aes-drbg,bearssl-aes,debug-drbg-interop --test drbg_equivalence_test -- --nocapture

echo ""
echo "3. Running HQC keygen tests with diagnostic logging..."
cargo test --features aes-drbg,bearssl-aes,debug-drbg-interop --test hqc_keygen_cross_compatibility_test -- --nocapture

echo ""
echo "4. Running HQC full operations tests with diagnostic logging..."
cargo test --features aes-drbg,bearssl-aes,debug-drbg-interop --test hqc_full_operations_consistency_test -- --nocapture

echo ""
echo "=== Diagnostic Tests Complete ==="
echo ""
echo "Summary:"
echo "- All diagnostic tests have been executed"
echo "- Check the output above for any differences between DRBG implementations"
echo "- Diagnostic logs show divergence points and comparison results"
echo ""
echo "For production use, choose a single DRBG implementation:"
echo "- Use 'aes-drbg' for pure Rust implementation"
echo "- Use 'bearssl-aes' for BearSSL-based implementation"
echo "- Avoid using 'debug-drbg-interop' in production"
