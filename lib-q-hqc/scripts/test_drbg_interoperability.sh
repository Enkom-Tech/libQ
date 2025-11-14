#!/bin/bash

echo "=== DRBG Interoperability Test Suite ==="
echo ""

echo "Phase 1: DRBG Output Compatibility"
cargo test --features aes-drbg,bearssl-aes --test drbg_equivalence_test -- --nocapture

echo ""
echo "Phase 2: HQC Keygen Cross-Compatibility"
cargo test --features aes-drbg,bearssl-aes --test hqc_keygen_cross_compatibility_test -- --nocapture

echo ""
echo "Phase 3: Full HQC Operations Consistency"
cargo test --features aes-drbg,bearssl-aes --test hqc_full_operations_consistency_test -- --nocapture

echo ""
echo "=== All Interoperability Tests Complete ==="
