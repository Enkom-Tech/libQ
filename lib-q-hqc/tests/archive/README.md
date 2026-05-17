# Archived Diagnostic Tests

This directory contains diagnostic and debug test files that were used during the development and debugging of the HQC implementation. These tests are preserved for historical reference and potential future regression testing.

## Purpose

These tests were created to:
- Debug AES implementation differences between various backends
- Analyze DRBG state transitions and counter behavior
- Compare intermediate values with reference implementations
- Investigate KAT (Known Answer Test) compatibility issues
- Trace vector generation and polynomial operations

## When They Were Used

These tests were actively used during:
- BearSSL AES porting to pure Rust (2025)
- DRBG interoperability analysis
- KAT compliance debugging
- Reference implementation comparison studies

## How to Run Archived Tests

To run these tests, you need to enable the `archive-tests` feature:

```bash
# Run a specific archived test
cargo test --features "archive-tests" --test debug_drbg_detailed

# Run all archived tests
cargo test --features "archive-tests"

# Run with specific algorithm features
cargo test --features "archive-tests,bearssl-aes,hqc128"
```

## Test Categories

### Debug AES Tests (6 files)
- `debug_aes_comparison.rs` - Compare different AES implementations
- `debug_aes_detailed.rs` - Detailed AES operation analysis
- `debug_aes_implementation.rs` - AES implementation debugging
- `debug_aes_openssl_comparison.rs` - OpenSSL AES comparison
- `debug_aes_with_instantiate_key.rs` - AES instantiation key debugging (archived 2025)
- `debug_aes_with_zero_key.rs` - AES zero-key testing (archived 2025)
- `debug_openssl_ecb_behavior.rs` - OpenSSL ECB mode behavior analysis (archived 2025)

### Debug DRBG Tests (15 files)
- `debug_block_by_block_comparison.rs` - Block-by-block DRBG analysis
- `debug_counter_increment_comparison.rs` - Counter increment behavior
- `debug_drbg_detailed.rs` - Detailed DRBG state analysis
- `debug_drbg_exact_flow.rs` - Exact DRBG flow tracing
- `debug_drbg_exact_trace.rs` - Exact DRBG trace debugging (archived 2025)
- `debug_drbg_reverse_engineer.rs` - DRBG reverse engineering (archived 2025)
- `debug_drbg_state_tracking.rs` - State tracking across operations
- `debug_drbg_state_transitions.rs` - State transition analysis
- `debug_drbg_step_by_step.rs` - Step-by-step DRBG execution (archived 2025)
- `debug_drbg_vs_keygen_test.rs` - DRBG vs keygen comparison
- `debug_same_instance_test.rs` - Same instance behavior testing
- `debug_single_call_vs_multiple_calls.rs` - Call pattern analysis
- `debug_state_transitions.rs` - General state transition debugging

### Debug Reference Tests (6 files)
- `debug_reference_approach.rs` - Reference implementation approach
- `debug_reference_behavior_test.rs` - Reference behavior analysis
- `debug_reference_comparison.rs` - Reference comparison studies
- `debug_reference_flow.rs` - Reference flow tracing
- `debug_reference_intermediates.rs` - Reference intermediate values

### Debug Hash and Crypto Tests (2 files)
- `debug_hash_i_test.rs` - Hash_i function verification (archived 2025)
- `debug_sha3_comparison.rs` - SHA3 implementation comparison (archived 2025)

### Debug Other Tests (6 files)
- `debug_detailed_sequence.rs` - Detailed sequence analysis
- `debug_direct_seed_kem.rs` - Direct seed KEM testing
- `debug_h_generation_detailed.rs` - H vector generation analysis
- `debug_h_vector_generation.rs` - H vector generation debugging
- `debug_hash_i_domains.rs` - Hash domain analysis
- `debug_kat_analysis.rs` - KAT analysis and debugging
- `debug_seed_derivation.rs` - Seed derivation debugging
- `debug_seed_ek_generation.rs` - Seed EK generation analysis

## Important Notes

- These tests are **excluded from default `cargo test`** runs
- They require the `archive-tests` feature to be compiled
- Some tests may have dependencies on features that are no longer available
- These tests are primarily for historical reference and debugging
- The main functional tests are in the parent `tests/` directory

## Recent Archival (2025)

The following 8 files were archived after successfully resolving HQC KAT test failures:
- `debug_aes_with_instantiate_key.rs` - AES instantiation debugging
- `debug_aes_with_zero_key.rs` - AES zero-key testing
- `debug_drbg_exact_trace.rs` - DRBG exact trace analysis
- `debug_drbg_reverse_engineer.rs` - DRBG reverse engineering
- `debug_drbg_step_by_step.rs` - DRBG step-by-step debugging
- `debug_hash_i_test.rs` - Hash_i function verification
- `debug_openssl_ecb_behavior.rs` - OpenSSL ECB behavior analysis
- `debug_sha3_comparison.rs` - SHA3 implementation comparison

**Achievement**: All HQC KAT tests now pass with correct parameter alignment (N2=384, N1N2=17664, CT_SIZE=4433).

## Current Status

As of the cleanup (2025), the HQC implementation:
- ✅ All 116+ tests passing (70 lib + 46+ integration tests)
- ✅ Full KAT compatibility with reference implementation
- ✅ Pure Rust BearSSL AES (`bearssl_aes_pure.rs`) for exact KAT compatibility
- ✅ Standard Rust AES (`aes_ctr_drbg.rs`) for general use
- ✅ Single-backend architecture with no C dependencies
- ✅ no_std, WASM, and SIMD support verified
- ✅ Public key generation matches reference exactly
- ✅ Encaps/Decaps roundtrip verified

The issues these diagnostic tests were investigating have been resolved through:
- Correct HQC-1 parameter alignment with reference implementation
- BearSSL AES porting to pure Rust
- SHAKE-256 PRNG implementation matching reference
- XOF byte consumption synchronization
- Vector serialization fixes
