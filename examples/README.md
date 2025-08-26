# lib-Q Examples

This directory contains examples demonstrating the usage of lib-Q post-quantum cryptography library.

## ML-DSA Examples

### Running ML-DSA Examples

Some ML-DSA examples require the `ml-dsa` feature to be enabled. Run them with:

```bash
# Full integration test (high-level and low-level APIs)
cargo run --example ml_dsa_full_integration_test --features "lib-q-sig/ml-dsa"

# No_std example (external randomness)
cargo run --example ml_dsa_no_std_example --features "lib-q-sig/ml-dsa"

# No_std trait test
cargo run --example ml_dsa_no_std_trait_test --features "lib-q-sig/ml-dsa"

# Working no_std example (uses lib_q_ml_dsa directly)
cargo run --example ml_dsa_working_no_std

# Integration test (uses main libq crate)
cargo run --example ml_dsa_integration_test
```

### Example Descriptions

#### `ml_dsa_full_integration_test.rs`
Comprehensive integration test demonstrating:
- High-level API with automatic randomness generation (std environment)
- Low-level API with external randomness provision (no_std compatible)
- ML-DSA-65 variant testing

#### `ml_dsa_no_std_example.rs`
Simple example showing ML-DSA usage in no_std environments:
- Keypair generation with external randomness
- Message signing with external randomness
- Signature verification
- Demonstrates rejection of invalid signatures

#### `ml_dsa_no_std_trait_test.rs`
Tests the Signature trait implementation in no_std environments:
- Verifies trait works with alloc feature
- Verifies trait behavior without alloc feature
- Tests proper return types based on feature flags

#### `ml_dsa_working_no_std.rs`
Working example using lib_q_ml_dsa directly:
- Demonstrates all ML-DSA variants (44, 65, 87)
- Shows proper no_std usage patterns
- No feature flags required

#### `ml_dsa_integration_test.rs`
Integration test using the main libq crate:
- Tests algorithm availability
- Tests signature context functionality
- No feature flags required

### Features

- **ML-DSA-44**: Level 1 security (128-bit)
- **ML-DSA-65**: Level 3 security (192-bit) 
- **ML-DSA-87**: Level 4 security (256-bit)

### Key Sizes (ML-DSA-65)
- **Public key size**: 1952 bytes
- **Secret key size**: 4032 bytes  
- **Signature size**: 3309 bytes

### Security Notes

⚠️ **Important**: The examples use deterministic randomness (all zeros) for demonstration purposes. In production, always use cryptographically secure random sources.

## Other Examples

### Hash Example

```bash
cargo run --example hash_example
```

Demonstrates various hash functions including SHA-3, Keccak, and cSHAKE.
