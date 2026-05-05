# Entropy Validation in lib-Q

## Overview

Entropy validation guards **optional deterministic seeds** and similar inputs in paths that use `lib-q-core`’s `SecurityValidator` / `EntropyValidator` (for example the **CB-KEM** `LibQCbKemProvider`). This document summarizes behavior and safe testing patterns; authoritative APIs are in `lib-q-core/src/security/`.

## Security Architecture

The entropy validation system is designed with security-first principles:

- **Production Mode**: Strict entropy validation by default
- **Testing Mode**: Configurable relaxed validation for deterministic testing
- **Feature Flags**: Compile-time configuration for different environments

## Entropy Validation Levels

### Strict Validation (Production)

Strict validation is the default mode and includes:

1. **Minimum Length Check**: Ensures keys meet minimum entropy requirements (128 bits)
2. **Pattern Detection**: Detects repeated and sequential patterns
3. **Entropy Estimation**: Basic entropy quality assessment
4. **Security Checks**: Prevents obviously weak keys (all zeros, all ones)

### Relaxed Validation (Testing)

Relaxed validation is designed for testing scenarios:

1. **Reduced Length Requirements**: Minimum 16 bytes instead of 128 bits
2. **Basic Security Checks**: Only prevents all-zeros and all-ones keys
3. **Pattern Tolerance**: Allows deterministic patterns for reproducible testing
4. **No Entropy Estimation**: Skips complex entropy analysis

## Configuration Methods

### Method 1: Runtime Configuration

```rust
use lib_q_cb_kem::LibQCbKemProvider;

// Create provider
let mut provider = LibQCbKemProvider::new()?;

// For testing: disable entropy validation
provider.security_validator_mut()
    .entropy_validator_mut()
    .set_entropy_validation(false);

// Use deterministic randomness for testing
let test_seed = b"deterministic_test_seed_for_reproducible_testing";
let keypair = provider.generate_keypair(Algorithm::CbKem348864, Some(test_seed))?;
```

### Method 2: Feature flag on `lib-q-core`

Relaxed validation is implemented **inside `lib-q-core`** behind the feature flag **`relaxed_entropy_validation`** (see `lib-q-core/src/security/entropy.rs`). Enable it from the crate that depends on `lib-q-core`, for example:

```toml
[dependencies]
lib-q-core = { path = "../lib-q-core", version = "0.0.2", features = ["relaxed_entropy_validation"] }
```

There is **no** separate `relaxed_entropy_validation` feature on `lib-q-cb-kem` itself—wire `lib-q-core` features through your dependency edge when you need compile-time relaxed checks in CI or tests.

## Usage Guidelines

### Production Applications

```rust
// ✅ CORRECT: Use secure randomness in production
let keypair = provider.generate_keypair(Algorithm::CbKem348864, None)?;
let (ciphertext, secret) = provider.encapsulate(Algorithm::CbKem348864, &public_key, None)?;
```

**Key Points:**
- Always use `None` for randomness parameter
- Entropy validation remains enabled
- Uses secure system entropy sources

### Testing Applications

```rust
// ✅ CORRECT: Use deterministic randomness for testing
let mut provider = LibQCbKemProvider::new()?;
provider.security_validator_mut()
    .entropy_validator_mut()
    .set_entropy_validation(false);

let test_seed = b"well_designed_deterministic_seed_for_testing";
let keypair = provider.generate_keypair(Algorithm::CbKem348864, Some(test_seed))?;
```

**Key Points:**
- Disable entropy validation for testing
- Use well-designed deterministic seeds
- Ensure reproducible test results

## Security Considerations

### ⚠️ Security Warnings

1. **Never disable entropy validation in production**
2. **Never use deterministic seeds in production**
3. **Always use secure randomness for real cryptographic operations**

### Best Practices

1. **Testing Seeds**: Design deterministic seeds to avoid obvious patterns
2. **CI/CD**: Use consistent seeds for reproducible builds
3. **Documentation**: Clearly document when relaxed validation is used
4. **Code Reviews**: Ensure production code doesn't disable validation

## Examples

### Production Example

See `examples/cb_kem_production_example.rs` for a complete production example.

### Testing Example

See `examples/cb_kem_testing_example.rs` for a complete testing example.

### Simple Example

See `examples/cb_kem_simple_example.rs` for a basic example with deterministic randomness.

## Implementation Details

### Entropy Validator API

```rust
impl EntropyValidator {
    /// Create new validator with default settings
    pub fn new() -> Result<Self>;
    
    /// Validate key entropy (uses strict or relaxed based on feature flags)
    pub fn validate_key_entropy(&self, key_data: &[u8]) -> Result<()>;
    
    /// Enable or disable entropy validation
    pub fn set_entropy_validation(&mut self, enabled: bool);
    
    /// Check if entropy validation is enabled
    pub fn is_entropy_validation_enabled(&self) -> bool;
}
```

### Security Validator API

```rust
impl SecurityValidator {
    /// Get immutable access to entropy validator
    pub fn entropy_validator(&self) -> &EntropyValidator;
    
    /// Get mutable access to entropy validator
    pub fn entropy_validator_mut(&mut self) -> &mut EntropyValidator;
}
```

## Troubleshooting

### Common Issues

1. **"Key contains sequential patterns"**: Use better deterministic seeds or disable validation for testing
2. **"Key does not have sufficient entropy"**: Ensure keys meet minimum length requirements
3. **Hanging during encapsulation**: Use deterministic randomness for testing or ensure system has sufficient entropy

### Solutions

1. **For Testing**: Disable entropy validation and use deterministic seeds
2. **For Production**: Ensure system entropy sources are available
3. **For CI/CD**: Use consistent deterministic seeds with relaxed validation

Treat entropy controls as **part of the integration surface**: keep validation on in production paths, and restrict deterministic seeds and `set_entropy_validation(false)` to tests and tooling.
