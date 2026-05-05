# lib-q-aead

A high-performance, quantum-resistant Authenticated Encryption with Associated Data (AEAD) library for Rust, designed for the libQ cryptographic ecosystem.

## Overview

lib-q-aead provides secure, post-quantum AEAD implementations using NIST-approved algorithms. The library emphasizes security-first design with comprehensive timing attack protection, constant-time operations, and robust input validation.

## Features

- **Quantum-Resistant**: Implements NIST-approved post-quantum algorithms
- **Security-First**: Comprehensive timing attack protection and constant-time operations
- **High Performance**: Optimized implementations with minimal overhead
- **Modular Design**: Pluggable architecture supporting multiple algorithms
- **Production Ready**: Extensive testing and security validation
- **No-Std Support**: Works in embedded and no-std environments

## Supported Algorithms

### SHAKE256 AEAD
- **Algorithm**: SHAKE256-based AEAD construction
- **Security Level**: 128-bit post-quantum security
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 256 bits (32 bytes)

### Saturnin AEAD
- **Algorithm**: Saturnin block cipher in AEAD mode
- **Security Level**: 128-bit post-quantum security
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 128 bits (16 bytes)

## Quick Start

### Basic Usage

```rust
use lib_q_aead::{create_aead, Algorithm, AeadKey, Nonce};

// Create an AEAD instance
let aead = create_aead(Algorithm::Shake256Aead)?;

// Generate or load your key and nonce
let key = AeadKey::new(vec![0x01; 32]); // In practice, use secure random generation
let nonce = Nonce::new(vec![0x02; 16]); // In practice, use secure random generation

// Your data to encrypt
let plaintext = b"Hello, World!";
let associated_data = b"metadata";

// Encrypt
let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data))?;

// Decrypt
let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data))?;

assert_eq!(decrypted, plaintext);
```

### Advanced Usage with Security Configuration

```rust
use lib_q_aead::{
    create_aead, Algorithm, AeadKey, Nonce,
    security::{SecurityConfig, SecurityContext}
};

// Create AEAD with custom security configuration
let aead = create_aead(Algorithm::Shake256Aead)?;

// Configure security settings
let security_config = SecurityConfig::strict();
let security_ctx = SecurityContext::with_config(security_config);

// Use with timing protection
let key = AeadKey::new(secure_random_bytes(32));
let nonce = Nonce::new(secure_random_bytes(16));

// Encrypt with security context
let ciphertext = security_ctx.protect_timing(|| {
    aead.encrypt(&key, &nonce, plaintext, Some(associated_data))
})?;
```

## Security Features

### Timing Attack Protection

The library provides comprehensive timing attack protection:

```rust
use lib_q_aead::security::timing::{TimingProtection, protect_timing};

// Automatic timing protection
let result = protect_timing(|| {
    // Your cryptographic operation
    aead.decrypt(&key, &nonce, &ciphertext, Some(aad))
})?;

// Custom timing protection configuration
let timing_protection = TimingProtection::strict();
let result = timing_protection.protect(|| {
    aead.decrypt(&key, &nonce, &ciphertext, Some(aad))
})?;
```

### Constant-Time Operations

All critical operations are implemented in constant time:

```rust
use lib_q_aead::security::constant_time::constant_time_eq;

// Secure comparison
let is_equal = constant_time_eq(&tag1, &tag2);

// Secure selection
let result = constant_time_select(condition, &value1, &value2);
```

### Input Validation

Comprehensive input validation prevents common security issues:

```rust
use lib_q_aead::security::validation::{validate_key, validate_nonce};

// Validate key material
validate_key(key_bytes)?;

// Validate nonce
validate_nonce(nonce_bytes)?;
```

## Performance

The library is optimized for high performance while maintaining security:

- **SHAKE256 AEAD**: ~2-5μs per operation (typical)
- **Saturnin AEAD**: ~1-3μs per operation (typical)
- **Memory Usage**: Minimal stack allocation with secure cleanup
- **Timing Protection**: <10% overhead in protected mode

## Feature Flags

- `shake256`: Enable SHAKE256 AEAD implementation (default)
- `saturnin`: Enable Saturnin AEAD implementation
- `std`: Enable standard library features (default)
- `no-std`: Disable standard library for embedded environments

## Security Considerations

### Key Management
- Always use cryptographically secure random number generation for keys
- Never reuse keys across different contexts
- Implement proper key rotation policies

### Nonce Management
- Never reuse nonces with the same key
- Use cryptographically secure random number generation for nonces
- Consider using counter-based nonces for high-throughput scenarios

### Timing Attacks
- The library provides timing protection, but ensure your application doesn't introduce timing leaks
- Use the provided security contexts for sensitive operations
- Test your application for timing vulnerabilities

## Examples

See the `examples/` directory for comprehensive usage examples:

- `basic_usage.rs`: Basic encryption/decryption
- `security_features.rs`: Advanced security features
- `performance_benchmarks.rs`: Performance testing
- `no_std_example.rs`: Embedded usage

## Testing

The library includes comprehensive tests:

```bash
# Run all tests
cargo test

# Run security tests
cargo test --test comprehensive_security_tests

# Run performance benchmarks
cargo bench
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Security

For security issues, please see the main libQ repository's security policy.

## Workspace

Exposes Saturnin and SHAKE-based AEAD integrations for [`lib-q-hpke`](../lib-q-hpke) and the umbrella stack. See the [workspace README](../README.md) for the full crate graph.
