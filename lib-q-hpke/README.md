# lib-q-hpke

RFC 9180 compliant Hybrid Public Key Encryption implementation using post-quantum cryptographic primitives.

## Overview

lib-q-hpke provides a secure, efficient implementation of HPKE (Hybrid Public Key Encryption) using NIST-approved post-quantum algorithms. The implementation follows a provider pattern that integrates with the lib-q ecosystem for algorithm-agnostic cryptographic operations.

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)
- ML-KEM-512 (Level 1 security)
- ML-KEM-768 (Level 3 security)
- ML-KEM-1024 (Level 5 security)

### Key Derivation Functions (KDF)
- HKDF-SHAKE128
- HKDF-SHAKE256
- HKDF-SHA3-256
- HKDF-SHA3-512

### Authenticated Encryption (AEAD)
- Saturnin-256
- SHAKE256-based AEAD
- Export-only mode

## Quick Start

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create HPKE context
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    
    // Encrypt message
    let message = b"Hello, HPKE!";
    let (encapsulated_key, ciphertext) = hpke_ctx.seal(
        &recipient_pk,
        b"application-info",
        b"additional-data",
        message,
    )?;
    
    // Decrypt message
    let decrypted = hpke_ctx.open(
        &encapsulated_key,
        &recipient_sk,
        b"application-info",
        b"additional-data",
        &ciphertext,
    )?;
    
    assert_eq!(decrypted, message);
    Ok(())
}
```

## HPKE Modes

### Base Mode
Standard HPKE without additional authentication.

```rust
let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session-info")?;
let ciphertext = sender_ctx.seal(b"aad", message)?;
```

### PSK Mode
Pre-shared key authentication.

```rust
let psk = b"shared-secret-key";
let psk_id = b"psk-identifier";
let mut sender_ctx = hpke_ctx.setup_sender_psk(
    &recipient_pk,
    b"session-info",
    psk,
    psk_id,
)?;
```

### Auth Mode
Sender authentication using asymmetric keys.

```rust
let mut sender_ctx = hpke_ctx.setup_sender_auth(
    &recipient_pk,
    b"session-info",
    &sender_sk,
    &sender_pk,
)?;
```

### AuthPSK Mode
Combined PSK and sender authentication.

```rust
let mut sender_ctx = hpke_ctx.setup_sender_auth_psk(
    &recipient_pk,
    b"session-info",
    psk,
    psk_id,
    &sender_sk,
    &sender_pk,
)?;
```

## Documentation

- [Architecture Overview](docs/hpke-architecture.md) - High-level architecture and design
- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [Security Considerations](docs/SECURITY_CONSIDERATIONS.md) - Security analysis and best practices
- [Architecture Details](docs/ARCHITECTURE.md) - Detailed implementation architecture

## Testing

The implementation includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test --test psk_mode_comprehensive_tests
cargo test --test authpsk_mode_comprehensive_tests
cargo test --test security_validation_comprehensive_tests
```

## Performance

Performance characteristics for different security levels:

| Algorithm | Security Level | Key Size | Ciphertext Size | Performance |
|-----------|---------------|----------|-----------------|-------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 bytes | 768 bytes | Fast |
| ML-KEM-768 | Level 3 (192-bit) | 1184 bytes | 1088 bytes | Balanced |
| ML-KEM-1024 | Level 5 (256-bit) | 1568 bytes | 1568 bytes | Secure |

## Dependencies

- `lib-q-core` - Core cryptographic types and interfaces
- `lib-q-kem` - Key encapsulation mechanism implementations
- `lib-q-hash` - Hash function implementations
- `lib-q-aead` - Authenticated encryption implementations
- `libq` - Unified lib-q provider

## License

This project is licensed under the same terms as the lib-q project.
