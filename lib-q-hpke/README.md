# lib-q-hpke

Post-Quantum Hybrid Public Key Encryption (HPKE) implementation for lib-q.

This crate provides RFC 9180 compliant HPKE using exclusively post-quantum cryptographic algorithms. The implementation follows lib-q's provider pattern architecture for modular algorithm integration.

## Status

**Development Phase**: Core HPKE framework is implemented with placeholder crypto integrations.

### Completed
- HPKE type definitions and algorithm specifications
- Provider pattern integration
- Core HPKE protocol structure
- Workspace integration

### Development Tasks
- ML-KEM integration for key encapsulation
- Saturnin integration for authenticated encryption
- Post-quantum key derivation functions
- Key schedule implementation

## Supported Algorithms

### Key Encapsulation Mechanisms
- ML-KEM-512 (Kyber-512)
- ML-KEM-768 (Kyber-768) 
- ML-KEM-1024 (Kyber-1024)

### Authenticated Encryption
- Saturnin-256 (post-quantum symmetric)
- SHAKE256-based constructions

### Key Derivation Functions
- HKDF-SHAKE128
- HKDF-SHAKE256
- HKDF-SHA3-256
- HKDF-SHA3-512

## Architecture

The HPKE implementation follows lib-q's provider pattern for modular algorithm integration:

```rust
use lib_q_hpke::HpkeContext;
use lib_q_core::Algorithm;

#[cfg(feature = "hpke")]
{
    let mut hpke_ctx = HpkeContext::new();
    // let (encapsulated_key, ciphertext) = hpke_ctx.seal(...)?;
}
```

## Features

- `default`: `alloc`, `ml-kem`, `saturnin`, `hash`
- `std`: Standard library support
- `alloc`: Heap allocation support
- `ml-kem`: ML-KEM key encapsulation algorithms
- `saturnin`: Saturnin authenticated encryption
- `hash`: Post-quantum hash functions

## Usage

```rust
use lib_q_hpke::HpkeContext;
use lib_q_core::Algorithm;

#[cfg(feature = "hpke")]
fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut hpke_ctx = HpkeContext::new();
    
    // let (enc, ciphertext) = hpke_ctx.seal(
    //     &recipient_public_key,
    //     b"info",
    //     b"aad", 
    //     b"secret message"
    // )?;

    Ok(())
}
```

## Security Model

This implementation exclusively uses post-quantum cryptographic algorithms:

- **KEMs**: ML-KEM (NIST PQC Standard)
- **AEAD**: Saturnin (post-quantum symmetric)
- **KDF**: SHAKE256-based key derivation
- **Hash**: SHAKE256, SHA3-256, SHA3-512

No classical algorithms are supported, ensuring resistance to quantum attacks.

## Development Status

**Pre-production**: Active development phase.

### Remaining Tasks
1. Complete cryptographic algorithm integrations
2. Comprehensive test suite implementation
3. Security audit and validation
4. Performance optimization and benchmarking

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).

## License

See the main [lib-q license](../LICENSE).
