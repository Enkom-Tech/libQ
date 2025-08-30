# lib-q-hpke

**Post-Quantum Hybrid Public Key Encryption (HPKE) for lib-q**

This crate provides RFC 9180 compliant HPKE implementation using only **post-quantum algorithms**. It integrates with lib-q's provider pattern architecture.

## ⚠️ Current Status

**This crate is in early development.** Core HPKE logic is implemented but crypto integrations are placeholders.

### Implemented
- ✅ HPKE types and algorithms (post-quantum only)
- ✅ Provider pattern integration
- ✅ Core HPKE logic structure
- ✅ Workspace integration

### In Progress
- 🔄 ML-KEM integration for KEM operations
- 🔄 Ascon integration for AEAD operations
- 🔄 Post-quantum KDF implementation
- 🔄 Key schedule implementation

### Supported Algorithms

#### KEM (Key Encapsulation)
- ✅ ML-KEM-512 (Kyber-512)
- ✅ ML-KEM-768 (Kyber-768)
- ✅ ML-KEM-1024 (Kyber-1024)

#### AEAD (Authenticated Encryption)
- ✅ Ascon-128
- ✅ Ascon-128a
- 🔄 Ascon-80pq (future)
- 🔄 Xoodyak (future)
- 🔄 Sparkle (future)

#### KDF (Key Derivation)
- ✅ HKDF-SHAKE128
- ✅ HKDF-SHAKE256
- ✅ HKDF-SHA3-256
- ✅ HKDF-SHA3-512

## Architecture

This crate follows lib-q's provider pattern:

```rust
use lib_q_hpke::HpkeContext;
use lib_q_core::Algorithm;

#[cfg(feature = "hpke")]
{
    // Create HPKE context with default provider
    let mut hpke_ctx = HpkeContext::new();

    // Single-shot encryption (when implemented)
    // let (encapsulated_key, ciphertext) = hpke_ctx.seal(...)?
}
```

## Features

- **`default`**: `alloc`, `ml-kem`, `ascon`, `hash`
- **`std`**: Enables standard library support
- **`alloc`**: Enables heap allocation
- **`ml-kem`**: ML-KEM KEM algorithms
- **`ml-dsa`**: ML-DSA authentication (future)
- **`hash`**: Post-quantum hash functions
- **`ascon`**: Ascon AEAD algorithms

## Usage

```rust
use lib_q_hpke::HpkeContext;
use lib_q_core::Algorithm;

#[cfg(feature = "hpke")]
fn example() -> Result<(), Box<dyn std::error::Error>> {
    // Create HPKE context
    let mut hpke_ctx = HpkeContext::new();

    // Future: Single-shot encryption
    // let (enc, ciphertext) = hpke_ctx.seal(
    //     &recipient_public_key,
    //     b"info",
    //     b"aad",
    //     b"secret message"
    // )?;

    Ok(())
}
```

## Security

This implementation uses **only post-quantum algorithms**:
- No classical elliptic curves (x25519, P256, etc.)
- No classical symmetric crypto (AES-GCM, ChaCha20Poly1305)
- No classical hash functions (SHA-256, etc.)

All cryptographic operations are designed to be resistant to quantum attacks.

## Development Status

**Not ready for production use.** This crate is under active development:

1. **Complete crypto integrations** (ML-KEM, Ascon, post-quantum KDF)
2. **Comprehensive testing** (unit, integration, fuzzing)
3. **Security audit**
4. **Performance optimization**

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).

## License

See the main [lib-q license](../LICENSE).
