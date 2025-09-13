# lib-q-hpke

Post-quantum Hybrid Public Key Encryption (HPKE) implementation compliant with RFC 9180.

## Overview

This crate provides a complete HPKE implementation using exclusively post-quantum cryptographic algorithms. It integrates with lib-q's provider pattern architecture for modular algorithm support and is designed to be algorithm-agnostic, allowing easy integration of new cryptographic primitives.

## Supported Algorithms

**Key Encapsulation**: ML-KEM-512, ML-KEM-768, ML-KEM-1024  
**Authenticated Encryption**: Saturnin-256  
**Key Derivation**: HKDF-SHAKE128, HKDF-SHAKE256, HKDF-SHA3-256, HKDF-SHA3-512

## Features

- `ml-kem`: ML-KEM key encapsulation algorithms
- `saturnin`: Saturnin authenticated encryption  
- `hash`: Post-quantum hash functions
- `std`: Standard library support
- `alloc`: Heap allocation support

## Usage

### Basic Encryption

```rust
use lib_q_hpke::HpkeContext;

let mut hpke_ctx = HpkeContext::new();
let message = b"Hello, HPKE!";

// Encrypt
let (encapsulated_key, ciphertext) = hpke_ctx.seal(
    &recipient_pk,
    b"application-info",
    b"additional-data", 
    message
)?;

// Decrypt
let decrypted = hpke_ctx.open(
    &encapsulated_key,
    &recipient_sk,
    b"application-info",
    b"additional-data",
    &ciphertext
)?;
```

### Context-based Operations

```rust
// Setup sender context for multiple messages
let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session-info")?;

// Encrypt multiple messages
let ciphertext1 = sender_ctx.seal(b"aad1", msg1)?;
let ciphertext2 = sender_ctx.seal(b"aad2", msg2)?;

// Export key material
let exported_key = sender_ctx.export(b"key-context", 32)?;
```

### Custom Cipher Suites

```rust
use lib_q_hpke::{HpkeKem, HpkeKdf, HpkeAead, HpkeCipherSuite};

let suite = HpkeCipherSuite::new(
    HpkeKem::MlKem768,
    HpkeKdf::HkdfSha3_256,
    HpkeAead::Saturnin256
);
```

## Architecture

### Comprehensive Algorithm-Agnostic Design

The HPKE implementation is designed to be comprehensively algorithm-agnostic through the provider pattern:

- **KEM Provider**: Abstracts key encapsulation mechanisms using `lib-q-kem` (currently ML-KEM variants)
- **KDF Provider**: Abstracts key derivation functions using `lib-q-hash` (HKDF variants)
- **AEAD Provider**: Abstracts authenticated encryption using `lib-q-aead` (currently Saturnin-256)
- **Crypto Provider**: Combines all providers for complete HPKE operations

This comprehensive design allows easy integration of new post-quantum algorithms without modifying the core HPKE protocol implementation.

### Provider Integration

The implementation uses lib-q abstractions for all cryptographic primitives, ensuring compatibility with the broader lib-q ecosystem:

- **KEM Operations**: Uses `lib-q-kem::create_kem()` for algorithm-agnostic KEM operations
- **Hash Operations**: Uses `lib-q-hash::create_hash()` for algorithm-agnostic hash functions
- **AEAD Operations**: Uses `lib-q-aead::create_aead()` for algorithm-agnostic authenticated encryption

```rust
use lib_q_kem::create_kem;
use lib_q_hash::create_hash;
use lib_q_aead::create_aead;
use lib_q_core::Algorithm;

// Create cryptographic instances algorithm-agnostically
let kem_impl = create_kem(Algorithm::MlKem512)?;
let hash_impl = create_hash("shake256")?;
let aead_impl = create_aead("saturnin")?;

// Use the instances for cryptographic operations
let keypair = kem_impl.generate_keypair()?;
let hash_output = hash_impl.hash(b"data")?;
let ciphertext = aead_impl.encrypt(&key, &nonce, b"plaintext", Some(b"aad"))?;
```

## Security

This implementation uses only post-quantum algorithms, providing resistance against both classical and quantum attacks. All operations follow constant-time principles where possible.

## License

See the main [lib-q license](../LICENSE).
