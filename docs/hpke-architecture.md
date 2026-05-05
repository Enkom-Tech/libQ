# HPKE Architecture

The lib-q-hpke implementation provides RFC 9180 compliant Hybrid Public Key Encryption using post-quantum cryptographic primitives. The architecture follows a provider pattern that integrates with the lib-q ecosystem for algorithm-agnostic cryptographic operations.

## Architecture Overview

The HPKE implementation uses a provider pattern that abstracts cryptographic operations through the lib-q ecosystem:

```
lib-q-hpke
├── PostQuantumProvider
│   ├── KEM: ML-KEM-512, ML-KEM-768, ML-KEM-1024
│   ├── KDF: HKDF-SHAKE128, HKDF-SHAKE256, HKDF-SHA3-256, HKDF-SHA3-512
│   └── AEAD: Saturnin-256, SHAKE256, duplex-sponge AEAD, Export-only
├── Security Layer
│   ├── Side-channel protection
│   ├── Memory safety
│   └── Input validation
└── Integration Layer
    ├── lib-q-core types
    ├── lib-q-kem operations
    └── lib-q-aead operations
```

## Security Levels

The implementation supports different security levels through algorithm selection:

- **Level 1 (NIST category 1)**: ML-KEM-512 — FIPS 203 parameter set ML-KEM-512
- **Level 3 (NIST category 3)**: ML-KEM-768 — FIPS 203 parameter set ML-KEM-768
- **Level 5 (NIST category 5)**: ML-KEM-1024 — FIPS 203 parameter set ML-KEM-1024

## Core Components

```rust
/// HPKE cipher suite specification
pub struct HpkeCipherSuite {
    /// Key encapsulation mechanism
    pub kem: HpkeKem,
    /// Key derivation function
    pub kdf: HpkeKdf,
    /// Authenticated encryption algorithm
    pub aead: HpkeAead,
}

/// HPKE context for stateful operations
pub struct HpkeContext {
    /// KEM context for key operations
    kem_ctx: KemContext,
    /// Cipher suite configuration
    cipher_suite: HpkeCipherSuite,
}

/// HPKE sender context for multiple message encryption
pub struct HpkeSenderContext {
    /// Shared secret from KEM
    pub shared_secret: Vec<u8>,
    /// Exporter secret
    pub exporter_secret: Vec<u8>,
    /// AEAD encryption key
    pub key: Vec<u8>,
    /// Base nonce
    pub nonce: Vec<u8>,
    /// Encapsulated key to be sent to receiver
    pub encapsulated_key: Vec<u8>,
    /// Sequence number
    pub sequence_number: u32,
    /// Context state
    pub state: HpkeContextState,
}

/// HPKE receiver context for multiple message decryption
pub struct HpkeReceiverContext {
    /// Shared secret from KEM
    pub shared_secret: Vec<u8>,
    /// Exporter secret
    pub exporter_secret: Vec<u8>,
    /// AEAD decryption key
    pub key: Vec<u8>,
    /// Base nonce
    pub nonce: Vec<u8>,
    /// Sequence number
    pub sequence_number: u32,
    /// Context state
    pub state: HpkeContextState,
}
```

## PostQuantumProvider Implementation

The PostQuantumProvider is the core provider that implements all HPKE operations using post-quantum algorithms. It provides a unified interface for all supported cryptographic primitives.

### Key Features

- **Algorithm-Agnostic Design**: Uses lib-q abstractions for all cryptographic operations
- **Comprehensive Algorithm Support**: Supports ML-KEM variants, post-quantum hash functions, and AEAD algorithms
- **Security-First Implementation**: Constant-time operations, secure memory management, and comprehensive input validation
- **RFC 9180 Compliance**: Full implementation of HPKE specification including all modes

### Implementation

```rust
/// Post-quantum provider implementation
pub struct PostQuantumProvider;

impl PostQuantumProvider {
    /// Create a new post-quantum provider
    pub fn new() -> Self {
        Self
    }

    /// Convert HPKE KEM to lib-q-core Algorithm
    fn hpke_kem_to_algorithm(kem: HpkeKem) -> Result<Algorithm, HpkeError> {
        match kem {
            HpkeKem::MlKem512 => Ok(Algorithm::MlKem512),
            HpkeKem::MlKem768 => Ok(Algorithm::MlKem768),
            HpkeKem::MlKem1024 => Ok(Algorithm::MlKem1024),
        }
    }

    /// Create a KEM instance using lib-q-kem abstraction
    fn create_kem_instance(kem: HpkeKem) -> Result<Box<dyn CoreKem>, HpkeError> {
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        create_kem(algorithm)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create KEM instance: {}", e)))
    }
}
```

## HPKE Modes and Authentication

The implementation supports all HPKE modes as specified in RFC 9180:

### Base Mode
Standard HPKE without additional authentication. Provides confidentiality through KEM encapsulation/decapsulation.

### PSK Mode
Pre-shared key authentication mode. PSK is incorporated into the key schedule with validation.

### Auth Mode
Sender authentication using asymmetric keys. Implements AuthEncap/AuthDecap for cryptographic sender verification.

### AuthPSK Mode
Combined PSK and sender authentication. Provides maximum security with both shared secret and sender verification.

### Authentication implementation

Auth / AuthPSK modes follow **RFC 9180** key schedules and use the same ML-KEM KEM id (`HpkeKem`) as base mode, with sender key material mixed into the HPKE context (see `lib-q-hpke/src/hpke_core/` and `auth_mode_tests.rs`). The repository previously included illustrative pseudocode here that did not match the checked-in implementation; read the crate sources and RFC for precise encap/decap ordering.

**Key security properties (intent):**

- **Sender authentication (Auth modes)** — Recipient can cryptographically verify that the sender used the claimed KEM secret key material, per RFC 9180.
- **RFC 9180 alignment** — Mode bits and suite IDs are exercised by `rfc9180_compliance_tests` and related tests in `lib-q-hpke/tests/`.
- **Forward secrecy** — Still governed by the ephemeral KEM half of the HPKE key schedule; see RFC 9180 security analysis for your deployment profile.

## Security Guarantees

The HPKE implementation provides comprehensive security guarantees:

### Post-Quantum Security
- **KEM Security**: All KEM algorithms (ML-KEM-512, ML-KEM-768, ML-KEM-1024) provide IND-CCA2 security
- **Key Derivation**: HKDF with post-quantum hash functions (SHAKE256, SHA3) ensures secure key derivation
- **AEAD Security**: Saturnin-256 provides authenticated encryption with post-quantum security

### Implementation Security

**Constant-Time Operations**: All cryptographic operations use constant-time algorithms to prevent timing attacks. Key functions include `constant_time_compare()`, `constant_time_select()`, and `verify_auth_tag_constant_time()`.

**Memory Safety**: Sensitive data is automatically zeroed using the `Zeroize` trait. Secure containers (`SecureBytes`, `SecureKey`, `SecureStackBuffer`) provide automatic cleanup.

**Input Validation**: Comprehensive validation includes side-channel resistant key validation, nonce validation, and ciphertext validation. All validation functions maintain constant-time properties.

**Error Handling**: Error messages are designed to prevent information leakage while maintaining consistent timing characteristics.

### Authentication Security
- **Sender Authentication**: AuthEncap/AuthDecap provides cryptographic proof of sender identity
- **Key Validation**: All keys are validated for correct size and format before use
- **Context Security**: Sequence numbers prevent replay attacks and ensure proper message ordering

### Performance Characteristics

| Algorithm | Security Level | Key Size | Ciphertext Size | Performance |
|-----------|---------------|----------|-----------------|-------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 bytes | 768 bytes | Fast |
| ML-KEM-768 | Level 3 (192-bit) | 1184 bytes | 1088 bytes | Balanced |
| ML-KEM-1024 | Level 5 (256-bit) | 1568 bytes | 1568 bytes | Secure |
| Saturnin-256 | Post-quantum | 32 bytes | 16 bytes | Fast |

## Integration with lib-Q Ecosystem

The HPKE implementation is designed to integrate seamlessly with the broader lib-Q ecosystem:

### Provider Pattern Integration
- **lib-q-core**: Uses `KemContext`, `KemPublicKey`, `KemSecretKey` for consistent key management
- **lib-q-kem**: Leverages `create_kem()` for algorithm-agnostic KEM operations
- **lib-q-hash**: Uses `create_hash()` for algorithm-agnostic hash functions
- **lib-q-aead**: Uses `create_aead()` for algorithm-agnostic authenticated encryption

### Algorithm Support
- **Current**: ML-KEM-512, ML-KEM-768, ML-KEM-1024; KDFs `HKDF-SHAKE128/256`, `HKDF-SHA3-256/512`; AEADs **Saturnin-256**, **SHAKE256**, **duplex-sponge AEAD**, **export-only** (see `lib-q-hpke/src/types.rs` `HpkeKdf` / `HpkeAead`)
- **Future**: Additional post-quantum algorithms as they become available

## Usage Examples

### Basic HPKE Usage

```rust
use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create HPKE context with the same provider used for key generation
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair using the same provider
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
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

### Authenticated Mode

```rust
// Setup sender with authentication
let mut sender_ctx = hpke_ctx.setup_sender_auth(
    &recipient_pk,
    b"session-info",
    &sender_sk,
    &sender_pk,
)?;

// Setup receiver with authentication
let mut receiver_ctx = hpke_ctx.setup_receiver_auth(
    &encapsulated_key,
    &recipient_sk,
    b"session-info",
    &sender_pk,
)?;
```

## Advanced Usage Examples

### Authenticated HPKE (Auth Mode)

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_hpke::{HpkeContext, HpkeMode};
use libq::LibQCryptoProvider;

fn authenticated_hpke_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pairs for both sender and recipient
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());
    
    // Setup authenticated sender context
    let mut sender_ctx = hpke_ctx.setup_sender_auth(
        &recipient_pk,
        b"authenticated-session",
        &sender_sk,
        &sender_pk,
    )?;
    
    // Encrypt message with sender authentication
    let message = b"Sensitive authenticated message";
    let ciphertext = sender_ctx.seal(b"metadata", message)?;
    
    // Setup authenticated receiver context
    let mut receiver_ctx = hpke_ctx.setup_receiver_auth(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"authenticated-session",
        &sender_pk,
    )?;
    
    // Decrypt and verify sender authentication
    let decrypted = receiver_ctx.open(b"metadata", &ciphertext)?;
    assert_eq!(decrypted, message);
    
    Ok(())
}
```

### PSK Mode with Pre-Shared Key

```rust
fn psk_hpke_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    
    // Define pre-shared key and identifier
    let psk = b"shared-secret-key-32-bytes-long";
    let psk_id = b"psk-identifier";
    
    // Setup PSK sender context
    let mut sender_ctx = hpke_ctx.setup_sender_psk(
        &recipient_pk,
        b"psk-session",
        psk,
        psk_id,
    )?;
    
    // Encrypt message with PSK authentication
    let message = b"Message authenticated with PSK";
    let ciphertext = sender_ctx.seal(b"metadata", message)?;
    
    // Setup PSK receiver context
    let mut receiver_ctx = hpke_ctx.setup_receiver_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"psk-session",
        psk,
        psk_id,
    )?;
    
    // Decrypt and verify PSK authentication
    let decrypted = receiver_ctx.open(b"metadata", &ciphertext)?;
    assert_eq!(decrypted, message);
    
    Ok(())
}
```

### Export-Only Mode for Key Derivation

```rust
fn export_only_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()?));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    
    // Setup sender context for key export
    let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"key-export-session")?;
    
    // Export keys for different purposes
    let encryption_key = sender_ctx.export(b"encryption-key", 32)?;
    let mac_key = sender_ctx.export(b"mac-key", 32)?;
    let session_id = sender_ctx.export(b"session-id", 16)?;
    
    // Setup receiver context for key export
    let mut receiver_ctx = hpke_ctx.setup_receiver(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"key-export-session",
    )?;
    
    // Export the same keys on receiver side
    let receiver_encryption_key = receiver_ctx.export(b"encryption-key", 32)?;
    let receiver_mac_key = receiver_ctx.export(b"mac-key", 32)?;
    let receiver_session_id = receiver_ctx.export(b"session-id", 16)?;
    
    // Keys should be identical
    assert_eq!(encryption_key, receiver_encryption_key);
    assert_eq!(mac_key, receiver_mac_key);
    assert_eq!(session_id, receiver_session_id);
    
    Ok(())
}
```

## Security Considerations and Best Practices

### Key Management

1. **Key Generation**: Always use cryptographically secure random number generators
2. **Key Storage**: Store secret keys in secure memory containers that auto-zeroize
3. **Key Rotation**: Implement regular key rotation for long-term security
4. **Key Validation**: Always validate key material before use

```rust
use lib_q_hpke::security::{validate_kem_key, KeyType, SecureKey};

// Secure key storage (length must match `KeyType::expected_length()`)
let secret_key = SecureKey::new(vec![1u8; 32], KeyType::AeadKey)?;
// Key material is zeroized on drop (`memory_safety::SecureKey`)

// KEM wire validation (inputs must match `HpkeKem::public_key_len` / `secret_key_len`)
let pk = [0u8; 800]; // ML-KEM-512 public key length
let sk = [1u8; 1632]; // ML-KEM-512 secret key length
validate_kem_key(HpkeKem::MlKem512, &pk, false)?;
validate_kem_key(HpkeKem::MlKem512, &sk, true)?;
```

### Context Management

1. **Sequence Numbers**: Monitor sequence numbers to prevent overflow
2. **Context State**: Check context state before operations
3. **Rekeying**: Implement proper rekeying when sequence numbers approach limits

```rust
use lib_q_hpke::HpkeContextState;

// `HpkeSenderContext` exposes `state` and `sequence_number` fields (see `lib-q-hpke/src/types.rs`)
if sender_ctx.state == HpkeContextState::NeedsRekey {
    sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"new-session")?;
}
if sender_ctx.sequence_number > 1_000_000 {
    // Application policy: consider rekeying long sessions
}
```

### Error Handling

1. **Never Ignore Errors**: Always handle HPKE errors appropriately
2. **Error Logging**: Log errors without exposing sensitive information
3. **Graceful Degradation**: Implement fallback mechanisms for critical operations

```rust
match hpke_ctx.seal(&recipient_pk, info, aad, message) {
    Ok((encapsulated_key, ciphertext)) => {
        // Success - proceed with encrypted data
    }
    Err(HpkeError::CryptoError(msg)) => {
        // Log error without sensitive details
        eprintln!("HPKE encryption failed: {}", msg);
        return Err("Encryption failed".into());
    }
    Err(e) => {
        // Handle other error types
        return Err(format!("HPKE error: {}", e).into());
    }
}
```

### Performance Optimization

1. **Context Reuse**: Reuse HPKE contexts for multiple messages when possible
2. **Algorithm Selection**: Choose appropriate algorithms based on security requirements
3. **Memory Management**: Use stack-allocated buffers when possible

```rust
// Reuse context for multiple messages
let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session")?;

for message in messages {
    let ciphertext = sender_ctx.seal(b"metadata", message)?;
    // Process ciphertext...
}
```

## API Documentation

For detailed API reference, see [API_REFERENCE.md](../lib-q-hpke/docs/API_REFERENCE.md).
