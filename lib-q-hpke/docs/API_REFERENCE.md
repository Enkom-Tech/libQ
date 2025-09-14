# HPKE API Reference

## Overview

The lib-q-hpke API provides RFC 9180 compliant Hybrid Public Key Encryption operations using post-quantum cryptographic primitives. The API is designed around a provider pattern that integrates with the lib-q ecosystem.

## Core Types

### HpkeContext

Main context for HPKE operations.

```rust
pub struct HpkeContext {
    // Private fields
}
```

**Methods:**

```rust
impl HpkeContext {
    /// Create a new HPKE context with the specified provider
    pub fn with_provider(provider: Box<dyn HpkeCryptoProvider>) -> Self
    
    /// Single-shot encryption (Base mode)
    pub fn seal(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError>
    
    /// Single-shot decryption (Base mode)
    pub fn open(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>
}
```

### Context Setup Methods

```rust
impl HpkeContext {
    /// Setup sender context for Base mode
    pub fn setup_sender(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
    ) -> Result<HpkeSenderContext, HpkeError>
    
    /// Setup receiver context for Base mode
    pub fn setup_receiver(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
    ) -> Result<HpkeReceiverContext, HpkeError>
    
    /// Setup sender context for PSK mode
    pub fn setup_sender_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeSenderContext, HpkeError>
    
    /// Setup receiver context for PSK mode
    pub fn setup_receiver_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeReceiverContext, HpkeError>
    
    /// Setup sender context for Auth mode
    pub fn setup_sender_auth(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeSenderContext, HpkeError>
    
    /// Setup receiver context for Auth mode
    pub fn setup_receiver_auth(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeReceiverContext, HpkeError>
    
    /// Setup sender context for AuthPSK mode
    pub fn setup_sender_auth_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeSenderContext, HpkeError>
    
    /// Setup receiver context for AuthPSK mode
    pub fn setup_receiver_auth_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeReceiverContext, HpkeError>
}
```

## Context Types

### HpkeSenderContext

Context for multiple message encryption.

```rust
pub struct HpkeSenderContext {
    // Private fields
}

impl HpkeSenderContext {
    /// Encrypt a message
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError>
    
    /// Export key material
    pub fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError>
    
    /// Get the encapsulated key
    pub fn encapsulated_key(&self) -> &[u8]
    
    /// Get current sequence number
    pub fn sequence_number(&self) -> u32
    
    /// Get context state
    pub fn state(&self) -> HpkeContextState
}
```

### HpkeReceiverContext

Context for multiple message decryption.

```rust
pub struct HpkeReceiverContext {
    // Private fields
}

impl HpkeReceiverContext {
    /// Decrypt a message
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError>
    
    /// Export key material
    pub fn export(&self, context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError>
    
    /// Get current sequence number
    pub fn sequence_number(&self) -> u32
    
    /// Get context state
    pub fn state(&self) -> HpkeContextState
}
```

## Algorithm Types

### HpkeKem

Key Encapsulation Mechanism algorithms.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl HpkeKem {
    /// Get algorithm identifier
    pub fn algorithm_id(&self) -> u16
    
    /// Get public key length
    pub fn public_key_len(&self) -> usize
    
    /// Get secret key length
    pub fn secret_key_len(&self) -> usize
    
    /// Get encapsulated key length
    pub fn encapsulated_key_len(&self) -> usize
}
```

### HpkeKdf

Key Derivation Function algorithms.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKdf {
    HkdfShake128,
    HkdfShake256,
    HkdfSha3_256,
    HkdfSha3_512,
}

impl HpkeKdf {
    /// Get algorithm identifier
    pub fn algorithm_id(&self) -> u16
    
    /// Get extract output length
    pub fn extract_output_len(&self) -> usize
}
```

### HpkeAead

Authenticated Encryption with Associated Data algorithms.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    Saturnin256,
    Shake256,
    Export,
}

impl HpkeAead {
    /// Get algorithm identifier
    pub fn algorithm_id(&self) -> u16
    
    /// Get key length
    pub fn key_len(&self) -> usize
    
    /// Get nonce length
    pub fn nonce_len(&self) -> usize
    
    /// Get tag length
    pub fn tag_len(&self) -> usize
}
```

### HpkeCipherSuite

Complete cipher suite specification.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCipherSuite {
    pub kem: HpkeKem,
    pub kdf: HpkeKdf,
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    /// Create a new cipher suite
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self
    
    /// Get suite identifier
    pub fn suite_id(&self) -> Vec<u8>
}
```

## Error Handling

### HpkeError

Comprehensive error type for HPKE operations.

```rust
#[derive(Debug, Clone)]
pub enum HpkeError {
    KemError {
        algorithm: HpkeKem,
        operation: KemOperation,
        cause: String,
    },
    KdfError {
        algorithm: HpkeKdf,
        operation: KdfOperation,
        cause: String,
    },
    AeadError {
        algorithm: HpkeAead,
        operation: AeadOperation,
        cause: String,
    },
    CryptoError(String),
    InvalidInput {
        parameter: String,
        value: String,
        expected: String,
    },
    ProtocolError {
        stage: ProtocolStage,
        cause: String,
    },
}

impl HpkeError {
    /// Create a KEM error
    pub fn kem_error(algorithm: HpkeKem, operation: KemOperation, cause: impl Into<String>) -> Self
    
    /// Create a KDF error
    pub fn kdf_error(algorithm: HpkeKdf, operation: KdfOperation, cause: impl Into<String>) -> Self
    
    /// Create an AEAD error
    pub fn aead_error(algorithm: HpkeAead, operation: AeadOperation, cause: impl Into<String>) -> Self
    
    /// Create a crypto error
    pub fn crypto_error(cause: impl Into<String>) -> Self
    
    /// Create an invalid input error
    pub fn invalid_input(parameter: impl Into<String>, value: impl Into<String>, expected: impl Into<String>) -> Self
}
```

## Provider Interface

### HpkeCryptoProvider

Trait for cryptographic operations.

```rust
pub trait HpkeCryptoProvider {
    type Error: Into<HpkeError>;
    
    /// Generate a key pair
    fn generate_keypair(
        &self,
        kem: HpkeKem,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    
    /// Encapsulate a shared secret
    fn encapsulate(
        &self,
        kem: HpkeKem,
        public_key: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    
    /// Decapsulate a shared secret
    fn decapsulate(
        &self,
        kem: HpkeKem,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// Authenticated encapsulation
    fn auth_encapsulate(
        &self,
        kem: HpkeKem,
        sender_sk: &[u8],
        recipient_pk: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    
    /// Authenticated decapsulation
    fn auth_decapsulate(
        &self,
        kem: HpkeKem,
        encapsulated_key: &[u8],
        recipient_sk: &[u8],
        sender_pk: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// Extract key material
    fn extract(
        &self,
        kdf: HpkeKdf,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// Expand key material
    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// Encrypt with AEAD
    fn seal(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// Decrypt with AEAD
    fn open(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}
```

## Security Types

### SecureKey

Secure key storage with automatic zeroization.

```rust
pub struct SecureKey {
    // Private fields
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(data: Vec<u8>) -> Self
    
    /// Get key data as slice
    pub fn as_slice(&self) -> &[u8]
    
    /// Get mutable key data
    pub fn as_mut_slice(&mut self) -> &mut [u8]
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Automatic zeroization
    }
}
```

### SecureBytes

Secure byte storage with automatic zeroization.

```rust
pub struct SecureBytes {
    // Private fields
}

impl SecureBytes {
    /// Create new secure bytes
    pub fn new(data: Vec<u8>) -> Self
    
    /// Get data as slice
    pub fn as_slice(&self) -> &[u8]
    
    /// Get mutable data
    pub fn as_mut_slice(&mut self) -> &mut [u8]
}
```

## Usage Examples

### Basic HPKE

```rust
use lib_q_core::{Algorithm, KemContext, KemPublicKey, KemSecretKey};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

fn basic_hpke_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    
    // Encrypt
    let message = b"Hello, HPKE!";
    let (encapsulated_key, ciphertext) = hpke_ctx.seal(
        &recipient_pk,
        b"application-info",
        b"additional-data",
        message,
    )?;
    
    // Decrypt
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
fn context_based_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Setup sender context
    let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session-info")?;
    
    // Encrypt multiple messages
    let ciphertext1 = sender_ctx.seal(b"aad1", b"message1")?;
    let ciphertext2 = sender_ctx.seal(b"aad2", b"message2")?;
    
    // Export key material
    let exported_key = sender_ctx.export(b"key-context", 32)?;
    
    Ok(())
}
```

### PSK Mode

```rust
fn psk_mode_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    let psk = b"shared-secret-key-32-bytes-long";
    let psk_id = b"psk-identifier";
    
    // Setup PSK sender
    let mut sender_ctx = hpke_ctx.setup_sender_psk(
        &recipient_pk,
        b"psk-session",
        psk,
        psk_id,
    )?;
    
    // Encrypt with PSK authentication
    let ciphertext = sender_ctx.seal(b"metadata", b"PSK message")?;
    
    Ok(())
}
```

### Auth Mode

```rust
fn auth_mode_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Setup authenticated sender
    let mut sender_ctx = hpke_ctx.setup_sender_auth(
        &recipient_pk,
        b"auth-session",
        &sender_sk,
        &sender_pk,
    )?;
    
    // Encrypt with sender authentication
    let ciphertext = sender_ctx.seal(b"metadata", b"authenticated message")?;
    
    Ok(())
}
```

## Error Handling

```rust
fn error_handling_example() -> Result<(), Box<dyn std::error::Error>> {
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
    
    Ok(())
}
```

## Security Considerations

- All cryptographic operations use constant-time algorithms where possible
- Sensitive data is automatically zeroized when dropped
- Input validation is performed on all parameters
- Error messages are designed to prevent information leakage
- Context state is validated before operations

## Thread Safety

The HPKE implementation is designed to be thread-safe:
- `HpkeContext` can be shared between threads using `Arc<Mutex<HpkeContext>>`
- Context objects (`HpkeSenderContext`, `HpkeReceiverContext`) are not thread-safe and should be used by a single thread
- Provider implementations must be thread-safe
