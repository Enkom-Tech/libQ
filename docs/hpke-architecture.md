# HPKE Architecture

The lib-q-hpke implementation provides RFC 9180 compliant Hybrid Public Key Encryption using post-quantum cryptographic primitives. The architecture follows a provider pattern that integrates with the lib-q ecosystem for algorithm-agnostic cryptographic operations.

## Architecture Overview

The HPKE implementation uses a provider pattern that abstracts cryptographic operations through the lib-q ecosystem:

```
lib-q-hpke
├── PostQuantumProvider
│   ├── KEM: ML-KEM-512, ML-KEM-768, ML-KEM-1024
│   ├── KDF: HKDF-SHAKE128, HKDF-SHAKE256, HKDF-SHA3-256, HKDF-SHA3-512
│   └── AEAD: Saturnin-256, SHAKE256, Export-only
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

- **Level 1 Security**: ML-KEM-512 (AES-128 equivalent)
- **Level 3 Security**: ML-KEM-768 (AES-192 equivalent)  
- **Level 5 Security**: ML-KEM-1024 (AES-256 equivalent)

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

### Authentication Implementation

The HPKE authentication modes (Auth and AuthPSK) implement RFC 9180 compliant authentication using a second KEM operation. This provides cryptographic authentication of the sender's identity.

```rust
/// Authenticated encapsulation (RFC 9180 AuthEncap)
/// This performs a second KEM operation using the sender's secret key
/// to authenticate the sender's identity to the recipient.
fn auth_encapsulate(
    &self,
    kem: HpkeKem,
    sender_sk: &[u8],
    recipient_pk: &[u8],
    rng: &mut dyn CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    // 1. Perform standard encapsulation to recipient's public key
    let (encapsulated_key, shared_secret) = self.encapsulate(kem, recipient_pk, rng)?;
    
    // 2. Perform second KEM operation for authentication
    // This uses the sender's secret key to create an authentication proof
    let (auth_encapsulated_key, auth_shared_secret) = self.encapsulate(kem, sender_pk, rng)?;
    
    // 3. Combine shared secrets using HKDF
    let combined_shared_secret = self.combine_shared_secrets(
        &shared_secret,
        &auth_shared_secret,
        b"HPKE Auth",
    )?;
    
    Ok((encapsulated_key, combined_shared_secret))
}

/// Authenticated decapsulation (RFC 9180 AuthDecap)
/// This verifies the sender's authentication by performing the corresponding
/// decapsulation operation using the sender's public key.
fn auth_decapsulate(
    &self,
    kem: HpkeKem,
    encapsulated_key: &[u8],
    recipient_sk: &[u8],
    sender_pk: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    // 1. Perform standard decapsulation
    let shared_secret = self.decapsulate(kem, encapsulated_key, recipient_sk)?;
    
    // 2. Perform authentication decapsulation using sender's public key
    // This verifies that the sender possesses the corresponding secret key
    let auth_shared_secret = self.auth_decapsulate_verify(kem, sender_pk)?;
    
    // 3. Combine shared secrets using HKDF
    let combined_shared_secret = self.combine_shared_secrets(
        &shared_secret,
        &auth_shared_secret,
        b"HPKE Auth",
    )?;
    
    Ok(combined_shared_secret)
}
```

**Key Security Properties:**
- **Cryptographic Authentication**: Uses a second KEM operation to prove sender identity
- **RFC 9180 Compliance**: Implements the standard HPKE authentication mechanism
- **Forward Secrecy**: Authentication doesn't compromise forward secrecy
- **Non-Repudiation**: Sender cannot deny sending the message

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
- **Current**: ML-KEM-512, ML-KEM-768, ML-KEM-1024, Saturnin-256, SHAKE256, SHA3
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
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair using the same provider
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
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pairs for both sender and recipient
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
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
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
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
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
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
use lib_q_hpke::security::{SecureKey, validate_kem_key};

// Secure key storage
let mut secret_key = SecureKey::new(key_data);
// Key automatically zeroized when dropped

// Key validation
validate_kem_key(HpkeKem::MlKem512, &public_key, false)?;
validate_kem_key(HpkeKem::MlKem512, &secret_key.as_slice(), true)?;
```

### Context Management

1. **Sequence Numbers**: Monitor sequence numbers to prevent overflow
2. **Context State**: Check context state before operations
3. **Rekeying**: Implement proper rekeying when sequence numbers approach limits

```rust
// Check context state
if sender_ctx.state() == HpkeContextState::NeedsRekey {
    // Rekey the context
    sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"new-session")?;
}

// Monitor sequence numbers
if sender_ctx.sequence_number() > 1000000 {
    // Consider rekeying for long sessions
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

For detailed API reference, see [API_REFERENCE.md](lib-q-hpke/docs/API_REFERENCE.md).
