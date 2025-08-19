# lib-Q API Design Specification

## Design Philosophy

lib-Q provides an API that makes post-quantum cryptography simple and secure to use. The API follows these principles:

1. **Simple functions for common problems**: Instead of low-level primitives, expose functions that solve real cryptographic problems
2. **Zero dynamic allocations**: All operations use stack-allocated buffers for constrained environments
3. **Consistent naming**: Predictable function names across all operations
4. **Secure by default**: All functions use secure parameters and prevent common mistakes
5. **Post-quantum only**: No classical cryptographic algorithms exposed

## API Architecture

### Core API Structure

```
lib-Q API Layers
├── Simple API     # High-level, problem-solving functions
├── Algorithm API                      # Algorithm-specific operations
├── Core API                          # Low-level cryptographic primitives
└── Platform API                      # Platform-specific optimizations
```

### Memory Management Strategy

```rust
// Stack-allocated key types (no dynamic allocations)
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);
pub struct SecretKey([u8; SECRET_KEY_SIZE]);
pub struct Signature([u8; SIGNATURE_SIZE]);
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);

// Fixed-size buffers for all operations
pub struct Ciphertext([u8; MAX_CIPHERTEXT_SIZE]);
pub struct Plaintext([u8; MAX_PLAINTEXT_SIZE]);
```

## Simple API (High-Level)

### Key Exchange

```rust
/// Generate a keypair for key exchange
/// 
/// Returns a public key and secret key for secure communication.
/// The keys are generated using the specified security level.
/// 
/// # Arguments
/// * `security_level` - Security level (1, 3, 4, or 5)
/// 
/// # Returns
/// * `(PublicKey, SecretKey)` - Generated keypair
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let (pk, sk) = simple::keygen(1)?;
/// ```
pub fn keygen(security_level: u32) -> Result<(PublicKey, SecretKey)>;

/// Perform key exchange to establish a shared secret
/// 
/// Combines your secret key with their public key to create a shared secret.
/// Both parties will derive the same shared secret.
/// 
/// # Arguments
/// * `my_secret` - Your secret key
/// * `their_public` - Their public key
/// 
/// # Returns
/// * `SharedSecret` - The established shared secret
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let shared = simple::exchange(my_secret, their_public)?;
/// ```
pub fn exchange(my_secret: &SecretKey, their_public: &PublicKey) -> Result<SharedSecret>;

/// Encapsulate a shared secret for one-way communication
/// 
/// Creates a shared secret and encapsulated key for secure one-way communication.
/// Only the recipient with the secret key can decapsulate the shared secret.
/// 
/// # Arguments
/// * `recipient_public` - Recipient's public key
/// 
/// # Returns
/// * `(SharedSecret, EncapsulatedKey)` - Shared secret and encapsulated key
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let (shared, enc) = simple::encapsulate(recipient_pk)?;
/// ```
pub fn encapsulate(recipient_public: &PublicKey) -> Result<(SharedSecret, EncapsulatedKey)>;

/// Decapsulate a shared secret from an encapsulated key
/// 
/// Extracts the shared secret from an encapsulated key using the recipient's secret key.
/// 
/// # Arguments
/// * `recipient_secret` - Recipient's secret key
/// * `encapsulated_key` - Encapsulated key from sender
/// 
/// # Returns
/// * `SharedSecret` - The extracted shared secret
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let shared = simple::decapsulate(recipient_sk, &enc)?;
/// ```
pub fn decapsulate(recipient_secret: &SecretKey, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret>;
```

### Digital Signatures

```rust
/// Generate a signature keypair
/// 
/// Creates a public key and secret key for digital signatures.
/// 
/// # Arguments
/// * `security_level` - Security level (1, 3, 4, or 5)
/// 
/// # Returns
/// * `(SigPublicKey, SigSecretKey)` - Generated signature keypair
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let (pk, sk) = simple::sign_keygen(1)?;
/// ```
pub fn sign_keygen(security_level: u32) -> Result<(SigPublicKey, SigSecretKey)>;

/// Sign a message
/// 
/// Creates a digital signature for a message using the secret key.
/// 
/// # Arguments
/// * `secret_key` - Secret key for signing
/// * `message` - Message to sign
/// 
/// # Returns
/// * `Signature` - Digital signature
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let signature = simple::sign(&sk, message)?;
/// ```
pub fn sign(secret_key: &SigSecretKey, message: &[u8]) -> Result<Signature>;

/// Verify a signature
/// 
/// Verifies a digital signature against a message using the public key.
/// 
/// # Arguments
/// * `public_key` - Public key for verification
/// * `message` - Original message
/// * `signature` - Digital signature to verify
/// 
/// # Returns
/// * `bool` - True if signature is valid
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let is_valid = simple::verify(&pk, message, &signature)?;
/// ```
pub fn verify(public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> Result<bool>;
```

### Authenticated Encryption

```rust
/// Encrypt a message with authenticated encryption
/// 
/// Encrypts a message using a symmetric key with authentication.
/// 
/// # Arguments
/// * `key` - Encryption key
/// * `message` - Message to encrypt
/// * `associated_data` - Optional associated data for authentication
/// 
/// # Returns
/// * `Ciphertext` - Encrypted message with authentication tag
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let ciphertext = simple::encrypt(&key, message, Some(ad))?;
/// ```
pub fn encrypt(key: &EncryptionKey, message: &[u8], associated_data: Option<&[u8]>) -> Result<Ciphertext>;

/// Decrypt a message with authenticated encryption
/// 
/// Decrypts and authenticates a message using a symmetric key.
/// 
/// # Arguments
/// * `key` - Encryption key
/// * `ciphertext` - Encrypted message with authentication tag
/// * `associated_data` - Optional associated data for authentication
/// 
/// # Returns
/// * `Plaintext` - Decrypted message
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let plaintext = simple::decrypt(&key, &ciphertext, Some(ad))?;
/// ```
pub fn decrypt(key: &EncryptionKey, ciphertext: &Ciphertext, associated_data: Option<&[u8]>) -> Result<Plaintext>;
```

### Hybrid Public Key Encryption (HPKE)

```rust
/// Encrypt using HPKE
/// 
/// Encrypts a message for a specific recipient using Hybrid Public Key Encryption.
/// 
/// # Arguments
/// * `recipient_public` - Recipient's public key
/// * `message` - Message to encrypt
/// * `associated_data` - Optional associated data
/// * `tier` - Security tier (UltraSecure, Balanced, Performance)
/// 
/// # Returns
/// * `Ciphertext` - Encrypted message
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let ciphertext = simple::hpke_encrypt(&recipient_pk, message, Some(ad), SecurityTier::Balanced)?;
/// ```
pub fn hpke_encrypt(
    recipient_public: &PublicKey,
    message: &[u8],
    associated_data: Option<&[u8]>,
    tier: SecurityTier
) -> Result<Ciphertext>;

/// Decrypt using HPKE
/// 
/// Decrypts an HPKE-encrypted message using the recipient's secret key.
/// 
/// # Arguments
/// * `recipient_secret` - Recipient's secret key
/// * `ciphertext` - Encrypted message
/// * `associated_data` - Optional associated data
/// 
/// # Returns
/// * `Plaintext` - Decrypted message
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let plaintext = simple::hpke_decrypt(&recipient_sk, &ciphertext, Some(ad))?;
/// ```
pub fn hpke_decrypt(
    recipient_secret: &SecretKey,
    ciphertext: &Ciphertext,
    associated_data: Option<&[u8]>
) -> Result<Plaintext>;
```

### Hashing

```rust
/// Hash data using SHAKE256
/// 
/// Creates a cryptographic hash of the input data.
/// 
/// # Arguments
/// * `data` - Data to hash
/// * `output_length` - Length of hash output in bytes
/// 
/// # Returns
/// * `Vec<u8>` - Hash output
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let hash = simple::hash(data, 32)?;
/// ```
pub fn hash(data: &[u8], output_length: usize) -> Result<Vec<u8>>;

/// Create a customizable hash using cSHAKE256
/// 
/// Creates a hash with custom domain separator and function name.
/// 
/// # Arguments
/// * `data` - Data to hash
/// * `domain_separator` - Domain separator for customization
/// * `function_name` - Function name for customization
/// * `output_length` - Length of hash output in bytes
/// 
/// # Returns
/// * `Vec<u8>` - Custom hash output
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let custom_hash = simple::custom_hash(data, b"MyApp", b"UserID", 32)?;
/// ```
pub fn custom_hash(
    data: &[u8],
    domain_separator: &[u8],
    function_name: &[u8],
    output_length: usize
) -> Result<Vec<u8>>;
```

### Key Derivation

```rust
/// Derive a key from a shared secret
/// 
/// Derives a cryptographic key from a shared secret using SHAKE256.
/// 
/// # Arguments
/// * `shared_secret` - Input shared secret
/// * `context` - Context string for key derivation
/// 
/// # Returns
/// * `EncryptionKey` - Derived encryption key
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let key = simple::derive_key(&shared_secret, b"encryption")?;
/// ```
pub fn derive_key(shared_secret: &SharedSecret, context: &[u8]) -> Result<EncryptionKey>;

/// Derive multiple keys from a shared secret
/// 
/// Derives multiple cryptographic keys from a shared secret.
/// 
/// # Arguments
/// * `shared_secret` - Input shared secret
/// * `contexts` - Array of context strings for each key
/// 
/// # Returns
/// * `Vec<EncryptionKey>` - Array of derived keys
/// 
/// # Example
/// ```rust
/// use lib-q::simple;
/// 
/// let keys = simple::derive_keys(&shared_secret, &[b"encryption", b"auth", b"metadata"])?;
/// ```
pub fn derive_keys(shared_secret: &SharedSecret, contexts: &[&[u8]]) -> Result<Vec<EncryptionKey>>;
```

## Algorithm API (Mid-Level)

### KEM Operations

```rust
/// Generate a KEM keypair
/// 
/// Creates a keypair for the specified KEM algorithm and security level.
/// 
/// # Arguments
/// * `algorithm` - KEM algorithm to use
/// 
/// # Returns
/// * `(KemPublicKey, KemSecretKey)` - Generated keypair
/// 
/// # Example
/// ```rust
/// use lib-q::kem;
/// 
/// let (pk, sk) = kem::keygen(KemAlgorithm::MlKem5)?;
/// ```
pub fn keygen(algorithm: KemAlgorithm) -> Result<(KemPublicKey, KemSecretKey)>;

/// Encapsulate a shared secret
/// 
/// Creates a shared secret and encapsulated key using the specified KEM.
/// 
/// # Arguments
/// * `algorithm` - KEM algorithm to use
/// * `public_key` - Recipient's public key
/// 
/// # Returns
/// * `(SharedSecret, EncapsulatedKey)` - Shared secret and encapsulated key
/// 
/// # Example
/// ```rust
/// use lib-q::kem;
/// 
/// let (shared, enc) = kem::encaps(KemAlgorithm::MlKem5, &pk)?;
/// ```
pub fn encaps(algorithm: KemAlgorithm, public_key: &KemPublicKey) -> Result<(SharedSecret, EncapsulatedKey)>;

/// Decapsulate a shared secret
/// 
/// Extracts a shared secret from an encapsulated key.
/// 
/// # Arguments
/// * `algorithm` - KEM algorithm to use
/// * `secret_key` - Recipient's secret key
/// * `encapsulated_key` - Encapsulated key
/// 
/// # Returns
/// * `SharedSecret` - Extracted shared secret
/// 
/// # Example
/// ```rust
/// use lib-q::kem;
/// 
/// let shared = kem::decaps(KemAlgorithm::MlKem5, &sk, &enc)?;
/// ```
pub fn decaps(algorithm: KemAlgorithm, secret_key: &KemSecretKey, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret>;
```

### Signature Operations

```rust
/// Generate a signature keypair
/// 
/// Creates a keypair for the specified signature algorithm and security level.
/// 
/// # Arguments
/// * `algorithm` - Signature algorithm to use
/// 
/// # Returns
/// * `(SigPublicKey, SigSecretKey)` - Generated keypair
/// 
/// # Example
/// ```rust
/// use lib-q::sig;
/// 
/// let (pk, sk) = sig::keygen(SigAlgorithm::Dilithium5)?;
/// ```
pub fn keygen(algorithm: SigAlgorithm) -> Result<(SigPublicKey, SigSecretKey)>;

/// Sign a message
/// 
/// Creates a digital signature using the specified algorithm.
/// 
/// # Arguments
/// * `algorithm` - Signature algorithm to use
/// * `secret_key` - Secret key for signing
/// * `message` - Message to sign
/// 
/// # Returns
/// * `Signature` - Digital signature
/// 
/// # Example
/// ```rust
/// use lib-q::sig;
/// 
/// let signature = sig::sign(SigAlgorithm::Dilithium5, &sk, message)?;
/// ```
pub fn sign(algorithm: SigAlgorithm, secret_key: &SigSecretKey, message: &[u8]) -> Result<Signature>;

/// Verify a signature
/// 
/// Verifies a digital signature using the specified algorithm.
/// 
/// # Arguments
/// * `algorithm` - Signature algorithm to use
/// * `public_key` - Public key for verification
/// * `message` - Original message
/// * `signature` - Digital signature to verify
/// 
/// # Returns
/// * `bool` - True if signature is valid
/// 
/// # Example
/// ```rust
/// use lib-q::sig;
/// 
/// let is_valid = sig::verify(SigAlgorithm::Dilithium5, &pk, message, &signature)?;
/// ```
pub fn verify(algorithm: SigAlgorithm, public_key: &SigPublicKey, message: &[u8], signature: &Signature) -> Result<bool>;
```

## Core API (Low-Level)

### Algorithm Enums

```rust
/// Supported KEM algorithms
pub enum KemAlgorithm {
    MlKem1,
    MlKem3,
    MlKem5,
    McEliece1,
    McEliece3,
    McEliece4,
    McEliece5,
    Hqc1,
    Hqc3,
    Hqc4,
    Hqc5,
}

/// Supported signature algorithms
pub enum SigAlgorithm {
    Dilithium1,
    Dilithium3,
    Dilithium5,
    Falcon1,
    Falcon5,
    Sphincs1,
    Sphincs3,
    Sphincs5,
}

/// Security tiers for HPKE
pub enum SecurityTier {
    UltraSecure,  // Pure post-quantum
    Balanced,     // Hybrid PQ + classical
    Performance,  // PQ + optimized classical
}
```

### Fixed-Size Constants

```rust
// KEM key sizes (in bytes)
pub const MLKEM1_PUBLIC_KEY_SIZE: usize = 800;
pub const MLKEM1_SECRET_KEY_SIZE: usize = 1632;
pub const MLKEM1_CIPHERTEXT_SIZE: usize = 768;
pub const MLKEM1_SHARED_SECRET_SIZE: usize = 32;

pub const MLKEM3_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM3_SECRET_KEY_SIZE: usize = 2400;
pub const MLKEM3_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM3_SHARED_SECRET_SIZE: usize = 32;

pub const MLKEM5_PUBLIC_KEY_SIZE: usize = 1568;
pub const MLKEM5_SECRET_KEY_SIZE: usize = 3168;
pub const MLKEM5_CIPHERTEXT_SIZE: usize = 1568;
pub const MLKEM5_SHARED_SECRET_SIZE: usize = 32;

// Signature key sizes (in bytes)
pub const DILITHIUM1_PUBLIC_KEY_SIZE: usize = 1952;
pub const DILITHIUM1_SECRET_KEY_SIZE: usize = 4000;
pub const DILITHIUM1_SIGNATURE_SIZE: usize = 3366;

pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 2976;
pub const DILITHIUM3_SECRET_KEY_SIZE: usize = 4864;
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 4978;

pub const DILITHIUM5_PUBLIC_KEY_SIZE: usize = 3936;
pub const DILITHIUM5_SECRET_KEY_SIZE: usize = 6096;
pub const DILITHIUM5_SIGNATURE_SIZE: usize = 6590;

// Maximum sizes for dynamic operations
pub const MAX_PUBLIC_KEY_SIZE: usize = 3936;  // Largest Dilithium5 public key
pub const MAX_SECRET_KEY_SIZE: usize = 6096;  // Largest Dilithium5 secret key
pub const MAX_SIGNATURE_SIZE: usize = 6590;   // Largest Dilithium5 signature
pub const MAX_SHARED_SECRET_SIZE: usize = 32; // All KEMs use 32 bytes
pub const MAX_CIPHERTEXT_SIZE: usize = 1568;  // Largest MlKem5 ciphertext
pub const MAX_MESSAGE_SIZE: usize = 65536;    // 64KB max message size
```

### Stack-Allocated Types

```rust
/// Fixed-size public key
pub struct PublicKey([u8; MAX_PUBLIC_KEY_SIZE]);

/// Fixed-size secret key
pub struct SecretKey([u8; MAX_SECRET_KEY_SIZE]);

/// Fixed-size signature
pub struct Signature([u8; MAX_SIGNATURE_SIZE]);

/// Fixed-size shared secret
pub struct SharedSecret([u8; MAX_SHARED_SECRET_SIZE]);

/// Fixed-size encryption key
pub struct EncryptionKey([u8; 32]);

/// Fixed-size encapsulated key
pub struct EncapsulatedKey([u8; MAX_CIPHERTEXT_SIZE]);

/// Fixed-size ciphertext
pub struct Ciphertext([u8; MAX_CIPHERTEXT_SIZE + MAX_MESSAGE_SIZE]);

/// Fixed-size plaintext
pub struct Plaintext([u8; MAX_MESSAGE_SIZE]);

/// KEM-specific public key
pub struct KemPublicKey([u8; MAX_PUBLIC_KEY_SIZE]);

/// KEM-specific secret key
pub struct KemSecretKey([u8; MAX_SECRET_KEY_SIZE]);

/// Signature-specific public key
pub struct SigPublicKey([u8; MAX_PUBLIC_KEY_SIZE]);

/// Signature-specific secret key
pub struct SigSecretKey([u8; MAX_SECRET_KEY_SIZE]);
```

## Platform API

### WASM Bindings

```rust
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct Lib-Q {
    // Internal state
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl Lib-Q {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // Initialize lib-Q
    }
    
    /// Generate a keypair (WASM)
    pub fn keygen(&self, security_level: u32) -> Result<JsValue, JsValue> {
        // WASM-specific implementation
    }
    
    /// Perform key exchange (WASM)
    pub fn exchange(&self, my_secret: &[u8], their_public: &[u8]) -> Result<JsValue, JsValue> {
        // WASM-specific implementation
    }
    
    /// Sign a message (WASM)
    pub fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<JsValue, JsValue> {
        // WASM-specific implementation
    }
    
    /// Verify a signature (WASM)
    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
        // WASM-specific implementation
    }
}
```

### C Bindings

```rust
#[cfg(feature = "c-bindings")]
use std::ffi::{c_char, CStr, CString};

#[cfg(feature = "c-bindings")]
#[no_mangle]
pub extern "C" fn libq_keygen(security_level: u32, public_key: *mut u8, secret_key: *mut u8) -> i32 {
    // C binding implementation
}

#[cfg(feature = "c-bindings")]
#[no_mangle]
pub extern "C" fn libq_exchange(
    my_secret: *const u8,
    their_public: *const u8,
    shared_secret: *mut u8
) -> i32 {
    // C binding implementation
}

#[cfg(feature = "c-bindings")]
#[no_mangle]
pub extern "C" fn libq_sign(
    secret_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *mut u8
) -> i32 {
    // C binding implementation
}

#[cfg(feature = "c-bindings")]
#[no_mangle]
pub extern "C" fn libq_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8
) -> i32 {
    // C binding implementation
}
```

## Error Handling

### Error Types

```rust
/// lib-Q error types
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Invalid key size
    InvalidKeySize {
        expected: usize,
        actual: usize,
    },
    /// Invalid signature size
    InvalidSignatureSize {
        expected: usize,
        actual: usize,
    },
    /// Invalid security level
    InvalidSecurityLevel {
        level: u32,
        supported: &'static [u32],
    },
    /// Verification failed
    VerificationFailed {
        operation: String,
    },
    /// Encryption failed
    EncryptionFailed {
        reason: String,
    },
    /// Decryption failed
    DecryptionFailed {
        reason: String,
    },
    /// Random number generation failed
    RandomGenerationFailed,
    /// Algorithm not implemented
    NotImplemented {
        algorithm: String,
    },
    /// Invalid input data
    InvalidInput {
        reason: String,
    },
    /// Memory allocation failed
    MemoryAllocationFailed,
    /// WASM-specific error
    WasmError {
        reason: String,
    },
}

/// Result type for lib-Q operations
pub type Result<T> = std::result::Result<T, Error>;
```

## Usage Examples

### Basic Key Exchange

```rust
use lib-q::simple;

fn main() -> lib-q::Result<()> {
    // Initialize lib-Q
    lib-q::init()?;
    
    // Generate keypairs for Alice and Bob
    let (alice_pk, alice_sk) = simple::keygen(1)?;
    let (bob_pk, bob_sk) = simple::keygen(1)?;
    
    // Alice and Bob perform key exchange
    let alice_shared = simple::exchange(&alice_sk, &bob_pk)?;
    let bob_shared = simple::exchange(&bob_sk, &alice_pk)?;
    
    // Both should have the same shared secret
    assert_eq!(alice_shared.as_ref(), bob_shared.as_ref());
    
    println!("Key exchange successful!");
    Ok(())
}
```

### Digital Signatures

```rust
use lib-q::simple;

fn main() -> lib-q::Result<()> {
    // Initialize lib-Q
    lib-q::init()?;
    
    // Generate signature keypair
    let (pk, sk) = simple::sign_keygen(1)?;
    
    // Sign a message
    let message = b"Hello, Post-Quantum World!";
    let signature = simple::sign(&sk, message)?;
    
    // Verify the signature
    let is_valid = simple::verify(&pk, message, &signature)?;
    assert!(is_valid);
    
    println!("Signature verification successful!");
    Ok(())
}
```

### HPKE Encryption

```rust
use lib-q::simple;

fn main() -> lib-q::Result<()> {
    // Initialize lib-Q
    lib-q::init()?;
    
    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = simple::keygen(1)?;
    
    // Encrypt a message for the recipient
    let message = b"Secret message for recipient";
    let associated_data = b"Additional context";
    
    let ciphertext = simple::hpke_encrypt(
        &recipient_pk,
        message,
        Some(associated_data),
        SecurityTier::Balanced
    )?;
    
    // Decrypt the message
    let plaintext = simple::hpke_decrypt(
        &recipient_sk,
        &ciphertext,
        Some(associated_data)
    )?;
    
    assert_eq!(message, plaintext.as_ref());
    println!("HPKE encryption/decryption successful!");
    Ok(())
}
```

### Algorithm-Specific Operations

```rust
use lib-q::{kem, sig, KemAlgorithm, SigAlgorithm};

fn main() -> lib-q::Result<()> {
    // Initialize lib-Q
    lib-q::init()?;
    
    // Use specific KEM algorithm
    let (pk, sk) = kem::keygen(KemAlgorithm::MlKem5)?;
    let (shared, enc) = kem::encaps(KemAlgorithm::MlKem5, &pk)?;
    let recovered = kem::decaps(KemAlgorithm::MlKem5, &sk, &enc)?;
    
    assert_eq!(shared.as_ref(), recovered.as_ref());
    
    // Use specific signature algorithm
    let (sig_pk, sig_sk) = sig::keygen(SigAlgorithm::Dilithium5)?;
    let message = b"Message to sign";
    let signature = sig::sign(SigAlgorithm::Dilithium5, &sig_sk, message)?;
    let is_valid = sig::verify(SigAlgorithm::Dilithium5, &sig_pk, message, &signature)?;
    
    assert!(is_valid);
    println!("Algorithm-specific operations successful!");
    Ok(())
}
```

## Performance Considerations

### Memory Usage

- **Stack allocation**: All operations use stack-allocated buffers
- **Fixed sizes**: No dynamic memory allocation during cryptographic operations
- **Memory zeroing**: Automatic zeroing of sensitive data
- **WASM optimization**: Minimal memory footprint for web applications

### Performance Targets

- **Key generation**: < 1ms for Level 1, < 5ms for Level 5
- **Encapsulation/Decapsulation**: < 0.5ms for Level 1, < 2ms for Level 5
- **Signing**: < 1ms for Level 1, < 5ms for Level 5
- **Verification**: < 0.5ms for Level 1, < 2ms for Level 5
- **HPKE**: < 2ms for encryption/decryption

### Optimization Strategies

- **Constant-time operations**: All cryptographic operations are constant-time
- **SIMD optimization**: Platform-specific optimizations where available
- **WASM optimization**: Optimized for web performance
- **Memory layout**: Optimized memory layout for cache efficiency
