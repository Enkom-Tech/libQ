# lib-Q Architecture

lib-Q is a post-quantum cryptography library that replaces classical cryptographic libraries with quantum-resistant alternatives. The architecture emphasizes simplicity, security, and performance while providing a complete post-quantum cryptographic ecosystem.

## Design Principles

1. **Post-Quantum Only**: No classical cryptographic algorithms
2. **Simple API**: High-level functions for common cryptographic problems
3. **Zero Dynamic Allocations**: Stack-only operations for constrained environments
4. **Memory Safe**: Rust's ownership model with secure memory management
5. **Cross-Platform**: Native Rust + WASM compilation support
6. **Interoperable**: Compatible with existing libraries and protocols

## Architecture Stack

```
lib-Q Architecture
├── Application Layer
│   ├── Simple API
│   ├── High-Level Functions
│   └── Problem-Solving Interfaces
├── Algorithm Layer
│   ├── KEMs (ML-KEM, CB-KEM, HQC, DAWN)
│   ├── Signatures (ML-DSA, FN-DSA, SLH-DSA)
│   ├── Hash Functions (SHAKE256, SHAKE128, cSHAKE256)
│   └── AEAD Constructions (Saturnin, SHAKE256-based)
├── Protocol Layer
│   ├── HPKE (4-tier system)
│   ├── Key Exchange Protocols
│   ├── TLS/SSH/WireGuard Integration
│   └── Custom Protocol Support
├── Memory Layer
│   ├── Stack-Allocated Types
│   ├── Zero Dynamic Allocations
│   ├── Secure Memory Management
│   └── Constrained Environment Support
├── Interoperability Layer
│   ├── Format Support (Binary, Text, Structured)
│   └── Protocol Integration
└── Platform Layer
    ├── Native Rust
    ├── WASM Compilation
    └── Platform-Specific Optimizations
```

## API Design

### Simple API
High-level functions for common cryptographic problems:

```rust
// Key Exchange
let (pk, sk) = simple::keygen(1)?;
let shared = simple::exchange(&sk, &their_pk)?;

// Digital Signatures
let (pk, sk) = simple::sign_keygen(1)?;
let signature = simple::sign(&sk, message)?;
let is_valid = simple::verify(&pk, message, &signature)?;

// Authenticated Encryption
let ciphertext = simple::encrypt(&key, message, Some(ad))?;
let plaintext = simple::decrypt(&key, &ciphertext, Some(ad))?;

// HPKE
let ciphertext = simple::hpke_encrypt(&recipient_pk, message, Some(ad), SecurityTier::Balanced)?;
let plaintext = simple::hpke_decrypt(&recipient_sk, &ciphertext, Some(ad))?;

// Hashing
let hash = simple::hash(data, 32)?;
let custom_hash = simple::custom_hash(data, b"MyApp", b"UserID", 32)?;

// Key Derivation
let key = simple::derive_key(&shared_secret, b"encryption")?;
let keys = simple::derive_keys(&shared_secret, &[b"encryption", b"auth", b"metadata"])?;
```

### Algorithm API
Direct access to specific algorithms:

```rust
// KEM Operations
let (pk, sk) = kem::keygen(KemAlgorithm::MlKem5)?;
let (shared, enc) = kem::encaps(KemAlgorithm::MlKem5, &pk)?;
let shared = kem::decaps(KemAlgorithm::MlKem5, &sk, &enc)?;

// Signature Operations
let (pk, sk) = sig::keygen(SigAlgorithm::Dilithium5)?;
let signature = sig::sign(SigAlgorithm::Dilithium5, &sk, message)?;
let is_valid = sig::verify(SigAlgorithm::Dilithium5, &pk, message, &signature)?;
```

### Core API (Low-Level)

Direct access to cryptographic primitives:

```rust
// Direct algorithm access
let ml_kem = ML-Kem::new(SecurityLevel::Level5);
let (pk, sk) = ml_kem.generate_keypair()?;
let (shared, enc) = ml_kem.encapsulate(&pk)?;
let recovered = ml_kem.decapsulate(&sk, &enc)?;
```

## Security Architecture

### Security Model

- **Post-Quantum Only**: No classical cryptographic algorithms
- **Constant-Time Operations**: All operations are side-channel resistant
- **Memory Safety**: Rust's ownership model with secure memory management
- **Input Validation**: Comprehensive validation of all inputs

### Security Tiers

1. **Ultra-Secure (Tier 1)**: Pure post-quantum with maximum security
   - KEMs: ML-KEM, CB-KEM, HQC, DAWN
   - Signatures: ML-DSA, FN-DSA, SLH-DSA
   - Symmetric: SHAKE256-based constructions, Saturnin
   - HPKE: Pure post-quantum HPKE with Saturnin AEAD

2. **Balanced (Tier 2)**: Post-quantum with good performance
   - KEMs: ML-KEM, CB-KEM, HQC, DAWN
   - Signatures: ML-DSA, FN-DSA, SLH-DSA
   - Symmetric: Post-quantum KEM + Saturnin AEAD
   - HPKE: Hybrid HPKE (PQ KEM + Saturnin)

3. **Performance (Tier 3)**: Post-quantum + optimized
   - KEMs: ML-KEM, DAWN, HQC
   - Signatures: ML-DSA, FN-DSA
   - Symmetric: Post-quantum KEM + Saturnin AEAD (optimized modes)
   - HPKE: Performance HPKE (PQ KEM + Saturnin)


### Forbidden Algorithms
- **KEMs**: RSA, ECC, DH, ECDH
- **Signatures**: RSA-PSS, ECDSA, Ed25519, Ed448
- **Hash Functions**: SHA-1, SHA-256, SHA-512, MD5
- **Symmetric Ciphers**: AES-128, ChaCha20, Poly1305

## Memory Architecture

### Zero Dynamic Allocation Model
- **Stack-Only Operations**: All cryptographic operations use stack-allocated buffers
- **Fixed-Size Types**: All cryptographic types have fixed, known sizes
- **Secure Memory Zeroing**: Automatic zeroing of sensitive data
- **Memory Safety**: Rust's ownership model prevents memory errors

### Fixed-Size Types
```rust
// Maximum sizes for all algorithms
pub const MAX_PUBLIC_KEY_SIZE: usize = 3936;  // Largest Dilithium5 public key
pub const MAX_SECRET_KEY_SIZE: usize = 6096;  // Largest Dilithium5 secret key
pub const MAX_SIGNATURE_SIZE: usize = 6590;   // Largest Dilithium5 signature
pub const MAX_SHARED_SECRET_SIZE: usize = 32; // All KEMs use 32 bytes
pub const MAX_CIPHERTEXT_SIZE: usize = 1568;  // Largest MlKem5 ciphertext
pub const MAX_MESSAGE_SIZE: usize = 65536;    // 64KB max message size

// Stack-allocated types
pub struct PublicKey([u8; MAX_PUBLIC_KEY_SIZE]);
pub struct SecretKey([u8; MAX_SECRET_KEY_SIZE]);
pub struct Signature([u8; MAX_SIGNATURE_SIZE]);
pub struct SharedSecret([u8; MAX_SHARED_SECRET_SIZE]);
pub struct Ciphertext([u8; MAX_CIPHERTEXT_SIZE + MAX_MESSAGE_SIZE]);
pub struct Plaintext([u8; MAX_MESSAGE_SIZE]);
```

### Memory Management Patterns

- **Automatic Zeroing**: Use `zeroize` crate for sensitive data
- **Memory Barriers**: Prevent compiler optimizations that could leak secrets
- **Secure Deallocation**: Ensure sensitive data is properly cleared
- **WASM Memory**: Optimized memory layout for web applications

## HPKE Architecture

### Four-Tier System

1. **Ultra-Secure HPKE**: Pure post-quantum with SHAKE256-based AEAD
   - KEM: ML-KEM (Level 5)
   - AEAD: SHAKE256-based construction
   - Use Case: Maximum security, performance secondary

2. **Balanced HPKE**: Post-quantum with Saturnin AEAD
   - KEM: ML-KEM (Level 3)
   - AEAD: Saturnin
   - Use Case: Strong security with good performance

3. **Performance HPKE**: Post-quantum + optimized Saturnin
   - KEM: ML-KEM (Level 1) / DAWN
   - AEAD: Saturnin (optimized modes)
   - Use Case: Maximum performance, strong security


### HPKE Implementation

### HPKE API
```rust
pub enum SecurityTier {
    UltraSecure,  // Pure post-quantum with SHAKE256-based AEAD
    Balanced,     // Post-quantum with Saturnin AEAD
    Performance,  // Post-quantum with optimized Saturnin
}

pub fn hpke_encrypt(
    recipient_public: &PublicKey,
    message: &[u8],
    associated_data: Option<&[u8]>,
    tier: SecurityTier
) -> Result<Ciphertext>;

pub fn hpke_decrypt(
    recipient_secret: &SecretKey,
    ciphertext: &Ciphertext,
    associated_data: Option<&[u8]>
) -> Result<Plaintext>;
```

## Interoperability

### Format Support
- **Binary Format**: Raw byte arrays for maximum efficiency
- **Text Format**: Base64 and Hex encoding for human-readable data
- **Structured Format**: JSON and CBOR for complex data structures
- **PEM Format**: Traditional PEM encoding for compatibility

### Library Compatibility
- **libsodium Compatibility**: API compatibility layer for easy migration
- **OpenSSL Compatibility**: Format compatibility and algorithm mapping
- **Protocol Integration**: TLS, SSH, WireGuard integration

### Serialization Examples

```rust
// Binary serialization
let public_key_bytes = public_key.as_ref();

// Base64 encoding
let public_key_b64 = base64::encode(public_key_bytes);

// JSON serialization
let key_json = serde_json::json!({
    "type": "public_key",
    "algorithm": "mlkem5",
    "data": base64::encode(public_key_bytes)
});

// PEM encoding
let pem_key = format!(
    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
    base64::encode(public_key_bytes)
);
```

## Performance Architecture

### Performance Targets

- **Key Generation**: < 1ms for Level 1, < 5ms for Level 5
- **Encapsulation/Decapsulation**: < 0.5ms for Level 1, < 2ms for Level 5
- **Signing**: < 1ms for Level 1, < 5ms for Level 5 (FN-DSA: < 0.5ms for compact signatures)
- **Verification**: < 0.5ms for Level 1, < 2ms for Level 5
- **HPKE**: < 2ms for encryption/decryption (Saturnin AEAD: < 1ms for balanced tier)
- **DAWN KEM**: < 0.3ms for encapsulation (smaller ciphertext sizes)

### Memory Requirements
- **Stack Usage**: < 16KB for all operations (Saturnin: < 8KB)
- **Heap Usage**: Zero dynamic allocations
- **WASM Size**: < 500KB total (with new algorithms: < 600KB)
- **Runtime Memory**: < 1MB (FN-DSA: compact signatures reduce memory usage)

### Optimization Strategies

- **Constant-Time Operations**: All cryptographic operations are constant-time
- **SIMD Optimization**: Platform-specific optimizations where available
- **WASM Optimization**: Optimized for web performance
- **Memory Layout**: Optimized memory layout for cache efficiency
- **Saturnin Optimization**: Bitsliced implementation for constrained devices
- **FN-DSA Optimization**: Fast Fourier Transform optimizations for compact signatures
- **DAWN Optimization**: Double encoding optimizations for smaller ciphertexts

## Platform Support

### Native Rust
- **Target Platforms**: x86_64, ARM64, ARM32
- **Optimizations**: SIMD, platform-specific optimizations
- **Memory Model**: Stack-only operations with secure memory management
- **Error Handling**: Comprehensive error handling with detailed error types
- **Algorithm Support**: All post-quantum algorithms (Saturnin, FN-DSA, DAWN)

### WASM Compilation
- **Target**: Web browsers and Node.js
- **Optimizations**: Size optimization, performance optimization
- **Memory Model**: WASM-specific memory management
- **JavaScript Bindings**: Idiomatic JavaScript API
- **Algorithm Support**: Full post-quantum algorithm suite with WASM optimizations


