# lib-Q Secure Architecture Implementation

## Overview

This document describes the secure architecture implementation of lib-Q, a post-quantum cryptography library built with modern secure development practices. The architecture ensures **API consistency** between Rust crate and WASM usage, eliminating technical debt and providing a robust foundation for cryptographic operations.

## Key Design Principles

### 1. **Unified API Design**
- **Single Source of Truth**: All cryptographic operations use the same core API regardless of target platform
- **Type Safety**: Strong type system prevents misuse and ensures compile-time safety
- **Zero-Cost Abstractions**: High-level API with no runtime overhead
- **Memory Safety**: Automatic zeroization of sensitive data using Rust's ownership system

### 2. **Secure Development Practices**

#### **Minimize Unsafe Code**
- No `unsafe` blocks in the public API
- All cryptographic operations are memory-safe by design
- Leverage Rust's type system for security invariants

#### **Constant-Time Operations**
- All comparisons use constant-time algorithms to prevent timing attacks
- Sensitive data handling follows constant-time principles
- No branching on secret data

#### **Memory Management**
- Automatic zeroization of secret keys using `Zeroize` and `ZeroizeOnDrop`
- Secure memory allocation patterns
- No secret data in stack traces or error messages

#### **Input Validation**
- Comprehensive input validation at API boundaries
- Size limits to prevent DoS attacks
- Algorithm validation to prevent misuse

## Architecture Components

### 1. **Core API (`lib-q-core/src/api.rs`)**

The unified API provides a consistent interface for all cryptographic operations:

```rust
// Algorithm enumeration with security levels
pub enum Algorithm {
    MlKem512,      // Level 1 (128-bit security)
    MlKem768,      // Level 3 (192-bit security)
    MlKem1024,     // Level 4 (256-bit security)
    Dilithium2,    // Level 1
    Dilithium3,    // Level 3
    Dilithium5,    // Level 4
    // ... more algorithms
}

// Secure context for cryptographic operations
pub struct KemContext {
    inner: Context<Self>,
}

impl KemContext {
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<KemKeypair>
    pub fn encapsulate(&self, algorithm: Algorithm, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)>
    pub fn decapsulate(&self, algorithm: Algorithm, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>
}
```

### 2. **Type-Safe Key Management**

```rust
// KEM keypair with automatic memory zeroization
pub struct KemKeypair {
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,  // Automatically zeroized on drop
}

// Public keys are safe to clone and share
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey {
    pub data: Vec<u8>,
}

// Secret keys are automatically zeroized
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey {
    pub data: Vec<u8>,
}
```

### 3. **Error Handling**

Comprehensive error types with detailed context:

```rust
pub enum Error {
    InvalidKeySize { expected: usize, actual: usize },
    InvalidAlgorithm { algorithm: String },
    InvalidSecurityLevel { level: u32, supported: &'static [u32] },
    VerificationFailed { operation: String },
    // ... more specific error types
}
```

## API Consistency: Crate vs WASM

### **Rust Crate Usage**

```rust
use libq::{KemContext, SignatureContext, HashContext, Algorithm, Utils};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize contexts
    let mut kem_ctx = KemContext::new();
    let mut sig_ctx = SignatureContext::new();
    let mut hash_ctx = HashContext::new();

    // Generate KEM keypair
    let kem_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;

    // Generate signature keypair
    let sig_keypair = sig_ctx.generate_keypair(Algorithm::Dilithium2)?;

    // Hash data
    let hash = hash_ctx.hash(Algorithm::Shake256, b"Hello, World!")?;

    // Generate random bytes
    let random_bytes = Utils::random_bytes(32)?;

    Ok(())
}
```

### **WASM Usage**

```javascript
// Initialize the library
const libq = new LibQ();
await libq.init();

// Generate KEM keypair (same algorithm names)
const kemKeypair = await libq.kem_generate_keypair("mlkem512");

// Generate signature keypair
const sigKeypair = await libq.sig_generate_keypair("dilithium2");

// Hash data
const hashResult = await libq.hash("shake256", new Uint8Array([1, 2, 3, 4]));

// Generate random bytes
const randomBytes = await libq.random_bytes(32);
```

**Key Point**: The API is **identical** in both environments - same algorithm names, same operations, same error handling patterns.

## Security Features

### 1. **Algorithm Validation**

```rust
impl KemContext {
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<KemKeypair> {
        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            return Err(Error::InvalidAlgorithm { 
                algorithm: format!("{:?} is not a KEM algorithm", algorithm) 
            });
        }
        // ... implementation
    }
}
```

### 2. **Security Level Management**

```rust
impl Algorithm {
    pub fn security_level(&self) -> u32 {
        match self {
            Algorithm::MlKem512 => 1,      // 128-bit security
            Algorithm::MlKem768 => 3,      // 192-bit security
            Algorithm::MlKem1024 => 4,     // 256-bit security
            // ... more mappings
        }
    }
}
```

### 3. **Constant-Time Utilities**

```rust
impl Utils {
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}
```

### 4. **Input Validation**

```rust
impl Utils {
    pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(Error::InvalidMessageSize { max: 0, actual: 0 });
        }
        
        const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB limit
        if length > MAX_RANDOM_SIZE {
            return Err(Error::InvalidMessageSize {
                max: MAX_RANDOM_SIZE,
                actual: length,
            });
        }
        // ... implementation
    }
}
```

## Modular Architecture

### **Workspace Structure**

```
libQ/
├── lib-q-core/          # Core types, traits, and unified API
├── lib-q-kem/           # Key encapsulation mechanisms
├── lib-q-sig/           # Digital signatures
├── lib-q-hash/          # Hash functions
├── lib-q-aead/          # Authenticated encryption
├── lib-q-utils/         # Utility functions
├── lib-q-zkp/           # Zero-knowledge proofs
└── lib.rs               # Main library (re-exports everything)
```

### **Dependency Management**

- **Single Responsibility**: Each crate has a focused purpose
- **Minimal Dependencies**: Only essential dependencies included
- **Feature Flags**: Conditional compilation for algorithms
- **No Circular Dependencies**: Clean dependency graph

## Testing Strategy

### **Unit Tests**

```rust
#[test]
fn test_unified_api() {
    // Test that the unified API works consistently
    let mut kem_ctx = KemContext::new();
    let mut sig_ctx = SignatureContext::new();
    let mut hash_ctx = HashContext::new();

    // Test KEM operations
    let kem_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    assert!(!kem_keypair.public_key().as_bytes().is_empty());
    assert!(!kem_keypair.secret_key().as_bytes().is_empty());

    // Test signature operations
    let sig_keypair = sig_ctx.generate_keypair(Algorithm::Dilithium2).unwrap();
    assert!(!sig_keypair.public_key().as_bytes().is_empty());

    // Test hash operations
    let hash = hash_ctx.hash(Algorithm::Shake256, b"test").unwrap();
    assert_eq!(hash.len(), 32);
}
```

### **Integration Tests**

- Cross-platform compatibility testing
- WASM compilation and execution tests
- Memory safety validation
- Performance benchmarking

## Security Considerations

### **1. Memory Safety**
- All secret data automatically zeroized
- No secret data in error messages
- Secure memory allocation patterns

### **2. Timing Attacks**
- Constant-time comparisons
- No branching on secret data
- Secure random number generation

### **3. Input Validation**
- Comprehensive validation at API boundaries
- Size limits to prevent DoS
- Algorithm validation

### **4. Error Handling**
- No information leakage in errors
- Graceful degradation
- Secure error reporting

## Performance Characteristics

### **Zero-Cost Abstractions**
- High-level API with no runtime overhead
- Compile-time optimizations
- Efficient memory usage

### **WASM Optimization**
- Optimized for web deployment
- Minimal bundle size
- Fast startup time

## Future Enhancements

### **1. Algorithm Implementation**
- Complete NIST PQC algorithm implementations
- Performance optimizations
- Hardware acceleration support

### **2. Advanced Features**
- Threshold cryptography
- Multi-party computation
- Advanced ZKP protocols

### **3. Security Audits**
- Third-party security audits
- Formal verification
- Penetration testing

## Conclusion

The lib-Q secure architecture provides a robust, type-safe, and consistent API for post-quantum cryptography. By following secure development practices and ensuring API consistency across platforms, the library eliminates technical debt and provides a solid foundation for secure applications.

Key benefits:
- **Unified API**: Same interface for Rust and WASM
- **Type Safety**: Compile-time safety guarantees
- **Memory Safety**: Automatic zeroization and secure patterns
- **Performance**: Zero-cost abstractions
- **Security**: Constant-time operations and comprehensive validation

This architecture serves as a model for secure cryptographic library design, demonstrating how modern Rust features can be leveraged to create both secure and performant cryptographic software.
