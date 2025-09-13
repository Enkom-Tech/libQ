# HPKE Architecture Documentation

## Overview

The lib-q-hpke implementation follows a modular, security-first architecture designed for post-quantum cryptography. This document describes the architecture, design decisions, and implementation details.

## Architecture Principles

### 1. Security-First Design
- **Constant-time operations**: All cryptographic operations are designed to prevent timing attacks
- **Memory safety**: Automatic zeroization of sensitive data using `Zeroize` trait
- **Input validation**: Comprehensive validation of all inputs with configurable security policies
- **Error handling**: Structured error types with context-rich information

### 2. Algorithm-Agnostic Design
- **Provider pattern**: Pluggable cryptographic providers for different implementations
- **lib-q-kem integration**: Uses lib-q-kem abstraction instead of direct algorithm coupling
- **Trait-based interfaces**: Clean abstractions for KEM, KDF, and AEAD operations
- **Modular architecture**: Each cryptographic primitive is in its own module
- **Integration layer**: Bridge between new architecture and existing lib-q-core types

### 3. Performance Optimization
- **Benchmarking infrastructure**: Built-in performance measurement and reporting
- **Memory efficiency**: Optimized memory usage with secure containers
- **Algorithm selection**: Support for different security/performance trade-offs

## Module Structure

```
src/
├── lib.rs                 # Main library entry point
├── types.rs              # Core HPKE types and enums
├── error.rs              # Enhanced error handling
├── hpke_core.rs          # Core HPKE protocol implementation
├── crypto_provider.rs    # Legacy crypto provider (for compatibility)
├── kdf.rs                # Legacy KDF implementation
├── security/             # Security utilities and validation
│   ├── mod.rs
│   ├── policy.rs         # Security policy configuration
│   ├── validation.rs     # Cryptographic validation
│   ├── constant_time.rs  # Constant-time operations
│   ├── memory.rs         # Secure memory management
│   └── prng.rs           # Pseudo-random number generation
├── providers/            # Cryptographic provider traits
│   ├── mod.rs
│   ├── traits.rs         # Provider trait definitions
│   └── post_quantum.rs   # Post-quantum provider implementation
├── kem/                  # Key Encapsulation Mechanism implementations
│   ├── mod.rs
│   ├── traits.rs         # KEM trait definitions
│   └── ml_kem.rs         # ML-KEM implementation
├── aead/                 # Authenticated Encryption implementations
│   ├── mod.rs
│   ├── traits.rs         # AEAD trait definitions
│   ├── saturnin.rs       # Saturnin AEAD implementation
│   └── shake256.rs       # SHAKE256 AEAD implementation
├── protocol/             # HPKE protocol implementation
│   ├── mod.rs
│   ├── key_schedule.rs   # Key schedule implementation
│   ├── labeled_functions.rs # Labeled extract/expand functions
│   └── context.rs        # HPKE context management
├── integration/          # Integration with lib-q-core
│   ├── mod.rs
│   ├── error_conversion.rs # Error type conversions
│   ├── provider_bridge.rs  # Provider bridge implementation
│   └── type_adapters.rs    # Type conversion utilities
└── benchmarking/         # Performance measurement
    ├── mod.rs
    ├── metrics.rs        # Performance metrics collection
    ├── profiler.rs       # Performance profiling
    └── reporter.rs       # Performance reporting
```

## Core Components

### 1. Security Module (`security/`)

The security module provides comprehensive security utilities:

#### Security Policy (`security/policy.rs`)
```rust
pub struct SecurityPolicy {
    pub require_constant_time: bool,
    pub validate_key_material: bool,
    pub enforce_zero_key_rejection: bool,
    pub strict_length_validation: bool,
    pub enable_side_channel_protection: bool,
    pub max_key_size: usize,
    pub max_nonce_size: usize,
    pub max_ciphertext_size: usize,
}
```

#### Cryptographic Validator (`security/validation.rs`)
```rust
pub struct CryptographicValidator {
    policy: SecurityPolicy,
}

impl CryptographicValidator {
    pub fn validate_kem_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), HpkeError>;
    pub fn validate_aead_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), HpkeError>;
    pub fn validate_aead_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), HpkeError>;
}
```

#### Secure Memory Management (`security/memory.rs`)
```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    data: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureNonce {
    data: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}
```

### 2. Provider System (`providers/`)

The provider system allows pluggable cryptographic implementations with algorithm-agnostic design:

#### Provider Traits (`providers/traits.rs`)
```rust
pub trait KemProvider {
    type Error: Into<HpkeError>;
    fn generate_keypair(&self, kem: HpkeKem, rng: &mut dyn CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    fn encapsulate(&self, kem: HpkeKem, public_key: &[u8], rng: &mut dyn CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    fn decapsulate(&self, kem: HpkeKem, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn auth_encapsulate(&self, kem: HpkeKem, sender_sk: &[u8], recipient_pk: &[u8], rng: &mut dyn CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;
    fn auth_decapsulate(&self, kem: HpkeKem, encapsulated_key: &[u8], recipient_sk: &[u8], sender_pk: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait KdfProvider {
    type Error: Into<HpkeError>;
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn expand(&self, kdf: HpkeKdf, prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, Self::Error>;
}

pub trait AeadProvider {
    type Error: Into<HpkeError>;
    fn seal(&self, aead: HpkeAead, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn open(&self, aead: HpkeAead, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
```

### 3. Enhanced Error Handling (`error.rs`)

The error system provides structured, context-rich error information:

```rust
pub enum HpkeError {
    KemError { algorithm: HpkeKem, operation: KemOperation, cause: String },
    KdfError { algorithm: HpkeKdf, operation: KdfOperation, cause: String },
    AeadError { algorithm: HpkeAead, operation: AeadOperation, cause: String },
    SecurityError { validation: SecurityValidation, cause: String },
    ProtocolError { stage: ProtocolStage, cause: String },
    // ... more error variants
}
```

### 4. Performance Benchmarking (`benchmarking/`)

The benchmarking system provides comprehensive performance measurement:

#### Performance Metrics (`benchmarking/metrics.rs`)
```rust
pub struct PerformanceMetrics {
    pub operation: OperationType,
    pub algorithm: AlgorithmType,
    pub execution_time_ns: u64,
    pub memory_usage_bytes: usize,
    pub iterations: u32,
    pub success_rate: f64,
    pub metadata: HashMap<String, String>,
}
```

#### Performance Profiler (`benchmarking/profiler.rs`)
```rust
pub struct PerformanceProfiler {
    start_time: Option<Instant>,
    start_memory: Option<usize>,
    operation: Option<OperationType>,
    algorithm: Option<AlgorithmType>,
}

impl PerformanceProfiler {
    pub fn profile_function<F, R>(&mut self, operation: OperationType, algorithm: AlgorithmType, iterations: u32, func: F) -> Result<(R, PerformanceMetrics), HpkeError>;
}
```

## Comprehensive Algorithm-Agnostic Implementation

### lib-q Integration

The HPKE implementation uses lib-q abstractions for all cryptographic primitives, ensuring comprehensive algorithm-agnostic design:

#### KEM Operations
```rust
impl PostQuantumProvider {
    fn create_kem_instance(kem: HpkeKem) -> Result<Box<dyn CoreKem>, HpkeError> {
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        create_kem(algorithm).map_err(|e| HpkeError::CryptoError(format!("Failed to create KEM instance: {}", e)))
    }
    
    fn hpke_kem_to_algorithm(kem: HpkeKem) -> Result<Algorithm, HpkeError> {
        match kem {
            HpkeKem::MlKem512 => Ok(Algorithm::MlKem512),
            HpkeKem::MlKem768 => Ok(Algorithm::MlKem768),
            HpkeKem::MlKem1024 => Ok(Algorithm::MlKem1024),
        }
    }
}
```

#### KDF Operations
```rust
impl PostQuantumProvider {
    fn create_hash_instance(kdf: HpkeKdf) -> Result<Box<dyn CoreHash>, HpkeError> {
        let algorithm_name = match kdf {
            HpkeKdf::HkdfShake128 => "shake128",
            HpkeKdf::HkdfShake256 => "shake256",
            HpkeKdf::HkdfSha3_256 => "sha3-256",
            HpkeKdf::HkdfSha3_512 => "sha3-512",
        };
        create_hash(algorithm_name).map_err(|e| HpkeError::CryptoError(format!("Failed to create hash instance: {}", e)))
    }
}
```

#### AEAD Operations
```rust
impl PostQuantumProvider {
    fn create_aead_instance(aead: HpkeAead) -> Result<Box<dyn CoreAead>, HpkeError> {
        let algorithm_name = match aead {
            HpkeAead::Saturnin256 => "saturnin",
            HpkeAead::Shake256 => "shake256",
            HpkeAead::Export => return Err(HpkeError::not_implemented("Export-only AEAD")),
        };
        create_aead(algorithm_name).map_err(|e| HpkeError::CryptoError(format!("Failed to create AEAD instance: {}", e)))
    }
}
```

### Benefits of Comprehensive Algorithm-Agnostic Design

1. **Extensibility**: Easy integration of new algorithms through lib-q abstractions
   - New KEM algorithms via `lib-q-kem::create_kem()`
   - New hash functions via `lib-q-hash::create_hash()`
   - New AEAD algorithms via `lib-q-aead::create_aead()`

2. **Maintainability**: Core HPKE logic is independent of specific algorithms
   - Provider pattern isolates algorithm-specific code
   - Consistent interfaces across all cryptographic primitives

3. **Consistency**: Uses the same interfaces as other lib-q components
   - Unified API across the entire lib-q ecosystem
   - Seamless integration with other lib-q crates

4. **Testing**: Comprehensive algorithm-agnostic tests verify compatibility
   - Cross-algorithm compatibility testing
   - Provider integration testing
   - Security property verification across all primitives

### Provider Implementation

The `PostQuantumProvider` implements all provider traits using the lib-q-kem abstraction:

```rust
impl KemProvider for PostQuantumProvider {
    fn generate_keypair(&self, kem: HpkeKem, rng: &mut dyn CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;
        let keypair = kem_impl.generate_keypair()
            .map_err(|e| HpkeError::CryptoError(format!("KEM key generation failed: {}", e)))?;
        Ok((keypair.public_key().as_bytes().to_vec(), keypair.secret_key().as_bytes().to_vec()))
    }
    
    fn encapsulate(&self, kem: HpkeKem, public_key: &[u8], rng: &mut dyn CryptoRng) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;
        let pk = KemPublicKey::new(public_key.to_vec());
        let (encapsulated_key, shared_secret) = kem_impl.encapsulate(&pk)
            .map_err(|e| HpkeError::CryptoError(format!("Encapsulation failed: {}", e)))?;
        Ok((encapsulated_key, shared_secret))
    }
    
    // ... other trait methods
}
```

## Integration with lib-q-core

The integration layer provides seamless integration with the existing lib-q ecosystem:

### Error Conversion (`integration/error_conversion.rs`)
- Converts between `HpkeError` and `lib_q_core::Error`
- Maintains error context and information

### Provider Bridge (`integration/provider_bridge.rs`)
- Bridges new provider system with lib-q crypto crates
- Provides fallback implementations for missing features

### Type Adapters (`integration/type_adapters.rs`)
- Converts between lib-q-core types and HPKE types
- Provides algorithm mapping utilities

## Security Considerations

### 1. Constant-Time Operations
All cryptographic operations use constant-time implementations to prevent timing attacks:

```rust
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

### 2. Memory Safety
Sensitive data is automatically zeroized using the `Zeroize` trait:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    data: Vec<u8>,
}
```

### 3. Input Validation
Comprehensive input validation with configurable security policies:

```rust
pub fn validate_key(&self, key: &[u8], expected_len: usize) -> Result<(), HpkeError> {
    if self.strict_length_validation && key.len() != expected_len {
        return Err(HpkeError::security_error(
            SecurityValidation::KeyLength,
            format!("Expected key length {}, got {}", expected_len, key.len()),
        ));
    }
    // ... more validation
}
```

## Performance Optimization

### 1. Benchmarking Infrastructure
Built-in performance measurement and reporting:

```rust
let mut profiler = PerformanceProfiler::new();
let (result, metrics) = profiler.profile_function(
    OperationType::KemKeyGeneration,
    AlgorithmType::MlKem512,
    100,
    || kem.generate_keypair(),
)?;
```

### 2. Memory Efficiency
Optimized memory usage with secure containers and efficient data structures.

### 3. Algorithm Selection
Support for different security/performance trade-offs through configurable cipher suites.

## Testing Strategy

### 1. Unit Tests
- Individual component testing
- Security validation testing
- Error handling testing

### 2. Integration Tests
- End-to-end functionality testing
- Provider integration testing
- Performance benchmarking testing

### 3. Property Tests
- Cryptographic property verification
- Security property validation

### 4. Test Vectors
- RFC compliance testing
- Edge case testing

### 5. Algorithm-Agnostic Testing
- Cross-algorithm compatibility testing
- Provider integration testing
- Algorithm-agnostic functionality verification

## Future Enhancements

### 1. Algorithm Extensions
- Additional post-quantum algorithms
- Hybrid classical/post-quantum modes

### 2. Performance Optimizations
- SIMD optimizations
- Hardware acceleration support

### 3. Security Enhancements
- Side-channel resistance improvements
- Formal verification integration

### 4. Documentation
- API documentation
- Usage examples
- Security guidelines

## Conclusion

The lib-q-hpke architecture provides a robust, secure, and performant foundation for post-quantum HPKE operations. The modular design allows for easy extension and maintenance, while the security-first approach ensures protection against various attack vectors.

The integration layer ensures compatibility with the existing lib-q ecosystem, while the new architecture provides enhanced security, performance measurement, and maintainability features.
