# HPKE Architecture Documentation

## Overview

The lib-q-hpke implementation follows a modular, security-first architecture for post-quantum cryptography. This document describes the architecture, design decisions, and implementation details.

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
├── error.rs              # Error handling
├── hpke_core.rs          # Core HPKE protocol implementation
├── security_tests.rs     # Security validation tests
├── security/             # Security utilities and validation
│   ├── mod.rs
│   ├── policy.rs         # Security policy configuration
│   ├── validation.rs     # Cryptographic validation
│   ├── constant_time.rs  # Constant-time operations
│   ├── memory.rs         # Secure memory management
│   ├── memory_safety.rs  # Memory safety utilities
│   ├── side_channel_protection.rs # Side-channel attack protection
│   ├── side_channel.rs   # Additional side-channel utilities
│   ├── prng.rs           # Pseudo-random number generation
│   ├── fuzzing.rs        # Fuzzing support
│   ├── key_rotation.rs   # Key rotation management
│   └── test_rng.rs       # Test RNG implementation
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
│   ├── shake256.rs       # SHAKE256 AEAD implementation
│   └── export.rs         # Export-only AEAD implementation
├── kdf/                  # Key Derivation Function implementations
│   ├── mod.rs
│   ├── traits.rs         # KDF trait definitions
│   └── hkdf.rs           # HKDF implementation
├── protocol/             # HPKE protocol implementation
│   └── mod.rs            # Protocol module (key schedule in hpke_core.rs)
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
- Configurable security policies for validation and enforcement
- Support for constant-time operations and side-channel protection
- Memory safety and zeroization policies

#### Cryptographic Validation (`security/validation.rs`)
- Input validation for keys, nonces, and ciphertexts
- Side-channel resistant validation functions
- Comprehensive parameter checking

#### Memory Safety (`security/memory_safety.rs`)
- Secure memory management with automatic zeroization
- Secure containers for sensitive data
- Memory pool management for secure allocations

#### Side-Channel Protection (`security/side_channel_protection.rs`)
- Constant-time operations for cryptographic primitives
- Side-channel attack mitigation
- Timing attack prevention

#### Additional Security Features
- **Fuzzing Support** (`security/fuzzing.rs`): Comprehensive fuzzing infrastructure
- **Key Rotation** (`security/key_rotation.rs`): Key rotation management
- **PRNG Security** (`security/prng.rs`): Secure random number generation

### 2. Provider System (`providers/`)

The provider system allows pluggable cryptographic implementations with algorithm-agnostic design:

#### Provider Traits (`providers/traits.rs`)
- **HpkeCryptoProvider**: Unified trait for all cryptographic operations
- **KEM Operations**: Key generation, encapsulation, and decapsulation
- **KDF Operations**: Key derivation and expansion
- **AEAD Operations**: Authenticated encryption and decryption
- **Authentication**: Sender authentication for Auth and AuthPSK modes

#### Post-Quantum Provider (`providers/post_quantum.rs`)
- Implements all provider traits using lib-q abstractions
- Integrates with `lib-q-kem`, `lib-q-hash`, and `lib-q-aead`
- Provides algorithm-agnostic cryptographic operations
- Supports all HPKE modes (Base, PSK, Auth, AuthPSK)

### 3. Error Handling (`error.rs`)

The error system provides structured, context-rich error information:

- **CryptoError**: General cryptographic operation errors
- **InvalidInput**: Input validation errors with parameter details
- **InconsistentPsk**: PSK parameter consistency errors
- **NotImplemented**: Unimplemented functionality errors
- **ContextError**: HPKE context state errors
- **ExportError**: Key export operation errors

The error system includes comprehensive error context and supports conversion to/from lib-q-core error types.

### 4. Performance Benchmarking (`benchmarking/`)

The benchmarking system provides performance measurement capabilities:

- **Performance Metrics**: Collection of execution time, memory usage, and success rates
- **Performance Profiler**: Function-level performance profiling
- **Performance Reporter**: Reporting and analysis of benchmark results

## Algorithm-Agnostic Implementation

### lib-q Integration

The HPKE implementation uses lib-q abstractions for all cryptographic primitives:

#### KEM Operations
- Uses `lib-q-kem` for algorithm-agnostic KEM operations
- Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- Integrates with `KemContext` and `KemPublicKey`/`KemSecretKey` types

#### KDF Operations
- Uses `lib-q-hash` for hash function operations
- Supports HKDF-SHAKE128, HKDF-SHAKE256, HKDF-SHA3-256, and HKDF-SHA3-512
- Implements labeled extract and expand functions per RFC 9180

#### AEAD Operations
- Uses `lib-q-aead` for authenticated encryption
- Supports Saturnin-256 and SHAKE256-based AEAD
- Includes export-only mode for key derivation

### Benefits of Algorithm-Agnostic Design

1. **Extensibility**: Easy integration of new algorithms through lib-q abstractions
2. **Maintainability**: Core HPKE logic is independent of specific algorithms
3. **Consistency**: Uses the same interfaces as other lib-q components
4. **Testing**: Comprehensive algorithm-agnostic tests verify compatibility

### Provider Implementation

The `PostQuantumProvider` implements all provider traits using lib-q abstractions:

- **KEM Operations**: Uses `lib-q-kem::create_kem()` for algorithm-agnostic KEM operations
- **Hash Operations**: Uses `lib-q-hash::create_hash()` for hash function operations
- **AEAD Operations**: Uses `lib-q-aead::create_aead()` for authenticated encryption
- **Error Handling**: Converts between HPKE and lib-q error types

## Integration with lib-q-core

The HPKE implementation integrates with the lib-q ecosystem through the provider pattern:

### Provider Integration
- Uses `lib-q-core` types (`KemContext`, `KemPublicKey`, `KemSecretKey`)
- Leverages `lib-q-kem` for algorithm-agnostic KEM operations
- Integrates with `lib-q-hash` for hash function operations
- Uses `lib-q-aead` for authenticated encryption operations

### Algorithm Mapping
- Maps HPKE algorithm identifiers to lib-q algorithm types
- Provides consistent interfaces across all cryptographic primitives
- Maintains compatibility with existing lib-q ecosystem

## Security Considerations

### 1. Constant-Time Operations
All cryptographic operations use constant-time implementations to prevent timing attacks:

- **Constant-time comparison**: Side-channel resistant equality checks
- **Constant-time selection**: Secure conditional operations
- **Constant-time copying**: Secure memory operations

### 2. Memory Safety
Sensitive data is automatically zeroized using the `Zeroize` trait:

- **Secure containers**: Automatic zeroization on drop
- **Memory pools**: Secure memory allocation and deallocation
- **Buffer management**: Secure buffer handling with automatic cleanup

### 3. Input Validation
Comprehensive input validation with side-channel resistant checks:

- **Key validation**: Side-channel resistant key parameter validation
- **Nonce validation**: Secure nonce parameter checking
- **Ciphertext validation**: Secure ciphertext parameter validation
- **PSK validation**: Pre-shared key parameter consistency checks

### 4. Additional Security Features
- **Fuzzing support**: Comprehensive fuzzing infrastructure for security testing
- **Key rotation**: Secure key rotation management
- **PRNG security**: Cryptographically secure random number generation

## Performance Optimization

The implementation includes performance measurement capabilities through the benchmarking module:

- **Built-in Profiling**: Performance measurement for cryptographic operations
- **Memory Efficiency**: Optimized memory usage with secure containers
- **Algorithm Selection**: Support for different security/performance trade-offs

## API Documentation

For comprehensive API reference and usage examples, see [API_REFERENCE.md](API_REFERENCE.md).

