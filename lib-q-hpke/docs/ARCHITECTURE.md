# HPKE Architecture Documentation

## Overview

The lib-q-hpke implementation follows a modular, security-first architecture for **post-quantum-only** HPKE (RFC 9180–aligned modes, key schedule, and labeled KDF). The default internal [`PostQuantumProvider`](../src/providers/post_quantum.rs) wires **ML-KEM** (`HpkeKem::*`) into encapsulation/decapsulation via [`LibQKemProvider`](../../lib-q-kem/README.md); other PQ KEMs may exist in the wider workspace but are not selected by the HPKE cipher suite in this crate until explicitly integrated.

[`HpkeContext`](../src/lib.rs) stores an active [`HpkeCipherSuite`](../src/types.rs), [`HpkePskWireFormat`](../src/types.rs) for PSK/AuthPSK on-the-wire policy, a `lib_q_core::KemContext` supplied by the caller’s `CryptoProvider` for ML-KEM key generation and validation, an `Arc<dyn HpkeCryptoProvider + Send + Sync>` (default [`PostQuantumProvider`](../src/providers/post_quantum.rs)) for HPKE encapsulation/KDF/AEAD/export, and a configurable RNG for setup and single-shot `seal` (default OS-backed when `secure-rng` is enabled).

## Interoperability module

[`interop.rs`](../src/interop.rs) exposes `HpkeInteropProfile`, `HpkeCapabilities`, and `negotiate_hpke_capabilities` for deterministic peer capability intersection. Workspace docs (`docs/interoperability.md`, `docs/hpke-architecture.md`) describe profile semantics and a representative mode×suite matrix.

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
├── lib.rs                 # HpkeContext, sender/receiver context methods, cipher suite + PSK wire format + HPKE crypto Arc + RNG
├── types.rs               # HpkeKem/Kdf/Aead, HpkeCipherSuite, HpkePskWireFormat, SecretBytes
├── interop.rs             # Profiles, capabilities, deterministic negotiation
├── hpke_session.rs        # HpkeSenderContext / HpkeReceiverContext (post-setup state)
├── error.rs               # HpkeError and conversion to lib-q-core::Error
├── hpke_core.rs           # Key schedule, setup/seal/open, PSK commitment parsing
├── wasm.rs                # wasm32 bindings (feature "wasm")
├── security_tests.rs      # Security validation tests (crate tests)
├── security/              # Security utilities and validation
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
├── aead/                  # HPKE-local AEAD helpers and trait bridge
│   ├── mod.rs
│   ├── traits.rs          # AEAD trait used inside HPKE
│   ├── saturnin.rs        # Saturnin AEAD implementation
│   ├── shake256.rs        # SHAKE256 AEAD implementation
│   └── export.rs          # Export-only AEAD stub
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

**Duplex-sponge AEAD:** `HpkeAead::DuplexSpongeAead` is routed to `lib-q-aead` (`Algorithm::DuplexSpongeAead`) when this crate is built with Cargo feature **`duplex-sponge-aead`**; there is no separate duplex source file under `src/aead/`.

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
- **`KemProvider`**: encapsulation, decapsulation, key validation, AuthEncap/AuthDecap
- **`KdfProvider`**: labeled HKDF-style extract/expand for `HpkeKdf`
- **`AeadProvider`**: seal/open and key/nonce validation for `HpkeAead`
- **`HpkeCryptoProvider`**: super-trait combining the three above (`KemProvider + KdfProvider + AeadProvider`) plus metadata (`name`, `supported_algorithms`)

#### Post-Quantum Provider (`providers/post_quantum.rs`)
- Implements `KemProvider`, `KdfProvider`, and `AeadProvider` using `lib-q-kem` (`LibQKemProvider`), `lib-q-hash` (`create_hash`), and `lib-q-aead` (`create_aead`)
- KEM path is ML-KEM only (`HpkeKem` ↔ `lib_q_core::Algorithm::MlKem*`)
- `HpkeAead::DuplexSpongeAead` is enabled only with Cargo feature **`duplex-sponge-aead`** (maps to `Algorithm::DuplexSpongeAead` in `lib-q-aead`)
- Supports HPKE modes Base, PSK, Auth, and AuthPSK (protocol orchestration in `hpke_core.rs` + `HpkeContext` in `lib.rs`)

### 3. Error Handling (`error.rs`)

[`HpkeError`](../src/error.rs) is structured by operation area. Important variants:

- **`KemError`**, **`KdfError`**, **`AeadError`**: algorithm + operation + cause string
- **`SecurityError`**: policy / validation failures (`SecurityValidation`)
- **`ProtocolError`**: protocol-stage failures (`ProtocolStage`)
- **`ConfigError`**: configuration issues
- **`CryptoError`**: general cryptographic failure messages
- **`InvalidInput`**: parameter validation with expected vs actual context
- **`FeatureNotEnabled`**, **`NotImplemented`**: missing Cargo features or unfinished paths
- **`InconsistentPsk`**: PSK / commitment mismatch (notably with `HpkePskWireFormat::LibQCommitmentSuffix` before decapsulation; RFC-only PSK wire typically surfaces failure at AEAD open)

The `From<HpkeError>` implementation for `lib_q_core::Error` means `HpkeContext` APIs returning `lib_q_core::Result` map most HPKE failures into `lib_q_core::Error::InternalError` (see `lib-q-hpke/src/error.rs`).

### 4. Performance Benchmarking (`benchmarking/`)

The benchmarking system provides performance measurement capabilities:

- **Performance Metrics**: Collection of execution time, memory usage, and success rates
- **Performance Profiler**: Function-level performance profiling
- **Performance Reporter**: Reporting and analysis of benchmark results

## Algorithm-Agnostic Implementation

### lib-q Integration

The HPKE implementation uses lib-q abstractions for all cryptographic primitives:

#### KEM Operations
- Uses [`LibQKemProvider`](../../lib-q-kem/README.md) inside `PostQuantumProvider` for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- Caller-facing key generation uses `KemContext` + `CryptoProvider` from `lib-q-core` (same ML-KEM parameter sets when using the default lib-q stack)

#### KDF Operations
- Uses `lib-q-hash` for hash function operations
- Supports HKDF-SHAKE128, HKDF-SHAKE256, HKDF-SHA3-256, and HKDF-SHA3-512
- Implements labeled extract and expand functions per RFC 9180

#### AEAD Operations
- Uses `lib-q-aead` (`create_aead`) for Saturnin, SHAKE256 AEAD, and optionally duplex-sponge AEAD
- Supports export-only mode (`HpkeAead::Export`) for exporter-secret-only usage (no message AEAD)

### Benefits of Algorithm-Agnostic Design

1. **Extensibility**: Easy integration of new algorithms through lib-q abstractions
2. **Maintainability**: Core HPKE logic is independent of specific algorithms
3. **Consistency**: Uses the same interfaces as other lib-q components
4. **Testing**: Comprehensive algorithm-agnostic tests verify compatibility

## Integration with lib-q-core

The HPKE crate integrates with the rest of lib-q as follows:

### Provider integration
- **`HpkeContext`** holds `KemContext` for operations that need the caller’s registered `CryptoProvider`
- **HPKE internals** construct a fresh `PostQuantumProvider` for KEM/KDF/AEAD steps inside `hpke_core` (see call sites in [`lib.rs`](../src/lib.rs))
- **Types**: `KemPublicKey`, `KemSecretKey`, and `lib_q_core::Result` on the public HPKE API

### Algorithm mapping
- Maps each `HpkeCipherSuite` component to `lib-q-core` / `lib-q-hash` / `lib-q-aead` algorithms
- `HpkePskWireFormat` affects only PSK / AuthPSK encapsulated-key parsing and commitment verification in `hpke_core.rs`

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

For workspace-level HPKE design (interoperability, PSK wire format, security framing), see [hpke-architecture.md](../../docs/hpke-architecture.md) in the repository `docs/` tree.
