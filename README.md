# lib-Q - Post-Quantum Cryptography Library

A modern cryptography library built exclusively with NIST-approved post-quantum algorithms. Written in Rust with WASM compilation support.

## Mission

lib-Q provides a clean, modern API for post-quantum cryptography, ensuring quantum resistance while maintaining intuitive, easy-to-use interfaces for developers.

## Key Features

- **Post-quantum first**: Post-quantum KEMs and signatures with tiered symmetric options
- **NIST-approved**: All algorithms are NIST PQC standardized
- **Memory safe**: Built in Rust with zero-cost abstractions
- **Cross-platform**: Native Rust + WASM compilation
- **Intuitive API**: Clean, consistent interface designed for modern development
- **Zero dependencies**: Self-contained implementations
- **Three security tiers**: Ultra-secure, balanced, and performance-optimized options
- **Modular design**: Use only what you need with individual crates and npm packages

## Package Structure

lib-Q is organized as a Rust workspace with individual crates and npm packages:

### Rust Crates (crates.io)

- **`lib-q`** - Complete library (re-exports everything)
- **`lib-q-core`** - Core types and traits
- **`lib-q-kem`** - Key Encapsulation Mechanisms (ML-KEM, McEliece, HQC, DAWN, RCPKC)
- **`lib-q-sig`** - Digital Signatures (ML-DSA, FN-DSA, SLH-DSA)
- **`lib-q-hash`** - Hash Functions (SHAKE256, SHAKE128, cSHAKE256)
- **`lib-q-aead`** - Authenticated Encryption (Saturnin)
- **`lib-q-utils`** - Utility functions
- **`lib-q-zkp`** - Zero-Knowledge Proofs

### NPM Packages (npmjs.com)

- **`@lib-q/core`** - Complete library for Node.js
- **`@lib-q/kem`** - KEM-only package
- **`@lib-q/sig`** - Signature-only package
- **`@lib-q/hash`** - Hash-only package
- **`@lib-q/utils`** - Utilities-only package

## Installation

### Rust (Complete Library)
```bash
cargo add lib-q
```

### Rust (Individual Crates)
```bash
# For KEM operations only
cargo add lib-q-kem

# For signatures only
cargo add lib-q-sig

# For hash functions only
cargo add lib-q-hash

# For utilities only
cargo add lib-q-utils
```

### Node.js (Complete Library)
```bash
npm install @lib-q/core
```

### Node.js (Individual Packages)
```bash
# For KEM operations only
npm install @lib-q/kem

# For signatures only
npm install @lib-q/sig

# For hash functions only
npm install @lib-q/hash

# For utilities only
npm install @lib-q/utils
```

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)
- **ML-KEM** (FIPS 203, Level 1, 3, 5)
- **Classic McEliece** (Level 1, 3, 4, 5)
- **HQC** (Level 1, 3, 4, 5)
- **DAWN** (NTRU-based, smaller and faster)
- **RCPKC** (Randomized Concatenated Public Key Cryptography)

### Digital Signatures
- **ML-DSA** (FIPS 204, Level 1, 3, 5)
- **FN-DSA** (FIPS 206, compact signatures)
- **SLH-DSA** (FIPS 205, Level 1, 3, 5)

### Hash Functions
- **SHAKE256** (for hash-based signatures)
- **SHAKE128** (for general hashing)
- **cSHAKE256** (customizable hashing)

### Authenticated Encryption
- **Saturnin** (post-quantum symmetric algorithm suite)

### Hybrid Public Key Encryption (HPKE)
- **Tier 1: Ultra-Secure** (Pure post-quantum with SHAKE256-based AEAD)
- **Tier 2: Balanced** (Post-quantum KEM + Saturnin AEAD)
- **Tier 3: Performance** (Post-quantum KEM + optimized Saturnin)
- **Tier 4: Hybrid Security** (RCPKC with algorithm diversity)

### Zero-Knowledge Proofs (ZKPs)
- **zk-STARKs** (scalable, transparent, post-quantum secure)
- **Proof generation and verification**
- **Privacy-preserving computation**
- **WASM compatible**

## Architecture

```
lib-Q/
├── lib-q-core/      # Core types and traits
├── lib-q-kem/       # Key Encapsulation Mechanisms
├── lib-q-sig/       # Digital Signatures
├── lib-q-hash/      # Hash Functions
├── lib-q-aead/      # Authenticated Encryption
├── lib-q-utils/     # Utilities and helpers
├── lib-q-zkp/       # Zero-Knowledge Proofs
└── lib-q/           # Main crate (re-exports everything)
```

## Security Model

- **Post-quantum only**: No reliance on classical algorithms
- **Constant-time operations**: All cryptographic operations are constant-time
- **Secure memory**: Automatic secure memory zeroing
- **No side-channels**: Designed to prevent timing and power analysis attacks

## Development Status

**Active Development** - Core cryptographic algorithms implemented and integrated

### Implemented Features
- ✅ **ML-DSA** (FIPS 204, 44, 65, 87) - Complete with provider pattern integration
- ✅ **Core Architecture** - Provider pattern with clean separation of interfaces
- ✅ **Hash Functions** - SHA3, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash
- ✅ **WASM Support** - Basic WASM bindings for web environments
- ✅ **Memory Safety** - Zero unsafe code, automatic memory management
- ✅ **Error Handling** - Consistent error types and fail-fast behavior

### In Progress
- 🔄 **Saturnin AEAD** - Post-quantum symmetric encryption implementation
- 🔄 **HPKE** - Four-tier Hybrid Public Key Encryption system
- 🔄 **FN-DSA** - FIPS 206 signature algorithm integration
- 🔄 **DAWN KEM** - NTRU-based key encapsulation mechanism
- 🔄 **RCPKC** - Randomized Concatenated Public Key Cryptography

### Planned
- 📋 **Additional KEMs** - McEliece, HQC post-core completion
- 📋 **Additional Signatures** - SLH-DSA post-core completion
- 📋 **Zero-Knowledge Proofs** - Advanced cryptographic protocols

## Documentation

- [Development Plan](docs/development-plan.md)
- [Security Model](docs/security.md)
- [API Design](docs/api-design.md)
- [HPKE Architecture](docs/hpke-architecture.md)
- [Memory Architecture](docs/memory-architecture.md)
- [Interoperability](docs/interoperability.md)
- [Architecture Summary](docs/architecture-summary.md)
- [AI-Generated Wiki](https://deepwiki.com/Enkom-Tech/libQ)

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Notice

⚠️ **This library is in active development with implemented cryptographic algorithms.**

**Current Status:**
- Core cryptographic primitives (ML-DSA, hashes) are implemented and tested
- Provider pattern architecture is in place with proper error handling
- No known security vulnerabilities in implemented algorithms
- **NOT READY FOR PRODUCTION USE** until:
  - Security audit completion
  - Comprehensive testing (fuzzing, side-channel analysis)
  - Performance optimization and validation
  - AEAD implementation for authenticated encryption

**Use only for:**
- Research and development
- Algorithm evaluation
- Educational purposes
- Non-production prototyping

For production use, wait for version 1.0.0 and security audit completion.
