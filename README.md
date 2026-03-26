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
- **Self-contained algorithms**: No external non-Rust tooling required for core use
- **Three security tiers**: Ultra-secure, balanced, and performance-optimized options
- **Modular design**: Use only what you need with individual crates and npm packages

## no_std, embedded, and WebAssembly

- **Umbrella `lib-q` crate**: Disabling default features applies `#![no_std]` to this crate's own code, but some path dependencies are still declared with `std` enabled (for example unified signature support via `lib-q-sig`). The final artifact may still link the standard library. For a **true** `no_std` + `alloc` dependency tree, use the **workspace crates you need** (`lib-q-core`, `lib-q-kem`, `lib-q-ml-dsa`, etc.) with `--no-default-features` and each crate's `alloc` / algorithm features. Per-crate READMEs describe WASM and `no_std` where relevant (for example [lib-q-saturnin/README.md](lib-q-saturnin/README.md)).

- **WASM and `getrandom`**: Match CI when compiling for `wasm32-unknown-unknown`: set `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS` to `--cfg getrandom_backend="wasm_js" -C panic=abort` (see [.github/actions/wasm-build/action.yml](.github/actions/wasm-build/action.yml), [scripts/build-wasm.ps1](scripts/build-wasm.ps1), [scripts/security-check.ps1](scripts/security-check.ps1)).

- **`lib-q-zkp`**: Built as a normal Rust library (not a `cdylib` npm bundle). CI runs `cargo check --target wasm32-unknown-unknown` with `wasm,zkp` to guard the ZKP stack on WASM without `wasm-pack`.

## Package Structure

lib-Q is organized as a Rust workspace with individual crates and npm packages:

### Rust Crates (crates.io)

- **`lib-q`** - Complete library (re-exports everything)
- **`lib-q-core`** - Core types and traits
- **`lib-q-kem`** - Key Encapsulation Mechanisms (ML-KEM, CB-KEM, HQC, DAWN)
- **`lib-q-sig`** - Digital Signatures (ML-DSA, SLH-DSA)
- **`lib-q-fn-dsa`** - FN-DSA Digital Signatures (FIPS 206)
- **`lib-q-hash`** - Hash Functions (SHAKE256, SHAKE128, cSHAKE256)
- **`lib-q-aead`** - Authenticated Encryption (Saturnin)
- **`lib-q-utils`** - Utility functions
- **`lib-q-zkp`** - Zero-Knowledge Proofs

### NPM Packages (npmjs.com)

- **`@lib-q/core`** - Complete library for Node.js
- **`@lib-q/kem`** - KEM-only package
- **`@lib-q/sig`** - Signature-only package
- **`@lib-q/fn-dsa`** - FN-DSA signature-only package
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

# For FN-DSA signatures only
cargo add lib-q-fn-dsa

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

# For FN-DSA signatures only
npm install @lib-q/fn-dsa

# For hash functions only
npm install @lib-q/hash

# For utilities only
npm install @lib-q/utils
```

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)
- **ML-KEM** (FIPS 203, Level 1, 3, 5)
- **CB-KEM** (Level 1, 3, 4, 5)
- **HQC** (Level 1, 3, 4, 5)
- **DAWN** (NTRU-based, smaller and faster)

### Digital Signatures
- **ML-DSA** (FIPS 204, Level 1, 3, 5)
- **FN-DSA** (FIPS 206, Level 1, 5) - Compact lattice-based signatures
- **SLH-DSA** (FIPS 205, Level 1, 3, 5)
- **SABER**

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

### Zero-Knowledge Proofs (ZKPs)
- **zk-STARKs** (scalable, transparent, post-quantum secure)
- **Proof generation and verification**
- **Privacy-preserving computation**
- **WASM compatible**
- The default API is in `lib-q-zkp` (backed by `lib-q-stark`); the full Plonky3-derived stack (univariate and batch STARK, Keccak AIR, lookup) is in `lib-q-plonky` and is fully implemented behind features.

## Architecture

```
lib-Q/
├── lib-q-core/      # Core types and traits
├── lib-q-kem/       # Key Encapsulation Mechanisms
├── lib-q-sig/       # Digital Signatures
├── lib-q-fn-dsa/    # FN-DSA Digital Signatures
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
- ✅ **FN-DSA** (FIPS 206, Level 1, 5) - Complete implementation with CI/CD integration
- ✅ **SLH-DSA** (FIPS 205, Level 1, 3, 5) - Complete implementation with all 12 parameter sets
- ✅ **ML-KEM** (FIPS 203, Level 1, 3, 5) - Complete KEM implementation
- ✅ **DAWN KEM** - Complete NTRU-based KEM with all parameter sets (α-512, α-1024, β-512, β-1024)
- ✅ **Saturnin AEAD** - Complete post-quantum symmetric encryption with AEAD, block cipher, hash, and stream modes
- ✅ **HPKE** - Complete RFC 9180 compliant Hybrid Public Key Encryption system
- ✅ **Core Architecture** - Provider pattern with clean separation of interfaces
- ✅ **Hash Functions** - SHA3, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash
- ✅ **WASM Support** - Basic WASM bindings for web environments
- ✅ **Memory Safety** - Automatic memory management; unsafe limited to documented performance-critical paths (e.g. SIMD)
- ✅ **Error Handling** - Consistent error types and fail-fast behavior
- ✅ **CI/CD Integration** - Complete testing, security validation, and publishing workflows
- ✅ **HQC** - Complete NIST-standardized code-based KEM (all parameter sets)

### Planned
- 📋 **Additional KEMs** - CB-KEM optimization
- 📋 **Zero-Knowledge Proofs** - Advanced cryptographic protocols

## Documentation

- [ROADMAP](ROADMAP.md)
- [Security Model](docs/security.md)
- [ZKP Implementation and Library Layout](docs/zkp-implementation.md)
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
- Implemented: ML-DSA, ML-KEM, SLH-DSA, FN-DSA, DAWN, HQC, Saturnin AEAD, HPKE, hash suite (SHA3, SHAKE, cSHAKE, etc.), provider pattern, WASM bindings
- No known security vulnerabilities in implemented algorithms
- **NOT READY FOR PRODUCTION USE** until:
  - Security audit completion
  - Comprehensive testing (fuzzing, side-channel analysis)
  - Performance optimization and validation

**Use only for:**
- Research and development
- Algorithm evaluation
- Educational purposes
- Non-production prototyping

For production use, wait for version 1.0.0 and security audit completion.
