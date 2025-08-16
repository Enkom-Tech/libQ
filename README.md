# lib-Q - Post-Quantum Cryptography Library

A modern cryptography library built exclusively with NIST-approved post-quantum algorithms. Written in Rust with WASM compilation support.

## Mission

lib-Q provides a libsodium-equivalent API for post-quantum cryptography, ensuring quantum resistance while maintaining familiar, easy-to-use interfaces.

## Key Features

- **Post-quantum first**: Post-quantum KEMs and signatures with tiered symmetric options
- **NIST-approved**: All algorithms are NIST PQC standardized
- **Memory safe**: Built in Rust with zero-cost abstractions
- **Cross-platform**: Native Rust + WASM compilation
- **Familiar API**: libsodium-style interface for easy migration
- **Zero dependencies**: Self-contained implementations
- **Three security tiers**: Ultra-secure, balanced, and performance-optimized options

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)
- **CRYSTALS-Kyber** (Level 1, 3, 5)
- **Classic McEliece** (Level 1, 3, 4, 5)
- **HQC** (Level 1, 3, 4, 5)

### Digital Signatures
- **CRYSTALS-Dilithium** (Level 1, 3, 5)
- **Falcon** (Level 1, 5)
- **SPHINCS+** (Level 1, 3, 5)

### Hash Functions
- **SHAKE256** (for hash-based signatures)
- **SHAKE128** (for general hashing)
- **cSHAKE256** (customizable hashing)

### Hybrid Public Key Encryption (HPKE)
- **PQ-HPKE** (pure post-quantum)
- **Hybrid HPKE** (PQ KEM + classical symmetric)
- **Performance HPKE** (PQ KEM + optimized classical)

### Zero-Knowledge Proofs (ZKPs)
- **zk-STARKs** (scalable, transparent, post-quantum secure)
- **Proof generation and verification**
- **Privacy-preserving computation**
- **WASM compatible**

## Architecture

```
lib-Q/
├── src/
│   ├── kem/           # Key Encapsulation Mechanisms
│   ├── sig/           # Digital Signatures
│   ├── hash/          # Hash Functions
│   ├── aead/          # Authenticated Encryption
│   ├── zkp/           # Zero-Knowledge Proofs
│   ├── utils/         # Utilities and helpers
│   └── wasm/          # WASM bindings
├── tests/             # Comprehensive test suite
├── benches/           # Performance benchmarks
├── docs/              # Documentation
└── examples/          # Usage examples
```

## Security Model

- **Zero classical crypto**: No reliance on classical algorithms
- **Constant-time operations**: All cryptographic operations are constant-time
- **Secure memory**: Automatic secure memory zeroing
- **No side-channels**: Designed to prevent timing and power analysis attacks

## Development Status

**Planning Phase** - Architecture and algorithm selection complete

## Documentation

- [Development Plan](docs/development-plan.md)
- [Security Model](docs/security.md)
- [API Design](docs/api-design.md)
- [HPKE Architecture](docs/hpke-architecture.md)
- [Memory Architecture](docs/memory-architecture.md)
- [Interoperability](docs/interoperability.md)
- [Architecture Summary](docs/architecture-summary.md)

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Notice

This library is in development. Do not use in production until a stable release is available.
