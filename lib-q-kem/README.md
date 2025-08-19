# lib-Q KEM - Post-Quantum Key Encapsulation Mechanisms

A secure implementation of post-quantum key encapsulation mechanisms (KEMs) for the lib-Q cryptographic library.

## Features

- **ML-KEM (FIPS 203)**: Complete implementation of the Module-Lattice-Based Key-Encapsulation Mechanism Standard
  - ML-KEM 512 (Level 1 security)
  - ML-KEM 768 (Level 3 security) 
  - ML-KEM 1024 (Level 5 security)
- **Secure by Design**: Implements secure development practices with infallible operations
- **Production Ready**: Comprehensive test coverage and security validation

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-q-kem = { version = "0.0.1", features = ["ml-kem"] }
```

Basic usage:

```rust
use lib_q_kem::{create_kem, available_algorithms};
use lib_q_core::Algorithm;

// Get available algorithms
let algorithms = available_algorithms();
println!("Available algorithms: {:?}", algorithms);

// Create a KEM instance
let kem = create_kem(Algorithm::MlKem512)?;

// Generate a keypair
let keypair = kem.generate_keypair()?;

// Encapsulate a shared secret
let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key)?;

// Decapsulate the shared secret
let decapsulated_secret = kem.decapsulate(&keypair.secret_key, &ciphertext)?;

assert_eq!(shared_secret, decapsulated_secret);
```

## Security Features

- **Infallible Operations**: All cryptographic operations use infallible methods to prevent information leakage
- **Constant-Time Execution**: Maintains constant-time operations for all cryptographic work
- **Runtime Validation**: Secure size validation with fail-safe behavior
- **No Fallible Parsing**: Eliminated dangerous fallible parsing that could leak secret information
- **Fail-Safe Design**: Cryptographic operations fail safely without exposing sensitive data
- **Verifiable Decapsulation**: All decapsulation operations are verifiable and secure

## Supported Algorithms

| Algorithm | Security Level | Public Key Size | Secret Key Size | Ciphertext Size |
|-----------|----------------|-----------------|-----------------|-----------------|
| ML-KEM 512 | Level 1 (128-bit) | 800 bytes | 1,632 bytes | 768 bytes |
| ML-KEM 768 | Level 3 (192-bit) | 1,184 bytes | 2,400 bytes | 1,088 bytes |
| ML-KEM 1024 | Level 5 (256-bit) | 1,568 bytes | 3,168 bytes | 1,568 bytes |

All algorithms produce a 32-byte shared secret.

## API Reference

### Core Functions

```rust
/// Get a list of available KEM algorithms
pub fn available_algorithms() -> Vec<Algorithm>

/// Create a KEM instance for the specified algorithm
pub fn create_kem(algorithm: Algorithm) -> Result<Box<dyn Kem>, Error>
```

### KEM Trait

```rust
pub trait Kem {
    /// Generate a new keypair
    fn generate_keypair(&self) -> Result<KemKeypair, Error>;
    
    /// Encapsulate a shared secret using the public key
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), Error>;
    
    /// Decapsulate a shared secret using the secret key and ciphertext
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}
```

## Features

### ml-kem
Enables ML-KEM (FIPS 203) implementations. This is the default and recommended feature.

```toml
[dependencies]
lib-q-kem = { version = "0.0.1", features = ["ml-kem"] }
```

## Testing

```bash
# Run all tests
cargo test

# Run tests with ML-KEM feature
cargo test --features ml-kem

# Run specific algorithm tests
cargo test test_mlkem512_encapsulation_decapsulation
```

## Security Considerations

**Important**: This implementation follows secure development practices but has not been independently audited. Use in production at your own risk.

### Security Features Implemented

- No Information Leakage: Eliminated fallible parsing that could leak secret key information
- Constant-Time Operations: All cryptographic operations maintain constant-time execution
- Fail-Safe Design: Cryptographic operations fail safely without exposing sensitive data
- Verifiable Decapsulation: All decapsulation operations are verifiable and secure
- Runtime Validation: Secure size validation with appropriate error handling

### Recommended Usage

- Use ML-KEM 768 or ML-KEM 1024 for production systems requiring high security
- ML-KEM 512 is suitable for testing and development
- Always validate key and ciphertext sizes before use
- Store secret keys securely and never expose them

## Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Enkom-Tech/libQ.git
cd libQ

# Install dependencies
cargo build --features ml-kem

# Run tests
cargo test --features ml-kem

# Run clippy for code quality
cargo clippy --features ml-kem
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.

## References

- [FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-ML-Kem](https://pq-crystals.org/ml_kem/)

## Changelog

### 0.0.1
- Initial release with ML-KEM (FIPS 203) support
- Secure implementation with infallible operations
- Comprehensive test coverage
- Production-ready security features
