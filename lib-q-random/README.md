# lib-q-random: Secure Random Number Generation for libQ

[![Crates.io](https://img.shields.io/crates/v/lib-q-random.svg)](https://crates.io/crates/lib-q-random)
[![Documentation](https://docs.rs/lib-q-random/badge.svg)](https://docs.rs/lib-q-random)
[![License](https://img.shields.io/crates/l/lib-q-random.svg)](https://github.com/Enkom-Tech/libQ/blob/main/LICENSE)

A comprehensive, secure random number generation system designed specifically for post-quantum cryptography applications in the libQ ecosystem.

## Features

- **Cryptographically Secure**: Uses OS entropy sources and hardware RNGs when available
- **Multiple Providers**: Support for OS, deterministic, and hardware entropy sources
- **Entropy Validation**: Comprehensive entropy quality assessment and validation
- **no_std Support**: Works in constrained environments without standard library
- **WASM Compatible**: Full support for WebAssembly and browser environments
- **Zero-Copy**: Efficient memory usage with minimal allocations
- **Thread-Safe**: Safe for use in multi-threaded environments
- **Extensible**: Plugin architecture for custom entropy sources

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
lib-q-random = "0.0.2"
```

### Basic Usage

```rust
use lib_q_rng::{LibQRng, new_secure_rng, new_deterministic_rng};

// Create a secure RNG for production use
let mut rng = new_secure_rng()?;

// Generate random bytes
let mut bytes = [0u8; 32];
rng.fill_bytes(&mut bytes);

// Create a deterministic RNG for testing
let mut test_rng = new_deterministic_rng(&[1, 2, 3, 4]);
test_rng.fill_bytes(&mut bytes);
```

### Advanced Usage

```rust
use lib_q_rng::{
    LibQRng, EntropyValidator, EntropyQuality,
    entropy::{EntropySourceFactory, UserEntropySource},
    traits::{RngConfig, SecurityLevel}
};

// Create a custom RNG with user-provided entropy
let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
let entropy_source = UserEntropySource::new(entropy_data);
let mut rng = LibQRng::new_custom(entropy_source);

// Create an RNG with custom configuration
let config = RngConfig {
    security_level: SecurityLevel::CryptographicallySecure,
    reseed_interval: Some(1024 * 1024), // 1MB reseed interval
    ..Default::default()
};
let mut rng = LibQRng::with_config(config)?;

// Validate entropy quality
let validator = EntropyValidator::new();
let quality = validator.validate_entropy(&bytes)?;
println!("Entropy quality: {}", quality);
```

## Architecture

The crate is organized into several key components:

### Core Traits

- **`SecureRng`**: Enhanced random number generator trait for cryptographic applications
- **`EntropySource`**: Trait for entropy sources that provide random data
- **`RngProvider`**: Trait for RNG providers that create and manage RNG instances

### Providers

- **`LibQRng`**: Main RNG implementation with unified interface
- **`OsEntropySource`**: Operating system entropy source
- **`HardwareEntropySource`**: Hardware random number generator
- **`DeterministicEntropySource`**: Deterministic source for testing
- **`UserEntropySource`**: User-provided entropy source

### Validation

- **`EntropyValidator`**: Comprehensive entropy validation and quality assessment
- **`EntropyQuality`**: Entropy quality assessment result
- **`quick_entropy_check`**: Quick entropy validation for small samples

## Security Considerations

- All RNGs are cryptographically secure by default
- Entropy validation ensures sufficient randomness
- Secure memory clearing prevents key material leakage
- Constant-time operations prevent timing attacks
- Comprehensive error handling prevents fallback to weak randomness

## Platform Support

### Operating Systems

- Linux (using `/dev/urandom`)
- macOS (using `SecRandomCopyBytes`)
- Windows (using `CryptGenRandom`)
- FreeBSD, OpenBSD, NetBSD
- WebAssembly (using `crypto.getRandomValues()`)

### Hardware RNGs

- Intel RDRAND (when available)
- ARM TRNG (when available)
- Platform-specific hardware RNGs

## Feature Flags

- **`std`**: Standard library support (default)
- **`alloc`**: Dynamic memory allocation support
- **`secure`**: Cryptographically secure RNGs (default)
- **`deterministic`**: Deterministic RNGs for testing
- **`hardware`**: Hardware RNG support
- **`zeroize`**: Secure memory clearing (default)
- **`entropy-validation`**: Entropy validation features
- **`wasm`**: WebAssembly support
- **`js`**: JavaScript bindings

## Examples

### Basic Random Generation

```rust
use lib_q_rng::new_secure_rng;

let mut rng = new_secure_rng()?;
let mut key = [0u8; 32];
rng.fill_bytes(&mut key);
```

### Deterministic Testing

```rust
use lib_q_rng::new_deterministic_rng;

let seed = [1, 2, 3, 4, 5, 6, 7, 8];
let mut rng = new_deterministic_rng(&seed);
let mut bytes = [0u8; 16];
rng.fill_bytes(&mut bytes);
// bytes will be the same every time with the same seed
```

### Custom Entropy Source

```rust
use lib_q_rng::{LibQRng, entropy::UserEntropySource};

let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
let entropy_source = UserEntropySource::new(entropy_data);
let mut rng = LibQRng::new_custom(entropy_source);
```

### Entropy Validation

```rust
use lib_q_rng::{EntropyValidator, validation::quick_entropy_check};

let validator = EntropyValidator::new();
let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

// Quick check
if quick_entropy_check(&data) {
    println!("Data appears to have good entropy");
}

// Full validation
match validator.validate_entropy(&data) {
    Ok(quality) => println!("Entropy quality: {}", quality),
    Err(e) => println!("Entropy validation failed: {}", e),
}
```

## Performance

The crate is designed for high performance with minimal overhead:

- Zero-copy operations where possible
- Efficient entropy source selection
- Optimized validation algorithms
- Minimal memory allocations

Benchmarks are available in the `benches/` directory.

## Testing

The crate includes comprehensive tests:

- Unit tests for all components
- Integration tests for end-to-end functionality
- Property-based tests for statistical properties
- Performance benchmarks

Run tests with:

```bash
cargo test
cargo test --features "test-vectors"
```

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Security

For security-related issues, please see our [Security Policy](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.

## Related Projects

- [libQ](https://github.com/Enkom-Tech/libQ) - Post-quantum cryptography library
- [lib-q-core](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-core) - Core types and traits
- [lib-q-kem](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-kem) - Key encapsulation mechanisms
