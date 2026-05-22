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
- **Custom Entropy Sources**: Secure callback-based system for plugging in custom entropy sources in `no_std` and WASM environments

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
lib-q-random = "0.0.4"

# For custom entropy sources in no_std/WASM environments
lib-q-random = { version = "0.0.4", features = ["custom-entropy"] }
```

### Basic Usage

```rust
use lib_q_random::{LibQRng, new_secure_rng, new_deterministic_rng};

// Create a secure RNG for production use
let mut rng = new_secure_rng()?;

// Generate random bytes
let mut bytes = [0u8; 32];
rng.fill_bytes(&mut bytes);

// Create a deterministic RNG for testing
let mut test_rng = new_deterministic_rng([1; 32]);
test_rng.fill_bytes(&mut bytes);
```

### Advanced Usage

```rust
use lib_q_random::{
    LibQRng, EntropyValidator, EntropyQuality,
    entropy::{EntropySourceFactory, UserEntropySource},
    traits::{RngConfig, SecurityLevel}
};

// Create a custom RNG with user-provided entropy
let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
let entropy_source = UserEntropySource::new(entropy_data);
```

### Custom Entropy Sources (no_std/WASM)

For `no_std` and WASM environments, you can plug in custom entropy sources:

```rust
#[cfg(feature = "custom-entropy")]
{
    use lib_q_random::{
        CustomEntropySource, EntropyContext, EntropyQuality, CustomEntropyConfig,
        register_custom_entropy_source, unregister_custom_entropy_source,
        new_secure_rng_no_std
    };

    // Define your custom entropy callback
    unsafe extern "C" fn my_entropy_callback(dest: *mut u8, len: usize, _context: *mut u8) -> i32 {
        // Fill dest with len bytes of entropy from your source
        // Return 0 on success, non-zero on failure
        for i in 0..len {
            unsafe {
                *dest.add(i) = get_entropy_from_hardware(i); // Your entropy source
            }
        }
        0
    }

    // Create and register the custom entropy source
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: my_entropy_callback,
        context,
        quality: EntropyQuality::Hardware, // or Os, User, Deterministic
        config,
        source_id: "my_hardware_rng",
    };

    // Register the source (must remain valid for the lifetime of usage)
    unsafe {
        register_custom_entropy_source(&source);
    }

    // Now create RNGs that will use your custom entropy source
    let mut rng = new_secure_rng_no_std().unwrap();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    // Clean up when done
    unregister_custom_entropy_source();
}
```

### Feature Flags

- `std`: Enable standard library features (default)
- `no_std`: Enable no_std compatibility
- `custom-entropy`: Enable custom entropy source support
- `secure`: Enable cryptographically secure RNGs
- `deterministic`: Enable deterministic RNGs for testing
- `entropy-validation`: Enable entropy quality validation
- `zeroize`: Enable automatic memory zeroization
- `wasm`: Enable WebAssembly support

## Security Considerations

- **Entropy Quality**: Always use high-quality entropy sources for cryptographic operations
- **Custom Entropy**: When using custom entropy sources, ensure they provide cryptographically secure randomness
- **Memory Safety**: Sensitive data is automatically zeroized when using the `zeroize` feature
- **Thread Safety**: All RNG implementations are thread-safe and can be used in multi-threaded environments

## Architecture

The crate is organized into several key components:

### Core Traits

- **`SecureRng`**: Enhanced random number generator trait for cryptographic applications
- **`EntropySource`**: Trait for entropy sources that provide random data
- **`RngProvider`**: Trait for RNG providers that create and manage RNG instances

### Providers

- **`LibQRng`**: Main RNG implementation with unified interface
- **`OsEntropySource`**: Operating system entropy source
- **`HardwareEntropySource`**: **RDRAND** on x86 / x86_64 when the `std` feature is enabled and the CPU supports it; otherwise unavailable (use **`OsEntropySource`** on other targets)
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
- **`deterministic`**: Deterministic RNGs for testing (KT128 expansion; always available with `lib-q-k12`)
- **`hash`**: HPKE `Kt128Rng` export
- **`hpke`**: HPKE RNG integration (`hash`)
- **`deterministic-saturnin`**: Optional Saturnin CTR deterministic RNG (`LibQRng::new_deterministic_saturnin`)
- **`hardware`**: Hardware RNG support
- **`zeroize`**: Secure memory clearing (default)
- **`entropy-validation`**: Entropy validation features
- **`wasm`**: WebAssembly support
- **`js`**: JavaScript bindings

## Examples

### Basic Random Generation

```rust
use lib_q_random::new_secure_rng;

let mut rng = new_secure_rng()?;
let mut key = [0u8; 32];
rng.fill_bytes(&mut key);
```

### Deterministic Testing

```rust
use lib_q_random::new_deterministic_rng;

let mut seed = [0u8; 32];
seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
let mut rng = new_deterministic_rng(seed);
let mut bytes = [0u8; 16];
rng.fill_bytes(&mut bytes);
// bytes will be the same every time with the same seed (KT128 / libQ-DET-RNG-v1)
```

### Migration (0.0.3 → 0.0.4)

Deterministic APIs are unchanged by name, but **output bytes differ**: ChaCha20 was replaced with KT128 (KangarooTwelve) and domain-separated expansion. `new_deterministic_from_u64` now uses SplitMix64 to form a 32-byte seed. Re-record any test vectors that pinned ChaCha20 output. See [CHANGELOG.md](CHANGELOG.md).

### Custom Entropy Source

```rust
use lib_q_random::{LibQRng, entropy::UserEntropySource};

let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
let entropy_source = UserEntropySource::new(entropy_data);
let mut rng = LibQRng::new_custom(entropy_source);
```

### Entropy Validation

```rust
use lib_q_random::{EntropyValidator, validation::quick_entropy_check};

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
