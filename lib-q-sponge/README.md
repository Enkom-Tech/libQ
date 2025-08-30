# lib-q-sponge: Cryptographic Sponge Functions

A collection of cryptographic sponge functions implemented in pure Rust for the lib-Q post-quantum cryptography library. This crate provides the foundational sponge primitives used by higher-level cryptographic algorithms.

## Overview

Sponge functions are cryptographic primitives that can absorb input data and squeeze out output data of arbitrary length. They form the basis for many modern cryptographic constructions, including hash functions, authenticated encryption, and key derivation.

## Supported Algorithms

### Keccak Family
- **Keccak-f[1600]** - The core permutation used in SHA-3 and related algorithms
- **Keccak-f[800]** - Smaller variant for constrained environments
- **Keccak-f[400]** - Compact variant for embedded systems
- **Keccak-f[200]** - Minimal variant for very constrained devices

### Ascon Family
- **Ascon** - Lightweight authenticated encryption and hashing family
- **Ascon-Hash** - Hash function variant
- **Ascon-Xof** - Extendable output function variant

## Architecture

This crate serves as the foundation for the lib-Q cryptographic library by providing:

- **Shared Primitives**: Common sponge functions used across multiple algorithms
- **Performance Optimizations**: SIMD-accelerated implementations where available
- **Memory Safety**: Zero-copy operations and secure memory handling
- **Flexibility**: Support for various sponge configurations and parameters

## Usage

### Basic Keccak Permutation

```rust
use lib_q_sponge::keccak;

// Initialize state
let mut state = [0u64; 25];

// Apply Keccak-f[1600] permutation
keccak::p1600(&mut state, 24); // 24 rounds for full security

// For reduced rounds (e.g., for performance)
keccak::p1600(&mut state, 12); // 12 rounds for reduced security
```

### SIMD Acceleration

When the `asm` feature is enabled, the implementation uses hardware acceleration:

```rust
// Enable SIMD features in Cargo.toml
// [features]
// asm = ["keccak/asm"]

// The same API automatically uses optimized implementations
let mut state = [0u64; 25];
keccak::p1600(&mut state, 24); // Uses SIMD if available
```

### Ascon Usage

```rust
use lib_q_sponge::ascon;

// Ascon permutation
let mut state = [0u64; 5];
ascon::permute_12(&mut state); // 12 rounds for Ascon-128
```

## Integration with lib-Q

This crate is designed to work seamlessly with other lib-Q components:

- **lib-q-hash**: Uses Keccak for SHA-3, SHAKE, and related hash functions
- **lib-q-aead**: Uses Ascon for authenticated encryption
- **lib-q-kem**: Provides sponge functions for key encapsulation mechanisms

## Performance

The implementation is optimized for:

- **Speed**: Efficient permutation implementations with minimal overhead
- **Memory**: Zero-copy operations and stack-based allocations
- **SIMD**: Hardware acceleration on ARMv8 and x86-64 platforms
- **Portability**: Fallback implementations for all target architectures

## Security

All implementations follow:

- **NIST Standards**: Keccak-f[1600] as specified in FIPS 202
- **CAESAR Standards**: Ascon as specified in the CAESAR competition
- **Best Practices**: Constant-time operations and secure memory handling
- **Cryptographic Review**: All algorithms have undergone extensive analysis

## Features

- `default` - Standard functionality
- `asm` - Enables ARMv8 assembly optimizations for Keccak
- `simd` - Enables SIMD optimizations (nightly Rust required)

## Benchmarks

The crate includes comprehensive benchmarks for all sponge functions:

```bash
cargo bench
```

This provides performance measurements for:
- Keccak permutations with different round counts
- SIMD vs scalar implementations
- Various input sizes and configurations

## Development

### Building

```bash
# Standard build
cargo build

# With optimizations
cargo build --release

# With SIMD support
cargo build --release --features asm
```

### Testing

```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Check for security issues
cargo audit
```

## License

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## References

- [Keccak Team Website](https://keccak.team/)
- [SHA-3 Standard (FIPS 202)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [Ascon Specification](https://ascon.iaik.tugraz.at/)
- [CAESAR Competition](https://competitions.cr.yp.to/caesar.html)
