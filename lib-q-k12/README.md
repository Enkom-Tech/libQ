# lib-q-k12

A pure Rust implementation of the KangarooTwelve (K12) extendable-output function, providing fast and secure hashing with customization support.

## Overview

KangarooTwelve is a fast and secure extendable-output function (XOF) based on the Keccak-p permutation. It offers excellent performance characteristics while maintaining cryptographic security, making it suitable for a wide range of applications including digital signatures, key derivation, and general-purpose hashing.

Key features of KangarooTwelve:
- **Fast performance**: Optimized for speed on modern processors
- **Extendable output**: Generate any amount of output data
- **Customization support**: Domain separation through customization strings
- **Security**: Based on proven Keccak cryptography
- **Parallel processing**: Internal tree structure enables parallelization

## Features

- **Pure Rust**: No unsafe code, memory-safe implementation
- **no_std Support**: Works in embedded and constrained environments  
- **Streaming Interface**: Process data incrementally
- **Customization**: Domain separation with customization strings
- **XOF Interface**: Generate arbitrary amounts of output
- **Constant-Time**: Operations resistant to timing attacks
- **Comprehensive Testing**: KAT tests, security validation, performance monitoring

## Usage

### Basic Hashing

```rust
use lib_q_k12::{KangarooTwelve, digest::{ExtendableOutput, Update}};

// Hash some data
let mut hasher = KangarooTwelve::default();
hasher.update(b"Hello, world!");
let result = hasher.finalize_boxed(32); // 32 bytes of output
```

### With Customization

```rust
use lib_q_k12::KangarooTwelve;
use lib_q_k12::digest::{ExtendableOutput, Update};

// Use customization for domain separation
let customization = b"MyApplication";
let mut hasher = KangarooTwelve::new(customization);
hasher.update(b"Some data to hash");
let result = hasher.finalize_boxed(64); // 64 bytes of output
```

### Streaming Interface

```rust
use lib_q_k12::{KangarooTwelve, digest::{ExtendableOutput, Update}};

let mut hasher = KangarooTwelve::default();

// Process data in chunks
hasher.update(b"First chunk");
hasher.update(b"Second chunk");
hasher.update(b"Final chunk");

let result = hasher.finalize_boxed(32);
```

### Extendable Output

```rust
use lib_q_k12::{KangarooTwelve, digest::{ExtendableOutput, Update, XofReader}};

let mut hasher = KangarooTwelve::default();
hasher.update(b"Input data");

// Get XOF reader for arbitrary output length
let mut reader = hasher.finalize_xof();
let mut output = [0u8; 1000]; // Large output buffer
reader.read(&mut output);
```

### Reset and Reuse

```rust
use lib_q_k12::{KangarooTwelve, digest::{ExtendableOutput, Update, Reset}};

// First hash
let mut hasher1 = KangarooTwelve::default();
hasher1.update(b"First message");
let result1 = hasher1.finalize_boxed(32);

// Second hash (new instance)
let mut hasher2 = KangarooTwelve::default();
hasher2.update(b"Second message");
let result2 = hasher2.finalize_boxed(32);
```

## API Reference

### KangarooTwelve

The main hasher struct implementing the KangarooTwelve algorithm.

#### Methods

- `new(customization: &[u8])` - Create hasher with customization string
- `default()` - Create hasher with empty customization
- `update(&mut self, data: &[u8])` - Add input data
- `finalize_boxed(self, output_size: usize) -> Box<[u8]>` - Generate output
- `finalize_xof(self) -> KangarooTwelveReader` - Get XOF reader
- `reset(&mut self)` - Reset to initial state
- `clone(&self) -> Self` - Clone current state

### KangarooTwelveReader

XOF reader for generating arbitrary amounts of output data.

#### Methods

- `read(&mut self, buffer: &mut [u8])` - Fill buffer with output data

## Performance

KangarooTwelve is designed for high performance:

- **Throughput**: Optimized for modern CPU architectures
- **Chunk Processing**: 8192-byte chunks for efficient processing  
- **Memory Efficiency**: Minimal memory allocation
- **Incremental Updates**: Efficient streaming interface

### Benchmarks

Typical performance on modern hardware:
- Small inputs (1KB): ~500µs for 32-byte output
- Large inputs: Scales linearly with input size
- XOF output: Scales linearly with output size

## Security

### Cryptographic Properties

- **Collision Resistance**: Computationally infeasible to find collisions
- **Preimage Resistance**: One-way function properties
- **Avalanche Effect**: Small input changes cause large output changes
- **Uniform Distribution**: Output appears random and uniformly distributed

### Side-Channel Resistance

- **Constant-Time Operations**: All operations execute in constant time
- **No Data-Dependent Branching**: Prevents timing-based attacks
- **Consistent Memory Access**: Uniform memory access patterns

### Security Level

KangarooTwelve provides:
- **128-bit security level** against collision attacks
- **256-bit security level** against preimage attacks
- Based on the proven security of the Keccak permutation

## Testing

The implementation includes comprehensive testing:

```bash
# Run all tests
cargo test

# Run specific test categories  
cargo test --test constant_time       # Side-channel resistance
cargo test --test security            # Cryptographic properties
cargo test --test performance         # Performance regression
```

### Test Categories

- **KAT Tests**: Known Answer Tests with official vectors
- **Constant-Time Tests**: Timing analysis for side-channel resistance  
- **Security Tests**: Cryptographic property validation
- **Performance Tests**: Regression monitoring and scaling verification

## Compatibility

### Standards Compliance

- Implements the KangarooTwelve specification
- Compatible with reference implementations
- Passes all official test vectors

### Platform Support

- **Rust Version**: 1.89+ (edition 2024)
- **Platforms**: All platforms supported by Rust
- **Architecture**: Portable, no architecture-specific code
- **Environment**: `std` and `no_std` compatible

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE-APACHE) for details.

## References

- [KangarooTwelve Specification](https://keccak.team/kangarootwelve.html)
- [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
- [Keccak Team](https://keccak.team/)
- [IETF Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/)

## Contributing

Contributions are welcome! Please ensure:

- All tests pass (`cargo test`)
- Code follows Rust conventions
- Security properties are maintained
- Performance is not degraded
- Documentation is updated

See [TESTING.md](TESTING.md) for detailed testing information.