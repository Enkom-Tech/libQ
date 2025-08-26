# lib-q-intrinsics

A comprehensive SIMD intrinsics library for lib-Q cryptographic operations, designed as a replacement for external intrinsics libraries like libcrux-intrinsics.

## Overview

lib-q-intrinsics provides platform-specific SIMD (Single Instruction, Multiple Data) operations optimized for cryptographic algorithms, particularly ML-DSA (Module-Lattice-based Digital Signature Algorithm). It offers:

- **Platform-specific optimizations** for x86_64 (AVX2) and ARM64 (NEON)
- **Generic fallback implementations** for platforms without SIMD support
- **Feature-gated compilation** to include only necessary intrinsics
- **Type-safe interfaces** with proper Rust abstractions

## Features

### Supported Platforms

- **x86_64 with AVX2**: Full AVX2 intrinsics support for high-performance cryptographic operations
- **ARM64 with NEON**: ARM NEON intrinsics for mobile and ARM server platforms
- **Generic fallback**: Portable implementations for platforms without SIMD support

### SIMD Operations

The library provides comprehensive SIMD operations including:

#### Vector Operations
- **Memory operations**: Load/store operations for aligned and unaligned memory
- **Vector creation**: Functions to create vectors with specific values or patterns
- **Arithmetic operations**: Addition, subtraction, multiplication with various integer types
- **Bitwise operations**: AND, OR, XOR, and shift operations
- **Comparison operations**: Equality, greater-than, and sign operations
- **Shuffle and blend**: Data rearrangement and mixing operations

#### Type Support
- **8-bit integers**: Byte-level operations
- **16-bit integers**: Half-word operations
- **32-bit integers**: Word-level operations (primary focus)
- **64-bit integers**: Double-word operations
- **32-bit floats**: Floating-point operations for certain algorithms

## Usage

### Basic Usage

```rust
use lib_q_intrinsics::*;

// Create a vector with all elements set to 42
let vector = mm256_set1_epi32(42);

// Add two vectors
let result = mm256_add_epi32(vector, mm256_set1_epi32(10));

// Store result to memory
let mut output = [0i32; 8];
mm256_storeu_si256_i32(&mut output, result);
```

### Feature Flags

The library uses feature flags to control which intrinsics are compiled:

```toml
[dependencies]
lib-q-intrinsics = { version = "0.0.3", features = ["simd256"] }
```

Available features:
- `simd128`: Enable 128-bit SIMD operations (ARM64 NEON)
- `simd256`: Enable 256-bit SIMD operations (x86_64 AVX2)
- `simd512`: Placeholder for future 512-bit SIMD operations

### Platform Detection

The library automatically detects platform capabilities:

```rust
use lib_q_intrinsics::platform;

// Check if AVX2 is available
if platform::has_avx2() {
    // Use AVX2 optimized code
}

// Get the best available SIMD support
let best_support = platform::best_simd_support();
```

## Architecture

### Module Structure

```
lib-q-intrinsics/
├── src/
│   ├── lib.rs          # Main library entry point and re-exports
│   ├── avx2.rs         # x86_64 AVX2 intrinsics
│   ├── arm64.rs        # ARM64 NEON intrinsics
│   ├── platform.rs     # Platform detection and feature queries
│   ├── generic.rs      # Generic fallback implementations
│   ├── simd128.rs      # Placeholder for SIMD128 operations
│   ├── simd256.rs      # Placeholder for SIMD256 operations
│   └── simd512.rs      # Placeholder for SIMD512 operations
```

### Key Components

#### AVX2 Module (`avx2.rs`)
Provides comprehensive AVX2 intrinsics for x86_64 platforms:
- **Vector types**: `Vec256`, `Vec128`, `Vec256Float`
- **Memory operations**: Load/store with various data types
- **Arithmetic**: Addition, subtraction, multiplication, division
- **Bitwise operations**: Logical operations and shifts
- **Comparison**: Equality, ordering, and sign operations
- **Shuffle/blend**: Data rearrangement operations

#### ARM64 Module (`arm64.rs`)
Provides NEON intrinsics for ARM64 platforms:
- **Vector types**: `Vec128`, `Vec128_16`, `Vec128_32`, `Vec128_64`
- **Memory operations**: Load/store operations
- **Arithmetic**: Basic arithmetic operations
- **Bitwise operations**: Logical operations
- **Comparison**: Comparison operations

#### Platform Module (`platform.rs`)
Provides platform detection and feature queries:
- **CPU feature detection**: Check for AVX2, NEON, etc.
- **SIMD support queries**: Determine best available SIMD level
- **Platform identification**: Current platform and architecture

#### Generic Module (`generic.rs`)
Provides fallback implementations for platforms without SIMD:
- **Generic vector types**: `GenericVec256`, `GenericVec128`
- **Basic operations**: Arithmetic and bitwise operations
- **Cryptographic helpers**: Hash and cipher fallbacks

## Integration with lib-Q

### lib-q-ml-dsa Integration

The library is specifically designed for use with lib-q-ml-dsa:

```rust
// In lib-q-ml-dsa Cargo.toml
[dependencies]
lib-q-intrinsics = { path = "../lib-q-intrinsics", features = ["simd256"] }

// In source files
use lib_q_intrinsics::*;
```

### Migration from libcrux-intrinsics

To migrate from libcrux-intrinsics:

1. **Update dependencies**:
   ```toml
   # Remove
   libcrux-intrinsics = { path = "../reference/libcrux-main/libcrux-intrinsics" }
   
   # Add
   lib-q-intrinsics = { path = "../lib-q-intrinsics", features = ["simd256"] }
   ```

2. **Update imports**:
   ```rust
   // Old
   use libcrux_intrinsics::avx2::*;
   
   // New
   use lib_q_intrinsics::*;
   ```

3. **Update feature flags**:
   ```toml
   # Old
   simd256 = ["lib-q-sha3/asm", "libcrux-intrinsics/simd256"]
   
   # New
   simd256 = ["lib-q-sha3/asm", "lib-q-intrinsics/simd256"]
   ```

## Performance

The library is designed for high-performance cryptographic operations:

- **Zero-cost abstractions**: All intrinsics are `#[inline(always)]`
- **Direct CPU instructions**: Minimal overhead between Rust and CPU intrinsics
- **Optimized for ML-DSA**: Functions specifically optimized for lattice-based cryptography
- **Platform-specific optimizations**: Best performance on supported platforms

## Security Considerations

- **No unsafe code exposure**: All unsafe operations are properly encapsulated
- **Memory safety**: Proper bounds checking and alignment requirements
- **Cryptographic correctness**: Functions maintain mathematical properties required for security
- **Constant-time operations**: Where applicable, operations are constant-time to prevent timing attacks

## Development

### Building

```bash
# Build with AVX2 support
cargo build --features simd256

# Build with NEON support
cargo build --features simd128 --target aarch64-unknown-linux-gnu

# Build generic version
cargo build
```

### Testing

```bash
# Run tests
cargo test

# Run tests with specific features
cargo test --features simd256
```

### Documentation

```bash
# Generate documentation
cargo doc --features simd256 --open
```

## Contributing

When contributing to lib-q-intrinsics:

1. **Follow Rust conventions**: Use standard Rust naming and documentation practices
2. **Maintain performance**: Ensure all intrinsics are properly optimized
3. **Add tests**: Include tests for new functionality
4. **Update documentation**: Keep documentation current with code changes
5. **Consider security**: Ensure cryptographic operations maintain security properties

## License

This library is part of the lib-Q project and follows the same licensing terms.

## Acknowledgments

- Based on libcrux-intrinsics for compatibility and correctness
- Optimized for ML-DSA cryptographic operations
- Designed for the lib-Q ecosystem
