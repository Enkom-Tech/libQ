# lib-q-sponge

Sponge functions for quantum-resistant cryptography.

## Overview

This crate provides a unified interface for sponge functions used in post-quantum cryptographic algorithms. It currently supports:

- Keccak sponge functions (f1600, f800, f400, f200)
- Ascon sponge functions (permute_1, permute_6, permute_8, permute_12)

## Usage

```rust
use lib_q_sponge::sponge::{absorb_keccak, squeeze_keccak};

// Create a Keccak state
let mut state = [0u64; 25];

// Absorb data into the state
let data = [0x01, 0x02, 0x03, 0x04];
absorb_keccak(&mut state, &data, 8);

// Squeeze data from the state
let mut output = [0u8; 32];
squeeze_keccak(&mut state, &mut output, 8);
```

## Features

- **High Performance**: Optimized implementations for various platforms
- **Comprehensive Testing**: Extensive test coverage with unit, integration, and property-based tests
- **No-std Support**: Compatible with embedded systems and WebAssembly
- **Quantum Resistance**: Designed for post-quantum cryptography

## Testing

The crate has comprehensive test coverage:

- **Unit Tests**: Test individual functions and components
- **Integration Tests**: Test interactions between components
- **Property-Based Tests**: Verify cryptographic properties like avalanche effect
- **Doc Tests**: Ensure documentation examples are correct

To run the tests:

```bash
cargo test
```

## Test Coverage

The crate maintains high test coverage for all core functionality. To run coverage analysis:

```bash
# Install cargo-tarpaulin if not already installed
cargo install cargo-tarpaulin

# Run coverage analysis
cargo tarpaulin --packages lib-q-sponge --out Html --output-dir coverage
```

## License

This project is licensed under the terms specified in the repository root.