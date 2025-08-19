# lib-q-ascon

A Rust implementation of the Ascon permutation, providing the core cryptographic primitive for the Ascon family of algorithms.

## Overview

Ascon is a lightweight authenticated encryption and hashing algorithm family designed for resource-constrained environments. This crate implements the core Ascon permutation that serves as the foundation for:

- Ascon-128 (AEAD)
- Ascon-Hash
- Ascon-XOF
- Ascon-HashA

## Features

- **Core Permutation**: 320-bit state permutation with configurable rounds (6, 8, 12)
- **Constant-Time**: All operations are constant-time to prevent timing attacks
- **Zero-Copy**: Efficient state manipulation without unnecessary allocations
- **no_std Support**: Works in embedded and constrained environments
- **Zeroization**: Secure memory clearing when the `zeroize` feature is enabled
- **Comprehensive Testing**: KAT tests, constant-time verification, security validation

## Usage

### Basic Permutation

```rust
use lib_q_ascon::State;

// Create a new state
let mut state = State::new(0x1234567890abcdef, 0, 0, 0, 0);

// Apply permutation with different round counts
state.permute_6();   // 6 rounds
state.permute_8();   // 8 rounds  
state.permute_12();  // 12 rounds

// Or use configurable rounds
state.permute_n(10); // 10 rounds
```

### State Conversion

```rust
use lib_q_ascon::State;

// Create a state first
let mut state = State::new(0x1234567890abcdef, 0, 0, 0, 0);

// Convert to/from bytes
let bytes = state.as_bytes();
let new_state = State::try_from(bytes.as_slice()).unwrap();

// Access individual words
let word0 = state[0];
state[1] = 0xdeadbeef;
```

### Features

Enable the `zeroize` feature for secure memory clearing:

```toml
[dependencies]
lib-q-ascon = { version = "0.0.1", features = ["zeroize"] }
```

## API Reference

### State

The core `State` struct represents a 320-bit Ascon state as five 64-bit words.

#### Methods

- `new(x0, x1, x2, x3, x4)` - Create a new state
- `permute_6()` - Apply 6-round permutation
- `permute_8()` - Apply 8-round permutation  
- `permute_12()` - Apply 12-round permutation
- `permute_n(rounds)` - Apply configurable rounds (1-12)
- `as_bytes()` - Convert to 40-byte array
- `try_from(bytes)` - Create from byte slice

#### Indexing

States support indexing for direct word access:

```rust
use lib_q_ascon::State;

let mut state = State::new(0x1234567890abcdef, 0, 0, 0, 0);
let word = state[0];     // Get word 0
state[1] = 0xdeadbeef;   // Set word 1
```

## Testing

The crate includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test --test kats_tests          # Known answer tests
cargo test --test constant_time       # Constant-time verification
cargo test --test security            # Security properties
cargo test --test performance         # Performance regression
```

### Test Categories

- **KAT Tests**: Validate against known test vectors
- **Constant-Time Tests**: Verify side-channel resistance
- **Security Tests**: Check cryptographic properties
- **Performance Tests**: Detect performance regressions

## Security Considerations

- All operations are constant-time
- Input validation prevents invalid round counts
- Bounds checking on all array accesses
- Optional zeroization for secure memory clearing
- Comprehensive avalanche effect testing

## Performance

The implementation is optimized for performance while maintaining security:

- Efficient bit manipulation
- Minimal memory allocations
- Optimized round function
- Configurable loop unrolling

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## References

- [Ascon Specification](https://ascon.iaik.tugraz.at/)
- [NIST Lightweight Cryptography](https://www.nist.gov/programs-projects/lightweight-cryptography)
- [Ascon v1.2](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf)
