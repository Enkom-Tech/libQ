# lib-q-core

Core types and traits for the lib-Q post-quantum cryptography library.

## Features

- **Algorithm Identifiers**: Unified enum for all supported post-quantum algorithms
- **Error Handling**: Comprehensive error types with detailed information
- **Key Types**: Secure key structures with automatic memory zeroization
- **WASM Support**: Full WebAssembly compatibility with JavaScript bindings
- **No-std Compatible**: Works in embedded and constrained environments

## No-std Support

This crate supports `no_std` environments through feature flags:

### Feature Flags

- **`std`** (default): Full standard library support with detailed error messages
- **`alloc`**: Allocation support for dynamic memory (Vec, String)
- **`no_std`**: Minimal no_std support without allocation
- **`getrandom`**: Cryptographically secure random number generation
- **`serde`**: Serialization support
- **`wasm`**: WebAssembly bindings

### Usage Examples

#### Full std support (default)
```rust
use lib_q_core::{Algorithm, KemContext, Utils};

let mut kem_ctx = KemContext::new();
let keypair = kem_ctx.generate_keypair(Algorithm::MlKem768)?;

// Full random number generation
let random_bytes = Utils::random_bytes(32)?;

// String formatting available
let hex = Utils::bytes_to_hex(&random_bytes);
```

#### No-std with allocation
```rust
use lib_q_core::{Algorithm, KemContext};

// In Cargo.toml: default-features = false, features = ["alloc"]
let mut kem_ctx = KemContext::new();
let keypair = kem_ctx.generate_keypair(Algorithm::MlKem768)?;
// Vec and String available, but no random generation
```

#### Minimal no-std
```rust
use lib_q_core::{Algorithm, KemContext};

// In Cargo.toml: default-features = false, features = ["no_std"]
let mut kem_ctx = KemContext::new();
let keypair = kem_ctx.generate_keypair(Algorithm::MlKem768)?;
// No allocation, no random generation, static error messages
```

### Error Handling in no_std

In no_std mode, error messages use static strings instead of dynamic allocation:

```rust
// std mode
Error::InvalidAlgorithm { algorithm: format!("{alg:?} is not a KEM algorithm") }

// no_std mode  
Error::InvalidAlgorithm { algorithm: "algorithm is not a KEM algorithm" }
```

### Random Number Generation

Random number generation requires the `getrandom` feature:

```rust
// With getrandom feature
let random_bytes = Utils::random_bytes(32)?;

// Without getrandom feature
let random_bytes = Utils::random_bytes(32); // Returns error
```

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)
- ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Classic McEliece: Multiple parameter sets
- HQC: HQC-128, HQC-192, HQC-256

### Digital Signatures
- ML-DSA (Dilithium): ML-DSA-44, ML-DSA-65, ML-DSA-87
- Falcon: Falcon-512, Falcon-1024
- SPHINCS+: Multiple variants with SHA-256 and SHAKE-256

### Hash Functions
- SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- SHAKE: SHAKE128, SHAKE256
- Customizable SHAKE: cSHAKE128, cSHAKE256
- KMAC: KMAC128, KMAC256
- TupleHash: TupleHash128, TupleHash256
- ParallelHash: ParallelHash128, ParallelHash256

## Usage

### Rust

```rust
use lib_q_core::{Algorithm, KemContext};

let mut kem_ctx = KemContext::new();
let keypair = kem_ctx.generate_keypair(Algorithm::MlKem768)?;
```

### WebAssembly

```javascript
import init, { available_algorithms, create_kem } from 'lib-q-kem';

await init();
const algorithms = available_algorithms();
const kem = create_kem(algorithms[0]);
```

## Security

All cryptographic operations are implemented following NIST standards and best practices:

- Constant-time operations where applicable
- Secure memory handling with automatic zeroization
- Side-channel resistance considerations
- Comprehensive input validation

## License

Licensed under the Apache License, Version 2.0.
