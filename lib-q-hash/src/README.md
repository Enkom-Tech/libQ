# lib-q-hash: Post-Quantum Hash Functions

A comprehensive Rust implementation of post-quantum cryptographic hash functions based on SHA-3 and related algorithms. This crate provides a unified interface for various hash functions that are resistant to quantum attacks.

## Supported Algorithms

### SHA-3 Family (NIST Standard)
- **SHA-3-224**, **SHA-3-256**, **SHA-3-384**, **SHA-3-512** - Fixed-length hash functions
- **SHAKE128** and **SHAKE256** - Extendable Output Functions (XOF)

### Customizable SHA-3 Variants
- **cSHAKE128** and **cSHAKE256** - Customizable XOFs as defined in NIST SP 800-185
- **TurboSHAKE128** and **TurboSHAKE256** - Accelerated SHAKE variants

### Keccak Variants
- **Keccak-224**, **Keccak-256**, **Keccak-384**, **Keccak-512** - Original Keccak submission variants
- **Keccak256Full** - CryptoNight variant with 200-byte output

### Modern Hash Functions
- **KangarooTwelve** - Fast parallel hash function based on Keccak

## Quick Start

### Fixed-Length Hashing (SHA-3)

```rust
use lib_q_hash::{Sha3_256, Digest};

let mut hasher = Sha3_256::new();
hasher.update(b"Hello, World!");
let result = hasher.finalize();

println!("SHA3-256 hash: {:x}", result);
```

### Extendable Output (SHAKE)

```rust
use lib_q_hash::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = Shake128::default();
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
println!("SHAKE128 output: {:x}", output);
```

### Customizable Hashing (cSHAKE)

```rust
use lib_q_hash::{CShake256, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = CShake256::new_customized(b"MyApp");
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
println!("cSHAKE256 output: {:x}", output);
```

### KangarooTwelve

```rust
use lib_q_hash::{KangarooTwelve, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = KangarooTwelve::new(b"customization");
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
println!("K12 output: {:x}", output);
```

## Using the lib-q-core Hash Trait

All hash functions are available through the unified `lib-q-core::Hash` trait:

```rust
use lib_q_hash::{create_hash, Hash};

// Create hash instances by name
let sha3_256 = create_hash("sha3-256").unwrap();
let k12 = create_hash("kangarootwelve").unwrap();
let keccak256 = create_hash("keccak256").unwrap();

// Hash data
let data = b"Hello, World!";
let sha3_result = sha3_256.hash(data).unwrap();
let k12_result = k12.hash(data).unwrap();
let keccak_result = keccak256.hash(data).unwrap();

println!("SHA3-256: {:x}", sha3_result);
println!("K12: {:x}", k12_result);
println!("Keccak256: {:x}", keccak_result);
```

## Available Algorithms

You can get a list of all available algorithms:

```rust
use lib_q_hash::available_algorithms;

let algorithms = available_algorithms();
println!("Available algorithms: {:?}", algorithms);
```

This returns:
```
["sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256", 
 "cshake128", "cshake256", "kangarootwelve", "keccak224", "keccak256", 
 "keccak384", "keccak512"]
```

## Architecture

This crate uses a shared Keccak permutation implementation from `lib-q-sponge`, ensuring consistent performance and security across all hash functions. The architecture follows these principles:

- **Shared Core**: All hash functions use the same underlying Keccak permutation
- **Unified API**: Consistent interface through the `lib-q-core::Hash` trait
- **Type Safety**: Strong typing with compile-time guarantees
- **Zero-Copy**: Efficient memory usage with minimal allocations

## Security Considerations

All implemented algorithms are:
- **NIST-approved** for cryptographic use
- **Quantum-resistant** based on sponge construction
- **Well-vetted** through extensive cryptanalysis

The SHA-3 family provides 128-bit security against collision attacks and 256-bit security against preimage attacks, making them suitable for post-quantum applications.

## Performance

The implementation is optimized for:
- **Speed**: Efficient block processing and minimal overhead
- **Memory**: Zero-copy operations where possible
- **SIMD**: Hardware acceleration on supported platforms (via the `asm` feature)

## Features

- `default` - Enables alloc and OID support
- `alloc` - Enables heap allocation for dynamic output sizes
- `oid` - Enables Object Identifier support for ASN.1
- `zeroize` - Enables secure memory wiping
- `asm` - Enables ARMv8 assembly optimizations

## License

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## References

- [SHA-3 Standard (FIPS 202)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [SHA-3 Derived Functions (SP 800-185)](https://csrc.nist.gov/pubs/sp/800/185/final)
- [KangarooTwelve Specification](https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html)