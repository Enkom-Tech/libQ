# lib-q-hash: Post-Quantum Hash Functions

Rust implementation of post-quantum cryptographic hash functions based on SHA-3 and related algorithms.

## Supported Algorithms

### SHA-3 Family
- **SHA-3-224**, **SHA-3-256**, **SHA-3-384**, **SHA-3-512** - Fixed-length hash functions
- **SHAKE128** and **SHAKE256** - Extendable Output Functions (XOF)

### Customizable Variants
- **cSHAKE128** and **cSHAKE256** - Customizable XOFs
- **TurboSHAKE128** and **TurboSHAKE256** - Accelerated SHAKE variants

### Keccak Variants
- **Keccak-224**, **Keccak-256**, **Keccak-384**, **Keccak-512** - Original Keccak variants
- **Keccak256Full** - CryptoNight variant with 200-byte output

### Modern Functions
- **KangarooTwelve** - Fast parallel hash function
- **KMAC128** and **KMAC256** - Keyed Message Authentication Code
- **TupleHash128** and **TupleHash256** - Tuple-based hashing
- **ParallelHash128** and **ParallelHash256** - Parallel processing

## Usage

### Fixed-Length Hashing

```rust
use lib_q_hash::{Sha3_256, Digest};

let mut hasher = Sha3_256::new();
hasher.update(b"Hello, World!");
let result = hasher.finalize();
```

### Extendable Output

```rust
use lib_q_hash::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = Shake128::default();
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
```

### Customizable Hashing

```rust
use lib_q_hash::{CShake256, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = CShake256::new_customized(b"MyApp");
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
```

### KMAC

```rust
use lib_q_hash::{Kmac128, digest::{Update, ExtendableOutput}};

let mut kmac = Kmac128::new(b"key", b"custom");
kmac.update(b"message");
let mut output = [0u8; 32];
kmac.finalize(&mut output);
```

### TupleHash

```rust
use lib_q_hash::{TupleHash128, digest::{Update, ExtendableOutput}};

let mut tuplehash = TupleHash128::new(b"custom");
let tuple = vec![b"first", b"second"];
tuplehash.update_tuple(&tuple);
let mut output = [0u8; 32];
tuplehash.finalize(&mut output);
```

### ParallelHash

```rust
use lib_q_hash::{ParallelHash128, digest::{Update, ExtendableOutput}};

let mut parallelhash = ParallelHash128::new(b"custom", 8192);
parallelhash.update(b"large data");
let mut output = [0u8; 32];
parallelhash.finalize(&mut output);
```

### KangarooTwelve

```rust
use lib_q_hash::{KangarooTwelve, digest::{Update, ExtendableOutput, XofReader}};

let mut hasher = KangarooTwelve::new(b"customization");
hasher.update(b"Hello, World!");
let mut reader = hasher.finalize_xof();

let mut output = [0u8; 32];
reader.read(&mut output);
```

## lib-q-core Hash Trait

All hash functions are available through the unified `lib-q-core::Hash` trait:

```rust
use lib_q_hash::{create_hash, Hash};

let sha3_256 = create_hash("sha3-256").unwrap();
let kmac128 = create_hash("kmac128").unwrap();
let tuplehash128 = create_hash("tuplehash128").unwrap();

let data = b"Hello, World!";
let result = sha3_256.hash(data).unwrap();
```

## Available Algorithms

```rust
use lib_q_hash::available_algorithms;

let algorithms = available_algorithms();
// Returns: ["sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256", 
//           "cshake128", "cshake256", "kangarootwelve", "keccak224", "keccak256", 
//           "keccak384", "keccak512", "kmac128", "kmac256", "tuplehash128", 
//           "tuplehash256", "parallelhash128", "parallelhash256"]
```

## Architecture

- **Shared Core**: All hash functions use the same underlying Keccak permutation
- **Unified API**: Consistent interface through the `lib-q-core::Hash` trait
- **Type Safety**: Strong typing with compile-time guarantees
- **Zero-Copy**: Efficient memory usage with minimal allocations

## Features

- `default` - Enables alloc and OID support
- `alloc` - Heap allocation for dynamic output sizes
- `oid` - Object Identifier support for ASN.1
- `zeroize` - Secure memory wiping
- `parallelhash` - Rayon-based parallel processing
- `asm` - ARMv8 assembly optimizations

## License

Apache License, Version 2.0