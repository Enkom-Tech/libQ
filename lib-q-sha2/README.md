# lib-q-sha2

Pure Rust implementation of SHA-2 hash functions for lib-Q.

## Supported Algorithms

- **SHA-224** - 224-bit hash function
- **SHA-256** - 256-bit hash function  
- **SHA-384** - 384-bit hash function
- **SHA-512** - 512-bit hash function

## Usage

### Basic Hashing

```rust
use lib_q_sha2::{Sha256, Digest};

let mut hasher = Sha256::new();
hasher.update(b"Hello, world!");
let result = hasher.finalize();
```

### Convenience Functions

```rust
use lib_q_sha2::{sha256, sha512};

let hash256 = sha256(b"Hello, world!");
let hash512 = sha512(b"Hello, world!");
```

## Features

- `default` - Enables alloc and OID support
- `alloc` - Heap allocation for dynamic output sizes
- `oid` - Object Identifier support for ASN.1
- `zeroize` - Secure memory wiping
- `asm` - Assembly optimizations (when available)

## Integration with lib-Q

This crate provides SHA-2 implementations that are compatible with the lib-Q ecosystem and can be used by other lib-Q crates that require SHA-2 hash functions, such as SLH-DSA (SPHINCS+).
