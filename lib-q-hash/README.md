# lib-q-hash

Post-quantum Hash Functions for lib-Q

This crate provides a comprehensive collection of post-quantum hash functions for the lib-Q cryptography library.

## Features

- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **SHAKE Family**: SHAKE128, SHAKE256
- **cSHAKE**: Customizable SHAKE functions
- **TurboSHAKE**: Accelerated SHAKE variant
- **KangarooTwelve**: Fast hash function based on Keccak

## Usage

```rust
use lib_q_hash::{Sha3_256, Digest};

let mut hasher = Sha3_256::new();
hasher.update(b"Hello, world!");
let result = hasher.finalize();
println!("Hash: {:x}", result);
```

## License

Licensed under Apache-2.0.
