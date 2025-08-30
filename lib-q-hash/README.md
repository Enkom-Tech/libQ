# lib-q-hash

Post-quantum hash functions for lib-Q.

## Features

- **SHA-3**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **SHAKE**: SHAKE128, SHAKE256
- **cSHAKE**: Customizable SHAKE functions
- **TurboSHAKE**: Accelerated SHAKE variant
- **KangarooTwelve**: Fast hash function based on Keccak
- **KMAC**: Keyed Message Authentication Code (128/256)
- **TupleHash**: Tuple-based hashing (128/256)
- **ParallelHash**: Parallel processing for large data (128/256)

## Usage

### Basic Hashing

```rust
use lib_q_hash::{Sha3_256, Digest};

let mut hasher = Sha3_256::new();
hasher.update(b"Hello, world!");
let result = hasher.finalize();
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

### State Serialization

```rust
use lib_q_hash::{Kmac128, digest::SerializableState};

let mut kmac = Kmac128::new(b"key", b"custom");
kmac.update(b"partial data");
let serialized = kmac.serialize();

let mut kmac2 = Kmac128::deserialize(&serialized).unwrap();
kmac2.update(b"more data");
```

## Features

- `default` - Enables alloc and OID support
- `alloc` - Heap allocation for dynamic output sizes
- `oid` - Object Identifier support for ASN.1
- `zeroize` - Secure memory wiping
- `parallelhash` - Rayon-based parallel processing
- `asm` - ARMv8 assembly optimizations

## License

Apache-2.0
