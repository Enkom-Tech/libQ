# lib-q-saturnin

Rust implementation of the Saturnin post-quantum symmetric algorithm suite.

Saturnin is the primary symmetric suite for HPKE/AEAD tiers in this workspace (see [`lib-q-hpke`](../lib-q-hpke), [`lib-q-aead`](../lib-q-aead)).

## Overview

Saturnin is a lightweight block cipher designed for post-quantum security. This implementation provides AEAD, block cipher, hash, and stream cipher modes.

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
lib-q-saturnin = "0.0.2"
```

### AEAD

```rust
use lib_q_saturnin::{SaturninAead, Aead, AeadKey, Nonce};

let aead = SaturninAead::new();
let key = AeadKey { data: vec![0u8; 32] };
let nonce = Nonce { data: vec![0u8; 16] };

let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
```

### Hash

```rust
use lib_q_saturnin::SaturninHash;

let hash = SaturninHash::new();
let output = hash.hash(b"data")?;
```

### Block Cipher

```rust
use lib_q_saturnin::SaturninBlockCipher;

let cipher = SaturninBlockCipher::new();
let encrypted = cipher.encrypt_block(&key, &block)?;
let decrypted = cipher.decrypt_block(&key, &encrypted)?;
```

### Stream Cipher

```rust
use lib_q_saturnin::SaturninStream;

let stream = SaturninStream::new();
let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
let plaintext = stream.decrypt(&key, &nonce, &ciphertext)?;
```

## Features

- `aead` - Authenticated encryption (default)
- `aead-short` - Faster AEAD variant (10 rounds vs 16)
- `block-cipher` - Block cipher operations
- `hash` - Hash function
- `stream` - Stream cipher
- `zeroize` - Secure memory zeroization

### Performance features

- `simd` enables runtime SIMD dispatch.
- `simd-avx2` enables AVX2 backend support on `x86_64` (runtime detected).
- `simd-neon` enables NEON backend support on `aarch64` (runtime detected).
- `parallel` enables multi-block parallel helpers on non-WASM targets.

Scalar `core` and `bs32_core` remain the audited reference implementations. SIMD paths are optimized implementations that must remain byte-for-byte equivalent to scalar outputs.

### WebAssembly

The crate builds for `wasm32-unknown-unknown`. Enable the `wasm` feature so that the `getrandom` dependency (via lib-q-core) compiles with `wasm_js`; otherwise the build will fail on that target. The `parallel` feature is not available on `wasm32` (the module is omitted on that target).

Example: `cargo build --target wasm32-unknown-unknown --features wasm`

## Security

- 256-bit post-quantum security
- Constant-time operations; AEAD tag verification uses constant-time comparison (see [SECURITY.md](SECURITY.md)).
- No side channels
- Validated against reference implementation

## Performance

Typical throughput on modern hardware:
- AEAD: ~200-400 MB/s
- Hash: ~400-600 MB/s
- Block cipher: ~150-300 MB/s
- Stream cipher: ~250-450 MB/s

## Testing

```bash
cargo test --all-features
cargo bench
```

### SIMD validation matrix

```bash
# Scalar reference path
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream"

# AVX2-enabled path (x86_64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-avx2"

# NEON-enabled path (aarch64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-neon"
```

### Benchmark protocol

- Run on an otherwise idle machine with fixed CPU frequency governor when possible.
- Collect scalar baseline first, then collect SIMD-enabled results on the same machine.
- Use identical workload sizes and warmup/sample settings for all runs.
- Report bytes/second and relative speedup (`simd / scalar`) for each workload.

Recommended commands:

```bash
# Scalar baseline
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream"

# AVX2 benchmark run
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream,simd-avx2"
```

### Performance acceptance gates

When evaluating SIMD changes, use these minimum expected speedups against scalar baseline on the same host:

- Hash throughput: `>= 1.30x`
- Stream throughput: `>= 1.25x`
- Block single-block encryption: `>= 1.05x`

If a change does not meet these thresholds, keep it behind feature gates until further optimization or analysis is completed.

## License

See the main [lib-q license](../LICENSE).

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).