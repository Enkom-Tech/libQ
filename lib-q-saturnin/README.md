# lib-q-saturnin

Rust implementation of the Saturnin post-quantum symmetric algorithm suite.

Saturnin is the primary symmetric suite for HPKE/AEAD tiers in this workspace (see [`lib-q-hpke`](../lib-q-hpke), [`lib-q-aead`](../lib-q-aead)).

## Overview

Saturnin is a lightweight block cipher designed for post-quantum security. This implementation provides AEAD, block cipher, hash, and stream cipher modes.

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
lib-q-saturnin = "0.0.9"
```

### AEAD

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninAead,
};

fn main() -> Result<()> {
    let aead = SaturninAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

### Saturnin-QCB (one-pass AEAD)

`SaturninQcb` is the one-pass, parallelizable AEAD from "An Update on Saturnin", built on the
Saturnin tweakable block cipher (`SaturninTbc` = `Saturnin16^d_{K⊕T}`). Message blocks use domain
9, the tag uses domain 10; each block is encrypted with a tweak binding the nonce and block index,
so encryption is rate-one and embarrassingly parallel.

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninQcb,
};

fn main() -> Result<()> {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

> ⚠️ **Spec-faithful interpretation, not a byte-compatible reference.** The update note only gives
> a high-level description of Saturnin-QCB; the full mode lives in the separate QCB paper
> (`[BBC+20]`), and no official QCB known-answer tests are published. This implementation follows
> everything the note specifies and documents every gap-filling choice (padding, tweak encoding,
> AD folding) in the [`qcb` module docs](src/qcb.rs). It is verified by round-trip, tamper, and
> pinned self-consistency vectors — not by designer KATs. See [SECURITY.md](SECURITY.md).

### Hash

```rust
use lib_q_saturnin::{Result, SaturninHash};

fn main() -> Result<()> {
    let hash = SaturninHash::new();
    let output = hash.hash(b"data")?;
    assert_eq!(output.len(), 32);
    Ok(())
}
```

### Block Cipher

```rust
use lib_q_saturnin::{Result, SaturninBlockCipher};

fn main() -> Result<()> {
    let cipher = SaturninBlockCipher::new();
    let key = vec![0u8; 32];
    let block = vec![0u8; 32];
    let encrypted = cipher.encrypt_block(&key, &block)?;
    let decrypted = cipher.decrypt_block(&key, &encrypted)?;
    assert_eq!(decrypted, block);
    Ok(())
}
```

### Stream Cipher

```rust
use lib_q_saturnin::{Result, SaturninStream};

fn main() -> Result<()> {
    let stream = SaturninStream::new();
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 16];
    let plaintext = b"Hello, World!";
    let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
    let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}
```

## Features

- `aead` - Authenticated encryption (default)
- `aead-short` — **Saturnin-Short** (spec section 2.3): single `Saturnin^6` block over `pad(nonce ‖ plaintext)`; fixed 32-byte ciphertext, no associated data, plaintext strictly under 128 bits. This is not CTR-Cascade (`aead`). Supports the update note's **shorter-nonce tweak** via `SaturninShortAead::with_nonce_len` (a shorter nonce frees room for longer plaintext: max plaintext = `31 - nonce_len` bytes).
- `qcb` — **Saturnin-QCB** (default): one-pass, parallelizable TBC-based AEAD from the update note. Exposes `SaturninQcb` and the reusable tweakable block cipher `SaturninTbc`. See the caveat above.
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