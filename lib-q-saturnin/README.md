# lib-q-saturnin

Rust implementation of the Saturnin post-quantum symmetric algorithm suite.

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

- `simd`, `lookup-tables`, `parallel`, and `assembly` are optional performance features.
- SIMD and assembly implementations currently delegate to the scalar implementation. The primary, KAT-validated production path is the scalar (no_std-safe) implementation in `core` and `bs32_core`.

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

## License

See the main [lib-q license](../LICENSE).

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).