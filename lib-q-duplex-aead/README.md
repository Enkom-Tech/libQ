# lib-q-duplex-aead

Duplex-sponge AEAD using **Keccak-f[1600]** (same permutation family as SHA-3). Rate 136 bytes, 256-bit key, 128-bit nonce, 256-bit tag.

## Usage

```rust
use lib_q_core::{Aead, AeadKey, Nonce};
use lib_q_duplex_aead::DuplexSpongeAead;

let aead = DuplexSpongeAead::new();
let key = AeadKey::new(vec![0u8; 32]);
let nonce = Nonce::new(vec![0u8; 16]);
let ct = aead.encrypt(&key, &nonce, b"message", Some(b"ad")).unwrap();
let pt = aead.decrypt(&key, &nonce, &ct, Some(b"ad")).unwrap();
```

## Features

- `std` — standard library (default with `alloc`)
- `alloc` — heap allocations (default)
- `simd-avx2` — optional AVX2 path on x86_64 (runtime detection via `std::arch` when `std` is enabled); duplex single-session path remains scalar

## Security

The permutation is NIST-standardized; the **AEAD mode** defined in this crate is custom. Obtain independent review before production deployment.
