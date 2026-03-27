# lib-q-tweak-aead

Tweakable-block CTR AEAD: each **32-byte** block uses an independent Keccak-f[1600] evaluation (key, nonce, counter), so four permutations can be run in parallel on x86_64 with the `simd-avx2` feature.

## Usage

```rust
use lib_q_core::{Aead, AeadKey, Nonce};
use lib_q_tweak_aead::TweakAead;

let aead = TweakAead::new();
let key = AeadKey::new(vec![0u8; 32]);
let nonce = Nonce::new(vec![0u8; 16]);
let ct = aead.encrypt(&key, &nonce, b"message", Some(b"ad")).unwrap();
let pt = aead.decrypt(&key, &nonce, &ct, Some(b"ad")).unwrap();
```

## Features

- `std`, `alloc` — defaults for `Aead` API
- `simd-avx2` — four-way parallel Keccak-f[1600] for bulk data on AVX2 CPUs

## Security

Uses the SHA-3 permutation only (no AES/ChaCha). The **mode** is custom; review before production use.
