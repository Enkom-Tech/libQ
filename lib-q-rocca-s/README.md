# lib-q-rocca-s

Rocca-S authenticated encryption (AEAD) for lib-Q.

Rocca-S is a high-throughput AEAD built on the AES round function, designed for
AES-accelerated hardware (targeting 6G-class links). This crate implements the
IETF draft variant (`draft-nakano-rocca-s`), matching the reference
implementation at <https://github.com/jedisct1/rust-rocca-s>, and exposes it
through the standard lib-Q [`Aead`] / [`AeadDecryptSemantic`] traits.

This crate is pinned to **`draft-nakano-rocca-s-06`** and accepts only 256-bit keys. The draft-06
key-expansion change (a key-length-dependent `S[6]` init that fixes identical initial states for
128/192-bit keys) therefore does **not** apply here; the all-zero known-answer test in
`tests/kat_tests.rs` matches draft-06.

## Parameters

| Parameter | Size |
| --------- | ---- |
| Key       | 256 bits (32 bytes) |
| Nonce     | 128 bits (16 bytes), nonce-respecting |
| Tag       | 256 bits (32 bytes) |

The 256-bit tag keeps forgery resistance at ~128 bits under a Grover-style
quantum search (a 128-bit tag would drop to ~64 bits).

## Usage

```rust
use lib_q_rocca_s::{Aead, AeadKey, Nonce, RoccaSAead};

let aead = RoccaSAead::new();
let key = AeadKey::new(vec![0u8; 32]);
let nonce = Nonce::new(vec![0u8; 16]);

let ct = aead.encrypt(&key, &nonce, b"secret", Some(b"header")).unwrap();
let pt = aead.decrypt(&key, &nonce, &ct, Some(b"header")).unwrap();
assert_eq!(pt, b"secret");
```

The returned ciphertext is `body || tag` (plaintext length + 32 bytes).

## Backends

The AES round runs on a hardware backend selected at runtime when the `simd`
features are enabled and the CPU supports it:

- **x86 / x86_64** — AES-NI (`AESENC`), via `simd-aesni`
- **aarch64** — ARMv8 crypto (`AESE` + `AESMC`), via `simd-neon`
- **portable** — a table-based software AES round (always available)

All three backends are bit-for-bit equivalent, enforced by
`tests/simd_equivalence.rs`. The official KAT is pinned in `tests/kat_tests.rs`.

## Features

| Feature | Effect |
| ------- | ------ |
| `default` | `aead`, `alloc` |
| `aead` | the AEAD API (pulls in `zeroize`) |
| `alloc` | `Vec`-returning API |
| `std` | enables runtime AES-NI detection |
| `simd` | `simd-aesni` + `simd-neon` |
| `simd-aesni` | x86 AES-NI backend (implies `std`) |
| `simd-neon` | aarch64 AES backend |

## Security

See [`SECURITY.md`](SECURITY.md). In particular: the **scalar** AES path is not
constant-time; enable a hardware backend (`simd`) for constant-time operation,
and never reuse a (key, nonce) pair.

## License

Apache-2.0.
