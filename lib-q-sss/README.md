# lib-q-sss

Constant-time [Shamir secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
over `GF(2^8)`.

Splits a bare 32-byte **symmetric** secret into `n` shares such that any `k` of them reconstruct
it and any `k - 1` reveal nothing — information-theoretically, classically or quantumly. The
secret is treated as 32 independent bytes, each shared by its own uniformly random
degree-`(k - 1)` polynomial over `GF(2^8)` (AES reduction polynomial `0x11B`).

```rust
use lib_q_sss::{reconstruct, split, Share};

let secret = [0x42u8; 32];
let mut rng = rand::rng();

// 3-of-5 sharing.
let shares: Vec<Share> = split(&secret, 3, 5, &mut rng).unwrap();

// Any 3 shares reconstruct; any 2 reveal nothing.
let recovered = reconstruct(&shares[..3]).unwrap();
assert_eq!(recovered, secret);
```

## Properties

- **Constant time.** `gf_mul` is a branchless carry-less multiply-and-reduce (bitmask select, no
  `if` on data, no log/antilog table and hence no secret-dependent table index). `gf_inv` is
  exponentiation by the fixed public exponent 254 via a fixed square-and-multiply chain — the
  same sequence of operations for every input. A `sca-test`-gated dudect-style timing probe
  guards `gf_mul` against a secret-dependent branch regressing in.
- **Zeroizing.** `Share` is `Zeroize` + `ZeroizeOnDrop`; `split` scrubs the random polynomial
  coefficients before returning.
- **Validated input, never panics on it.** `split` rejects `k < 2` and `k > n`; `reconstruct`
  rejects an empty set, a zero index (reserved for the secret's own point), and duplicate
  indices — all as typed `ShamirError`s, not panics.

## Scope

Feed `split` **symmetric key material only** — a key that participates in no asymmetric
operation itself. Never destructure a KEM or signature secret key into bytes to share it here:
Shamir-sharing a key whose use is non-linear is structurally unsound. The API takes a bare
`[u8; 32]` and offers no conversion from any asymmetric-key type precisely so this cannot happen
by accident.

`reconstruct` takes no threshold parameter — it interpolates through exactly the shares it is
given. Enforcing "at least `k` genuine shares" is the caller's responsibility, against whatever
`k` and share provenance the surrounding scheme committed to out of band.

## `no_std` / wasm

`#![no_std]` unless the `std` feature is on. The primitive is gated behind the `alloc` feature
(on by default); `Share` and `ShamirError` compile with neither `std` nor `alloc`. Builds for
`wasm32-unknown-unknown` and bare-metal `thumbv7em-none-eabi(hf)`.

| build | features |
| --- | --- |
| host (tests, std) | `--features std` (default) |
| no_std + heap | `--no-default-features --features alloc` |
| no_std, types only | `--no-default-features` |

## License

Apache-2.0.
