# lib-q-mayo

MAYO multivariate signature scheme — NIST additional-signatures **round 2**,
MAYO_2 parameter set (security level 1).

| | bytes |
|---|---|
| signing key (seed) | 24 |
| verification key | 4912 |
| signature (fixed) | 186 |

Hand-written in Rust from the round-2 MAYO specification and validated
byte-for-byte against the authors' reference implementation
([PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C)) via the official
round-2 KAT file (`PQCsignKAT_24_MAYO_2.rsp`, all 100 vectors: keygen, sign,
verify).

## Status

**Experimental / pre-standard.** MAYO is a round-2 candidate in NIST's
additional-signatures on-ramp, not a finished standard. Parameters may still
change between rounds; downstream protocols should pin suite identifiers to
"MAYO round-2 parameters" and retire the suite rather than swap parameters in
place.

## Usage

```rust
use lib_q_mayo::mayo_2;

// randomness in, keys/signatures out — supply CSPRNG output in production
let keypair = mayo_2::generate_key_pair(key_seed);            // [u8; 24]
let signature = mayo_2::sign(&keypair.signing_key, msg, r)?;  // r: [u8; 24]
mayo_2::verify(&keypair.verification_key, msg, &signature)?;
```

Signing is hedged per the round-2 spec: the salt is derived from
`H(msg) || R || seed_sk`, so all-zero `R` gives deterministic signing while
fresh `R` gives the randomized mode (used by the KATs).

## Constant-time posture

- Integer-only GF(16) arithmetic — no lookup tables (nibble-sliced `u64`
  kernels, carryless multiply).
- Constant-time comparison masks pass through `core::hint::black_box`
  optimizer barriers (the Rust analogue of the reference implementation's
  volatile blockers), so the compiler cannot lower them back to branches.
- The linear-system solve is the reference implementation's constant-time
  echelon form: secret pivot rows are gathered and written back with masks;
  back-substitution never indexes memory by secret values.
- The only secret-derived branch in signing is the public "system unsolvable
  → restart" predicate of the retry loop, matching the reference
  implementation's explicit declassification.
- Secret material (expanded key, vinegar vectors, solver state) is wiped on
  exit; `Mayo2SigningKey` zeroizes on drop and `Debug`-prints `[REDACTED]`.
- A dudect-style wall-clock timing smoke for `sign` runs behind
  `--features hardened,dudect-smoke-tests`.

## Features

- `std` *(default)* — standard library.
- `mayo2` *(default)* — the MAYO_2 parameter set.
- `zeroize` / `hardened` — zeroize-backed secret wiping (constant-time masks
  and barriers are always on, not feature-gated).
- `no_std`: build with `--no-default-features --features mayo2`
  (wasm32-unknown-unknown supported).

## Internals

`P1`/`P2` expand from the 16-byte pk seed via AES-128-CTR (zero IV,
big-endian counter); everything else (secret-key expansion, message digest,
target vector, vinegar sampling, salt) uses SHAKE256 — exactly as the
round-2 spec mandates. The packed m-vector representation (16 GF(16)
coefficients per `u64` limb) is byte-exact with the wire encoding for MAYO_2
because `m = 64` is a multiple of 16.
