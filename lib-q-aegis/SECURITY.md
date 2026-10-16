# Security notes: lib-q-aegis

## Post-quantum posture

AEGIS-256 uses a 256-bit key, so a Grover-style key search costs about 2^128,
which matches lib-Q's symmetric floor. No SHA-2 and no classical public-key
primitive is involved. Key exchange and signatures stay with the protocol
(ML-KEM / ML-DSA in lib-Q).

## AEGIS-256

- **Status:** RFC 10032 (IRTF CFRG, Informational, September 2026); CAESAR
  final portfolio. Analysis is listed in RFC 10032 Section 9.3.
- **Security:** 256-bit key and state recovery; at least 128-bit forgery
  resistance, with no restriction on decryption queries. The 256-bit tag
  (`Aegis256`) also gives more than 128-bit security against differential
  forgery (RFC 10032 Section 9.3). `Aegis256Tag128` exists for protocols that fix a
  128-bit tag on the wire.
- **Nonces:** 256-bit. Reuse of a (key, nonce) pair leaks the XOR of the
  messages and lets an attacker recover the state. Nonces MUST be unique.
- **Commitment:** key-committing in the receiver-binding game. Not fully
  committing if the adversary controls the associated data (RFC 10032
  Section 9.1.2). Protocols that need context commitment must bind the context
  into the key derivation.

## Constant-time contract

- Hardware backends (`AESENC`, `AESE`/`AESMC`) are constant-time.
- The portable backend (`lib-q-intrinsics`, `aes_round::soft`) evaluates SubBytes
  as a Boolean circuit over bit planes: no table lookups, no secret-dependent
  branches, no secret-dependent addresses; `xtime` is mask-based. Unlike the scalar
  fallback in `lib-q-rocca-s`, a build without `simd` (or `no_std`) is slower but
  still constant-time.
- Tag comparison uses `lib_q_core::Utils::constant_time_compare`. Decryption
  always runs the full schedule before comparing. On failure the output buffer
  is zeroized and no plaintext is returned.
- Key staging buffers are zeroized; the cipher state is overwritten with
  volatile stores when an operation ends.

## Reporting

See the repository-level `SECURITY.md`.
