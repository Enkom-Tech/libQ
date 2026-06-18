# Security notes — lib-q-rocca-s

## Specification

This crate implements **Rocca-S as defined by the IETF draft
`draft-nakano-rocca-s`** (256-bit key, 128-bit nonce, 256-bit tag), matching the
reference implementation at <https://github.com/jedisct1/rust-rocca-s>. The IETF
revision addresses the tag-forgery weakness identified in the original Rocca-S
proposal; do **not** substitute vectors or constants from the original design.

Correctness is pinned by the official all-zero known-answer test plus
cross-generated vectors covering non-zero keys/nonces and partial blocks
(`tests/kat_tests.rs`).

## Nonce reuse

Rocca-S is **nonce-respecting**, not nonce-misuse-resistant. Reusing a
(key, nonce) pair for two different messages breaks confidentiality and
authenticity. Callers must guarantee unique nonces per key (random 128-bit
nonces, or a counter). For a misuse-resistant AEAD, use a Romulus-M or
SIV-style construction instead.

## Constant-time behavior

- **Hardware backends** (`simd-aesni` on x86, `simd-neon` on aarch64) use the
  AES hardware instructions, which are constant-time. This is the recommended
  configuration for any setting where timing side channels matter.
- **Scalar fallback** uses a table-based AES S-box and is therefore **not**
  constant-time; its timing is data-dependent. It exists for portability and
  `no_std` targets without AES hardware. Avoid it for secret-dependent workloads
  on shared hardware.

## Decryption / verification timing

Decryption always performs the full bulk decryption and recomputes the tag over
the associated data and ciphertext, then compares it to the received tag in
constant time (`lib_q_core::Utils::constant_time_compare`) before deciding
success. Bulk symmetric work is not skipped on authentication failure, and the
recovered plaintext buffer is held in a `Zeroizing` buffer and never returned on
a tag mismatch. The [`lib_q_core::AeadDecryptSemantic`] layer reports
authentication failure as a value rather than an error, without exposing
plaintext.

## Memory hygiene

Key and nonce material is staged in `Zeroizing` buffers, and recovered plaintext
on the decrypt path is held in `Zeroizing` storage, so it is cleared on drop.

## Reporting

Report suspected vulnerabilities through the libQ repository's `SECURITY.md`
process.
