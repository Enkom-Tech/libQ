# Security notes — `lib-q-duplex-aead`

## Decrypt / verify schedule

Decryption (`crypto::decrypt_core`) performs a **single** duplex walk over the ciphertext body:

1. Initialize from key/nonce, absorb associated data, then duplex-decrypt each body block into the output buffer (same sponge trajectory as encryption, in reverse).
2. Derive the authentication tag from the final sponge rate and **constant-time compare** it to the trailing tag (`subtle::ConstantTimeEq`).

The body walk always runs to completion **regardless of tag validity** (no early exit on a failed comparison). Invalid tags still leave computed candidate plaintext in the buffer until the caller handles it: Layer A `decrypt` zeroizes that buffer before returning `Err`; Layer B `decrypt_semantic` returns `Ok(AuthenticationFailed)` after zeroizing any candidate plaintext.

## Constant-time primitives

Tag comparison uses `subtle`. This does not by itself guarantee resistance to all microarchitectural or remote timing observers; treat Layer C (fixed latency / remote timing) as out of scope unless separately modeled.
