# Security notes — `lib-q-duplex-aead`

## Decrypt / verify schedule

Decryption uses a **two-pass** duplex schedule over the ciphertext body (see `crypto::decrypt_core`):

1. **Authentication pass:** absorb associated data, advance the duplex state over ciphertext blocks without emitting plaintext, derive the tag from the state, then **constant-time compare** the computed tag to the received tag (`subtle::ConstantTimeEq`).
2. **Decrypt pass:** re-initialize from key/nonce, re-absorb AD, then duplex-decrypt the ciphertext body into the output buffer.

Both passes run **regardless of tag validity** (the decrypt pass does not short-circuit on a failed comparison). Invalid tags still yield computed plaintext in the buffer; Layer A `decrypt` zeroizes that buffer before returning `Err`; Layer B `decrypt_semantic` returns `Ok(AuthenticationFailed)` after zeroizing any candidate plaintext.

## Constant-time primitives

Tag comparison uses `subtle`. This does not by itself guarantee resistance to all microarchitectural or remote timing observers; treat Layer C (fixed latency / remote timing) as out of scope unless separately modeled.
