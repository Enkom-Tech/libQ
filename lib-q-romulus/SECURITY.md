# Security notes — Romulus AEAD (`lib-q-romulus`)

## Decrypt / verify schedule (facade)

`RomulusNAead` / `RomulusMAead` delegate to `romulus_n_decrypt` / `romulus_m_decrypt` in this crate. Both perform in-place decryption of the ciphertext body, derive the expected tag from the internal state, then **constant-time compare** (`subtle`) to the received tag. On mismatch, the plaintext buffer is **zeroed** before returning an error (Layer A) or before reporting `DecryptSemanticOutcome::AuthenticationFailed` (Layer B).

## Layer B

`lib_q_core::AeadDecryptSemantic` is implemented on the facade types using the same single-pass `romulus_n_decrypt_core` / `romulus_m_decrypt_core` as the in-place APIs—no second decrypt of the message.
