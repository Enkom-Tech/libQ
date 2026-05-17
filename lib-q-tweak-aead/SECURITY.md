# Security notes — `lib-q-tweak-aead`

## Decrypt / verify schedule

Decryption (`crypto::decrypt_core`) performs:

1. **Tag derivation** over `key ‖ 0x03 ‖ nonce ‖ len(AD) ‖ AD ‖ len(CT) ‖ CT_body` via a Keccak-f[1600] sponge absorb, producing a 32-byte tag.
2. **Constant-time comparison** of the computed tag to the received tag (`subtle::ConstantTimeEq`).
3. **CTR-style XOR decrypt** of the ciphertext body into the output buffer. This XOR step **always runs**, independent of whether the tag matched.

On Layer A `decrypt`, a failed tag comparison zeroizes the candidate plaintext and returns `Err`. Layer B `decrypt_semantic` returns `Ok(AuthenticationFailed)` after zeroizing any candidate plaintext buffer.

## Constant-time primitives

Tag comparison uses `subtle`. XOR decrypt timing is not a substitute for a full side-channel analysis; remote timing (Layer C) is out of scope unless separately modeled.
