# Security — lib-q-sah (Stream-AEAD-H)

## Draft status

Spec version `0.2.0` is **DRAFT**. The round constants, rotations, and S-box are
provisional placeholders with **no security claim**. This crate must not be used
to protect real data until a `frozen` profile passes the freeze gates in the
research PLAN (Part 9): reduced-round differential/linear analysis, symmetry
checks, avalanche/diffusion thresholds, a bitsliceable constant-time S-box, and
external cryptographer review.

## Nonce sensitivity (by design)

S-A-H is a **nonce-sensitive** stream AEAD. It is **not** misuse-resistant and
has no SIV/MRAE mode.

- **Uniqueness requirement:** each nonce MUST be used at most once per
  `(key, direction)`. Integration layers MUST derive nonces from a monotone
  per-key/direction record counter, never from a random source small enough to
  collide, and MUST rekey before the counter would wrap (hard-fail, never wrap).
- **Consequence of reuse:** reusing a nonce under one key reveals the XOR of the
  two plaintexts (keystream reuse) and undermines integrity guarantees. This is
  a deliberate trade for throughput; `tests/tamper_tests.rs::nonce_reuse_is_observable`
  documents it as an enforced, tested property.
- **When you cannot guarantee uniqueness:** use Romulus-M1 (`lib-q-romulus`)
  instead.

## Constant-time discipline

- Tag verification uses `subtle::ConstantTimeEq`; plaintext is zeroized on
  authentication failure.
- Decryption completes the full cryptographic schedule before the tag branch.
- ARX and the linear layer are inherently data-independent. **The draft S-box is
  a table lookup and is NOT constant-time** — acceptable only because the profile
  is draft. The frozen S-box is required to admit a bitsliced circuit so the
  production path performs no secret-indexed memory access.
- `open`/`open_detached` report inputs shorter than the tag as
  `AuthenticationFailed`, exposing no malformed-vs-forged oracle.

## Reporting

This is pre-release research code. Report findings through the libQ
`SECURITY.md` process.
