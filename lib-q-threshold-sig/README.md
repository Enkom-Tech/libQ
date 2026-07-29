# lib-q-threshold-sig — WITHDRAWN

> **This crate is not a signature scheme. It never provided any security. Do not use it.**
>
> Every key-generation, signing and verification entry point fails closed. The construction
> behind them has been removed from the source. There is no configuration, feature flag, or
> build mode that restores it.

## Status

**WITHDRAWN — cryptographically unsound.** This is not a "pre-standard" or "provisional" caveat.
The scheme did not authenticate anything, and the defect is structural rather than a matter of
parameters or tuning.

## What was wrong

Three independent defects, each individually fatal, were confirmed against the public API:

1. **The published verifier set was the secret.** Key generation copied each party's raw
   byte-wise Shamir share directly into that party's *published* `verifying_key`. Public and
   private material were byte-identical for every party.
2. **The group key was the master secret.** The "public" group key was Lagrange interpolation of
   those published verifying keys at zero — precisely the Shamir master secret. Any
   threshold-sized subset of purely public data reconstructed it, including subsets wholly
   disjoint from the ones the dealer used.
3. **Verification was a public computation.** The accept/reject relation combined the aggregated
   nonce, a hash of public values, and the group key. It contained no secret input and no
   one-way step, so it could be satisfied directly rather than by signing.

### Why it could not be patched

The construction's only arithmetic was bytewise `XOR` and multiplication in `GF(2^8)`. Both are
efficiently invertible, and a 256-element field admits exhaustive search regardless. There is no
hard problem anywhere in the design, so there is no one-way map from the secret to the published
key and no trapdoor to recover. Hashing the shares, re-deriving the challenge, or rewriting the
verification equation does not create one — a sound scheme needs an actual hardness assumption,
which means a different construction.

## If you used this crate

- Treat any `ThresholdSigPublicKey` that was ever published, transmitted, logged or persisted as
  **full disclosure of the signing key and of every party's share**. Rotate whatever it
  protected; revocation alone does not undo the exposure.
- Any protocol that relied on this crate for authentication, authorization, admission control or
  attestation obtained **no cryptographic assurance** from it. Re-evaluate decisions made on that
  basis as unauthenticated.
- Signatures it previously produced **cannot be validated retroactively**. The original verifier
  accepted forgeries as readily as genuine signatures, so the two are indistinguishable after the
  fact. There is deliberately no "verify legacy signatures" mode.

## What the API does now

| Surface | Behaviour |
|---|---|
| `keygen_shares`, `sign_round1`, `sign_round2`, `aggregate`, `verify`, `identify_abort`, `proactive_refresh` | Return `ThresholdSigError::SchemeWithdrawn` on every call. Also marked `#[deprecated]`, so callers get a compile-time signal as well as a hard runtime failure. `verify` cannot return `Ok(true)` — it cannot return `Ok` at all. |
| All `@lib-q/threshold-sig` WASM/JS exports | Throw on every call, including the wire codecs. |
| `setup` | Returns inert profile metadata. Confers no capability. |
| `encode_threshold_sig_wire_v1`, `decode_threshold_sig_wire_v1`, `encode_signature`, `decode_signature` (Rust only) | Still work. Pure length-and-framing serialization carrying **no security claim** — see below. |

### Why the Rust wire codecs are retained

They are byte framing, not cryptography. Keeping them lets operators parse and decommission
legacy stored blobs, and keeps the byte parser covered by the existing fuzz harnesses. A
successful decode means the bytes were well-formed and nothing more; it is not an authenticity
check, and nothing decoded can subsequently be verified, because `verify` refuses unconditionally.

The JavaScript package does **not** retain them. It is a product surface, where leaving part of a
withdrawn scheme callable invites the conclusion that the rest still works.

## Wire format (historical)

`threshold_sig_wire_v1`: `[ver=1][profile=1][sig_len u16 LE][sig][meta_len u16 LE][meta]`.
Ceilings `WIRE_BUDGET_THRESHOLD_SIG_BYTES = 11264` and `PROFILE_ENVELOPE_BUDGET_BYTES = 8192`
still govern the retained codec.

## Known-answer vectors

Withdrawn. `tests/vectors/` now carries a withdrawal notice instead of a signature blob, and the
regeneration path is closed. A withdrawn scheme has no correct answers to know.

## Replacement

There is no drop-in replacement, because this crate's API was shaped around a construction that
never worked. Choose a threshold signature scheme with a stated hardness assumption and a
published security analysis. Within this workspace, `lib-q-threshold-raccoon` documents itself as
the successor to this crate; evaluate it on its own merits before adopting it.
