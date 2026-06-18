# ADR 001: Keccak / CryptoNight vs FIPS-202 surface

## Status

**Accepted — Option B (separate crate).** Raw Keccak-224–512 and `Keccak256Full` live in [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest). [`lib-q-sha3`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-sha3) exposes NIST-traceable SHA-3, SHAKE, cSHAKE, TurboSHAKE, and [`block_core`](https://docs.rs/lib-q-sha3) for composition.

## Context

- **NIST-traceable** types: SHA-3, SHAKE, cSHAKE, TurboSHAKE (FIPS 202 / SP 800-185 / RFC 9861 stack) — `lib-q-sha3` crate root.
- **Non–FIPS-202** fixed digests: raw **Keccak-224**–**512**, **Keccak256Full** (200-byte output) — `lib-q-keccak-digest` crate root.

These have different padding from SHA-3. A single re-export surface mixed `Sha3_256` and `Keccak256` in one namespace; that is a recurring source of cross-protocol mistakes.

## Decision

1. **Separate crate** [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) (package / lib `lib_q_keccak_digest`) holds all raw Keccak fixed-output types.
2. **No** re-export of those types from `lib-q-sha3` at the crate root. **No** default prelude in either crate that blurs FIPS vs pre-FIPS.
3. **v1 implementation:** `lib-q-keccak-digest` uses `lib_q_sha3::block_core::SpongeHasherCore` and `KECCAK_DIGEST_PAD` from `block_core` so the sponge **core** stays a single implementation. A **slimmer** dependency graph for Keccak-only consumers (without a full `lib-q-sha3` line in `cargo tree` for every use case) is a **follow-up** — see [ADR 002](../../lib-q-keccak-digest/docs/adr/002-keccak-digest-dependency-extraction.md).

## Options considered (record)

1. **Monolith + documentation only** — Rejected: insufficient separation in `use` and `cargo tree`.
2. **`keccak_legacy` feature** in `lib-q-sha3` — Rejected: operational (features) instead of structural (crates) for the chosen policy.
3. **Separate crate** — **Chosen:** clearest audit boundary; internal version coupling in v1 accepted until extraction ADR 002.

## Consequences

- Downstream crates import Keccak from `lib_q_keccak_digest` and SHA-3 / XOF types from `lib_q_sha3` (e.g. [`lib-q-hash`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-hash) re-exports as documented).
- Migration: [Keccak split migration](../migration/keccak-split.md) (workspace).

## cSHAKE / `XofHasherTraits` (serialization)

Unchanged: using `buffer_xof!` with `XofHasherTraits` alone would provide digest’s default **wrapper** `SerializableState` including the `block_buffer`, which does not match the **core-only** `U400` layout that KMAC, ParallelHash, and TupleHash expect when they delegate to `CShake*`. The façade types keep `CoreProxy` and manual `SerializableState` for `CShake128` / `CShake256` in `lib-q-sha3` / `lib-q-hash` until a coordinated layout change is designed. See [RustCrypto/hashes#834](https://github.com/RustCrypto/hashes/issues/834).

## References

- [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (SHA-3 / SHAKE)
- [SP 800-185](https://csrc.nist.gov/pubs/sp/800-185/final) (cSHAKE)
- Keccak pre-draft padding (non–FIPS-202 / protocol-specific uses)
