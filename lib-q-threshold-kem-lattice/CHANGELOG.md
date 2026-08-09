# Changelog — lib-q-threshold-kem-lattice

All notable changes to this crate are documented here.

## Unreleased

### BREAKING — `Ciphertext`/`PartialDecap` wire encoding now carries a version byte

`profile::WIRE_VERSION_V1` was defined and publicly re-exported but never emitted by any
serializer: `Ciphertext::to_bytes`/`from_bytes` and `PartialDecap::to_bytes`/`from_bytes` only
length-checked, so the declared downgrade guard did not exist — a same-length `V2` encoding would
have been silently parsed as `V1`.

**What changes on the wire:**
- `Ciphertext::to_bytes()` now prepends one leading `WIRE_VERSION_V1` byte before the `(p, v)`
  ring-element blocks. `Ciphertext::BYTES` grows from `(KAPPA + 1)·RQ_BYTES` to
  `1 + (KAPPA + 1)·RQ_BYTES`.
- `PartialDecap::to_bytes()` now emits `version ‖ index ‖ rq_le(value)` instead of
  `index ‖ rq_le(value)`. `PartialDecap::BYTES` grows from `1 + RQ_BYTES` to `2 + RQ_BYTES`.
- `ThresholdKemLatticePublicKey` and `SecretShare` are unchanged — neither has a whole-struct
  `to_bytes`/`from_bytes` pair (their fields are raw byte blobs assembled by the caller, not
  parsed as a standalone wire message), so there is no ambiguous-length ombudsman for a version
  byte to disambiguate.

**What happens to an existing serialized value:** a pre-fix `Ciphertext`/`PartialDecap` blob fed
to the new `from_bytes` is one byte short of the new `BYTES` length and is rejected with
`ThresholdKemError::EncodingCiphertext` / `EncodingPartial` (wrong length) — it does not silently
misparse. A blob produced by a hypothetical future `V2` encoder that happens to match the new
length is rejected with the new, distinct `ThresholdKemError::UnsupportedWireVersion { found }`
rather than being misparsed as `V1`.

**Not affected:** the profile parameter-set digest and the KDF/shared-secret derivation
(`kem::kdf`, `kem::ct_digest`) hash the ring elements directly, not `to_bytes()` output, so they
are unchanged. Only the pinned ciphertext-bytes digest in `tests/kat.rs` (`PIN_CT_DIGEST`) moved
(`bd96da29…` → `44c97ce8…`); `PIN_PROFILE_DIGEST` and `PIN_SHARED_SECRET` are unaffected. The
`tests/data/kat_*.bin` fixtures (public key + shares) are byte-identical — they do not depend on
`Ciphertext`/`PartialDecap` serialization.

This crate is RED (not production-approved) and unreleased at 0.0.11, so this window was used to
close the gap rather than deferring to a real `v1` → `v2` migration later. Both this crate and its
downstream consumer `lib-q-zk-encryption-proof` (which folds `ct.to_bytes()` into Fiat-Shamir
transcripts) moved together in the same change; see that crate's CHANGELOG.

See card `t_79295151`.
