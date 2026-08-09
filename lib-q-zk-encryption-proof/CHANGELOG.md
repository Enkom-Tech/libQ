# Changelog — lib-q-zk-encryption-proof

All notable changes to this crate are documented here.

## Unreleased

### BREAKING (transcript-coupling) — `lib-q-threshold-kem-lattice` ciphertext wire encoding gained a version byte

`lib-q-threshold-kem-lattice`'s `Ciphertext::to_bytes()` now prepends a leading
`WIRE_VERSION_V1` byte (fixing an undeliverable downgrade guard — the constant existed but was
never emitted). This crate folds `ct.to_bytes()` into its Fiat-Shamir transcripts at five sites:
`encryption_proof.rs:479`, `:1021`, `:2222`, and `relation_assembly.rs:444`, `:506` (verified by
`grep -rn "\.to_bytes()" lib-q-zk-encryption-proof/src lib-q-threshold-kem-lattice/src`, 7 total
hits — 5 in this crate's `ct.to_bytes()` calls, plus 2 unrelated hits in the KEM crate itself that
do not feed a transcript).

**What changes:** every absorbed-ciphertext transcript byte string gains a one-byte prefix, so any
proof, statement digest, or Fiat-Shamir challenge derived through those five call sites shifts.
This crate has no pinned KATs or hardcoded transcript-hash fixtures (`grep -rn "\"[0-9a-f]{40,}\""
lib-q-zk-encryption-proof/src` — no matches), so there is nothing to regenerate here; a value
computed against the pre-fix `to_bytes()` output is simply no longer reproducible against the
current code.

Both crates are RED (not production-approved) and unreleased at 0.0.11 — this window was used to
close the wire-version gap rather than deferring it. See
`lib-q-threshold-kem-lattice/CHANGELOG.md` for the full wire-format change and card `t_79295151`.
