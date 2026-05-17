# Changelog — `lib-q-keccak-digest`

## 0.0.2 — initial release (workspace)

- New crate: pre–FIPS `Keccak224` … `Keccak512` and `Keccak256Full`, building on `lib_q_sha3::block_api::SpongeHasherCore` and `KECCAK_DIGEST_PAD` (see `lib-q-sha3` [ADR 001](https://github.com/Enkom-Tech/libQ/blob/main/lib-q-sha3/docs/adr/001-keccak-nonfips-surface.md)).
- KATs and performance tests moved from `lib-q-sha3` with identical vectors.
