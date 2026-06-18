# Changelog — `lib-q-sha3`

## Unreleased

### Breaking

- **`sha256` renamed to `sha3_256`** — the old name implied FIPS 180-4 SHA-256; this helper has always computed **SHA3-256** (FIPS 202). Update call sites from `lib_q_sha3::sha256` to `lib_q_sha3::sha3_256`.
- **Keccak digests removed from this crate’s public API** — `Keccak224` … `Keccak512` and `Keccak256Full` are now in [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) ([ADR 001](docs/adr/001-keccak-nonfips-surface.md), [migration](docs/migration/keccak-split.md)). Output values for those algorithms are unchanged; only the crate path changes.
- **`block_api` module renamed to `block_core`** — the local module's basename collided with the external `digest::block_api`, which confused dependency-graph tooling. Update `lib_q_sha3::block_api::…` to `lib_q_sha3::block_core::…` (e.g. `SpongeHasherCore`, `SpongeReaderCore`, `KECCAK_DIGEST_PAD`, `CShake128Core`/`CShake256Core`). No cryptographic behavior change.
- **`block_core`:** `Sha3HasherCore` / `Sha3ReaderCore` renamed to `SpongeHasherCore` / `SpongeReaderCore` (no cryptographic behavior change). `KECCAK_DIGEST_PAD` is the shared pre-FIPS padding byte for use with `lib-q-keccak-digest`.

### Non-breaking

- Optional **dev-dependency** on `lib-q-keccak-digest` for tests that compare Keccak to SHA-3 (does not affect normal dependents).
