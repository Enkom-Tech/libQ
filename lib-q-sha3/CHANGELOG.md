# Changelog — `lib-q-sha3`

## Unreleased

### Breaking

- **Keccak digests removed from this crate’s public API** — `Keccak224` … `Keccak512` and `Keccak256Full` are now in [`lib-q-keccak-digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest) ([ADR 001](docs/adr/001-keccak-nonfips-surface.md), [migration](docs/migration/keccak-split.md)). Output values for those algorithms are unchanged; only the crate path changes.
- **`block_api`:** `Sha3HasherCore` / `Sha3ReaderCore` renamed to `SpongeHasherCore` / `SpongeReaderCore` (no cryptographic behavior change). `KECCAK_DIGEST_PAD` is the shared pre-FIPS padding byte for use with `lib-q-keccak-digest`.

### Non-breaking

- Optional **dev-dependency** on `lib-q-keccak-digest` for tests that compare Keccak to SHA-3 (does not affect normal dependents).
