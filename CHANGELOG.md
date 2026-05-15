# Changelog

All notable changes to this workspace are documented here. Versions follow the shared `[workspace.package]` version in the root `Cargo.toml`.

## 0.0.2

### Added

- **AEAD Layer B (semantic decrypt):** `lib-q-core` exposes `DecryptSemanticOutcome` and `AeadDecryptSemantic::decrypt_semantic` (see `docs/adr/003-aead-decrypt-layers.md`). Implementations ship on `lib-q-saturnin` full AEAD and Saturnin-Short; `lib-q-hpke` exposes `SaturninAeadImpl::decrypt_semantic` with `open` implemented as a thin wrapper for consistent auth failure mapping.

### Unchanged

- **Layer A:** `Aead::decrypt`, `AeadOperations`, and HPKE provider `open`/`seal` remain `Result`-first; no breaking change to existing decrypt call sites.

### Fixed

- **HPKE Saturnin:** `alloc` without `std` builds import `alloc::string::ToString` where `.to_string()` is used on `&str` in the Saturnin `open` error path.

### Documentation

- Saturnin module docs describe the full-AEAD decrypt schedule (tag binding + constant-time compare, full CTR, then outcome). `lib-q-core` README summarizes layers and migration.
