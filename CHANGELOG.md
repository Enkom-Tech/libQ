# Changelog

All notable changes to this workspace are documented here. Versions follow the shared `[workspace.package]` version in the root `Cargo.toml`.

## 0.0.4

### Changed

- **Workspace:** All crates and path dependency pins aligned to **0.0.4** (shared `[workspace.package]` version).
- **`lib-q-random`:** Deterministic RNG expansion uses **KT128** (domain `libQ-DET-RNG-v1`) with SplitMix64 for `*_from_u64` seeds; ChaCha20 removed. Optional `deterministic-saturnin` feature for Saturnin CTR test streams. Golden vectors in `lib-q-random/tests/data/kt128_det_rng_v1.json`.
- **`lib-q-hpke`:** Test RNG and auth encap tests use `lib-q-random` KT128 expander; `rand_chacha` dependency removed.

### Documentation

- `docs/security.md` and `lib-q-random` README/CHANGELOG describe KT128 deterministic paths and migration from ChaCha20 output.

## 0.0.2

### Added

- **AEAD Layer B (semantic decrypt):** `lib-q-core` exposes `DecryptSemanticOutcome` and `AeadDecryptSemantic::decrypt_semantic` (see `docs/adr/003-aead-decrypt-layers.md`). Implementations ship on `lib-q-saturnin` full AEAD and Saturnin-Short; `lib-q-hpke` exposes `SaturninAeadImpl::decrypt_semantic` with `open` implemented as a thin wrapper for consistent auth failure mapping.
- **HPKE interoperability:** `lib_q_hpke::interop` adds `HpkeInteropProfile`, `HpkeCapabilities`, and `negotiate_hpke_capabilities` for deterministic PQ suite/mode/PSK-wire intersection. `HpkeContext`, `HpkeSenderContext`, and `HpkeReceiverContext` hold `Arc<dyn HpkeCryptoProvider + Send + Sync>` so encapsulation, KDF, AEAD, and exporter paths share one injectable backend (`with_hpke_crypto`, `set_hpke_crypto`); default RNG for setup/seal uses OS-backed entropy when `secure-rng` is enabled. Auth modes verify sender secret/public key consistency before encapsulation. Workspace docs describe `RfcStrictPq` vs `LibQExtensions` profiles; frozen JSON fixtures live under `lib-q-hpke/tests/fixtures/`. WASM sender/receiver deserialization attaches the same default `PostQuantumProvider` backend as native `HpkeContext::new`.

### Changed

- **HPKE API:** `hpke_core::{setup_sender, setup_receiver, setup_sender_with_mode, setup_receiver_with_mode, open, open_with_mode}` take a trailing `Arc<dyn HpkeCryptoProvider + Send + Sync>` aligned with the session object’s backend. Callers of these low-level functions should pass the same `Arc` used for `&dyn HpkeCryptoProvider` operations (or `clone()` of it).

### Unchanged

- **Layer A:** `Aead::decrypt`, `AeadOperations`, and HPKE provider `open`/`seal` remain `Result`-first; no breaking change to existing decrypt call sites.

### Fixed

- **HPKE Saturnin:** `alloc` without `std` builds import `alloc::string::ToString` where `.to_string()` is used on `&str` in the Saturnin `open` error path.

### Documentation

- Saturnin module docs describe the full-AEAD decrypt schedule (tag binding + constant-time compare, full CTR, then outcome). `lib-q-core` README summarizes layers and migration.
- Workspace **HPKE interoperability** docs (`docs/interoperability.md`, `docs/hpke-architecture.md`, `docs/api-design.md`) and `lib-q-hpke/docs/*` describe `RfcStrictPq` vs `LibQExtensions`, the injected HPKE crypto backend, RNG defaults, and fixture layout under `lib-q-hpke/tests/fixtures/`.
