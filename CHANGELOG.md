# Changelog

All notable changes to this workspace are documented here. Versions follow the shared `[workspace.package]` version in the root `Cargo.toml`.

## 0.0.7

### Added

- **`lib-q-saturnin` — Saturnin update ("An Update on Saturnin"):** new **Saturnin-QCB** one-pass AEAD (`qcb` feature, default) built on a reusable Saturnin tweakable block cipher `SaturninTbc` (`Saturnin16^d_{K⊕T}`); message blocks use domain 9, the tag domain 10, AD domain 11. Also adds the **shorter-nonce tweak** for Saturnin-Short (`SaturninShortAead::with_nonce_len`, max plaintext `31 - nonce_len`). QCB is a spec-faithful interpretation pinned to derived self-consistency vectors — no official designer KATs exist; see `lib-q-saturnin/SECURITY.md`.
- **npm WASM packages for tier-4b primitives** (parity with crates.io 0.0.6): `@lib-q/mac`, `@lib-q/blind-pcs`, `@lib-q/double-kem`, `@lib-q/fhe`, `@lib-q/threshold-kem`, `@lib-q/threshold-sig` — each with `wasm` feature, `src/wasm.rs`, wasm-bindgen smoke tests, CI wasm-build/bindgen-test matrix entries, and CD `publish-wasm-packages` rows.
- **`@lib-q/types`:** TypeScript interfaces for MAC, double-KEM, FHE, and threshold KEM/sig wire shapes.

### Wire-stable (pending 0.0.7 tag)

- **`lib-q-duplex-aead`:** Wire format v0 frozen — 32-byte key, 16-byte nonce, 32-byte tag, Keccak-f[1600] duplex-sponge. KAT fixtures in `tests/kat.rs` and `examples/dump_duplex_kat.rs`. GIP integration: `aead_id = 2` via `gip-crypto` feature `duplex-sponge`.

### Hardened attestation (pending 0.0.7 tag)

- **`lib-q-ml-kem`:** `hardened` feature enables Boolean masked decapsulation, shuffled NTT, `subtle` constant-time comparisons. Dudect smoke test: `tests/hardened_dudect_smoke.rs`.
- **`lib-q-ml-dsa`:** `hardened` feature enables masked signing path. Dudect smoke test: `tests/hardened_dudect_smoke.rs` (requires `dudect-smoke-tests`).
- **Attestation:** `docs/hardened-attestation.md` documents hardening scope, CI evidence requirements, and GIP `GIP_CRYPTO_LIBQ_HARDENED_ATTESTATION` contract.

**Gate before crates.io tag `0.0.7`:** dudect smoke green on x86_64 and at least one ARM64 target with CI evidence linked in GIP `LIBQ_SIDECHANNEL_UPSTREAM.md`. Hardened claims ship on the **same** `0.0.7` semver tag — there is no separate `-hardened` suffix tag.

### Changed

- **Workspace:** Version **0.0.7**; npm package count **22 → 28**.
- **CI:** `scripts/ci-guard-new-crates-and-npm.sh` now requires every `publish-rust-tier-4b-new-primitives` crate to appear in `publish-wasm-packages`.
- **Docs:** `docs/npm-packages.md`, `docs/npm-coverage.md`, `docs/npm-wasm-api.md` updated for the six new packages.

## 0.0.6

### Added

- **`lib-q-threshold-kem`:** Provisional threshold KEM (`ThresholdKemProfileV1`) — ML-KEM-768 group encapsulation, byte-wise Shamir shares over GF(256), `threshold_kem_wire_v1` wire format, exportable KAT fixtures, CI byte-budget gates, and wire round-trip tests.
- **`lib-q-threshold-sig`:** Provisional threshold signature (`ThresholdSigProfileV1`) — POP wire format, identify-abort fuzz targets, KAT vectors, budget gates, and wire decode fuzzing.
- **`lib-q-double-kem`:** Provisional double-KEM composition crate with profile wiring and README.
- **`lib-q-fhe`:** Provisional FHE core extracted to `fhe.rs` with profile scaffolding.
- **`lib-q-blind-pcs`:** Provisional blind polynomial commitment core with KAT manifest.
- **`lib-q-zkp`:** Recovery-policy STARK proofs — `RecoveryPolicyAir` (v0) and hybrid v1 (`RecoveryPolicyHybridAir`), wire encodings `recovery_zk_proof_v0` / `recovery_zk_proof_v1`, exportable KAT fixtures under `tests/vectors/recovery-policy-v0/` and `recovery-policy-v1/`, byte-budget documentation, and recovery ZK wire decode fuzz target.

### Changed

- **Workspace:** All crates and path dependency pins aligned to **0.0.6** (shared `[workspace.package]` version).
- **`lib-q-slh-dsa`:** `typenum` bumped to **1.20.1** (Dependabot).

## 0.0.5

### Added

- **`lib-q-lattice-zkp`:** Wire v0 — frozen `LatticeZkpProfileV0`, `lattice_zkp_wire_v0` canonical encodings, exportable KAT fixtures under `tests/vectors/`, CI byte-budget tests, and wire decode fuzz targets.
- **`lib-q-lattice-zkp`:** Constant-time prover hardening (`hardened` feature): shared `lib-q-ring` CT primitives, first-order `MaskedWitness` masking, fixed-iteration rejection with CT first-accept selection, amortise canonicalization, dudect-style CI smokes.
- **`lib-q-sca-test`:** Side-channel self-certification harness — `report` (`EvaluationReport`/`SelfCertReport`, JSON schema `libq.sca.self-cert.v1` + Markdown), `self_cert` fixed-vs-random TVLA battery over the hardened ML-KEM, ML-DSA, and lattice-ZKP paths with an evidence-package writer, and `ingest` for feeding externally acquired power/EM/cycle traces through the same Welch gate.
- **`lib-q-hqc`:** Authoritative KAT tree `kats/official/` with `PROVENANCE.md` (SHA-256 pins); NIST KEM KAT driver `tests/nist_kem_kat.rs` — byte-exact `pk`/`ct`/`ss`/`sk` (NIST wire layout) for HQC-128/192/256.
- **`lib-q-hqc`:** `HqcKemSecretKey::to_nist_bytes()` / `from_nist_bytes()` for NIST `dk_pke ‖ sigma ‖ ek_pke` interop.
- **`lib-q-hqc`:** `hardened` feature — `subtle` constant-time implicit-rejection in decapsulation; `tests/hardened_dudect_smoke.rs`.
- **`lib-q-sca-test`:** `hqc-hardened` builds `lib-q-hqc` with `hardened` — nine wall-clock TVLA targets with CI smoke tests.

### Fixed

- **`lib-q-hqc`:** Closed audit findings F1 (randomized decapsulation reliability) and F2 (Reed–Muller message-length). Both were stale: ~62,000 random-key round-trips across HQC-128/192/256 on portable and AVX2 paths show zero decapsulation mismatches, and the Reed–Muller decoder round-trips the full N1-byte block. Restored real assertions — un-ignored the `pke_roundtrip_basic.rs` tests, made `test_pke_integration` assert message equality over distinct keypairs, added `test_kem_roundtrip_varied_keys_all_params`, and tightened the Reed–Muller error-correction test to the full 46-byte block. Removed the misleading "rare PKE decode mismatches" comments.
- **`lib-q-hqc`:** Official KAT alignment — gate on `kats/official/` only; removed legacy `kats/ref/`, `kats/x86_64/`, and `kats/archive/` trees.

### Changed

- **Workspace:** All crates and path dependency pins aligned to **0.0.5** (shared `[workspace.package]` version).
- **Workspace:** Removed workspace `rand_chacha` and `rand_xoshiro` dependencies; test-only deterministic RNG call sites now use `lib-q-random` KT128 helpers (`new_deterministic_rng`, `new_deterministic_rng_from_u64`, `new_deterministic_rng_no_std`). Regenerated `lib-q-lattice-zkp` wire v0 KAT hex fixtures under `tests/vectors/`.
- **`lib-q-lattice-zkp`:** Wire v0 privacy revision — QROM committed-first-message Fiat–Shamir (`fs_w_digest`), hidden PVTN Merkle index + clearance on wire, issuer-keyed blind issuance (`IssuerCommitmentParams`, `issuer_params_digest` on kind `0x08`). PVTN KAT **2558 B** (budget 4096 B).
- **`lib-q-ring`:** Branch-free `Poly::infinity_norm`; `normalize_mod_q_assign` and `scalar_mul_by_u32_mod_q` for shared ML-DSA / lattice-ZKP hardened paths.

### Documentation

- `lib-q-lattice-zkp/DESIGN.md`, `README.md`, and `BLIND_ISSUANCE.md` document wire v0 limits, QROM FS, issuer-keyed blind issuance, PVTN privacy, and KAT regeneration.
- `docs/sca-self-certification.md` defines the ISO/IEC 17825 / FIPS 140-3-aligned self-certification process, gates, and evidence package; `docs/higher-order-masking-milestone.md` scopes the planned higher-order masking work. `docs/hardened-attestation.md` and `lib-q-lattice-zkp/DESIGN.md` reference both.
- **`lib-q-hqc`:** Rewrote `README.md`, `SECURITY.md`, and `tests/README.md` to remove false production-ready / "100% failure rate" claims; reconciled object sizes to `lib-q-types::hqc`; corrected the HQC-128 `N2` parameter (384, not 640); `docs/audit-package/README.md` records F1–F4 with boundaries; crate remains not production-ready.
- **`docs/sca-self-certification.md`:** Added nine `lib-q-hqc` targets to the self-certification table.

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
