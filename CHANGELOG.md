# Changelog

All notable changes to this workspace are documented here. Versions follow the shared `[workspace.package]` version in the root `Cargo.toml`.

## 0.0.10

### Removed

- **`lib-q-threshold-sig` deleted from the workspace.** Following the withdrawal recorded below, the
  crate has been removed outright rather than kept as a fail-closed shell. Its defect was structural
  — the design rests on no hardness assumption, so there was no patch to make and nothing for a
  future revision to build on. Keeping a withdrawn crate in the tree only invited someone to
  "re-enable" it. The threshold-signature capability is served by **`lib-q-threshold-raccoon`**
  (lattice, stated hardness assumption, consumes `lib-q-dkg` shares); it is not wire-compatible, so
  keys and signatures must be regenerated.
- Removed with it: the `lib-q-threshold-sig/` sources and its out-of-workspace `fuzz/` crate, both
  root `Cargo.toml` workspace entries (`members` and the fuzz `exclude`), its `Cargo.lock` entry,
  the `test-matrix` / `wasm-validation` / `wasm-bindgen-smoke` rows and feature selector in
  `.github/workflows/ci.yml`, `export/kat-vectors/threshold-sig-pop-v1.json` and its
  `scripts/export-primitive-kat-vectors.sh` copy step, the crate's entry in
  `scripts/ci-guard-primitive-banned-terms.sh`, and the `ThresholdSig*` type declarations from
  `npm/lib-q-types/index.d.ts`. `README.md`, `docs/npm-coverage.md`, `docs/npm-packages.md` and
  `docs/npm-wasm-api.md` now describe it as removed rather than as a withdrawn workspace member.
  Publish paths needed no change — the withdrawal had already dropped it from every `cd.yml` matrix
  and from `scripts/publish-npm-ordered.sh`, and npm package counts are unaffected because
  `@lib-q/threshold-sig` was already out of `publish-wasm-packages`.
- **Supersedes the "Changed" notes below**, which described the crate as remaining a workspace
  member compiled and CI-gated to keep the withdrawal verified, and its CI rows as deliberately
  left in place. That is no longer the case: with the crate deleted there is nothing to fail
  closed and nothing to verify, so those rows were removed too (a matrix row naming a package that
  does not exist fails CI). Its link to `lib-q-threshold-sig/README.md` no longer resolves for the
  same reason; the analysis it pointed to is preserved in this file and in the commit that
  withdrew the crate. The rest of the withdrawal entry stands as written.
- **No published version of this crate was ever sound.** Do not reinstate it from git history or
  install any previously published `lib-q-threshold-sig` / `@lib-q/threshold-sig` artifact. The
  guidance in the withdrawal entry below still applies in full to anyone who used it.
- `lib-q-dkg`'s documentation previously described its share/key shapes as mirroring
  `lib-q-threshold-sig`; it now names `lib-q-threshold-raccoon`, which is the signer that actually
  consumes those shares. `lib-q-dkg`'s own types and wire format are unchanged.

### Security

- **`lib-q-threshold-sig` WITHDRAWN.** The crate is not a signature scheme and never provided any
  security: its published verifying keys were the private Shamir shares, its group key was the
  master secret recoverable from public data, and verification contained no secret input. The
  defect is structural, not a matter of parameters — see
  [`lib-q-threshold-sig/README.md`](lib-q-threshold-sig/README.md) for the analysis (deliberately
  without forgery steps). `keygen_shares`, `sign_round1`, `sign_round2`, `aggregate`, `verify`,
  `identify_abort`, and `proactive_refresh` now return `ThresholdSigError::SchemeWithdrawn`
  unconditionally and are `#[deprecated]`; the vulnerable construction has been deleted from the
  source rather than feature-gated, so it cannot be re-enabled by any downstream feature
  unification. All `@lib-q/threshold-sig` WASM exports throw.
- **Anyone who used this crate should treat any published, transmitted, logged, or persisted
  `ThresholdSigPublicKey` as full disclosure of the signing key and of every party's share**, and
  re-evaluate as unauthenticated any decision made on its output. Signatures it produced cannot be
  validated retroactively. Versions 0.0.6–0.0.8 remain installable from crates.io and npm until
  they are yanked.

### Fixed

- **`lib-q-fn-dsa` — portable key generation never terminated for degree n ≥ 8.** One arm of the
  `poly_sub_scaled` n=2 negacyclic-product unroll computed the wrong result, so the portable keygen
  path livelocked on every non-x86 target (aarch64, armv7, wasm32) — broken since the crate's first
  import, and invisible on the AVX2 CI runners that never exercise the portable path. Added a
  regression test asserting all four `logn <= 3` unrolled arms are bit-identical to the general
  loop, un-ignored the two keygen tests that had been masking this, and added a `fn-dsa-no-avx2` CI
  job that runs the portable path on every PR.
- **`lib-q-fn-dsa`:** `shake256x4` was a fully-wired Cargo feature that could not actually be built
  per-crate — the feature was not forwarded to `lib-q-fn-dsa-comm`, so enabling it standalone
  failed to compile.
- **CI (coverage gate):** the PR coverage gate was scoring `lib-q-fn-dsa` from 6 of 33 tests
  (42.86%) instead of the true 80.12%, due to a stale test-name filter. Removed the filter,
  tightened `coverage-skip` substring matching, and added a coverage-honesty guard
  (`scripts/ci-guard-coverage-honesty.sh`) so a filter like this fails CI instead of silently
  under-reporting.

### Added

- **`lib-q-sig` / `lib-q-slh-dsa`:** SLH-DSA (FIPS 205) gains signing-context support —
  `sign_with_randomness_and_context` / `verify_with_context`, `SLH_DSA_CONTEXT_MAX_LEN` (255) —
  and the WASM bindings now thread the ML-DSA (FIPS 204) signing context through instead of
  hardcoding an empty one, so a domain-separated signature produced under a GIP context (e.g.
  `wapp.sh/entitlement-v0`) is verifiable from a browser. Both algorithms reject an over-long
  context as a hard error rather than truncating it silently. Context-free entry points are
  unchanged — they delegate with `&[]` and are byte-identical to the prior output, KAT-pinned.

### Changed

- **Workspace:** Version **0.0.9 → 0.0.10**; all intra-workspace path dependency pins repinned to
  **0.0.10**.
- **`lib-q-blind-token` (PROVISIONAL, not audited):** Module-SIS core-SVP raised over the 128-bit
  quantum floor — modulus q ≈2^48 → ≈2^51 (BKZ blocksize 450 → 491; quantum soundness 119 → 130
  bit, classical 131 → 143 bit), cost model cross-checked against `lattice-estimator`. Small-width
  secret-bearing Gaussian samplers made isochronous (constant-time reverse-CDT + branchless
  BerExp), a secret-dependent branch in gadget-coset reconstruction closed, and the remaining
  f64/FFT timing caveat certified via a numeric-range argument. Wire format bumped profile 1 → 2
  (incompatible; downgrade-guarded), KAT v1 → v2. Still RED / research-grade, not a completed
  side-channel audit.
- **Dev/test profile:** `opt-level = 2` for all external dependencies and 49 math-heavy workspace
  crates (the hash stack, algorithm cores, lattice/threshold/proof crates, STARK+plonky proving
  stacks), so `cargo test --workspace` finishes in practical time locally; `debug-assertions` and
  `overflow-checks` stay on.
- **Toolchain:** pinned to `nightly-2026-07-24` (previously a floating `nightly`, which could
  reformat or re-lint otherwise-untouched files under CI without warning). Bumping the pin is now
  a deliberate, self-contained PR.
- **`lib-q-tweak-aead`:** the `simd-avx2` keystream compiled on every PR but was executed by
  nothing — no workflow enabled the feature and CI's `cargo test --all-features` pass was gated
  off. Added a differential test against the portable path and byte-pinned KATs reaching past the
  batched loop's 256-block counter boundary; wired the crate into `ci.yml` with and without
  `simd-avx2`.
- **`lib-q-fn-dsa`:** `flr_emu.rs`, the software binary64 backend shipped to wasm32/armv7, was
  executed by no test anywhere. Added a bit-exact differential against the native backend (which
  it passed) and a CI job that runs it.
- **`lib-q-k12`:** constant-time tests now compare timings at equal customization-string length
  (a prior version compared across lengths, which is not a meaningful constant-time property) and
  take the minimum of repeated measurements rather than one sample — tightening, not relaxing, the
  existing tolerance bands.
- **CI:** `cargo-tarpaulin` installed from a prebuilt binary instead of built from source (saved
  ~3 min/job); PR coverage cap raised 45 → 60 min. Whole-workspace **debug** test rows no longer
  re-run the slow lattice keygen/proof crates already covered by their own release-ci rows (their
  release-mode coverage is unchanged). `.mcp.json` (Enkom-internal agent config) untracked from
  the public repo.
- **Dependencies:** serde 1.0.228 → 1.0.229, serde_json 1.0.150 → 1.0.151; thiserror 2.0.18 →
  2.0.19; portable-atomic 1.13.1 → 1.14.0; aes 0.9.1 → 0.9.2; `actions/setup-node` 5 → 7.

- **CD (`.github/workflows/cd.yml`):** `lib-q-threshold-sig` removed from the crates.io
  `publish-rust-tier-4b-new-primitives` matrix and from the npm `publish-wasm-packages` matrix.
  `scripts/publish-npm-ordered.sh` no longer lists it. The crate's `Cargo.toml` now sets
  `publish = false`, so `cargo publish` refuses it even if run manually. It remains a workspace
  member — compiled, tested (`cargo test`, wasm32 checks, wasm-bindgen smoke tests), and lint-gated
  in CI — but ships to neither crates.io nor npm.
- **CI (`.github/workflows/ci.yml`):** removed from the `publish-readiness` dry-run matrix (there is
  nothing to ready a withdrawn, `publish = false` crate for). Left in place everywhere the
  withdrawal itself is being verified: the `test-matrix`, `wasm-validation`, and
  `wasm-bindgen-smoke` rows.
- **Docs:** `README.md`, `docs/npm-coverage.md`, `docs/npm-packages.md`, and `docs/npm-wasm-api.md`
  no longer describe `lib-q-threshold-sig` / `@lib-q/threshold-sig` as a usable package; npm package
  counts updated accordingly (30 → 29 total, 29 → 28 wasm-pack bundles).

## 0.0.8

### Added

- **`lib-q-transcript`:** Shared CFRG sigma / Fiat–Shamir duplex-transcript discipline for lib-Q ZK proofs, with two instantiations — **K12** (out-of-circuit) and **Poseidon-256** (in-circuit, behind the optional `poseidon` feature). `no_std` + `alloc` capable; bare-metal builds via `--no-default-features --features alloc[,poseidon]`. **STATUS: RED — experimental / research, not proven sound, not audited, not production-ready; pending human sign-off on the construction + labels.**
- **`lib-q-mve`:** Multi-recipient verifiable encryption ("verifiable rekey"). A producer distributes a fresh group key `K` to many recipients (each wrapped under that recipient's ML-KEM update key) with a **single** proof that every recipient receives the **same** `K`, checkable by an untrusted relay **without** the relay learning `K` (insider-robustness / anti-split). **STATUS: RED — experimental / research, not proven sound, not audited, not production-ready; pending human cryptographer sign-off.**
- **`lib-q-stark-baby-bear`:** The BabyBear prime field `F_p` (`p = 2^31 - 2^27 + 1`), implemented as a `lib-q-stark-monty31` instance; the base field for the Arm B membership STARK.
- **`lib-q-zkp` — unlinkable set-membership proof** (Fiat–Shamir domain `libq.zkfri.membership.v0`), in two arms:
  - **Arm A:** value field `Complex<Mersenne31> = GF(p^2)`, FRI challenge field a degree-3 extension `GF(p^6)` (~186 bits). Reaches **128-bit post-quantum** *only at the PCS/commitment layer* (binding on the SHAKE256 Merkle commitment); the Poseidon-over-`GF(p^2)` round-count soundness obligation (O1) is **still unverified**, so this is not a complete soundness proof.
  - **Arm B:** BabyBear base field + Poseidon2, with a **quintic `F_{p^5}` challenge field** (≈155 bits). Reaches **128-bit post-quantum** *at the PCS/commitment layer* (binding on the SHAKE256 Merkle commitment; conjectured and provable-Johnson query bounds both clear 128) — upgraded from the original degree-4 config, which capped at ~116-bit conjectured / ~99-bit provable. The AIR/Poseidon2 round-count soundness obligations (O1/O4) remain **unverified**, so this is not a complete soundness proof.
  - **STATUS for BOTH arms: RED / NOT signed off** — pending human cryptographer review (ADR-113 freeze gate). Not peer-reviewed: an IACR ePrint submission was desk-rejected; a self-published preprint + open-source reproduction artifact accompany it for review.

### Changed

- **Workspace:** Version **0.0.7 → 0.0.8**; all intra-workspace path dependency pins repinned to **0.0.8**.
- **CD (`.github/workflows/cd.yml`):** Publish pipeline gains `lib-q-stark-baby-bear` at **tier 10**, and `lib-q-mve` + `lib-q-transcript` at a new **tier 16b** (after `lib-q-zkp` tier 16, before the `lib-q` umbrella tier 17). The three new crates are **crates.io-only** (no npm / wasm packages).
- **CI:** `lib-q-blind-token` is crates.io-only (`crate-type = ["rlib"]`, no wasm-pack bindings) and is now **exempt from the tier-4b npm-parity guard** (`scripts/ci-guard-new-crates-and-npm.sh`).
- **Workspace:** Workspace-wide `no_std` / `wasm32` / SIMD (AVX2 / NEON / AVX-512) cross-compile hardening.

## 0.0.7

### Added

- **`lib-q-saturnin` — Saturnin update ("An Update on Saturnin"):** new **Saturnin-QCB** one-pass AEAD (`qcb` feature, default) built on a reusable Saturnin tweakable block cipher `SaturninTbc` (`Saturnin16^d_{K⊕T}`); message blocks use domain 9, the tag domain 10, AD domain 11. Also adds the **shorter-nonce tweak** for Saturnin-Short (`SaturninShortAead::with_nonce_len`, max plaintext `31 - nonce_len`). QCB is a spec-faithful interpretation pinned to derived self-consistency vectors — no official designer KATs exist; see `lib-q-saturnin/SECURITY.md`.
- **npm WASM packages for tier-4b primitives** (parity with crates.io 0.0.6): `@lib-q/mac`, `@lib-q/blind-pcs`, `@lib-q/double-kem`, `@lib-q/fhe`, `@lib-q/threshold-kem`, `@lib-q/threshold-sig` — each with `wasm` feature, `src/wasm.rs`, wasm-bindgen smoke tests, CI wasm-build/bindgen-test matrix entries, and CD `publish-wasm-packages` rows.
- **`@lib-q/types`:** TypeScript interfaces for MAC, double-KEM, FHE, and threshold KEM/sig wire shapes.
- **`lib-q-duplex-aead`:** Wire format v0 frozen — 32-byte key, 16-byte nonce, 32-byte tag, Keccak-f[1600] duplex-sponge. KAT fixtures in `tests/kat.rs` and `examples/dump_duplex_kat.rs`. Crypto integration: `aead_id = 2` via the `duplex-sponge` feature.
- **`lib-q-rocca-s`:** Rocca-S AEAD (IETF draft-nakano-rocca-s) — 256-bit key, 128-bit nonce, 256-bit authentication tag, AES-accelerated. Wired into `lib-q-aead` as `rocca-s` feature and into `@lib-q/aead` npm package. Published at crates.io tier-1 (before `lib-q-aead` in CD order).
- **`lib-q-ml-kem`:** `hardened` feature enables Boolean masked decapsulation, shuffled NTT, `subtle` constant-time comparisons. Dudect smoke test: `tests/hardened_dudect_smoke.rs`.
- **`lib-q-ml-dsa`:** `hardened` feature enables masked signing path. Dudect smoke test: `tests/hardened_dudect_smoke.rs` (requires `dudect-smoke-tests`).
- **Attestation:** `docs/hardened-attestation.md` documents hardening scope, CI evidence requirements, and the hardened-attestation contract.

### Changed

- **Workspace:** Version **0.0.7**; npm package count **22 → 28**.
- **CI:** `scripts/ci-guard-new-crates-and-npm.sh` now requires every `publish-rust-tier-4b-new-primitives` crate to appear in `publish-wasm-packages`.
- **Docs:** `docs/npm-packages.md`, `docs/npm-coverage.md`, `docs/npm-wasm-api.md` updated for the six new packages and Rocca-S.
- **`lib-q-romulus`:** bump `aead` 0.5 → 0.6.
- **Workspace:** bump `itertools` 0.14 → 0.15.

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
