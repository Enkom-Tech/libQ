# Changelog

All notable changes to this workspace are documented here. Versions follow the shared `[workspace.package]` version in the root `Cargo.toml`.

## Unreleased

### Changed — BREAKING (wire format)

- **`lib-q-blind-pcs`: commitment hash moved from SHA-256 (`sha2`) to SHA3-256 (`lib-q-sha3`).**
  A classical hash had no place in a post-quantum library; the `sha2` dependency is removed.
  Every commitment changes: those published in 0.0.6-0.0.10 do not verify under this code and
  there is no compatibility flag. `verify` also switched from a short-circuiting `zip().all()`
  comparison to `subtle::ConstantTimeEq`.

- **`lib-q-saturnin`: Saturnin-QCB now conforms to Algorithm 1 of the QCB paper.** Every QCB
  ciphertext changes; nothing produced by 0.0.8 or earlier decrypts under this code, and there is
  no compatibility flag (keeping the old construction reachable would keep the forgery below
  reachable).

  The mode was built from the "An Update on Saturnin" note alone. That note's Figure 1 is
  captioned "Saturnin-QCB, **encryption**" and shows only the message path — the tag and the
  associated data are in the QCB paper's Figure 3, which the note does not reproduce — so the
  previous code inferred the tag and AD handling from a figure that does not contain them. The
  normative source is Bhaumik, Bonnetain, Chailloux, Leurent, Naya-Plasencia, Schrottenloher and
  Seurin, *QCB: Efficient Quantum-secure Authenticated Encryption*, ASIACRYPT 2021 (full version
  IACR ePrint 2020/1304), Algorithm 1 plus its *Instantiation with Saturnin* paragraph.

  Three divergences are fixed:

  - **The nonce is back in the associated-data tweak.** AD tweaks previously zeroed the nonce
    field, making the AD's whole contribution to the tag a nonce-independent constant. The paper
    forbids exactly this (Section 5, *Avoiding Quantum Attacks*: "It is important to include the
    IV in the tweak when processing the AD. Otherwise, there is a quantum forgery attack based on
    Deutsch's algorithm."), which is the Q2 unforgeability QCB exists to provide over
    Saturnin-CTR-Cascade. It also gave a **purely classical** forgery whenever a nonce repeated:
    two encryptions under one nonce with associated data `A` and `A'` reveal
    `Σ(A) ⊕ Σ(A')`, and XORing that offset into the tag of any later genuine ciphertext under any
    fresh nonce relabels it from `A` to `A'` and verifies. Regression-tested end to end by
    `tests/qcb_spec.rs::ad_difference_does_not_transfer_across_nonces`.
  - **Five domain separators, not three.** The paper fixes `D = 9, 10, 11, 12, 13`; two of the
    three libQ used were assigned to the wrong roles. Now: `9` full message block (line 5), `10`
    final padded message block (line 7), `11` full AD block (line 10), `12` final padded AD block
    (line 12), `13` tag/checksum (line 13). Previously `10` was the tag and `11` covered the final
    padded AD block as well as the full ones. The final padded message block and the tag also move
    to tweak index `l` (the last full block's index) as Algorithm 1 specifies.
  - **Empty associated data now absorbs one padded block.** Algorithm 1 line 12 is unconditional,
    so `pad(A_*) = 10*` is absorbed even when `A` is empty; the previous code short-circuited to
    zero. This is the only throughput change in the fix (+1 Saturnin call per empty-AD message).

  `tests/qcb_spec.rs` checks `SaturninQcb::encrypt` against an independent transcription of
  Algorithm 1 over a 63-case length sweep, and the five pinned self-consistency vectors in
  `qcb::tests::pinned_kat_vectors` were regenerated. QCB remains an OCB-family mode, so nonce
  reuse remains catastrophic for confidentiality. At the time of this fix QCB was still not
  key-committing; the CMT-1 break in `tests/key_commitment.rs` has since been closed in this same
  unreleased cycle by the CTX transform (next entry).

- **`lib-q-saturnin`: Saturnin-QCB tags are now key-committing via the CTX transform (RED,
  pending cryptographer sign-off).** The demonstrated CMT-1 break (one ciphertext accepted under
  two distinct keys; 200/200 instances broken in closed form) is closed by wrapping the tag:
  `T' = SaturninHash(LABEL ‖ K ‖ N ‖ T ‖ A)`, `LABEL = b"libq.saturnin.qcb.ctx.v0"` — CTX (John
  Chan and Phillip Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022, ePrint
  2022/1260, Fig. 2 / Theorem 2), instantiated with Saturnin-Hash. **Breaking (wire format):**
  every QCB tag changes; nothing produced by earlier code verifies under this code, and there is
  no compatibility flag. **Claimed, not proven:** the target is CMT-4, capped by Saturnin-Hash's
  designer-claimed collision resistance of 2^112 classical / ~2^75 quantum. That is the designers'
  claimed *floor*, not the generic bound: the best-known generic classical cost is 2^128 by the
  birthday bound (spec §5.4.1), and they claim below it for margin ("additional constant factors
  that these bounds do not take into account, which is why our final security claims are reduced").
  It is not a NIST-LWC floor. The
  transform is proven but the instantiation is RED pending cryptographer sign-off on named
  obligations recorded in `lib-q-saturnin/src/commit.rs` (the published bound; Theorem 2's
  length-preserving assumption versus QCB's `10*` padding; and whether CTX∘QCB preserves QCB's
  Q2 security — CTX's proof is classical-ROM). The old CMT-1 attack is retained as a regression
  test in `lib-q-saturnin/tests/key_commitment.rs` and was shown able to fail. `SaturninShortAead`
  remains non-committing by design. Details: `lib-q-saturnin/CHANGELOG.md`.

  **UPDATED later in this same unreleased cycle — two statements above were true when written and
  are not now.** (1) *"`SaturninAead` (CTR-Cascade) is not covered"* is superseded: CTX was
  extended to CTR-Cascade as `SaturninAeadCtx`, which is the mode every product actually uses, so
  the committing transform now sits on the reachable path and not only on opt-in QCB. (2) *"three
  named obligations"* is superseded by **five**: the 2026-08-07 primary-source review added **L-1**
  (Chan–Rogaway's Theorem 3 is single-user and single-verification-query) and **RK-1** (the spec
  grants related-key resistance for "a small number of keys" while QCB uses up to `2^95`), narrowed
  S-2 without closing it, and widened Q-1. Nothing was closed. A separate obligation, **Q-2**, lands
  on the base CTR-Cascade mode rather than on the transform. Note also that `~2^75` is the
  `M_q → T` corner of the designers' actual claim `T^5 × M_q < 2^448`, not a scalar bound.

- **HQC-192 and HQC-256 public keys shrink by 8 bytes**, to the sizes the specification requires:
  `4522 → 4514` and `7245 → 7237`. HQC-128 is unaffected (already 2241).

  The old sizes were the HQC **round-3 (2020)** values, which carried a 40-byte seed. HQC-128 was
  migrated to the 2025 32-byte-seed format and the other two parameter sets were not, so
  `hqc_pke.rs` derived the vector length from `PUBLIC_KEY_BYTES - 32` instead of
  `VEC_N_SIZE_BYTES` and left 8 bytes of zero padding on the end of every key. The padding was
  inert — it was never read — so this was an interoperability defect, not a correctness or
  security one.

  **What moves.** The whole public key is absorbed into `hash_h`, so this changes the public key,
  the NIST secret key, the ciphertext **and the derived shared secret** for HQC-192/256. Keys
  stored at rest convert losslessly by truncation (`pk[..4514]` / `pk[..7237]`); the removed bytes
  are zeros. Live peers on either side of the change do not interoperate.

  **What it buys.** libQ previously rejected any public key that was not 4522/7245 bytes, so it
  could not read a conforming HQC key from any other implementation — there was no interoperability
  to lose, only self-compatibility with previously stored libQ keys.

  The sizes are now derived (`kem_public_key_bytes(n_bits) = 32 + n_bits.div_ceil(8)`) rather than
  written as literals, and `lib-q-hqc/tests/pk_wire_length_conformance.rs` asserts the relation
  against `VEC_N_SIZE_BYTES` instead of restating a constant. The previous guard in
  `params_correct.rs` compared a constant to its own definition and passed when the value was
  falsified to 9999.

- **`lib-q-zk-encryption-proof`: the narrow proof tiers now challenge on the whole statement, so
  their proof bytes change.** `assemble_e_provenance_{prover,verifier}` and
  `assemble_r3a_f_provenance_{prover,verifier}` derived the Fiat–Shamir challenge from the
  ciphertext alone (`derive_zetas(ct)`), while the full tier derived it from `(pk_digest ‖ ct)`.
  All six now use the shared `statement_zetas(pk_digest, ct)`, so the multi-target separation the
  crate documents (the "H4 transcript half") holds for every tier rather than one of three.
  **Breaking:** a proof produced by earlier code does not verify under this code and vice versa.
  No KAT in this repo pinned the old transcript, and the crate is RED/unsigned and pre-1.0, so no
  compatibility path is provided. `encryption_proof::tests::all_tiers_absorb_pk_digest_into_zeta`
  pins the new derivation and was shown to fail against each of the four old call sites
  individually. The older relation layer (`prove::{prove,verify}_relation_layer`) still derives
  the challenge from the ciphertext alone; there the public key enters the verifier as an explicit
  `t0` argument, and unifying it is tracked separately.

### Changed — BREAKING (API)

- **`lib-q-core`: `TimingValidator::constant_time_select`/`constant_time_assign` tighten their
  generic bound from `T: Copy` to `T: subtle::ConditionallySelectable`**, which `subtle` implements
  for the integer types but not for arbitrary `Copy` types. This is the visible half of the
  constant-time fix below; no in-tree caller used these methods.

### Fixed

- **`lib-q-core`: `TimingValidator::constant_time_select`/`constant_time_assign`/`constant_time_copy`
  were a plain `if`/`else` — not constant time, despite the crate's docs and name claiming
  otherwise, in the crate whose stated job is validating that property. Reimplemented branchlessly
  on `subtle::ConditionallySelectable` (see the API break above). A dispatch-canary test
  (`select_and_assign_dispatch_through_subtle_not_a_branch`) now pins the branchless path — it was
  shown to fail against the old `if`/`else` bodies. The methods still take a `bool`, so the caller
  is responsible for deriving that `bool` in constant time; the doc comments now say so.

- **`lib-q-hqc --features simd-avx2` no longer fails to compile off x86_64.** An AVX2-only import
  was gated on the feature alone with no `target_arch` guard, so enabling it for `wasm32` or
  `aarch64` produced `error[E0432]: unresolved import crate::simd::Avx2`. No CI job built that
  combination — the wasm gate only checks default features — so a new `hqc-simd-avx2-arch-gate`
  job builds both targets directly.

- **`lib-q-saturnin`'s `SaturninCore` no longer computes a non-Saturnin permutation** at
  `(rounds = 16, domain = 7 | 8)`. Hand-copied constant tables stored `RC0`/`RC1` transposed
  relative to how the round function reads them. No shipped output was affected — those two
  configurations are only ever used by the hash, which runs on a different core — and the fix is a
  pure deletion in favour of the specification's LFSR. See `lib-q-saturnin/docs/HARDWARE.md`.

## 0.0.10

> **Every libQ version prior to 0.0.10 is being yanked from crates.io as part of this release.**
>
> The yank sweep is a credentialed step performed immediately after the tag is published, so there
> is a short window in which this release exists and the older versions are not yet yanked. Read
> this as a statement of intent for that window, not as a claim about registry state at the instant
> you fetched it.
>
> This is deliberate and applies to all crates, not only the withdrawn ones. Releases 0.0.6-0.0.9
> carry defects that this release fixes, including a non-constant-time HQC decapsulation path, an
> aarch64 ML-DSA masking function that was not SHAKE256, an HPKE Auth mode whose tag did not
> authenticate the sender, and two predictable nonce/RNG sources reachable from safe public API.
> See the Security section below.
>
> Yanking does **not** break existing builds — an already-resolved `Cargo.lock` continues to work.
> It prevents new resolution onto an affected version. If a pre-0.0.10 libQ crate appears in your
> lockfile, upgrade rather than relying on resolution to fail.
>
> npm deprecation is a separate action and is tracked independently; a yanked crate does not imply
> a deprecated npm package.

### Removed

- **`lib-q-double-kem` deleted from the workspace.** The crate misimplemented its cited
  construction (Maul, ePrint 2025/1755): its second KEM leg derived the shared secret from
  transmitted wire bytes and the public `ek_b` alone, so the second decapsulation key was never
  required by either party. It therefore delivered plain ML-KEM-768 security — no dual-key
  property — at 1260 wire bytes where a single ML-KEM-768 ciphertext (`lib-q-ml-kem`) delivers the
  same security in 1088. The paper's construction itself is sound; this implementation of it was
  not, and it is deleted rather than repaired. Its only known consumer retracted the mode and
  permanently rejects its wire id (`kem_id = 8`).
- Removed with it: the `lib-q-double-kem/` sources (the `fuzz/` exclude entry at `Cargo.toml` was
  already stale — no fuzz crate existed), both root `Cargo.toml` workspace entries (`members` and
  the fuzz `exclude`), its `Cargo.lock` entry, the publish-readiness / `test-matrix` /
  `wasm-validation` / `wasm-bindgen-smoke` rows and feature selector in
  `.github/workflows/ci.yml`, the `cd.yml` crates.io and npm publish rows, both operator fallback
  scripts (`scripts/publish-crates-io-ordered.ps1`, `scripts/publish-npm-ordered.sh`),
  `export/kat-vectors/double-kem-v1.json` and its `scripts/export-primitive-kat-vectors.sh` copy
  step, the crate's entries in `scripts/ci-guard-primitive-banned-terms.sh` and
  `scripts/wasm-size-check.sh`, and the `DoubleKemEncapResult` type declaration from
  `npm/lib-q-types/index.d.ts`. Publish matrices are decremented accordingly: crates.io 80 → 79,
  npm 30 → 29. `README.md`, `docs/npm-coverage.md`, `docs/npm-packages.md` and
  `docs/npm-wasm-api.md` now describe it as removed; `docs/npm-coverage.md` also gains the
  previously-missing `@lib-q/threshold-kem-lattice` row so its stated npm package map agrees with
  `cd.yml`.
- **No published version of this crate should be trusted for dual-key custody.** The published
  `0.0.7` crates.io and npm artifacts are not yet yanked (operator decision pending); treat
  anything derived through them as plain ML-KEM-768 security, never as two-key custody.
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
- **`lib-q-threshold-kem` deleted from the workspace.** `partial_decap` returned the party's raw
  Shamir share, so `t` partials reconstructed the underlying ML-KEM-768 decapsulation key in full.
  ML-KEM decapsulation is a non-linear function of the decapsulation key, so a Shamir-shared `dk`
  admits no correct partial-decapsulation function at all — a structural defect, not a parameter or
  implementation bug, so it cannot be patched, only replaced. **`lib-q-threshold-kem-lattice`** is
  the successor (dual-Regev / GPV KEM over a BDLOP-committed `lib-q-dkg` key, FO⊥ + flooding
  hardened) and remains in the workspace, untouched by this change; it is not wire-compatible, so
  ciphertexts must be regenerated. Card `t_8ca3fd06`.
- **`lib-q-fhe` deleted from the workspace.** `decrypt` never read the key: it computed
  `body[i] - mask[i]`, and both `body` and `mask` are public ciphertext fields, so "decryption" was
  public-data arithmetic with no confidentiality. `mask` is load-bearing for `eval`
  (`MulConstant` scales it, `AddCiphertext` adds them), so removing it as a fix would require a
  real RLWE rewrite of the whole scheme — a structural defect, so the crate is deleted rather than
  repaired. Card `t_2a349708`.
- Removed with both: the `lib-q-threshold-kem/` and `lib-q-fhe/` sources (the
  `lib-q-threshold-kem/fuzz` exclude entry at `Cargo.toml` was already stale — no fuzz crate
  existed), both root `Cargo.toml` workspace entries (`members` and the fuzz `exclude`), their
  `Cargo.lock` entries, the `publish-readiness` / `test-matrix` / `wasm-validation` /
  `wasm-bindgen-smoke` rows and feature selectors in `.github/workflows/ci.yml` (already dropped
  from every `cd.yml` matrix and from `scripts/publish-crates-io-ordered.ps1` in a preceding commit
  on this branch), the remaining rows in `scripts/publish-npm-ordered.sh`,
  `export/kat-vectors/threshold-kem-v1.json` and its
  `scripts/export-primitive-kat-vectors.sh` copy step (`lib-q-fhe` had no KAT export), the crates'
  entries in `scripts/ci-guard-primitive-banned-terms.sh` and `scripts/wasm-size-check.sh`, and the
  `Fhe*` / `ThresholdKem*` type declarations from `npm/lib-q-types/index.d.ts`. Publish matrices are
  decremented accordingly: crates.io 79 → 77, npm 29 → 27. `README.md`, `docs/npm-coverage.md`,
  `docs/npm-packages.md`, `docs/npm-publish.md` and `docs/npm-wasm-api.md` now describe both as
  removed; `lib-q-threshold-kem-lattice/README.md` and its `dev/conformance/integration/`
  LIBQ_API.md no longer link to the deleted sibling.
- **No published version of either crate should be trusted.** The published `0.0.6`–`0.0.9`
  crates.io and npm artifacts for both `lib-q-threshold-kem` and `lib-q-fhe` remain installable —
  yanking is an operator decision pending, not yet done. Treat any transmitted or logged set of `t`
  `lib-q-threshold-kem` partial-decapsulation shares as full disclosure of the ML-KEM-768
  decapsulation key, and any `lib-q-fhe` ciphertext as providing no confidentiality at all: anyone
  who can see `body` and `mask` can recover the plaintext. Sources are archived (not merely
  deleted) for forensic reference outside the repository.

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
  validated retroactively. Versions **0.0.6, 0.0.7, 0.0.8 and 0.0.9** remain installable from
  crates.io and npm until they are yanked — note that 0.0.9 is the version a fresh `cargo add` or
  `npm i` resolves to, so a reader who checks a lockfile against a "0.0.6–0.0.8" range will wrongly
  conclude they are unaffected.

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

### Known limitations of this release

Recorded because each of these is a gap someone could reasonably mistake for coverage. None is a
known defect; all are things this release did **not** verify.

- **`lib-q-stark-monty31`'s AVX-512 backend has never been executed.** Its portable-vs-packed
  equivalence test exists and compiles, but no machine available to this project has AVX-512F, so
  the test has not run on any hardware. The AVX2 and NEON siblings *are* executed (natively and
  under QEMU respectively), and the AVX2 one caught a real sign-inversion bug in `neg()` during
  this cycle — which is precisely why the untested third copy is called out rather than assumed
  correct by symmetry. Treat `+avx512f` builds of that crate as unverified.
- **The HQC Reed-Solomon constant-time gate proves branch-freeness, not table-freeness.** The
  committed dudect test (`|t| < 15` at n=8000) reliably catches control-flow leaks — it was
  observed failing at `|t| = 28–194` against the pre-fix code. It would *not* catch a decoder that
  removed the early return while retaining secret-indexed GF lookup tables, because that residual
  cache signal is sub-nanosecond and both input classes execute identical operation counts. The
  current implementation is table-free by construction and by review; the gate is what guards
  against regression, and it is weaker than its green result suggests.
- **The release pipeline (`cd.yml`) does not execute aarch64 code.** `ci.yml` gained a job that
  genuinely runs aarch64 under QEMU — the absence of one is why four aarch64 defects shipped
  previously. The tag-time pipeline has no equivalent, so publishing does not independently
  re-verify the NEON paths.
- **Line coverage is below the documented 70% policy floor for two measured crates.** Test *counts*
  moved substantially this cycle — three crates went from zero declared tests to 63, 24 and 25 —
  but a count is not coverage, so it was measured (cargo-tarpaulin, LLVM engine, Windows host;
  CI's Linux figures will differ slightly):

  | crate | measured | policy floor | |
  |---|---|---|---|
  | `lib-q-stark-rayon` | 84.44% (38/45) | 70% | pass |
  | `lib-q-zkp` | 71.54% (3046/4258) | 65% | pass |
  | `lib-q-stark-commit` | 71.07% (140/197) | 70% | pass, by 1.07 points |
  | `lib-q-ml-dsa` | 68.67% (2558/3725) | 60% | pass |
  | `lib-q-stark-commit` (after) | 83.50% (172/206) | 70% | pass |
  | `lib-q-stark-monty31` (after) | 77.32% (600/776) | 70% | pass |
  | `lib-q-hqc` (after) | 70.71% (1412/1997) | 70% | pass |

  All three now clear the floor, by two different routes, and the distinction matters:

  **Scoping** (`lib-q-stark-monty31`, 30.65% → 77.32%). 1244 of its 2052 measured lines are the
  `x86_64_avx2/`, `x86_64_avx512/` and `aarch64_neon/` trees, gated on `target_feature` in
  `src/lib.rs` — a default build never compiles them, so they were inflating the denominator with
  code the runner cannot execute. Excluded, with the same justification and precedent as the
  existing `lib-q-keccak` and `lib-q-ml-dsa` entries. `no_packing/` stays measured: it *is*
  compiled. No tests were added and none were needed.

  **Real tests** (`lib-q-hqc` 51.00% → 70.71%, `lib-q-stark-commit` 70.87% → 83.50%). hqc gained
  55 tests; `error.rs` went from 0/73, covered by driving the code paths that *produce* each error
  rather than by constructing variants. stark-commit's `pcs.rs` went 0/20 → 20/20 after
  investigation showed it was a genuine gap, not a tooling artifact: `TrivialPcs` left five
  optional `Pcs` trait defaults un-overridden and no test called through them. Six of those default
  bodies are now mutation-verified.

  hqc's exclusion set is deliberately narrower than first proposed. `src/simd/avx2/` is gated on
  `#[cfg(target_arch = "x86_64")]`, **not** on the `simd-avx2` feature, so on any x86_64 build —
  including CI — those files are compiled and belong in the denominator. Only the two whose bodies
  carry `#[target_feature(enable = "avx2", enable = "pclmulqdq")]` are excluded, plus the genuinely
  feature-gated `wasm.rs`.

  One caveat on how to read hqc's figure: five of the added tests cover the AVX2 *dispatch* arms in
  the default (no `simd-avx2`) configuration, where those functions delegate to the portable
  implementation. They cover compiled, reachable code and their negative controls were observed
  failing, but they do not exercise SIMD instructions. Do not read 70.71% as "the AVX2 path is
  tested". A related naming problem this surfaced is tracked separately.

  Coverage still gates nothing on the release path: `cd.yml` runs no coverage step and
  `coverage.yml` does not sweep the `lib-q-stark-*` crates. These numbers are recorded because they
  had never been measured before.
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
