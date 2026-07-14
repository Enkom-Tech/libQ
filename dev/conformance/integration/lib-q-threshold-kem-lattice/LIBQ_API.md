# lib-q-threshold-kem-lattice — LIBQ_API contract (v1, PROVISIONAL)

Consumer-protocol-agnostic contract for the lattice threshold KEM whose decapsulation key is produced
dealerlessly by [`lib-q-dkg`](../lib-q-dkg/LIBQ_API.md). This document is the normative description of
what the crate guarantees and the assumptions surfaced for RED-zone review; it carries no
consumer-protocol references. It is the KEM analogue of
[`lib-q-threshold-raccoon`](../lib-q-threshold-raccoon/LIBQ_API.md).

## 1. Scheme choice (for RED-zone review)

- **Protocol:** a **dual-Regev / GPV** threshold KEM over the shared ring
  `R_q = Z_q[X]/(X^N+1)`, `N = 1024`, `q ≈ 2^48` (the `lib-q-dkg` ring), hardened with an
  **explicit-rejection Fujisaki–Okamoto transform (FO⊥)**: encryption of the fresh 256-bit message
  `μ` is fully derandomized from `XOF(pk, μ)` with integer-only sampling, decapsulation re-encrypts
  the decoded message and rejects any mismatch, and the shared secret is `K = KDF(pk, μ, ct)`.
- **Why this and not ML-KEM Shamir:** the sibling `lib-q-threshold-kem` GF(256)-Shamir-shares an
  encoded ML-KEM decapsulation key — a **non-linear** encoding that no linear VSS (and hence no
  dealerless DKG) can produce. Dual-Regev decryption is the **linear** map `⟨r, ·⟩`, so it Shamir-
  shares homomorphically and a dealerless DKG can generate the key.
- **The key identity.** The DKG group key is a BDLOP commitment
  `T = commit(s; r) = (t0, t1) = (B0·r, ⟨b1,r⟩ + s)` to a short secret `s` under short randomness `r`.
  **`t0 = B0·r` is exactly a dual-Regev public key** whose short decryption key is `r`. The DKG
  already `t`-of-`n` Shamir-shares `r`: every `SigningShare` carries `rand(j) = f_ρ(j)` with
  `Σ_{j∈S} λ_j·rand(j) = r` (and `t0 = B0·Σ_dealer ρ_{dealer,0}`). So the KEM reuses the DKG output
  **verbatim** — only the `rand` half of each share, and only the `t0` prefix of the group key.
- **Encapsulation / decapsulation.**
  ```text
  encap:  μ ← {0,1}^256 ;  (e, f, g) = XOF(pk-digest ‖ μ)     [e ternary R_q^MU ; f, g uniform [-B,B]]
          p = B0ᵀ·e + f  (∈ R_q^KAPPA)
          v = ⟨t0, e⟩ + g + encode(μ)  (∈ R_q)          ct = (p, v) ;  K = KDF(pk, μ, ct)
  decap:  ⟨r, p⟩ = Σ_{j∈S} λ_j·⟨rand(j), p⟩              (linear; no key reconstruction)
          w = v − ⟨r, p⟩ = encode(μ) + (g − ⟨r, f⟩ [+ flooding])   μ' = decode(w)
          FO⊥: reject unless Enc(pk, μ') == ct ;         K = KDF(pk, μ', ct)
  ```
  All encryption randomness is integer-only rejection sampling from SHAKE-256, so `Enc(pk, μ)` is
  bit-exact on every platform/build — the property the FO⊥ re-encryption comparison rests on.
  Cancellation uses the **ring** adjoint identity `Σ_i (B0·r)_i·e_i = Σ_k r_k·(B0ᵀ·e)_k` (negacyclic
  ring products; verified by `lib-q-dkg`'s `b0_transpose_adjoint_identity`). The single additive helper
  `lib_q_dkg::lattice::bdlop::b0_transpose_apply` is the only change to `lib-q-dkg`; it touches no
  commitment/proof/wire surface.
- **References (candidate basis):** dual-Regev / GPV trapdoor encryption (Gentry–Peikert–Vaikuntanathan,
  STOC 2008); BDLOP commitments (eprint 2017/1230); threshold PKE with noise flooding / smudging
  (Boneh et al., threshold FHE lineage); the co-designed `lib-q-dkg` (GJKR-style dealerless DKG) and
  `lib-q-threshold-raccoon`.

## 2. Parameters

| symbol | value | meaning |
|--------|-------|---------|
| `N` | 1024 | ring degree (`lib-q-dkg`) |
| `q` | 281 474 976 694 273 (≈2⁴⁸) | modulus (`lib-q-dkg`) |
| `MU` | 6 | `t0 ∈ R_q^MU`; dual-Regev "rows" (`lib-q-dkg` BDLOP) |
| `KAPPA` | 9 | `p ∈ R_q^KAPPA`; dual-Regev "columns" (`lib-q-dkg` BDLOP) |
| `ENC_ERROR_BOUND` (`B`) | 2²⁰ | encryption errors `f, g` **uniform** in `[-B, B]` (integer-only for FO) |
| `FLOOD_BOUND` | 2⁴⁰ | per-partial flooding noise, uniform in `[-2⁴⁰, 2⁴⁰]` (distributed path) |
| `RECOMMENDED_DECAP_BUDGET` | 2²⁰ | per-key decapsulation budget `Q_d` (distributed path; §7.3) |
| `MESSAGE_BITS` | 256 | message bits per ciphertext (one per low ring coefficient) |
| ciphertext size | `(KAPPA+1)·RQ_BYTES` = 10·6144 = **61 440 B** | `p ‖ v` |
| max committee | 16 | `PROFILE_MAX_PARTIES_V1` (matches `lib-q-dkg`) |

Pinned parameter digest: `SHA3-256(PARAMETER_SET_CANONICAL_BLOB_V1)`, blob
`"libq-threshold-kem-lattice-v1-dualregev-N1024-q281474976694273-MU6-K9-encU20-fo-flood40-mbits256"`
(the blob binds the **exact** prime `q`, not its bit size — pre-release pin change 2026-07-10, see
`tests/kat.rs` pin history)
(digest pinned by `tests/kat.rs`).

## 3. Correctness (no decapsulation failure — worst-case exact)

Decode noise is `g − ⟨r, f⟩ + Σ flood`. With `r` a sum of ≤16 ternary vectors (`|r_k|∞ ≤ 16`),
`‖f‖∞, ‖g‖∞ ≤ B = 2²⁰` and ≤16 flooded partials at `FLOOD_BOUND = 2⁴⁰`, the **worst-case** noise
coefficient is `≤ 9·1024·16·2²⁰ + 2²⁰ + 16·2⁴⁰ ≈ 2^44.01`, below `q/4 ≈ 2^46.0` with ≈3.9×
worst-case margin (≈450× on the un-flooded reference path). Decapsulation is therefore **exact**
(worst-case inequality, not a tail bound), and the FO⊥ check never falsely rejects (`δ = 0`).
`encode` places bit `i` at coefficient `i` as `⌈q/2⌉`; `decode` thresholds the centered coefficient
at `q/4`. See `SECURITY_ANALYSIS.md` §3.

## 4. Public interface (semantics fixed; names per this crate)

| function | role |
|----------|------|
| `setup() -> ThresholdKemLatticeProfileV1` | the frozen `V1` profile |
| `keygen_shares(profile, t, n, rng) -> KeygenSharesOutput` | trusted-dealer **reference** keygen (same share format as the DKG) |
| `public_key_from_dkg(&VerificationKeySet) -> PublicKey` | **dealerless** path: extract `t0` from a `lib-q-dkg` group key |
| `share_from_dkg(&SigningShare) -> SecretShare` | re-wrap a DKG share (byte-identical) |
| `encapsulate(pk, rng) -> (shared_secret, Ciphertext)` | KEM encapsulation (fresh `μ`; FO-derandomized body) |
| `kem::encapsulate_derand(t0, μ) -> Ciphertext` | the deterministic `Enc(pk, μ)` (the FO re-encryption function; KAT-pinned) |
| `partial_decap(share, subset, ct) -> PartialDecap` | reference partial: `λ_i·⟨rand(i), p⟩` (not individually private) |
| `threshold::partial_decap_masked(share, subset, ct, seeds, rng) -> PartialDecap` | share-private partial: `λ_i·⟨rand(i), p⟩ + m_i + flood_i` (zero-share + flooding) |
| `combine(pk, partials, ct) -> Result<shared_secret>` | sum partials → `⟨r,p⟩` → decode → **FO⊥ re-encrypt check** (rejects with `InvalidCiphertext`) |
| `decapsulate_reference(pk, shares, ct) -> Result<shared_secret>` | convenience: trusted-combiner full decap (FO⊥-checked) |

`SecretShare` is byte-identical to `lib_q_dkg::SigningShare`; `PublicKey.t0_bytes` is the `MU`-element
prefix of `VerificationKeySet::group_key`. So `lib_q_dkg::dkg_run_honest` is a **drop-in dealerless
keygen** (proven by `dealerless_dkg_key_encaps_and_decaps`).

**Input validation (2026-07-10 audit pass, all release-enforced):** the partial-decap entry points
reject zero/duplicate/missing subset indices, sub-threshold subsets, and structurally malformed
ciphertexts (`p` count ≠ KAPPA) *before* touching the share; `combine` requires ≥ `threshold`
distinct partials. Error variants distinguish the failure origin: `EncodingCiphertext` /
`EncodingPublicKey` / `EncodingShare` (structure/wire faults, incl. non-canonical coefficients) vs
`InvalidSubset` (caller error) vs `InvalidCiphertext` (cryptographic FO⊥ rejection) — callers
implementing the §7.3 well-formed-ct discipline can log these separately.

## 5. Load-bearing properties

- **Linear, reconstruction-free decapsulation:** each holder contributes `λ_i·⟨rand(i), p⟩`; the
  contributions sum to `⟨r, p⟩`. The decryption key `r` is never materialized.
- **Dealerless keygen:** the DKG output drives the KEM unchanged — no trusted dealer, no re-encoding.
- **Distributed-partial privacy (layered):** the ciphertext-bound additive zero-share makes each
  broadcast uniform over `R_q` against **outsiders** (masks cancel exactly); the added **flooding**
  (`FLOOD_BOUND`) is the protection against an inside coalition that knows the honest party's
  pairwise seeds — without it, ~9 honest decapsulations leak the share by linear algebra
  (`SECURITY_ANALYSIS.md` §4).
- **FO⊥ (explicit rejection):** `Enc(pk, μ)` is deterministic and platform-exact (integer-only
  XOF sampling); `combine` re-encrypts and compares in constant time (coefficient-level XOR fold,
  hard length guard); `δ = 0` (no failure boosting). A malformed/mauled ciphertext yields
  `InvalidCiphertext`, never a key. `encode`/`decode` of the message and the secret-`w` centering
  are **branchless** (2026-07-10 audit pass).
- **no_std + wasm:** the crate is `no_std + alloc` (bare-metal-gated in CI on
  `thumbv7em-none-eabi`) and ships wasm bindings (`@lib-q/threshold-kem-lattice`), both riding on
  the now-`no_std`-capable `lib-q-dkg` lattice core.

## 6. Wire (v1, provisional)

`Ciphertext::to_bytes` / `from_bytes`: `p` (`KAPPA` ring elements) followed by `v` (1 element), each
the canonical 6-byte-per-coefficient `RQ_BYTES = 6144` encoding (non-canonical coefficients rejected
on parse); total `61 440 B`. The public key is `t0` = `MU·RQ_BYTES = 36 864 B`. Shares are the
`lib-q-dkg` `value ‖ rand` encoding (`(1+KAPPA)·RQ_BYTES = 61 440 B`).

**The v1 wire is FROZEN and KAT-pinned** (`tests/kat.rs`: profile digest, ciphertext digest and
shared secret for a fixed key/message, exact on every platform/target since the FO path is
integer-only). A pin change is a versioned wire break (`v1` → `v2`), never a silent edit. Fixtures
regenerate only via `tests/kat_gen.rs` (`--ignored`).

## 7. Assumptions / caveats surfaced for RED-zone review

1. **Decapsulation-key hiding = the DKG's hiding, already estimator-gated.** Recovering `r` from the
   public `t0 = B0·r` is the *same* Module-LWE instance `lib-q-dkg` / `lib-q-threshold-raccoon`
   estimator-gated at BKZ **β = 636 ⇒ 186-bit classical / 169-bit quantum** core-SVP (see that crate's
   `SECURITY_ANALYSIS.md` §6). No new estimate needed for the key side.
2. **Ciphertext hiding — estimator-gated (RESOLVED, 2026-07-10).** The distinct ciphertext-side
   Module-LWE instance (`n = MU·N = 6144`, `m = 10240`, ternary secret, uniform `[-B, B]` error)
   was run through the lattice-estimator: **no feasible attack located** at any swept bound
   (`rough = inf` for `B ∈ {2¹⁸..2²⁴}`); the full estimate at the easiest swept point costs
   ≈2⁹⁷¹ rop. The ciphertext side is nowhere near the bottleneck; §7.1's 169-bit quantum
   (key side) binds. See `SECURITY_ANALYSIS.md` §2/§6 + `ciphertext_estimate.{py,log}`.
3. **Chosen-ciphertext posture — FO⊥ + flooding + budget (implemented); the REMAINING boundary is
   the malformed-ciphertext insider probe (primary review item).** `combine` enforces an
   explicit-rejection FO re-encryption check (δ = 0, deterministic integer-only `Enc`), masked
   partials carry `2⁴⁰` flooding, and deployments must enforce the per-key budget
   `RECOMMENDED_DECAP_BUDGET = 2²⁰`. What this does **not** close: a `t−1`-corrupt coalition that
   gets an honest party to emit a partial on an **adversarially amplified** `p` reads ~7 high bits
   of the share per probe (flooding hides only the low ~41 of 48 bits) — **~63 malformed queries
   recover the honest share**; the FO check fires only at `combine`, *after* partials are
   broadcast. Deployments MUST ensure partials are only computed on ciphertexts from an
   **authenticated / identity-verified encapsulator** (so a `t−1` coalition cannot inject spike
   ciphertexts), and SHOULD additionally cap partials-per-key below the probe length for untrusted
   senders (`MALFORMED_PROBE_SAFE_DECAPS = 32`) with DKG key rotation. **A ciphertext
   *well-formedness* proof is NOT sufficient** — a proof that only bounds `‖f‖` accepts the spike
   `f = δ·unit_k` (`‖f‖∞ = 1`) and binds no specific decomposition; the minimal sufficient statement
   is **proof of correct encryption / knowledge of `μ`** (`lib-q-mve` proves a different statement and
   does **not** apply). Quantified in `SECURITY_ANALYSIS.md` §4; full treatment and closure landscape
   in `THRESHOLD_SECURITY.md`. **No formal threshold IND-CCA theorem is claimed** (it is conditional
   on the closure in force).
4. **Partial-decapsulation authentication is out of scope in `v1`.** A partial reveals only
   `⟨rand(i), p⟩`, from which the published `ShareVerifier` commitment cannot be recomputed, so a
   malformed partial is not caught by `combine` (a malicious holder can corrupt the result — an
   availability, not confidentiality, break). A verifiable partial decryption (a short proof that the
   contribution is consistent with the committed share) is future work.
5. **Constant-time posture (hardened 2026-07-10, adversarially-verified audit).** Decapsulation's
   `⟨rand(i), p⟩` is a fixed-pattern ring computation (data-independent control flow); the FO
   comparison is a constant-time coefficient-level XOR fold with a hard length guard;
   `encode_msg`/`decode_msg` and the secret-`w` centering are now **branchless**. The XOF/RNG
   rejection samplers have data-dependent iteration counts that depend only on stream uniformity,
   not on accepted values. Zeroization now covers `μ`, the decode input `w`, the re-encryption,
   the ephemeral `e` (+ NTT image), the decoded share, all pre-mask partial intermediates, the
   dealer's keygen secrets, and buffered RNG entropy. See `SECURITY_ANALYSIS.md` §7 for the full
   posture including what is deliberately *not* scrubbed (stack temporaries) and the audit's
   refuted claims.
6. **Key non-reuse across primitives.** Do **not** reuse one DKG instance for both this KEM (uses `r`)
   and `lib-q-threshold-raccoon` (uses `s` and `r`): the KEM leaks linear images of `r` and the signer
   also binds `r`. Each primitive gets its own DKG.
7. **Large ciphertext.** `61 440 B` per ciphertext (lattice, `q ≈ 2^48`), comparable to the DKG's
   ~30 KB commitments — acceptable for a threshold-transport / rare-decapsulation setting, not
   bandwidth-optimized.
8. **Research-grade.** Lattice threshold KEM over a dealerless binding DKG is a concrete
   published-candidate instantiation for evaluation, not a standardized scheme.

## 8. Type mapping to `lib-q-dkg`

| this crate | `lib-q-dkg` | note |
|------------|-------------|------|
| `SecretShare { index, threshold, share_bytes }` | `SigningShare` | byte-identical `value ‖ rand` |
| `PublicKey.t0_bytes` | `VerificationKeySet::group_key[..MU·RQ_BYTES]` | the `t0 = B0·r` prefix |
| `keygen_shares` | `dkg_run_honest` | same share format; DKG is the dealerless path |
