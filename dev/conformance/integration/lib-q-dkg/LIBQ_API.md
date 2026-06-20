# lib-q-dkg — LIBQ_API contract (v1, PROVISIONAL)

libQ-agnostic contract for the dealerless DKG / lattice VSS crate. This document is the normative
description of what the crate guarantees; it carries no consumer-protocol references.

## 1. Scheme choice (for RED-zone review)

- **Protocol:** Gennaro–Jarecki–Krawczyk–Rabin–style **dealerless DKG**. Each party runs a
  verifiable secret sharing as a dealer; qualified contributions are summed. The group secret is
  never reconstructed.
- **Lattice instantiation:** coefficient commitments are **BDLOP / Baum-style** commitments
  (message in the clear) over a self-contained ring \(R_q = \mathbb{Z}_q[X]/(X^{1024}+1)\),
  `q = 281 474 976 694 273` (prime, `q ≡ 1 (mod 2N)`, `q < 2^48`). A commitment is
  `C = (t0, t1) = (B0·ρ, ⟨b1, ρ⟩ + a)` with ternary randomness `ρ ∈ R_q^KAPPA`. `t1` binds an
  **arbitrary** (non-short) `R_q` message `a`, which is exactly what a Shamir evaluation
  `f(j) = Σ_i jⁱ·aᵢ` needs (the `jⁱ` span `Z_q`, so `f(j)` is non-short). The commitment is additively
  homomorphic, giving a genuine Feldman/Pedersen relation over `R_q`.
- **Why the large modulus:** over a small modulus (e.g. ML-DSA `q ≈ 2^23`) BDLOP cannot fit both a
  hiding and a binding margin. At `q ≈ 2^48` the commitment is **statistically binding** (see §2a) —
  the kernel-injection attack is defeated with *no* computational assumption.
- **Why not classical:** a discrete-log Feldman/Pedersen (`g^a`) instantiation is non-conformant;
  this construction relies only on lattice assumptions.
- **References (candidate basis):** BDLOP commitments (eprint 2017/1230); Lyubashevsky Fiat–Shamir
  with aborts (Asiacrypt 2009 / eprint 2011/537); lattice PVSS (arXiv:2504.14381); threshold ML-DSA
  Shamir DKG (arXiv:2601.20917); GJKR DKG (J. Cryptology 2007).

## 2. Hardness assumptions

- **Binding** of coefficient commitments: **statistical** at this instance (no assumption) — see §2a.
- **Hiding** of the secret contribution: **Module-LWE** — recovering the unique short `ρ` from
  `t0 = B0·ρ` (and hence `a = t1 − ⟨b1, ρ⟩`) is hard.
- **Knowledge soundness** of the proof of correct sharing: Fiat–Shamir; sparse challenge weight
  `τ = 22` over `N = 1024` gives `|C| = 2^τ·C(N,τ) ≈ 2^171`, i.e. ≫128-bit (QROM heuristic).

### 2a. Value binding of the no-dealer check (the review fix)

A bare Ajtai commitment `com = A·x` binds only **short** witnesses, while `f(j)` is non-short. The
relation `commit(f(j)) == Σ_i jⁱ·Cᵢ` then places the share in the correct *coset* but does **not**
bind its value: an adaptive dealer can add a non-short kernel vector `κ` (`A·κ ≡ 0`) to a victim's
share — the image is unchanged, yet the value is corrupted (breaking identifiable abort).

This crate fixes it on two layers:

1. **Statistically-binding commitment.** With `MU = 6`, `KAPPA = 9`, `q ≈ 2^48`, the shortest nonzero
   vector of the kernel lattice `{x : B0·x ≡ 0}` is `≈ 2^36.5` (Gaussian heuristic), while the
   worst-case (ℓ∞-enforced) relaxed-opening difference an FS extractor can produce is `≈ 2^29.5` (over
   `KAPPA·N = 9216` dimensions). The chance a shorter kernel vector exists scales as
   `(2^-7.0)^9216 ≈ 2^-64500`, so a commitment opens to **one** message — unconditionally.
2. **Proof of correct sharing.** Linearity gives `Σ_i jⁱ·Cᵢ = (B0·f_ρ(j), ⟨b1, f_ρ(j)⟩ + f(j))` with
   the **non-short** `f_ρ(j) = Σ_i jⁱ·ρᵢ`, so the homomorphic opening alone still leaves the dealer
   free randomness. Each share therefore carries a **Fiat–Shamir-with-aborts proof** of knowledge of
   **short** `{ρᵢ}` such that, for recipient `j`,
   - `(A)  B0·ρᵢ = t0ᵢ` for all `i` (pins `ρᵢ` to its committed, short value), and
   - `(B)  ⟨b1, Σ_i jⁱ·ρᵢ⟩ = (Σ_i jⁱ·t1ᵢ) − s_j`.
   Soundness forces `s_j = f(j)` (relaxed by an invertible challenge-difference factor `c−c'`), so a
   kernel-injected `s_j + κ` is rejected. The proof is HVZK (Lyubashevsky rejection sampling, mask
   width `s_y(t) ≈ 11·‖c·ρ‖₂`, response bound `≈ 12·s_y ≪ q/2`), so reusing the same `{ρᵢ}` across
   every recipient's proof leaks nothing about the secret coefficients.

Covered by `kernel_injection_is_rejected_by_binding_proof` (tampered value rejected, commitment
preserved) and the `bdlop` unit tests (`honest_share_proof_verifies`,
`kernel_injected_share_is_rejected`, `proof_does_not_transfer_across_recipients`).

**No regime restriction.** Because BDLOP binds arbitrary `R_q` messages, there is **no** `(n, t)`
cap — the legacy verify-time norm bound and `BindingRegimeExceeded` are gone. Any `1 ≤ t ≤ n ≤ 16`
is supported.

## 3. Public interface (semantics fixed; names per this crate)

| function | role |
|----------|------|
| `setup() -> DkgProfileV1` | the frozen `V1` profile |
| `dkg_round1_commit(profile, n, t, party, rng) -> (SecretPolynomial, CoeffCommitments)` | sample degree-`t-1` poly + BDLOP coefficient commitments |
| `dkg_eval_share(poly, j, rng) -> ShareEvaluation` | evaluate at `j`; attaches the binding proof of correct sharing |
| `dkg_verify_share(commitments, dealer, recipient, share) -> bool` | binding no-dealer check (homomorphic opening **and** proof); **false** for any inconsistent share |
| `dkg_build_complaint(dealer, recipient, share) -> Complaint` | package a disputed share |
| `dkg_check_complaint(commitments, c) -> bool` | **true** iff the complaint is upheld; verifiable from commitments alone |
| `dkg_finalize_share(qualified) -> SigningShare` | sum qualified sub-shares for one recipient |
| `dkg_assemble_vk_set(qualified, parties) -> VerificationKeySet` | homomorphic sum of commitments → group key + per-party keys |
| `dkg_reshare(old, lagrange, new_committee, new_t, rng) -> ReshareRound1` | dealerless change-of-committee; no reconstruction |
| `lagrange_coeff_at_zero(subset, i) -> i64` | `Z_q` Lagrange weight for resharing |
| `signing_share_commitment(share) -> Vec<u8>` | recompute `commit(value; rand)` to match a verification key |
| `dkg_run_honest(profile, n, t, rng) -> KeygenSharesOutput` | full honest run (convenience / KAT) |

The crate (and the `lattice` module: `lattice::ring`, `lattice::bdlop`) is **std-gated** — the FS
mask needs `f64`. The `no_std` build exposes only `error` + `profile`.

## 4. Load-bearing properties

- **Value-binding soundness of `dkg_verify_share`:** an adaptive dealer cannot produce a share that
  verifies but carries the wrong value — the check enforces both the homomorphic commitment equation
  and the proof of correct sharing, and the commitment is statistically binding. There is no `(n, t)`
  regime exclusion.
- **Public verifiability of `dkg_check_complaint`:** decided from the commitments + the disclosed
  share only — no private state. A tampered share is upheld as a valid complaint.
- **No reconstruction:** the secret key is never materialized.
- **Binding-verifiable resharing (improvement):** `dkg_reshare`'s constant term is `lagrange·old_value`
  committed with **fresh ternary** randomness, so reshared sub-shares carry full proofs of correct
  sharing and verify under `dkg_verify_share`. The group **secret** is preserved (the new committee's
  finalized shares interpolate to the same constant term); the group-key **commitment** is
  re-randomized, so a fresh verification-key set is published. Covered by
  `reshare_is_binding_and_preserves_secret`.

## 5. Type mapping to `lib-q-threshold-sig` (drop-in target)

| this crate | `lib-q-threshold-sig` | note |
|------------|-----------------------|------|
| `SigningShare { index, threshold, share_bytes }` | `SecretShare` | `share_bytes` = `value ‖ rand` (`1 + KAPPA` `R_q` elements) |
| `ShareVerifier { index, verifying_key }` | `ShareVerifier` | `verifying_key` = serialized `commit(value; rand)` (`MU` `t0` + `t1`) |
| `VerificationKeySet { threshold, group_key, share_verifiers }` | `ThresholdSigPublicKey` | |
| `KeygenSharesOutput { public_key, secret_shares }` | `KeygenSharesOutput` | |

The crate is intentionally **independent** of `lib-q-threshold-sig` (no dependency on a PROVISIONAL
crate); shapes are mirrored, not re-exported. **Field-compatibility:** `lib-q-threshold-sig` is a
**GF(256)** byte-wise Shamir/Schnorr placeholder over `[u8;32]` secrets — a `Z_q`/`R_q` lattice share
cannot feed it. The PQ signer that *does* consume these shares is the co-designed
[`lib-q-threshold-raccoon`](../lib-q-threshold-raccoon/LIBQ_API.md): its `SecretShare` is
byte-identical to [`SigningShare`] and its `ThresholdRaccoonPublicKey.group_key` equals
[`VerificationKeySet::group_key`], so `dkg_run_honest` is a drop-in dealerless keygen for it (proven
by that crate's `dealerless_dkg_key_signs_and_verifies` test). The secret constant term is sampled
**short** ([`SECRET_KEY_WIDTH`]) precisely so the reconstructed key is a valid lattice signing key.

## 6. Wire (v1, provisional)

`encode_round1_commitments` / `decode_round1_commitments` and `encode_complaint` /
`decode_complaint`. Header `[ver=1][profile=1]`; ring elements use the canonical 6-byte-per-
coefficient encoding (`RQ_BYTES = 1024·6 = 6144`). A commitment is `MU + 1 = 7` ring elements
(`≈ 43 KB`); a round-1 broadcast at `t = 16` is `≈ 672 KB` (`WIRE_BUDGET_DKG_ROUND1_BYTES = 786 432`).
A complaint additionally carries the disclosed `value ‖ rand` and the proof `(c, z)` with
`|z| = t·KAPPA` ring elements (`WIRE_BUDGET_DKG_COMPLAINT_BYTES = 1 048 576`). Layouts are provisional
until the interoperable wire freeze.

## 7. Assumptions / caveats surfaced for RED-zone review

1. **Statistical-binding margin is a Gaussian-heuristic estimate.** The `≈ 2^36.5` shortest-kernel-
   vector figure (vs the `≈ 2^29.5` worst-case relaxed-extractor gap) is the Gaussian heuristic for a
   random `B0`. The `≈ 7.0`-bit margin is *not* a `2^-7.0` failure probability: the count of kernel
   vectors shorter than `GH/2^7.0` scales as `(2^-7.0)^9216 ≈ 2^-64500`, so binding is statistically
   certain. Hiding (recovering the unique short `ρ` from `t0`) is computational Module-LWE, and the
   authoritative **lattice-estimator** run (the gate) gives BKZ blocksize **β = 636 ⇒ 186-bit
   classical / 169-bit quantum** core-SVP at `KAPPA = 9` — see
   `lib-q-threshold-raccoon/SECURITY_ANALYSIS.md` §6. (At `KAPPA = 8` a hand estimate claimed 150-bit
   quantum but the estimator returned only 98-bit; the hand model was over-optimistic, which is why
   `KAPPA` was raised to 9.)
2. **Relaxed binding.** Soundness binds `s_j = f(j)` up to an invertible challenge-difference factor
   `(c − c')`. In this fully-splitting ring, short challenge differences are invertible with
   overwhelming probability (Lyubashevsky–Seiler); the kernel attack is defeated regardless (a forged
   offset would have to lie in the annihilator of `(c − c')`, which an attacker cannot freely hit).
3. **Hiding is computational (Module-LWE).** Statistical binding makes `ρ` information-theoretically
   unique given `t0`, so hiding of the secret coefficient rests on the hardness of recovering it
   (Module-LWE / inhomogeneous-SIS at `N = 1024`, `q ≈ 2^48`). This should also be estimated.
4. **Constant-time posture (improved this pass).** The branchless modular reduction
   (`mont_reduce`/`modadd`/`modsub`) and a **constant-time CDT base sampler** for the secret
   (`sample_secret_poly`, fixed-width table with a branchless scan) are now **implemented + unit
   tested** (`SECURITY_ANALYSIS.md` §8). Masks are sampled from fresh, secret-independent randomness,
   so their (non-CT) timing leaks nothing about the key. The residual channel is the **Lyubashevsky
   rejection** *iteration count* in `prove_share` / single-signer `signer` (inherent to FS-with-aborts;
   the per-iteration accept/abort is now isochronous). Use the rejection-free distributed path for
   secret keys vs. a timing adversary. Production CT items: 128-bit-fixed-point CDT, CT large-σ mask
   sampler, and a timing-measurement campaign.
5. **Large objects.** `N = 1024`, `q ≈ 2^48` ⇒ commitments `≈ 30 KB` each and proofs `≈ 0.1–0.6 MB`;
   acceptable for a setup protocol, not bandwidth-optimized.
6. **Threshold-native signing.** The PQ signer (`lib-q-threshold-raccoon`) provides **both** a
   caller-side Lagrange *combine* (`combine_opening` + `sign`) and a **distributed t-of-n protocol**
   (`threshold`, no key reconstruction) using additive zero-sharing to keep the aggregated response
   short despite non-short Lagrange-weighted per-party randomness (Threshold-Raccoon technique). The
   distributed path is rejection-free with a per-key flooding budget — see that crate's
   `LIBQ_API.md` §3a/§7 and `SECURITY_ANALYSIS.md` §4/§7.
7. **Complaints disclose a pairwise share.** As in standard Pedersen-VSS; acceptable, but it leaks
   one dealer↔recipient share.
8. **Research-grade.** Lattice threshold VSS is nascent; this is a concrete published-candidate
   instantiation for evaluation, not a standardized scheme.
