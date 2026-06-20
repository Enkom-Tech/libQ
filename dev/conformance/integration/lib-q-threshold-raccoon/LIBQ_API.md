# lib-q-threshold-raccoon — LIBQ_API contract (v1, PROVISIONAL)

GIP-agnostic contract for the lattice threshold signature that consumes `lib-q-dkg` shares. Normative
description of what the crate guarantees; no consumer-protocol references. The quantitative security
analysis (core-SVP estimates, flooding/Rényi signature budget, unforgeability reduction, constant-time
analysis) lives in [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) (reproduce via `security_estimate.py`).

## 1. Scheme choice (for RED-zone review)

- **Construction:** a Raccoon-family lattice Fiat–Shamir signature. The public key is a BDLOP
  commitment `T = commit(s; r) = (B0·r, ⟨b1, r⟩ + s)` (reusing `lib_q_dkg::lattice::bdlop`,
  `N = 1024`, `q ≈ 2^48`, `MU = 6`, `KAPPA = 9`) to a **short** secret `s`. A signature is a proof of
  knowledge of the short opening `(s, r)` bound to the message. Parameters are sized for ≥128-bit
  **quantum** core-SVP hiding (**169-bit**, malb lattice-estimator — the gate) with a 66.0 KiB
  signature — see [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) §0–§2/§6.
- **Why this binds to the DKG:** the DKG group key is exactly `Σ_dealer C_{dealer,0} = commit(s; r)`
  with `s` short (the DKG samples the secret constant term short) and `r = Σ_dealer ρ_{dealer,0}` a
  sum of ternary randomness — hence **short**. So `T` binds `s` (statistical binding) and hides it
  (Module-LWE), and `(s, r)` is recoverable from a threshold of shares by Lagrange at zero.
- **References:** Raccoon (NIST PQC additional signatures); Threshold Raccoon (del Pino–Katsumata–
  Reichle–Takemure, CRYPTO 2024); Lyubashevsky FS-with-aborts (eprint 2011/537); BDLOP (2017/1230).

## 2. Hardness assumptions

- **Unforgeability:** BDLOP **binding** (statistical at this instance — a short `z_r` forces a short
  extracted `r`, and `T` then binds a unique `s`) + **Module-LWE** (recovering `s`/`r` from `T`).
- **Knowledge soundness:** Fiat–Shamir; sparse challenge `τ = 22` ⇒ `|C| ≈ 2^171`.
- **Zero-knowledge:** the response `z_s` is uniform over `R_q` (perfect hiding of the non-short `s`);
  `z_r` is Gaussian + rejection-sampled (witness-independent).

## 3. Public interface

| function | role |
|----------|------|
| `setup() -> ThresholdRaccoonProfileV1` | the frozen `V1` profile |
| `keygen_shares(profile, t, n, rng) -> KeygenSharesOutput` | centralized trusted-dealer keygen (reference; `lib_q_dkg::dkg_run_honest` is the dealerless equivalent, same share format) |
| `combine_opening(shares) -> (s, r)` | recover the short signing opening from a threshold subset (Lagrange at zero) |
| `group_commitment(pk) -> Commitment` | decode the group key `T` |
| `sign(rng, pk, opening, msg) -> Signature` | single-party sign with a recovered opening |
| `verify(pk, msg, sig) -> bool` | verify (accepts both single-party and distributed signatures) |
| `encode_signature` / `decode_signature` | versioned, budget-gated wire codec |

### 3a. Distributed t-of-n protocol (`threshold`)

A 3-round protocol in which **no party reconstructs the key** (each uses only its own share):

| function | role |
|----------|------|
| `ZeroShareSeeds::setup(parties, rng)` | one-time pairwise seeds for additive zero-sharing |
| `sign_round1(index, rng) -> (Round1State, Round1Commit)` | sample masking; commit to `w_i = H(commit(y_s,i; y_r,i))` |
| `sign_round1_reveal(state) -> Round1Reveal` | open `w_i` |
| `aggregate_commitment(commits, reveals) -> Commitment` | check openings vs commitments; return `W = Σ w_i` |
| `sign_round2(state, share, subset, T, msg, W, seeds) -> PartialSignature` | masked partial `z_s,i`, `z_r,i + m_i` |
| `aggregate(partials, subset, T, msg, W) -> Signature` | zero-shares cancel ⇒ clean short `z_r`; standard signature |

The output is a normal [`Signature`] verified by `verify`. The non-short per-party `z_r,i` (Lagrange
blowup) is hidden by a uniform zero-share `m_i` (`Σ_{i∈S} m_i = 0`); the masks cancel on aggregation
so `z_r = Y_r + c·r_grp` is short. The message part `z_s,i` is flooded by a uniform `y_s,i`. The
commit-then-reveal first round prevents a rushing adversary from biasing the challenge. Verified by
`distributed_dealerless_threshold_signature` (subsets `{1,2,3}` and `{2,4,5}` both sign a dealerless
DKG key) and `tampered_round1_opening_is_rejected`.

## 4. Type identity with `lib-q-dkg` (the field-mismatch closure)

`SecretShare { index, threshold, share_bytes }` is **byte-identical** to `lib_q_dkg::SigningShare`
(`share_bytes = value ‖ rand`, `1 + KAPPA` `R_q` elements), and `ThresholdRaccoonPublicKey.group_key`
is the same serialized commitment as `lib_q_dkg::VerificationKeySet.group_key`. So a dealerless DKG
run is a drop-in keygen for this signer — verified by the `dkg_end_to_end` integration test
(`dealerless_dkg_key_signs_and_verifies`). This replaces the GF(256) `lib-q-threshold-sig` (which a
`Z_q`/`R_q` lattice share cannot feed) for PQ root/recovery keys.

## 5. Load-bearing properties

- **Correctness / subset independence:** any threshold subset reconstructs the same `(s, r)` and
  produces a verifying signature (`keygen_sign_verify_and_subset_independence`).
- **Sub-threshold rejection:** `combine_opening` errors below `threshold` shares.
- **Distributed t-of-n (§3a):** any qualified subset jointly produces a verifying signature without
  reconstructing the key; tampered round-1 openings are rejected.
- **Unforgeability** rests on §2 (binding + Module-LWE). Single-signer EUF-CMA and distributed
  TS-UF-1 have paper-grade reductions to those assumptions (+ a PRF and the flooding budget) in
  `SECURITY_ANALYSIS.md` §7, with the relaxed-opening and QROM steps flagged.

## 6. Wire (v1, provisional)

`[ver=1][profile=1] c  z_s  z_r[KAPPA]` — `2 + KAPPA` ring elements in the canonical 6-byte-per-
coefficient encoding (`RQ_BYTES = 6144`), budget `WIRE_BUDGET_SIGNATURE_BYTES = 131 072`. Provisional
until the interoperable wire freeze.

## 7. Assumptions / caveats surfaced for RED-zone review

1. **Distributed signing uses noise flooding (no rejection) → a per-key signature budget.** The
   distributed t-of-n protocol (§3a) uses additive zero-sharing (no key reconstruction); masks are
   flooded, so a Rényi bound caps signatures per key at `MAX_SIGNATURES_PER_KEY = 2^20` (worst case
   `t=2, n=16`; up to `2^23` at `t=16`). A deployment **MUST** enforce this as a per-key counter
   (`SECURITY_ANALYSIS.md` §4). The pairwise zero-share seeds are sampled by a helper here; a
   deployment establishes them via authenticated pairwise key agreement during/after the DKG.
   `combine_opening` + single-party `sign` (rejection-sampled, no budget) remain available for
   trusted-combine settings.
2. **Hiding is estimator-gated; binding is a Gaussian-heuristic statistical margin.** Hiding
   (Module-LWE) was run through malb's lattice-estimator (the gate): **β = 636 ⇒ 186-bit classical /
   169-bit quantum** core-SVP — clears ≥128 quantum with 41 bits of headroom. Binding is statistical:
   ≈7.0-bit GH margin over dimension 9216 (~2⁻⁶⁴⁵⁰⁰ failure), with SIS confirmed infeasible by the
   estimator. The earlier `KAPPA=8` hand estimate (150-bit quantum) was over-optimistic — the
   estimator gave 98-bit, which is why `KAPPA` was raised to 9. See `SECURITY_ANALYSIS.md` §6.
3. **Constant-time posture (improved).** The branchless ring reduction and a constant-time CDT base
   sampler for the secret are **implemented + tested** (`SECURITY_ANALYSIS.md` §8); the distributed
   path is rejection-free (CT by design). The single-signer rejection loop is isochronous per
   iteration but its iteration count is still a channel — use the distributed path for secret keys vs.
   a timing adversary. Production CT items: 128-bit-fixed-point CDT, CT large-σ mask sampler, timing
   measurement campaign.
4. **Research-grade.** A concrete published-candidate-style instantiation for evaluation, not a
   standardized scheme.
