# Security analysis — lib-q-threshold-kem-lattice (PROVISIONAL)

RED-zone analysis for the dealerless-keygen lattice threshold KEM (dual-Regev over the
BDLOP-committed DKG key), covering (1) both Module-LWE instances (decapsulation key and
ciphertext), (2) the exact-correctness noise budget, (3) the flooding / per-key decapsulation
budget for the distributed path, (4) the FO⊥ chosen-ciphertext posture — including a **quantified
attack** on the one boundary FO cannot close (insider probing with malformed ciphertexts), and
(5) the constant-time posture. Hardness figures are the canonical
[lattice-estimator](https://github.com/malb/lattice-estimator)'s, not hand estimates — §6 gives the
invocation ([`ciphertext_estimate.py`](ciphertext_estimate.py), archived log
[`ciphertext_estimate.log`](ciphertext_estimate.log)); the decapsulation-key instance reuses the
DKG/raccoon archive run (their §6).

This crate is **PROVISIONAL / RED** and awaits cryptographer sign-off, like its siblings. The
honest status of each claim is stated inline: *estimator-gated*, *worst-case-arithmetic* (exact),
or *heuristic* (stated, not proven).

## 0. Parameters

| symbol | value | meaning |
|--------|-------|---------|
| `N` | 1024 | ring degree, `R_q = Z_q[X]/(X^N+1)` (shared with `lib-q-dkg`) |
| `q` | 281 474 976 694 273 (≈2⁴⁸) | modulus (prime, `q ≡ 1 mod 2N`) |
| `MU` | 6 | rows of `B0` ⇒ public key `t0 = B0·r ∈ R_q^MU`; ciphertext-secret dimension `MU·N = 6144` |
| `KAPPA` | 9 | decryption-key width (`r ∈ R_q^KAPPA`); ciphertext width `p ∈ R_q^KAPPA` |
| `ENC_ERROR_BOUND` (`B`) | 2²⁰ | encryption errors `f, g` uniform in `[-B, B]` per coefficient |
| `FLOOD_BOUND` | 2⁴⁰ | per-partial flooding, uniform in `[-2⁴⁰, 2⁴⁰]` per coefficient |
| `MESSAGE_BITS` | 256 | message bits per ciphertext (one per low-order coefficient) |
| `RECOMMENDED_DECAP_BUDGET` (`Q_d`) | 2²⁰ | per-key decapsulation budget (distributed path, §4) |
| max parties | 16 | `PROFILE_MAX_PARTIES_V1` (⇒ `‖r‖∞ ≤ 16`, ≤ 16 flooded partials) |

Ciphertext: `p = B0ᵀe + f`, `v = ⟨t0, e⟩ + g + encode(μ)` with `e` uniform ternary in `R_q^MU`.
All of `(e, f, g)` are expanded from `SHAKE-256(dom ‖ pk-digest ‖ μ)` with **integer-only**
rejection sampling (FO derandomization, §5). `K = SHAKE-256(dom ‖ pk-digest ‖ μ ‖ ct-digest)`.

## 1. Decapsulation-key hiding (Module-LWE) — estimator-gated (archived run)

Recovering `r` from `t0 = B0·r` is **exactly** the BDLOP-randomness Module-LWE instance the
DKG/raccoon stack was estimator-gated on (`B0 = [I | B0']` HNF; secret/error ternary; dimensions
`(KAPPA−MU)·N` / `MU·N`): BKZ blocksize **β = 636 ⇒ ≈186-bit classical / ≈169-bit quantum
core-SVP**. This instance is now reproducible **in-tree** — `key_estimate.py` emits the exact
config (`n=3072`, `m=6144`, `q≈2^48`, `Xs=Xe=U(-1,1)`) and `key_estimate.log` archives the full
per-attack table (vendored from the authoritative raccoon run of this byte-identical instance;
provenance in the log header) — closing review finding **H3** (see also
`../lib-q-threshold-raccoon/SECURITY_ANALYSIS.md` §2/§6). Nothing in this crate changes that
instance; it is the **binding hardness constraint** of the KEM.

## 2. Ciphertext hiding (Module-LWE) — estimator-gated (this run)

The ciphertext is a *distinct* instance: secret `e` ternary of dimension `MU·N = 6144`, samples
`(KAPPA+1)·N = 10240` (`p` plus `v`), error uniform `[-B, B]`. IND-CPA of the ciphertext is
decision-MLWE here.

Estimator result (§6): the `rough` sweep reports **no feasible attack** (`inf`) at every swept
bound `B ∈ {2¹⁸, 2²⁰, 2²², 2²⁴}`, and the full estimate at the *easiest* swept point `B = 2¹⁸`
already costs **≈2⁹⁷¹ rop** (`bdd_hybrid`, default cost model; β = 1755). Hardness is monotone
increasing in `B`, so the deployed `B = 2²⁰` is bracketed from below by an instance ~800 bits
above the 128-bit bar. Cost-model spread is irrelevant at this altitude (the paranoid ADPS16
lower bound is ~0.79× the exponent — still ≫ 700 bits).

**Why so hard:** the secret dimension 6144 is 6× a Kyber-1024-class instance while
`q/σ ≈ 2²⁸` — the modulus-to-noise ratio is generous, but hardness is dominated by the huge
dimension. The ciphertext side is **nowhere near the security bottleneck**; §1 (169-bit quantum)
binds. Uniform (not Gaussian) noise is deliberate — it makes the FO re-encryption integer-exact
(§5) — and is what the estimator was run with (`Xe = U(-B, B)`).

## 3. Correctness — exact (worst-case arithmetic, no failure probability)

Decapsulation computes `w = v − ⟨r, p⟩ = encode(μ) + g − ⟨r, f⟩ + Σ flood_i` and decodes each
coefficient against the threshold `q/4 ≈ 2⁴⁶·⁰`. Worst-case coefficient bounds (`‖r‖∞ ≤ 16` since
`r` is a sum of ≤ 16 ternary vectors — one per DKG dealer):

| term | bound | log₂ |
|------|-------|------|
| `g` | `B` | 20.0 |
| `⟨r, f⟩` | `KAPPA·N·‖r‖∞·B = 9·1024·16·2²⁰` | ≈37.2 |
| `Σ flood_i` (≤16 partials) | `16·2⁴⁰` | 44.0 |
| **total** | | **≈44.01** |

Margin to `q/4`: **≈3.9× worst-case** (reference un-flooded path: ≈450×). Decoding therefore
**never fails** and the FO re-encryption check **never falsely rejects** (`δ = 0`) — these are
worst-case inequalities, not tail bounds.

## 4. Flooding + per-key decapsulation budget (distributed path)

Threat model: up to `t−1` corrupt parties **inside the decapsulating subset**. The pairwise
zero-share masks `m_i` make each broadcast uniform to *outsiders*, but an inside coalition knows
every seed the honest party `h` mixes, strips `m_h`, and sees `y = λ_h·⟨rand(h), p⟩ + flood_h`.

**Flooding is load-bearing.** Without it, each honest ciphertext hands the coalition `N = 1024`
*exact* linear equations in the `KAPPA·N = 9216` unknown coefficients of `rand(h)`: **9 honest
decapsulations ⇒ full share recovery by linear algebra**, and `rand(h)` plus the coalition's own
`t−1` shares reconstructs `r`.

**With flooding, honest ciphertexts leak an LWE instance far above the bar** *(estimator-style
argument, instance stated so it can be gated)*: each query gives `linear_p(rand(h)) + flood` with
`flood` uniform `2⁴⁰`, i.e. LWE with dimension 9216, modulus `q ≈ 2⁴⁸`, noise-to-modulus
`≈ 2⁻⁸`, and at most `Q_d·N` samples. At dimension 9216 this is *far* harder than the §2 instance
(same shape, larger dimension, larger relative noise), so any feasible `Q_d` is safe by domination;
`Q_d = 2²⁰` ([`RECOMMENDED_DECAP_BUDGET`]) is a conservative, raccoon-consistent budget. *Status:
heuristic-by-domination (no dedicated estimator run; the dominating instance §2 is gated).*

**What flooding does NOT stop — the malformed-ciphertext insider probe (quantified):** an insider
who can get honest parties to run `partial_decap_masked` on an **adversarial** `p` defeats
flooding by amplification. Sketch: choose `p = δ·X⁰·unit_k` (a single scaled ring element); then
`y = λ_h·δ·rand(h)_k + flood_h`. `flood` hides only the low ~41 bits of a 48-bit coefficient, so
each probe leaks ~7 high bits of every coefficient of `rand(h)_k`; **~7 adaptively scaled probes
per ring element × KAPPA = 9 ⇒ ~63 malformed queries recover the full share.** The FO⊥ check at
`combine` rejects the *output* but runs **after** the partials are broadcast, so it does not
prevent this. Consequences for deployment (also in `LIBQ_API.md` §7):

1. Honest parties must only contribute partials for ciphertexts that are **known well-formed** —
   e.g. produced inside an authenticated session protocol (an identity-verified encapsulator, so a
   `t−1` coalition cannot inject spike ciphertexts).
2. The per-key budget `Q_d = 2²⁰` addresses the honest-ciphertext leakage above and is **not** a
   defense against this probe at that value (63 ≪ 2²⁰). For *untrusted* senders, cap partials-per-key
   below the probe length (`MALFORMED_PROBE_SAFE_DECAPS = 32`) and rotate the key via the DKG
   resharing before the cap — a bounded-leakage mitigation, not a cryptographic closure.

> **Correction (2026-07-10) — a ciphertext *well-formedness* proof is NOT sufficient.** An earlier
> draft of this section suggested closing the boundary with "a verifiable-encryption well-formedness
> proof (`lib-q-mve` candidate)." That is **wrong**: a proof certifying only `e` ternary and
> `‖f‖∞ ≤ B` does **not** stop the probe. The adversary is the encryptor, so it attacks with its
> *actual* `(e,f)` regardless of any proof about *some* decomposition; and the spike `f = δ·unit_k`
> with `δ = 1` has `‖f‖∞ = 1` — well inside the norm ball, so a norm proof *accepts* it. Bounding the
> norm constrains `f`'s magnitude, not its **direction**. The minimal statement that *does* close it
> is **knowledge of `μ`** (proof of correct encryption: `(e,f,g) = XOF(pk‖μ)`), which forces `f`
> pseudorandom. The only assumption-free realization is a ZK-STARK of the SHAKE expansion (heavy,
> RED); `lib-q-mve` proves a *different* statement (ML-KEM single-`K` consistency) and does not apply.
> The full treatment, the exact algebra, and the closure landscape are in **`THRESHOLD_SECURITY.md`**.

This is the sharpest open boundary of the construction and the primary item for cryptographer
review. It is intrinsic to *any* linear threshold decryption without a **proof of correct
encryption** (not merely well-formedness), not an artifact of this implementation.

## 5. Chosen-ciphertext posture — FO⊥ (explicit rejection)

- **Derandomization (FO-T):** `(e, f, g) = XOF(dom ‖ pk-digest ‖ μ)`; encryption is a bit-exact,
  platform-independent function of `(pk, μ)` because every sampler is integer-only rejection
  sampling (no floats anywhere on the path — the classic FO determinism trap with `f64` Gaussians
  is avoided by construction, and the KATs pin it).
- **Re-encryption check:** `combine`/`finish_decap` decode `μ'`, recompute `Enc(pk, μ')`, and
  compare against the received ciphertext with a **constant-time, no-early-exit** byte fold;
  mismatch ⇒ `InvalidCiphertext`, no key material released (explicit rejection, FO⊥).
- **δ = 0:** correctness is worst-case exact (§3), so the FO transform runs at zero decryption
  failure — no failure-boosting attack surface.
- **K binding:** `K = KDF(pk-digest, μ, ct-digest)` binds the shared secret to the public key and
  ciphertext (multi-target hygiene).
- *Status:* the single-decryptor FO⊥ argument is standard ROM material at these choices
  (deterministic re-encryption, explicit rejection, δ=0); **no formal proof is claimed for the
  threshold setting** — the partial-decapsulation oracle is *stronger* than the decapsulation
  oracle in the FO theorem, and §4's malformed-ct probe is exactly the gap. RED-zone review should
  treat "IND-CCA" as **conditional on the §4 closure being in force**. The full threshold treatment
  — the honest-ct LWE budget, the proof that a norm-only well-formedness proof is *insufficient*
  (the minimal sufficient statement is proof of *correct encryption* / knowledge of `μ`), and the
  closure landscape (assumption-free ZK-STARK-of-SHAKE vs. deployable authenticated-origin + budget
  + rotation) — is in **`THRESHOLD_SECURITY.md`** (the S3 write-up).

## 6. Canonical estimator invocation (the gate — status: RUN, 2026-07-10)

```text
export PYTHONPATH=/home/unix/lattice-estimator
/home/unix/miniforge3/envs/sage/bin/python key_estimate.py         # §1 load-bearing gate → key_estimate.log
/home/unix/miniforge3/envs/sage/bin/python ciphertext_estimate.py  # §2 (far above bar)  → ciphertext_estimate.log
```

Both estimators are self-contained (tkem consts only) and their archived runs are vendored in-tree
(`key_estimate.log`, `ciphertext_estimate.log`), so **both instances are reproducible-from-config
here** — no sibling-repo dependency for the load-bearing number (closes H3).

Instance: `LWE.Parameters(n=6144, q=281474976694273, Xs=ND.Uniform(-1,1), Xe=ND.Uniform(-B,B),
m=10240)`, `deny_list=("bkw", "arora-gb")` (pathologically slow, never minimal). Output archived in
[`ciphertext_estimate.log`](ciphertext_estimate.log):

```text
rough: B=2^18 → inf ; B=2^20 → inf ; B=2^22 → inf ; B=2^24 → inf   (no feasible attack located)
full (default model), B=2^18: bdd ≈ 2^981.2  ; bdd_hybrid ≈ 2^971.0  (β=1755)  ← easiest swept point
full (default model), B=2^20: bdd ≈ 2^1376.9 ; bdd_hybrid ≈ 2^1344.9 (β=1755)  ← deployed value
```

(The script's `B=2^20: full=inf` summary line is a float64 overflow — `2^1344 > 2^1024` — the
per-attack lines above it in the log carry the real costs; noted in the archived log.) The sweep
was terminated after bracketing (hardness is monotone in `B`; the easiest point is ~800 bits above
the bar; cost-model spread cannot change the verdict at this altitude).

## 7. Constant-time / side-channel posture (implementation status)

Updated 2026-07-10 after an adversarially-verified multi-dimension audit (findings implemented; the
refutations are as informative as the fixes and are noted where load-bearing).

- **Ring arithmetic** (`lib-q-dkg` NTT/Montgomery): branchless reductions, no secret-dependent
  control flow (see raccoon §8 — shared code). `centered_coeffs` — which the decode path runs on
  the secret `w` — now uses a branchless conditional subtract (previously an `if v > half` branch
  per coefficient).
- **Message encode/decode**: `encode_msg` (runs on the recovered `μ'` during FO re-encryption) and
  `decode_msg` (runs on the secret `w`) are **branchless** — mask-select for the `⌊q/2⌋`
  coefficient write, sign-fold absolute value and threshold-compare for the bit read. Previously
  both branched per message bit.
- **Keygen secret sampling**: constant-time CDT (`sample_secret_coeff_ct`, shared with the DKG).
- **Rejection samplers** (ternary `e`, uniform `f, g`, flooding): iteration counts are
  data-dependent but depend only on *uniformity* of the XOF/RNG stream, not on the accepted
  values; accepted-value computation is branch-free. Residual: an observer timing encapsulation
  learns rejection counts — under the PRF assumption on SHAKE-256 these are geometric variables
  independent of `μ` (audit-verified refutation of the naive "seeded by `μ'` ⇒ leaks `μ'`" claim).
- **FO comparison** (`ct_eq`): constant-time XOR fold over the coefficient arrays directly (no
  serialization, no allocation, no early exit within the data). The element-count guard is now a
  **hard, release-enforced** check — a hand-built ciphertext with the wrong `p` length compares
  unequal instead of silently truncating the comparison (previously a `debug_assert`), and every
  secret-touching entry point additionally rejects such a ciphertext up front
  (`EncodingCiphertext`).
- **`finish_decap` timing**: decode → re-encrypt → compare runs unconditionally; only the final
  KDF is conditioned on accept. With **explicit** rejection the accept/reject outcome is public by
  design, so the conditional KDF leaks nothing beyond the returned error. The re-encryption's
  rejection-sampling timing is `μ'`-dependent only through the PRF argument above.
- **Zeroization**: `μ` (encap and both decap paths), the decode input `w`, the re-encrypted
  ciphertext `recheck`, the ephemeral `e` and its NTT image, the decoded share (`Zeroizing`), the
  pre-mask partial intermediates (`⟨rand, p⟩`, the λ-weighted value, the zero-share mask, the
  flooding polynomial), the dealer's sharing polynomial + commitment randomness in
  `keygen_shares`, and `BufRng`'s buffered entropy (on drop). Stack-temporary ring elements inside
  the NTT helpers are *not* individually scrubbed (proportionality: heap lifetimes were the audit
  findings; stack frames are transient and overwritten by subsequent calls).
- The masked partial (`⟨rand, p⟩` inner product) runs on the branchless ring ops; Lagrange
  weighting is public. The flooding/zero-share samplers are per-broadcast fresh randomness.
- **Entry-point validation** (defense-in-depth, all release-enforced): subsets must be
  `≥ threshold` distinct nonzero indices containing the caller's index (index `0` is the Shamir
  evaluation point of the secret itself — `λ₀ = 1` would make a hand-built index-0 "share" a
  direct claim on `f(0)`); `combine` requires `≥ threshold` distinct partials; structurally
  malformed ciphertexts (`p` element count ≠ KAPPA, reachable only via the `pub` fields, never via
  `from_bytes`) fail closed before any share is touched.

## 8. Wire freeze + KATs

The v1 wire (ciphertext = `(KAPPA+1)·RQ_BYTES = 61440` bytes, canonical 6-byte little-endian
coefficients, non-canonical rejected on parse) and the FO/KDF domain separators are **frozen** and
pinned by `tests/kat.rs` (profile digest, ciphertext digest, shared secret — all integer-exact on
every platform/target). A pin change is a versioned wire break (`v1` → `v2`), never a silent edit.
`PARAMETER_SET_CANONICAL_BLOB_V1` encodes `(N, q, MU, KAPPA, B, FO, flood, message bits)` so any
parameter drift changes the profile digest.
