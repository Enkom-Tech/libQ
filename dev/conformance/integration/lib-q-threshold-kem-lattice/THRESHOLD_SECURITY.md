# lib-q-threshold-kem-lattice — Threshold security treatment (S3, RED)

> **Status: RED — analysis, not a signed proof.** This document is the "everything a cryptographer
> would write down" treatment of the threshold security of `lib-q-threshold-kem-lattice`, produced
> without a human cryptographer available. Its algebraic claims are checkable and are stated so they
> *can* be checked; its reduction sketches are **not** peer-reviewed theorems. It supersedes the
> forward-looking hand-waves in `SECURITY_ANALYSIS.md` §4–§5 with a precise account of exactly what
> is and is not closed, and — importantly — **corrects** a load-bearing error in the earlier
> deployment guidance (a ciphertext *well-formedness* proof is **not** sufficient; see §4).

Cross-references: numbered `Enc`/`Dec`/FO facts are in `SECURITY_ANALYSIS.md` (correctness §3,
flooding/budget §4, FO⊥ §5, estimator §6, constant-time §7); the wire/API contract is in
`LIBQ_API.md`.

---

## 1. Objects and threat model

Ring `R_q = Z_q[X]/(X^N+1)`, `N = 1024`, `q = 281 474 976 694 273 ≈ 2^48` (the `lib-q-dkg` ring).
BDLOP dimensions `MU = 6`, `KAPPA = 9`. Public commitment matrix `B0 ∈ R_q^{MU×KAPPA}`.

- **Group public key** `t0 = B0·r ∈ R_q^MU` — a dual-Regev public key whose short decryption key
  `r` (aggregate `‖r‖∞ ≤ 16`) is `t`-of-`n` Shamir-shared. Party `i` holds `rand(i) ∈ R_q^KAPPA`, a
  Shamir *evaluation* (**non-short** — coefficients ≈ uniform in `[0, q)`), with
  `Σ_{i∈S} λ_i·rand(i) = r` for any qualified subset `S`.
- **Per-party commitment** `t0_i = B0·rand(i) ∈ R_q^MU` — **public** (the DKG's
  `ShareVerifier.verifying_key` prefix).
- **Ciphertext** `(p, v)`: `p = B0ᵀ·e + f ∈ R_q^KAPPA`, `v = ⟨t0, e⟩ + g + encode(μ)`, with
  `(e, f, g) = XOF(pk-digest ‖ μ)` — `e` ternary in `R_q^MU`, `f, g` uniform `‖·‖∞ ≤ B = 2^20`.
  Every sampler is integer-only rejection sampling, so `Enc` is a bit-exact function of `(pk, μ)`.
- **Partial decapsulation** (`partial_decap_masked`): party `i` broadcasts
  `value_i = λ_i·⟨rand(i), p⟩ + m_i + flood_i`, where `m_i` is a pairwise additive zero-share
  (`Σ_{i∈S} m_i = 0`) and `flood_i` is fresh uniform noise `‖flood_i‖∞ ≤ 2^40`.
- **Combine**: sums the `value_i`, recovers `w = v − ⟨r, p⟩`, decodes `μ'`, and runs the FO⊥
  re-encryption check `Enc(pk, μ') == (p, v)` before releasing `K = KDF(pk, μ', ct)`.

**Adversary.** Static corruption of up to `t−1` parties, all inside the decapsulating subset `S`
(the worst case: `S` has exactly one honest party `h`). The coalition additionally controls the
**ciphertext submitted for decapsulation** (it acts as, or colludes with, the encryptor) and adaptively
requests partials. It knows every pairwise zero-share seed the honest party mixes (each such seed is
shared with a corrupt party), so it can **strip `m_h`** from `h`'s broadcast. This is strictly stronger
than the single-decryptor CCA oracle: the coalition sees a *partial-decapsulation* oracle — a share-linear
function of the honest secret — not just accept/reject.

**Goal.** (a) *Key hiding / IND-CCA*: the shared secret is pseudorandom to the coalition. (b)
*Robustness / availability*: a corrupt partial cannot silently corrupt the output (it is either
absorbed harmlessly or rejected by FO⊥, never yielding a wrong-but-accepted key).

---

## 2. What is solidly established

1. **Decapsulation-key hiding = the DKG's Module-LWE hiding** — recovering `r` from `t0 = B0·r` is
   the estimator-gated instance (BKZ β = 636 ⇒ 169-bit quantum core-SVP; `SECURITY_ANALYSIS.md` §6).
2. **Ciphertext (IND-CPA) hiding** — the distinct ciphertext-side Module-LWE instance
   (`n = 6144, m = 10240`, ternary secret, uniform `[-B,B]` error) is estimator-gated at ≈2^971 rop
   (`SECURITY_ANALYSIS.md` §2/§6). A dual-Regev `(p, v)` reveals nothing about `μ` to a passive party.
3. **Single-decryptor FO⊥ ⇒ IND-CCA in the ROM** — deterministic integer-only re-encryption,
   explicit rejection, worst-case exact correctness (`δ = 0`, `SECURITY_ANALYSIS.md` §3) place this in
   standard FO⊥ territory *for a monolithic decryptor*. This is the launch point, not the threshold
   result.
4. **Robustness (no wrong-but-accepted key).** On FO⊥ acceptance, `μ' = μ` and
   `K = KDF(pk-digest, μ, ct)` is the unique correct secret regardless of any corrupt partial: a cheat
   is either within the decode margin (absorbed, output unchanged) or shifts a decoded bit (FO⊥
   rejects, no key released). A corrupt coalition can therefore cause **denial of service** but not
   **key forgery**. *(This is the observation that lets the accountability layer in §6 be
   dispute-triggered rather than always-on.)*

---

## 3. Honest-ciphertext leakage — the flooding / Rényi budget

For an **honestly generated** `p = B0ᵀe + f` (with `e, f = XOF(μ)` fresh and pseudorandom), the
coalition-stripped view of the honest party is

```
y = λ_h·⟨rand(h), p⟩ + flood_h.
```

Using the ring adjoint identity `⟨rand(h), B0ᵀe + f⟩ = ⟨B0·rand(h), e⟩ + ⟨rand(h), f⟩ = ⟨t0_h, e⟩ + ⟨rand(h), f⟩`,
and subtracting the **public** `⟨t0_h, e⟩` term, this is
`λ_h·⟨rand(h), f⟩ + flood_h`. Across `Q_d` honest queries, `{⟨rand(h), f^{(t)}⟩ + flood^{(t)}}`
is an **LWE instance** in the `KAPPA·N = 9216` unknown coefficients of `rand(h)`: modulus `q ≈ 2^48`,
noise `2^40` (ratio `2^-8`), at most `Q_d·N` samples — because each honest `f^{(t)}` is a *fresh,
high-entropy, full-rank* set of matrix rows. This dominates the (already ≈2^971) §2 instance by
dimension and relative noise, so any feasible `Q_d` is safe.
`RECOMMENDED_DECAP_BUDGET = 2^20` is a conservative, raccoon-consistent cap.

*Status:* heuristic-by-domination (no dedicated estimator run for the dimension-9216 instance; the
dominating §2 instance is gated). The **load-bearing premise** is the word *fresh/high-entropy/full-rank*
— it is exactly this premise that a malformed ciphertext violates.

*External validation:* eprint 2026/1627 (Zhang–Zhou–Han–Liu–Huang) formalizes exactly this class of
argument (their Lemma 6, a min-entropy bound for a share conditioned on adversarial linear "matrix
hints", via Matrix-Hint LWE) for a polynomial — not super-polynomial — flooding term, where this
section is heuristic-by-domination. See §10.

---

## 4. The malformed-ciphertext insider probe — and why a norm proof does **not** close it

### 4.1 The probe

The security in §3 rests on the queried `f^{(t)}` being *random, full-rank* matrix rows. The coalition
controls the ciphertext, so it need not oblige. Choose the **spike**

```
p = δ · unit_k        (a single R_q coordinate scaled by δ),
```

for which `⟨rand(h), p⟩ = δ · rand(h)_k`. The stripped view is
`y = λ_h·δ·rand(h)_k + flood_h`. Since `rand(h)_k` has coefficients ≈ uniform in `[0, q)` (≈48 bits)
and `flood_h` is bounded by `2^40` (a 41-bit window in a 48-bit modulus), **each probe leaks the top
≈7 bits of every coefficient of `rand(h)_k`**. Sweeping `δ ∈ {1, 2, 4, …, 2^6}` (all with
`‖f‖∞ ≤ 2^6 ≪ B`) recovers all 48 bits per coefficient; `≈7` probes per coordinate × `KAPPA = 9`
coordinates ⇒ **≈63 malformed queries recover the entire share `rand(h)`**, which with the coalition's
own `t−1` shares reconstructs `r`. FO⊥ rejects the *output* but fires at `combine`, **after** the
partials are broadcast.

### 4.2 A bounded-norm well-formedness proof is INSUFFICIENT (the correction)

Earlier guidance (`SECURITY_ANALYSIS.md` §4, `LIBQ_API.md` §7.3 as first written) suggested closing
this with "a ciphertext well-formedness / verifiable-encryption proof (`lib-q-mve` candidate)."
**A proof that only certifies `e` ternary and `‖f‖∞ ≤ B` does not close the boundary.** Two
independent reasons, both exact ring arithmetic:

1. **The prover does not commit to a *unique* decomposition.** A norm proof certifies that *some*
   `(e', f')` with `‖f'‖∞ ≤ B` and `p = B0ᵀe' + f'` exists. It does **not** bind the specific `(e, f)`
   the encryptor actually used. The coalition — being the encryptor — attacks with its *actual*
   `(e_adv, f_adv)`; it subtracts `⟨t0_h, e_adv⟩` (needs only the public `t0_h` and its own `e_adv`)
   and is left with `⟨rand(h), f_adv⟩`, irrespective of any proof about `(e', f')`.

2. **Even the honest decomposition is exploitable.** The spike `f = δ·unit_k` with `δ = 1` has
   `‖f‖∞ = 1`, well *inside* the norm ball — a norm proof **accepts it**. Bounding the norm constrains
   the *magnitude* of `f` but not its *direction*: the adversary is free to place all of `f`'s weight
   on one coordinate, collapsing the query to a single-coordinate extraction. The `2^40` flood budget
   is `2^8` below `q`, so ≈7 bits leak per query regardless of how small the certified norm is.

The property that actually restores §3's hardness is that `f` be **pseudorandom and full-rank across
queries**, not merely short. That is *not* verifiable from `(p, v)` in isolation.

### 4.3 The minimal sufficient statement: knowledge of `μ`

The boundary closes **iff** the proof certifies **knowledge of `μ`** such that
`(e, f, g) = XOF(pk-digest ‖ μ)` **and** `p = B0ᵀe + f` (equivalently, a proof of *correct
encryption* / verifiable encryption of the plaintext, not a proof of *bounded error*). This forces
`f` to be the specific XOF-pseudorandom output for that `μ`, so the adversary cannot steer `f` to a
spike; under the XOF-as-PRF (ROM) assumption `⟨rand(h), f⟩` is then a pseudorandom linear function
and §3's LWE hardness is restored. It simultaneously enforces (i) `f`'s pseudorandom distribution,
(ii) freshness per distinct `μ`, and (iii) full-rank query matrices — the three premises §3 needs.

*(Refuted along the way, recorded so they are not re-attempted: a **public centered-norm filter** on
`p` — honest `p` is itself pseudorandom/high-norm by IND-CPA (§2), so no norm threshold separates
honest from spike ciphertexts; **larger flooding** — drowning a `δ` up to `q/2` needs `flood > 2^47`,
but subset-summed flooding must stay `< q/4` for correctness (§3), so it is infeasible at these
parameters; a **decapping-party-only interactive check** — the parties cannot verify `p = B0ᵀe + f`
without `e`, the encryptor's secret. `lib-q-mve` proves ML-KEM single-`K` multi-recipient consistency
— a **different statement** over a **different field** — and does not certify knowledge of `μ` here.)*

*External validation:* eprint 2025/1665 (Brzuska–Klooß–Woo) documents the identical class of gap for
TPKE in general (their footnote 11, with details in §4). See §9.

*External validation:* eprint 2026/1627's OTSS-NIZK (a knowledge-sound, extractable proof of the LWE
witness) is a *different* primitive from the norm-only membership proof §4.2 rules out — extraction
pins the specific `(e,f)`, closing exactly the gap §4.2 item 1 identifies. See §10.

---

## 5. Closing the boundary — the landscape

| # | Closure | Sound? | Deployment assumption | Cost / status |
|---|---------|--------|-----------------------|---------------|
| A | **PoK of `μ` in ZK** — STARK/FRI proof that `XOF(pk‖μ)=(e,f,g)` ∧ `p=B0ᵀe+f`, verified before any partial | **Yes, assumption-free** | none | **Built**: `lib-q-zk-encryption-proof`'s `encryption_proof::assemble_full_provenance_prover/_verifier` (Keccak-f/SHAKE-256 arithmetized in an AIR + integer rejection loops over `MU·N`/`KAPPA·N` coefficients) composed with the gate (`gate::gated_partial_decap_masked*`, `gated_partial_decap_authenticated_budgeted`); **RED** pending cryptographer sign-off |
| B | **Authenticated / accountable encryptor** — partials only for ciphertexts carrying a verifiable authorization bound to an identity-verified encapsulator | **Yes** | PKI / authenticated-session; corrupt coalition cannot mint an authorized identity | **Low–medium**: a signature over `ct` + a PKI layer (deployment-owned); the KEM exposes the enforcement hook |
| C | **Hard per-epoch decap budget + DKG key rotation** — cap partials-per-key below the probe length, reshare before the cap | **Partial** (bounded-leakage, not a cryptographic closure) | rotation is executed before the cap each epoch | **Low**: an in-library counter (§6) + the existing `lib-q-dkg` change-of-committee resharing |
| — | Norm-only WF proof (§4.2), public norm filter, flood re-tuning, party-only check | **No** | — | ruled out |

**Only (A) is assumption-free**, and it is the only path that turns the boundary GREEN without a
deployment premise — at the cost of a heavy, novel, still-RED SHAKE-in-STARK circuit. (B) and (C) are
sound-but-conditional and are how deployed threshold decryption schemes handle this class of oracle;
they are what the library can enforce *today* (§6). A production deployment SHOULD combine (B) and
(C): authenticated origin as the primary control, the epoch budget + rotation as defense-in-depth.

*External validation:* eprint 2025/1665 §5's non-interactive proof of randomness (NIPoR) is a candidate
formal target for closure A's PoK of `μ`. See §9.

*External validation:* eprint 2026/1627's TD1/TD2 gate partial decryption on such an OTSS-NIZK
(verified before any partial is computed) plus their Lemma 6 flooding, functioning as a candidate
closure distinct from (A)-(C) — call it closure D. See §10.

### 5.1 The budget arithmetic (closure C)

The probe needs ≈63 malformed partials on one key. Two regimes:

- **Authenticated senders (closure B in force):** malformed ciphertexts cannot be injected, so the
  only leakage is the honest-ct LWE instance of §3 — cap `Q_d = 2^20`.
- **Unauthenticated / untrusted senders:** any partial might be a probe. A hard per-key-epoch cap
  `Q_epoch < 63` (the library ships a conservative `MALFORMED_PROBE_SAFE_DECAPS = 32`) keeps the probe
  from ever completing, provided the DKG resharing rotates the key (new `r`, new shares) before the cap
  is reached. Leakage per epoch is then `< 32` noisy high-bit reads of a *rotated* share — never a full
  share. This is a *mitigation*, not a proof: it bounds the exposure window, it does not make the
  partial oracle hard.

---

## 6. What the library enforces (closure C, in code)

The library cannot verify an arbitrary authorization scheme (closure B is a deployment contract), and
closure A now has a built-but-RED gated entry point in `lib-q-zk-encryption-proof` (`gate::
gated_partial_decap_masked_budgeted` / `gated_partial_decap_authenticated_budgeted` compose it with
closures C/B respectively — see §5 row A), but this crate itself still makes closure C **enforceable
by construction** rather than a doc-only recommendation:

- `DecapBudget` — a saturating per-key decapsulation counter the caller threads through
  `partial_decap*`. It refuses to produce a partial once the configured cap is reached
  (`Err(BudgetExhausted)`), so a deployment cannot silently exceed its epoch budget.
- Constants make the two §5.1 regimes explicit: `RECOMMENDED_DECAP_BUDGET = 2^20` (authenticated
  senders) and `MALFORMED_PROBE_SAFE_DECAPS = 32` (untrusted senders — below the ≈63-query probe).
- The `partial_decap*` entry points already reject structurally malformed ciphertexts, sub-threshold
  and index-0 subsets, etc. (`SECURITY_ANALYSIS.md` §7); the budget adds the *rate* dimension.

The authorization hook for closure B is surfaced as an explicit contract (the caller MUST gate
`partial_decap*` on an authenticated-origin decision); the library does not embed a specific signature
scheme so as not to dictate the deployment's PKI.

---

## 7. Threshold IND-CCA — what is and isn't claimed

- **Claimed (RED, argued not proven):** (i) key hiding against a passive/honest-ct adversary reduces
  to the §2/§3 LWE instances; (ii) robustness/no-forgery holds unconditionally via FO⊥ (§2.4); (iii)
  under closure A (PoK of `μ`) the partial-decapsulation oracle is reduced to the honest-ct case, so
  threshold IND-CCA holds in the ROM at the §2/§3 hardness; (iv) under closures B+C the residual
  leakage is bounded and quantified (§5.1).
- **Not claimed:** a formal threshold IND-CCA theorem in the bare model. The partial-decapsulation
  oracle is strictly stronger than the FO⊥ decryption oracle, and without closure A the malformed-ct
  probe (§4) is a real gap, not an artifact. "IND-CCA" for this construction is **conditional on the
  §5 closure in force** and remains the primary item for human-cryptographer sign-off.

*External input:* eprint 2025/1665 Theorem 10 (§5, NIPoR) is a candidate proof route for turning closure
A's "argued not proven" claim into a cited construction. See §9.

*External input:* eprint 2026/1627 §1 (Lemma 6) is a candidate route to a cited, non-heuristic bound
for exactly the §3/§5.1 flooding-vs-budget arithmetic this section leaves as "argued not proven." See
§10.

---

## 8. Repronotes / open items for the reviewer

1. Confirm the §3 dimension-9216 LWE domination or run a dedicated estimator point.
2. Confirm §4.2: a bounded-norm proof is insufficient (spike `f = δ·unit_k`, `δ = 1`). *We believe
   this is airtight ring arithmetic; it is the single most important correction here.*
3. If closure A is pursued: the SHAKE-in-STARK PoK-of-`μ` is the only assumption-free closure —
   scope the Keccak-f AIR + integer-rejection-loop arithmetization (candidate stack: `lib-q-zkp` /
   `lib-q-stark-fri`), noting the field is FRI-native (BabyBear/M31) while `q ≈ 2^48`, so the lattice
   relation `p = B0ᵀe + f` must be carried by a bridged/emulated argument — this is the hard part.
4. Sign off (or refute) the §7 conditional threshold IND-CCA statement.
5. Scope eprint 2026/1627's closure D (§10): an OTSS-NIZK of the LWE relation gating
   `partial_decap*`, sized via its Lemma 6 min-entropy bound instead of the current ad hoc
   `RECOMMENDED_DECAP_BUDGET` / `MALFORMED_PROBE_SAFE_DECAPS` constants (§5.1, §6).

---

## 9. Related literature (external validation)

Brzuska, Klooß, and Woo, "Threshold Public-Key Encryption: Definitions, Relations, and CPA-to-CCA
Transforms" ([Cryptology ePrint Archive, Report 2025/1665](https://eprint.iacr.org/2025/1665)),
independently documents, for TPKE in general, the same class of gap this document
derives concretely for dual-Regev in §4.2–§4.3.

- **Matches §4.2.** Their footnote 11 (§1.2, referring to §4): *"The gap in [FP01,
  Theorem 1] is, at a high level, that the Naor–Yung transform requires perfect correctness, but the
  natural analogue is not enough for TPKE when partial decryption queries are admitted."* This is the
  general-TPKE statement of the failure mode §4.2 derives concretely here: a ciphertext
  well-formedness/bounded-norm proof (the classic Naor–Yung-style attached NIZK) does not stop a
  partial-decapsulation-oracle adversary, because well-formedness does not pin the ciphertext to the
  *specific* honest `(e, f)` decomposition the encryptor used (§4.2 items 1–2 here; their Section 4
  intro, same root cause). Their own fix for the classic Naor–Yung route is not "attach any NIZK" but
  requiring the underlying TPKE to be **semi-malicious CPA**-secure first (Definition 7: adversary may
  choose randomness for non-challenge ciphertexts) before their NIZK-well-formedness transform (Theorem
  7) is sound — this crate's dual-Regev TPKE has not been shown semi-malicious-CPA-secure, so Theorem
  7's route does not apply here without further work, consistent with §4.2's finding.

- **Candidate closure for §4.3 / closure A (§5, §7).** Their Section 5 introduces a
  **non-interactive proof of randomness (NIPoR)** (Definitions 8–9): a proof that a public value
  `y = f(m; r)` was produced from a secret input under honestly sampled randomness, formalized
  through a programmable random oracle. Freshness is in that formal sense; §5.1 explicitly allows
  a malicious prover to select among polynomially many random strings. This is stronger than
  merely proving knowledge of some coins satisfying an encryption relation.

  Closure A — `lib-q-zk-encryption-proof`'s
  `encryption_proof::assemble_full_provenance_prover/_verifier`, the SHAKE-in-STARK PoK of `μ` —
  has the same structural aim: bind the dual-Regev ciphertext to the encryptor's pseudorandom
  computation rather than just bounded errors. This motivates a **candidate NIPoR interpretation**,
  not an established instantiation of Definition 8 or its security properties.

  Theorem 10 (§5.3, Fig. 11) gives the candidate formal target: it upgrades the paper's
  SIM-CPA/IND-CPA notions to SIM-CCA/IND-CCA in the ROM, without Theorem 7's semi-malicious
  strengthening. Its hypotheses include a hiding, straightline-extractable binding commitment
  and a **SIMEXT NIPoR with a stateless tag-only extractor**; weak SIMEXT alone is not the stated
  hypothesis. Theorem 9 (§5.2, Fig. 10) supplies a candidate NIPoR construction from commitments
  and NIZKs with the specified extraction properties.

  For human-cryptographer sign-off, map the SHAKE-derived coins, ciphertext relation, and proof
  gate to that syntax and establish those security properties, as well as the underlying TPKE's
  CPA security in the paper's model (including partial-decryption queries and revealed randomness
  for non-challenge encryptions). Only after establishing the hypotheses and the correspondence
  to the transform could Theorem 10 support §7's currently "argued not proven" claim.

- **Status of this note.** This is external validation and a candidate proof route, **not** a proof:
  nobody has yet checked that libQ's specific SHAKE-in-STARK circuit satisfies their NIPoR syntax or
  the SIMEXT and extraction requirements of Theorem 10. It is a concrete input for the pending human-cryptographer
  sign-off on §7's conditional threshold IND-CCA statement (§8 item 4), not a resolution of it. No
  crate, parameter, wire format, or public API is touched by this note.

---

## 10. Related literature — eprint 2026/1627

Zhang, Zhou, Han, Liu, and Huang, "Adaptively Secure Threshold Decryption from LWE with Polynomial
Modulus" (Cryptology ePrint Archive, Report 2026/1627, https://eprint.iacr.org/2026/1627), resolves
an open problem of Devevey et al. [PKC 2021] — the same super-poly-vs-polynomial-modulus tradeoff
`SECURITY_ANALYSIS.md` and this document navigate for `lib-q-threshold-kem-lattice` — by giving three
non-interactive `(t,N)`-threshold-decryption schemes (TD0/TD1/TD2), all with polynomial modulus, that
are adaptively CCA-secure (TD1, TD2) or CPA-secure (TD0) against a partial-decryption-oracle adversary
that additionally corrupts up to `t-1` decryptors adaptively during the game — the same threat model
§1 states for this crate (static corruption here, not adaptive; see the caveat below).

- **Structural match to this crate's masked path.** TD2's partial decryption (their eq. 7),
  `h_i := λ_{i,S}·c^T sk_i + y_i + Δ_i` — Shamir shares, a polynomial noise term `y_i`, *and* a
  pairwise zero-sum mask `Δ_i` (Σ Δ_i = 0 over the combining set, cancelling at combine, their eq. 8)
  — is the same three-part shape as `threshold::partial_decap_masked`'s `value_i = λ_i·⟨rand(i),
  p⟩ + m_i + flood_i` (§1 here: `m_i` is this crate's zero-sum mask, `flood_i` its noise). This crate
  independently arrived at the TD2 architecture; eprint 2026/1627 is the first place a formal
  min-entropy bound for that combination (their Lemma 6, Subsect. 4.3) is derived rather than assumed.

- **Their Lemma 6 vs. this document's §3.** Lemma 6 bounds the average min-entropy of a share `sk_i`
  conditioned on `(A·sk_i, E·sk_i + y)` — a "matrix hint" `E` (the stacked LWE-error rows of every
  queried ciphertext) plus polynomial flooding `y` of norm `O(√ℓ)` for `ℓ` bounded queries — via
  Matrix-Hint LWE (their Def. 2, adapted from [56]). This is a **general, adversarially-chosen-`E`**
  version of exactly the argument §3 makes only for **honest, fresh, full-rank** `f^{(t)}`; §3 is
  explicit that this freshness premise is "exactly the premise a malformed ciphertext violates" — the
  premise their Lemma 6 does *not* need. Their bound is also explicitly cited as tighter than adapting
  prior entropy-analysis techniques (their Remark 1, Appendix B.2) — i.e., they are aware of and reject
  the more conservative alternative this document's heuristic-by-domination §3 argument resembles.

- **The load-bearing difference from the ruled-out §4.2 proof, and closure D.** TD1/TD2's CCA proof
  requires every ciphertext to carry a tag-based one-time-simulation-sound NIZK (OTSS-NIZK) proving
  `c` is an LWE sample *with an extractable witness* `(s, e)`, verified **before** any partial
  decryption is computed. §4.2 item 1 here rules out a norm-only *membership* proof precisely because
  it "does not commit to a unique decomposition" — a plain proof that *some* short `(e,f)` exists does
  not pin the encryptor's actual choice, so the coalition (as encryptor) can still submit its own
  `(e_adv, f_adv)` including a spike. An OTSS proof of *knowledge* is different: the reduction
  *extracts* the witness the adversary used, which is exactly what pins it to a specific `(s, e)` (their
  "Thirdly" proof step) — this is a **knowledge-sound** proof, not the membership proof §4.2 excludes.
  Composed with their Lemma 6, this gives a fourth candidate closure — **closure D** — lighter than
  closure A's SHAKE-in-STARK PoK of `μ` (it certifies the *LWE relation*, not correct derivation of
  `(e,f,g)` from `μ` via the XOF), and formal rather than closure C's bounded-but-unproven mitigation.
  §8 item 5 tracks scoping this.

- **Two concrete scoping gaps before closure D is actionable, not drop-in.**
  1. *Ring vs. plain LWE.* TD0/TD1/TD2 are built over **plain LWE**, not module/ring-LWE, because the
     paper states the only known standard-model OTSS-NIZK construction ([36], their §1) is LWE-based;
     they note "any future module-LWE-based OTSS-NIZK could be incorporated" but do not supply one.
     This crate is Module-LWE over `R_q = Z_q[X]/(X^1024+1)` (§1 here). Porting their OTSS-NIZK to this
     crate's ring setting is unsolved, not a citation away.
  2. *Sharing scheme.* TD1 (RSS, combining coefficients `λ_{i,S} = 1`) needs polynomial modulus **only
     for small `N`** — their own example is `N ≤ 16`, which happens to equal this crate's
     `PROFILE_MAX_PARTIES_V1` cap (`LIBQ_API.md` §2), but RSS is not this crate's sharing scheme: this
     crate (via `lib-q-dkg`) is `t`-of-`n` **Shamir**, matching TD2's sharing scheme, not TD1's.
     Adopting TD1 verbatim would mean replacing `lib-q-dkg`'s Shamir DKG with RSS — out of scope for a
     documentation note.

- **Adaptive vs. static corruption.** §1 here states this crate's threat model as **static**
  corruption of `t-1` parties. eprint 2026/1627's TD schemes are proven under **adaptive** corruption
  (§7 here does not currently claim this crate achieves that stronger notion at all, with or without
  closure A/D) — closure D would supply a formal *bound on the malformed-ciphertext-probe leakage*
  (§4), not by itself an upgrade from static to adaptive corruption security, which is a separate,
  unaddressed gap in this document.

- **Status of this note.** External validation and a fourth candidate closure, **not** a proof or an
  implementation. Nobody has checked TD1/TD2's OTSS-NIZK-plus-Lemma-6 construction against this crate's
  ring/Shamir setting, ported the OTSS-NIZK to Module-LWE, or re-derived Lemma 6's bound for this
  crate's specific `(q, N, MU, KAPPA)` parameters. It is input for the pending human-cryptographer
  sign-off (§8 item 4), not a resolution of it. No crate, parameter, wire format, or public API is
  touched by this note. Filed from the literature triage of eprint 2026/1627.
