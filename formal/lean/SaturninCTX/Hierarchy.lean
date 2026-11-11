/-!
# Bellare-Hoang committing-AE hierarchy (Appendix A)

The formal-verification programme's Gate D task (item 1, second part) asks to "prove ... the Bellare-Hoang Appendix A implications that are
used: CMTD-3/4 to CMT-3/4 by correctness, then CMT-1."

Source: Bellare and Hoang, *Efficient Schemes for Committing Authenticated Encryption*, EUROCRYPT
2022 / IACR ePrint 2022/268, §3 ("Committing AE Framework") and Appendix A ("Relations Among
Committing Notions"). This is the *general* framework paper (`commit.rs`'s S-2 obligation cites its
Appendix A by page number: "Its Appendix A (p.33) proves `CMT-3 ⇒ CMT-4` from the correctness
requirement and the determinism of `SE.Dec` alone"). It predates Chan-Rogaway's CTX and is not
about CTX specifically; it is the source of the `CMT-ℓ`/`CMTD-ℓ` notions and their relations.

Definitions (paper Fig. 4, specialised to `ℓ ∈ {1, 3, 4}`, the only levels the paper uses):
* `CMT-ℓ`  — the adversary presents two full encryption inputs; wins if their ciphertexts collide
  and their `WiCℓ`-projections differ. `WiC1 = K`, `WiC3 = (K,N,A)`, `WiC4 = (K,N,A,M)`.
* `CMTD-ℓ` — the "decryption-based" variant: the adversary presents a single ciphertext `C` plus
  two full `(K,N,A,M)` tuples, and wins if `C` decrypts to each `M` under its own `(K,N,A)` and the
  `WiCℓ`-projections differ. Unlike `CMT-ℓ`, `C` need not come from `Enc` at all.

Below, each Bellare-Hoang "`X → Y`" heading (read "`X`-secure implies `Y`-secure", their own
convention, Introduction: "Clearly CMT-4 → CMT-1, meaning any scheme that is CMT-4-secure is also
CMT-1-secure") is mechanised as its *contrapositive*: a witness breaking `Y` is turned into a
witness breaking `X`. That is the actual constructive content of every proof in their Appendix A
(none of them touch probability; every one repackages, or lightly reasons about, a winning tuple).
`Secure`-level corollaries follow immediately.
-/

namespace SaturninCTX.Hierarchy

variable {K N A M C : Type}

/-- Correctness: decryption reverses encryption (Bellare-Hoang §2). -/
def Correct (Enc : K → N → A → M → C) (Dec : K → N → A → C → Option M) : Prop :=
  ∀ k n a m, Dec k n a (Enc k n a m) = some m

/-- Tidiness (Bellare-Hoang §2, citing Rogaway-Shrimpton): every ciphertext that decrypts
successfully is the canonical encryption of the message it decrypts to. Only needed for the
"gray arrow" `CMT-ℓ → CMTD-ℓ` below — **not** used by `SaturninCTX.Binding.binding_direct`, and
`SaturninCTX.QcbTidiness` shows it fails for `SaturninQcb`. -/
def Tidy (Enc : K → N → A → M → C) (Dec : K → N → A → C → Option M) : Prop :=
  ∀ k n a c m, Dec k n a c = some m → Enc k n a m = c

/-! ## Winning instances -/

/-- A `CMT-1` win: two full encryption inputs with distinct keys, colliding ciphertexts. -/
def CMT1Wins (Enc : K → N → A → M → C)
    (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  k₁ ≠ k₂ ∧ Enc k₁ n₁ a₁ m₁ = Enc k₂ n₂ a₂ m₂

/-- A `CMT-3` win: distinct `(K,N,A)`, colliding ciphertexts. -/
def CMT3Wins (Enc : K → N → A → M → C)
    (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  (k₁, n₁, a₁) ≠ (k₂, n₂, a₂) ∧ Enc k₁ n₁ a₁ m₁ = Enc k₂ n₂ a₂ m₂

/-- A `CMT-4` win: distinct full `(K,N,A,M)` tuples, colliding ciphertexts. -/
def CMT4Wins (Enc : K → N → A → M → C)
    (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  (k₁, n₁, a₁, m₁) ≠ (k₂, n₂, a₂, m₂) ∧ Enc k₁ n₁ a₁ m₁ = Enc k₂ n₂ a₂ m₂

/-- A `CMTD-1` win: a single ciphertext `c` decrypting to both messages, under distinct keys. -/
def CMTD1Wins (Dec : K → N → A → C → Option M)
    (c : C) (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  k₁ ≠ k₂ ∧ Dec k₁ n₁ a₁ c = some m₁ ∧ Dec k₂ n₂ a₂ c = some m₂

/-- A `CMTD-3` win: a single ciphertext decrypting under two distinct `(K,N,A)`. -/
def CMTD3Wins (Dec : K → N → A → C → Option M)
    (c : C) (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  (k₁, n₁, a₁) ≠ (k₂, n₂, a₂) ∧ Dec k₁ n₁ a₁ c = some m₁ ∧ Dec k₂ n₂ a₂ c = some m₂

/-- A `CMTD-4` win: a single ciphertext decrypting under two distinct full `(K,N,A,M)` tuples. -/
def CMTD4Wins (Dec : K → N → A → C → Option M)
    (c : C) (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M) : Prop :=
  (k₁, n₁, a₁, m₁) ≠ (k₂, n₂, a₂, m₂) ∧ Dec k₁ n₁ a₁ c = some m₁ ∧ Dec k₂ n₂ a₂ c = some m₂

/-- No adversary produces a `CMT-ℓ`-winning instance (`ℓ` fixed by which `Wins` predicate is
supplied). -/
def CMTSecure (Wins : K → N → A → M → K → N → A → M → Prop) : Prop :=
  ¬ ∃ (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M),
      Wins k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂

/-- No adversary produces a `CMTD-ℓ`-winning instance for any ciphertext `c`. -/
def CMTDSecure (Wins : C → K → N → A → M → K → N → A → M → Prop) : Prop :=
  ¬ ∃ (c : C) (k₁ : K) (n₁ : N) (a₁ : A) (m₁ : M) (k₂ : K) (n₂ : N) (a₂ : A) (m₂ : M),
      Wins c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂

variable {Enc : K → N → A → M → C} {Dec : K → N → A → C → Option M}
variable {k₁ k₂ : K} {n₁ n₂ : N} {a₁ a₂ : A} {m₁ m₂ : M}

/-! ## The "leftward arrows are trivial" (Appendix A, opening line)

`WiC1` differing (`k₁ ≠ k₂`) already certifies `WiC3` and `WiC4` differing (the full tuples must
differ wherever `k` does), so a `CMT-1`/`CMTD-1` win is *automatically* a `CMT-3`/`CMT-4` (resp.
`CMTD-3`/`CMTD-4`) win with the very same witness — no correctness, no tidiness, nothing beyond
`Prod` extensionality. -/

theorem cmt3_wins_of_cmt1_wins (h : CMT1Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT3Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨fun heq => h.1 (congrArg Prod.fst heq), h.2⟩

theorem cmt4_wins_of_cmt1_wins (h : CMT1Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT4Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨fun heq => h.1 (congrArg Prod.fst heq), h.2⟩

theorem cmtd3_wins_of_cmtd1_wins {c : C} (h : CMTD1Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD3Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨fun heq => h.1 (congrArg Prod.fst heq), h.2.1, h.2.2⟩

theorem cmtd4_wins_of_cmtd1_wins {c : C} (h : CMTD1Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD4Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨fun heq => h.1 (congrArg Prod.fst heq), h.2.1, h.2.2⟩

/-! ## `CMTD-3 → CMTD-4` (Appendix A, first result)

Paper: "Suppose `A` is an adversary that violates CMTD-4 ... If `(K₁,N₁,A₁) ≠ (K₂,N₂,A₂)` then `A`
violates CMTD-3 ... so suppose `(K₁,N₁,A₁) = (K₂,N₂,A₂)`. But since `SE.Dec` is deterministic it
must be that `SE.Dec(K₁,N₁,A₁,C) = SE.Dec(K₂,N₂,A₂,C)`, meaning `M₁ = M₂` ... which contradicts our
assumption." `Dec` is a plain Lean function, so "deterministic" needs no hypothesis: it is
definitional. -/

theorem cmtd3_wins_of_cmtd4_wins {c : C} (h : CMTD4Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD3Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ := by
  refine ⟨fun heq => h.1 ?_, h.2.1, h.2.2⟩
  simp only [Prod.mk.injEq] at heq
  obtain ⟨hk, hn, ha⟩ := heq
  have hm : m₁ = m₂ := by
    have h1 := h.2.1
    rw [hk, hn, ha, h.2.2] at h1
    exact (Option.some.inj h1).symm
  simp only [Prod.mk.injEq]
  exact ⟨hk, hn, ha, hm⟩

/-! ## `CMT-3 → CMT-4` (Appendix A, second result)

Same shape, using `Correct` in place of raw `Dec`-determinism to recover `M₁`/`M₂` from the
colliding ciphertext. -/

theorem cmt3_wins_of_cmt4_wins (hcorrect : Correct Enc Dec)
    (h : CMT4Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT3Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ := by
  refine ⟨fun heq => h.1 ?_, h.2⟩
  simp only [Prod.mk.injEq] at heq
  obtain ⟨hk, hn, ha⟩ := heq
  have hm : m₁ = m₂ := by
    have hd1 := hcorrect k₁ n₁ a₁ m₁
    have hd2 := hcorrect k₂ n₂ a₂ m₂
    rw [h.2, hk, hn, ha] at hd1
    rw [hd1] at hd2
    exact Option.some.inj hd2
  simp only [Prod.mk.injEq]
  exact ⟨hk, hn, ha, hm⟩

/-! ## `CMTD-ℓ → CMT-ℓ` (Appendix A, third result) — **exactly the step the card names**

Paper: "Let `Ae` be an adversary attacking `CMT-ℓ`. We build `Ad` attacking `CMTD-ℓ` as follows.
`Ad` runs `((K₁,N₁,A₁,M₁),(K₂,N₂,A₂,M₂)) ← Ae`, sets `C₁ ← SE.Enc(K₁,N₁,A₁,M₁)`, returns
`(C₁, tuple₁, tuple₂)`. ... If `Ae` wins then `C₁ = C₂`, meaning `M₂ = SE.Dec(K₂,N₂,A₂,C₁)`, and
thus `Ad` also wins." This is `CMT-ℓ`-attack ⟹ `CMTD-ℓ`-attack (using only `Correct`), whose
contrapositive is the security statement in the heading: `CMTD-ℓ`-secure ⟹ `CMT-ℓ`-secure. -/

theorem cmtd1_wins_of_cmt1_wins (hcorrect : Correct Enc Dec)
    (h : CMT1Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD1Wins Dec (Enc k₁ n₁ a₁ m₁) k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, hcorrect k₁ n₁ a₁ m₁, h.2 ▸ hcorrect k₂ n₂ a₂ m₂⟩

theorem cmtd3_wins_of_cmt3_wins (hcorrect : Correct Enc Dec)
    (h : CMT3Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD3Wins Dec (Enc k₁ n₁ a₁ m₁) k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, hcorrect k₁ n₁ a₁ m₁, h.2 ▸ hcorrect k₂ n₂ a₂ m₂⟩

theorem cmtd4_wins_of_cmt4_wins (hcorrect : Correct Enc Dec)
    (h : CMT4Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMTD4Wins Dec (Enc k₁ n₁ a₁ m₁) k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, hcorrect k₁ n₁ a₁ m₁, h.2 ▸ hcorrect k₂ n₂ a₂ m₂⟩

/-- Security corollary: `CMTD-3`-secure `⟹` `CMT-3`-secure, via correctness. First half of the
card's "CMTD-3/4 to CMT-3/4 by correctness". -/
theorem cmt3_secure_of_cmtd3_secure (hcorrect : Correct Enc Dec)
    (hsecure : CMTDSecure (CMTD3Wins Dec)) : CMTSecure (CMT3Wins Enc) := by
  rintro ⟨k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, hw⟩
  exact hsecure ⟨_, k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, cmtd3_wins_of_cmt3_wins hcorrect hw⟩

/-- Security corollary: `CMTD-4`-secure `⟹` `CMT-4`-secure, via correctness. Second half of "CMTD-
3/4 to CMT-3/4 by correctness". -/
theorem cmt4_secure_of_cmtd4_secure (hcorrect : Correct Enc Dec)
    (hsecure : CMTDSecure (CMTD4Wins Dec)) : CMTSecure (CMT4Wins Enc) := by
  rintro ⟨k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, hw⟩
  exact hsecure ⟨_, k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, cmtd4_wins_of_cmt4_wins hcorrect hw⟩

/-! ## `CMT-ℓ → CMTD-ℓ` for tidy schemes (Appendix A, fourth result) — the "gray arrow"

Paper: "Suppose that SE is tidy. Let `Ad` be an adversary attacking CMTD-ℓ. We build `Ae` attacking
CMT-ℓ ... If `Ad` wins then `Mi = SE.Dec(Ki,Ni,Ai,C)` for each `i`. From the tidiness of SE, this
means that `C = SE.Enc(Ki,Ni,Ai,Mi)` ... and thus `Ae` also wins." Included for a faithful, full
mechanisation of Appendix A's four results; **not** used by `SaturninCTX.Binding.binding_direct`,
and `SaturninCTX.QcbTidiness` shows its hypothesis fails for `SaturninQcb`. -/

theorem cmt1_wins_of_cmtd1_wins (htidy : Tidy Enc Dec) {c : C}
    (h : CMTD1Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT1Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, (htidy k₁ n₁ a₁ c m₁ h.2.1).trans (htidy k₂ n₂ a₂ c m₂ h.2.2).symm⟩

theorem cmt3_wins_of_cmtd3_wins (htidy : Tidy Enc Dec) {c : C}
    (h : CMTD3Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT3Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, (htidy k₁ n₁ a₁ c m₁ h.2.1).trans (htidy k₂ n₂ a₂ c m₂ h.2.2).symm⟩

theorem cmt4_wins_of_cmtd4_wins (htidy : Tidy Enc Dec) {c : C}
    (h : CMTD4Wins Dec c k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂) :
    CMT4Wins Enc k₁ n₁ a₁ m₁ k₂ n₂ a₂ m₂ :=
  ⟨h.1, (htidy k₁ n₁ a₁ c m₁ h.2.1).trans (htidy k₂ n₂ a₂ c m₂ h.2.2).symm⟩

/-! ## The composed chain: "CMTD-3/4 to CMT-3/4 by correctness, then CMT-1"

Exactly the sentence in the card. Chains the `CMTD-4 → CMT-4` step above with the trivial
`CMT-4 → CMT-1` step (`cmt4_wins_of_cmt1_wins`'s contrapositive) to get `CMTD-4`-secure `⟹`
`CMT-1`-secure — the published justification, in full, for treating `SaturninQcb`/
`SaturninAeadCtx`'s direct binding argument (`Binding.binding_direct`, which needs none of this
machinery) as at least as strong as anything this hierarchy could have offered. -/

theorem cmt1_secure_of_cmtd4_secure (hcorrect : Correct Enc Dec)
    (hsecure : CMTDSecure (CMTD4Wins Dec)) : CMTSecure (CMT1Wins Enc) := by
  rintro ⟨k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, hw⟩
  have hw4 := cmt4_wins_of_cmt1_wins hw
  exact hsecure ⟨_, k₁, n₁, a₁, m₁, k₂, n₂, a₂, m₂, cmtd4_wins_of_cmt4_wins hcorrect hw4⟩

end SaturninCTX.Hierarchy
