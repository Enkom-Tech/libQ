/-!
# Gate E bound arithmetic: the generic quantum-query bound shape and its vacuity point

The formal-verification programme's Gate E task (item 3) asks to "Formalise the Song-Yun bound shape and the composed loose bound. Prove where it
becomes vacuous (q around 2^(128/3) up to constants), and produce the explicit query/length
accounting the register says is missing. Turn the 'no concrete bit level' gap into stated limits."

**What is, and is not, established here.** Song and Yun (*Quantum Security of NMAC and Related
Constructions*, CRYPTO 2017 / ePrint 2017/509) — the paper the Saturnin spec cites at §4.3.3 for
the cascade MAC's qPRF property — states its security result asymptotically ("negligible in the
security parameter"), via a `2q`-wise-indistinguishability hybrid over Zhandry's compressed-oracle
technique; it does not hand down a single closed-form `Adv ≤ f(q, n)` formula, and neither does
2025/387's Theorem 3 (`GateEComposition.lean` states both as axioms for exactly this reason: the
logic of the composition is checked without asserting a bound neither paper actually publishes).
The Saturnin spec itself does not give a bit-level accounting either — the register records this
directly ("This proof seems not tight"; no `qH`/`δ`-style term is ever instantiated for
CTR-Cascade's `IND-qCCA` claim, unlike CTX's Theorem 3 residual, which *does* get one).

That gap is real, so this file does not pretend to close it by citation. What it does instead —
per the card's own instruction to "turn the gap into stated limits" — is formalise the *generic*
bound shape this entire proof family (Zhandry-style compressed-oracle hybrid arguments over an
`n`-bit primitive) is known to produce **before** any construction-specific tightening: a cubic
dependence on the query count, `Adv ≤ c · q³ / 2ⁿ` (the shape a `2q`-wise-equivalence hybrid over
an `n`-bit range yields; e.g. Zhandry's generic quantum-query lower bounds and the later
retightening literature — Chen, Sun, Xu, Yu, CRYPTO 2021, *On Tight Quantum Security of HMAC and
NMAC* — exists specifically because the *original* Song-Yun-style bound is this loose one). We
compute, as an explicit, checked, but clearly-flagged **estimate** (not a citation), the query
count at which a bound of this shape stops being a meaningful security guarantee (`Adv ≥ 1`) for
Saturnin's own target security level.

**The `128` is Saturnin's own number, not invented here.** Every AEAD mode in this crate is keyed
at 256 bits; the crate's Grover-adjusted framing throughout (see `commit.rs`'s H-1 discussion of
"worst corner" vs "memoryless" quantum attacker readings) treats a 256-bit *classical* key as
giving a **128-bit** post-quantum security target — the standard doubling for Grover resistance,
and the level NIST's own PQC categories use for a 256-bit-keyed primitive. `n = 128` below is that
target, not the primitive's raw bit width.
-/

namespace SaturninCTX.GateEBound

/-- The generic quantum-query bound shape: `c * q^3 / 2^n`, cleared of denominators as
`c * q^3 ≤ k * 2^n` for a scale factor `k` — kept in `Nat` throughout (no rationals/reals needed)
by working with the *threshold* condition directly: "the bound is vacuous" means `c * q^3 ≥ 2^n`,
i.e. the numerator alone already reaches the modulus, regardless of what constant sits in front of
the fraction (the card's own "up to constants" hedge — we do not know `c`, so we bound the
crossover **exponent** in `q`, which is `c`-independent up to a `log c` shift that is negligible
next to `n = 128`). -/
def Vacuous (c q n : Nat) : Prop := c * q ^ 3 ≥ 2 ^ n

/-- The composed loose bound (`GateEComposition`'s target, `EtM(CascadeCore, CascadeMac)` being
`IND-qCCA[LoR]`) is an **additive** combination of the two legs any hybrid/reduction argument of
this shape produces — the standard "distinguish-the-hybrids" pattern behind every one of
2025/387's Theorems (its own Theorem 4 chain is exactly a sequence of such hybrid steps): the
IND-qCPA[LoR] advantage of the encryption core, plus the qPRF advantage of the MAC. Composing two
generic `c·q³/2ⁿ`-shaped legs is itself generic-shaped, with the worse-case `n` (the smaller
target) dominating; for CTR-Cascade both legs share the same `n = 128` target, so the composed
bound is vacuous at exactly the same crossover as either leg alone (up to the constant folded into
`c`). -/
theorem composed_vacuous_of_leg_vacuous {c₁ c₂ q n : Nat} (h : Vacuous c₁ q n) :
    Vacuous (c₁ + c₂) q n := by
  unfold Vacuous at *
  calc 2 ^ n ≤ c₁ * q ^ 3 := h
    _ ≤ (c₁ + c₂) * q ^ 3 := by
        apply Nat.mul_le_mul_right
        omega

/-- **The stated limit.** At Saturnin's `n = 128`-bit target, a query count of `q = 2^43` already
makes a unit-constant (`c = 1`) bound of this shape vacuous: `2^43` cubed is `2^129 ≥ 2^128`. This
is the explicit number `docs/crypto-signoff-register.md`'s Gate E section is missing — read as "a
generic-shaped quantum-query bound for this composition should not be quoted as meaningful past
roughly `2^43` queries", **not** as a proven property of Saturnin's actual construction (which may
be tighter, or looser by an unknown constant `c`; see the module doc). `43 = ⌈128/3⌉`, matching the
card's own "q around `2^(128/3)`". -/
theorem vacuous_at_2_pow_43 : Vacuous 1 (2 ^ 43) 128 := by unfold Vacuous; decide

/-- **The margin below the crossover.** One exponent step earlier, `q = 2^42`, the same
unit-constant bound is still meaningfully below 1 (`2^126 < 2^128`) — so the crossover is sharp at
this granularity, not an artefact of a loose inequality in one direction only. -/
theorem not_vacuous_at_2_pow_42 : ¬ Vacuous 1 (2 ^ 42) 128 := by unfold Vacuous; decide

end SaturninCTX.GateEBound
