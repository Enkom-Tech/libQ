/-!
# Gate E composition skeleton

The formal-verification programme's Gate E task (item 4) asks to "State SAT-JQPRF, nonce-respecting IND-qCPA, and 2025/387 Thm 3/4/Cor 1 as
explicit Lean axioms and hypotheses, then derive IND-qCCA[LoR] for the frozen CTR-Cascade syntax
(domains 1-5, padded terminal block, EtM over (N,A,C)). This mechanises the LOGIC of the
conditional sign-off, including the implementation-to-model mapping. It does not prove the quantum
assumptions themselves."

**Scope, precisely.** This file states four things as Lean `axiom`s — three published theorems
from Lang, Leuther and Lucks (*Generic Composition: From Classical to Quantum Security*, ePrint
2025/387, PQCrypto 2026: Theorem 3, Theorem 4, and their Corollary 1) plus one unproven
cryptographic assumption about Saturnin's own construction (`SAT-JQPRF`, the register's name for
"the Saturnin LWC spec §4.3.3 Song-Yun-derived qPRF claim for the CTR-Cascade MAC actually
discharges 2025/387's hypothesis" — `docs/crypto-signoff-register.md`, Gate E: "Whether Saturnin's
§4.3.3 argument actually discharges 2025/387's hypothesis is the open question, and nobody has
ratified it"). It then *derives* `IND-qCCA[LoR]` for the EtM composition from those four axioms by
plain propositional logic — no additional cryptographic content, and in particular Corollary 1
itself is derived from Theorem 3 + Theorem 4 rather than re-axiomatised, matching how 2025/387
actually proves it (§5, "Proof. [Theorem 4] ... Corollary 1 ... follows").

**What this is not.** `SAT-JQPRF` is stated as an axiom, i.e. assumed, not proved — proving it
needs a QROM/compressed-oracle argument for Saturnin's specific cascade MAC, which is exactly the
"not feasible yet" quantum game-based proof work the card's own top-level description defers (no
mature Lean quantum-game framework exists; see this file's README-level survey note (`formal/lean/README.md`)). Nothing
below discharges that obligation; it only makes precise **what would need to be true**, and shows
the composition logic that already goes through once it is.

**The frozen syntax.** `SaturninAead` (CTR-Cascade) is wire-frozen: `src/aead.rs` documents
"domains 1–5" for its cores and a padded terminal block; `src/aead_ctx.rs`/`SECURITY.md` describe
its `IND-qCCA` claim as Encrypt-then-MAC — the MAC covers `(N, A, C)`, i.e. `AuthE = F_L(E_K(M,N),
N, A)` in 2025/387's own EtM notation (Definition 3), generalised with associated data per its
§6. `CascadeCore`/`CascadeMac` below stand for that frozen `E`/`F` pair; this file does not model
their bytes (domains, padding, block layout) — only their *security-notion* interface, which is
all the composition logic needs. -/

namespace SaturninCTX.GateEComposition

/-- Opaque type of (nonce-based, deterministic) unauthenticated encryption schemes. Stands for
`SaturninAead`'s confidentiality-only core (CTR-Cascade proper, domains 1–5 plus the padded
terminal block, `src/aead.rs`) — the bytes are out of scope; only its `IND-qCPA[LoR]` status
matters below. -/
axiom Enc : Type

/-- Opaque type of (nonce-based, deterministic) MACs. Stands for the frozen construction's tag
step, which authenticates `(N, A, C)` — an Encrypt-then-MAC composition (2025/387 Definition 3,
`AuthE = F_L(E_K(M,N), N, A)`). -/
axiom Mac : Type

/-- Opaque type of (nonce-based) authenticated-encryption schemes: the composed result. -/
axiom AE : Type

/-- The Encrypt-and+then-MAC composition (2025/387, right of Fig. 1, `Construction 1` in
[CEV22a]): the MAC covers ciphertext *and* plaintext. Present only because Theorem 3 is stated for
it; Saturnin's frozen wire format is `EtM`, reached via `Thm4_EtM`/`Cor1_EtM` below. -/
axiom EatM : Enc → Mac → AE

/-- The Encrypt-then-MAC composition (2025/387 Fig. 1 / Definition 3): the MAC covers only the
ciphertext (here, generalised per 2025/387 §6 to `(N, A, C)`) — this is `SaturninAead`'s actual,
frozen wire shape. -/
axiom EtM : Enc → Mac → AE

/-- `IND-qCPA[LoR]` security (Boneh-Zhandry, restated 2025/387 Definition 5): chosen-plaintext
indistinguishability with quantum-superposition encryption queries and classical, left-or-right
challenge queries. -/
axiom INDqCPA_LoR : Enc → Prop

/-- `qPRF` security (Zhandry; 2025/387 Definition 1): indistinguishable from a uniform random
function against superposition queries — the *strongest* notion for a MAC in the Q2 setting, and
the hypothesis 2025/387's Theorem 1 shows the weaker "plus-one unforgeable" notion is *not*
sufficient to replace (disproving [SJS16]'s claim, which is what put Gate E's obligation Q-2 on
the register in the first place). -/
axiom QPRF : Mac → Prop

/-- `IND-qCCA[LoR]` security (2025/387 Definition 4, generalised to nonce-based AEAD with
associated data in §6): chosen-ciphertext indistinguishability with quantum-superposition
encryption *and* decryption queries, classical left-or-right challenge queries. This is the
property Gate E's blocking claim needs for `SaturninAead`. -/
axiom INDqCCA_LoR : AE → Prop

/-! ## The three published results, as axioms -/

/-- **2025/387 Theorem 3.** "The EatM composition of an IND-qCPA[LoR] secure symmetric encryption
scheme `SE` and a qPRF `F` (used as a MAC) is IND-qCCA[LoR] secure." (Proved there via their
Lemma 1 + Theorem 2, i.e. by reduction to Chevalier et al.'s stronger `qIND`-model result; not
re-derived here — this is the "does not prove the quantum assumptions themselves" boundary.) -/
axiom Thm3 (se : Enc) (f : Mac) : INDqCPA_LoR se → QPRF f → INDqCCA_LoR (EatM se f)

/-- **2025/387 Theorem 4** (§5.3): given an `IND-qCPA[LoR]`-secure `SE` and a `qPRF` `F`, the
`EatM`, `EtM` and `EaM` compositions of `SE` and `F` are equi-secure for `IND-qCCA[LoR]`. Stated
here as the two equivalences the EtM leg of Corollary 1 actually needs (the paper proves all three
pairwise; `EaM`'s is omitted as unused by Saturnin's frozen EtM wire format). -/
axiom Thm4_EtM (se : Enc) (f : Mac) :
    INDqCPA_LoR se → QPRF f → (INDqCCA_LoR (EatM se f) ↔ INDqCCA_LoR (EtM se f))

/-- **2025/387 Corollary 1**, *derived* (not re-axiomatised) from `Thm3` + `Thm4_EtM`, matching
the paper's own proof structure ("Proof. [Theorem 4] ... Corollary 1 ... follows"): "If the EatM
composition `AE₁` of `SE` and `F` is IND-qCCA[LoR] secure, then ... the EtM composition `AE₂` of
`SE` and `F` [is] also IND-qCCA[LoR] secure." -/
theorem Cor1_EtM (se : Enc) (f : Mac) (hcpa : INDqCPA_LoR se) (hqprf : QPRF f) :
    INDqCCA_LoR (EtM se f) :=
  (Thm4_EtM se f hcpa hqprf).mp (Thm3 se f hcpa hqprf)

/-! ## The Saturnin-specific assumptions -/

/-- The frozen `SaturninAead` (CTR-Cascade) confidentiality core: domains 1–5, padded terminal
block (`src/aead.rs`). Its bytes are out of scope here; it is named so the axioms below attach to
a specific term, not an arbitrary one. -/
axiom cascadeCore : Enc

/-- The frozen construction's MAC step, covering `(N, A, C)`. -/
axiom cascadeMac : Mac

/-- **Nonce-respecting `IND-qCPA[LoR]` of the Cascade core.** CTR-mode confidentiality under a
non-repeating nonce is the classically-established, unsurprising half of Gate E — Anand et al.
(cited by 2025/387 §1) show CTR-style modes achieve `IND-qCPA` when the underlying block cipher is
a (q)PRF, and this crate's own `SaturninAead` has "no cheap break found" on this front
(`README.md`'s CMT-1 table). Stated as an axiom because the block-cipher-level qPRF reduction for
Saturnin16 itself is, like `SAT-JQPRF` below, outside what this development re-derives — but unlike
`SAT-JQPRF`, the register does not list this as an open, disputed obligation. -/
axiom CascadeCore_INDqCPA : INDqCPA_LoR cascadeCore

/-- **`SAT-JQPRF`.** The register's name (libQ PR #76 sign-off) for: the Saturnin LWC spec's
§4.3.3 argument, citing Song-Yun (ePrint 2017/509) Theorem 5.1, establishes that `cascadeMac` is a
`qPRF`. This is exactly Gate E's open item: "Ratify or refute the citation swap. ... nobody has
ratified it" (`docs/crypto-signoff-register.md`). Stated here as an axiom, not proved — this file
mechanises what follows *if* it holds, which is the entire content of "signed conditional on
SAT-JQPRF". -/
axiom SAT_JQPRF : QPRF cascadeMac

/-! ## The conditional sign-off -/

/-- **Gate E, mechanised.** `IND-qCCA[LoR]` for `SaturninAead`'s frozen `EtM(CascadeCore,
CascadeMac)` syntax, conditional on `SAT_JQPRF` and `CascadeCore_INDqCPA`, via 2025/387's
Corollary 1. This is the logic PR #76 signed off on: remove `SAT_JQPRF` from the axiom list (by
actually proving it) and this theorem's premises are fully discharged; until then, every use of
this theorem — and every restatement of `SaturninAead`'s `IND-qCCA` claim anywhere in the repo —
inherits the same "conditional on SAT-JQPRF" caveat `scripts/ci-guard-standards-claims.sh` already
enforces textually. -/
theorem gate_e_cascade_INDqCCA : INDqCCA_LoR (EtM cascadeCore cascadeMac) :=
  Cor1_EtM cascadeCore cascadeMac CascadeCore_INDqCPA SAT_JQPRF

end SaturninCTX.GateEComposition
