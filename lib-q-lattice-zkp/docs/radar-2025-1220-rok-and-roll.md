# Radar triage: ePrint 2025/1220 — RoK and Roll: Verifier-Efficient Random Projection for Õ(λ)-size Lattice Arguments

Paper: *RoK and Roll — Verifier-Efficient Random
Projection for Õ(λ)-size Lattice Arguments*, Klooß, Lai, Nguyen, Osadnik, IACR ePrint 2025/1220
(<https://eprint.iacr.org/2025/1220>). Radar relevance tag: "Zero-knowledge & credentials"
(medium, conf 0.75).

This is a **triage note**, not a security claim. Everything below is either read out of the paper
or the tree (marked **VERIFIED**) or a fit judgement (marked **INFERRED**). Nothing here has been
reviewed by a cryptographer. No proving/verifying code changed on this branch.

## 1. What the paper is (VERIFIED — full version read via the IACR reader)

A **lattice-based SNARK** for bounded-norm linear relations `F·w = y mod q, ‖w‖ ≤ β` over a
cyclotomic ring `R = Z[ζ]`, where `F` carries a tensor structure and the witness `w ∈ R^m` can be
**arbitrarily large** (`m` is not fixed — it scales with the statement, e.g. a circuit trace or a
multilinear-polynomial evaluation table). The paper's headline result is the first construction to
break the `Õ(λ²)` proof-size barrier that every prior succinct (`poly(log m, λ)`-verifier) lattice
argument was stuck at, reaching `Õ(λ)` communication while keeping succinct verification. It targets
the **vanishing-SIS (vSIS) commitment-opening relation** [CLM23] and **multilinear polynomial
evaluation over `R_q`**, i.e. it is pitched as a building block for general-purpose SNARKs via the
Polynomial-IOP framework, not as a fixed-shape credential proof.

Two new reductions of knowledge do the work, layered onto the "split-and-fold" line
[FMN24,AFLN24,CMNW24,KLNO24] this paper calls RPS ("RoK, Paper, SISsors" [ASIACRYPT'24]):

- **Structured random projections (`Π_⊗RP`).** Replaces RPS's subtractive-set shortness proof
  (§1.1: cardinality-bounded challenge sets force `Ω(λ/log λ)` repetitions and hence `Õ(λ²)`) with a
  block-diagonal random projection `J = I ⊗ J'` that preserves the relation's tensor structure, so
  the verifier only ever processes the small `J'` block (`O(λ)` rows/cols), not the full witness.
  The projected image is committed and adjoined back into the same relation (`Π_join`) and folded
  recursively (`Π_norm → Π_b-decomp → Π_split → Π_⊗RP → Π_fold`) until the witness is down to
  `Θ̃(λ)` ring elements — independent of the original `m`.
- **Unstructured random projection + tower-of-rings lifting (`Π_RP`).** Below that size, the
  remaining `Θ(λ)`-element witness is projected LaBRADOR-style [BS23] over `Z_q` coefficients and
  sent in plain. The paper's actual new idea is *how* that `Z_q`-level claim gets lifted back into
  the `R_q` relation: instead of lifting directly (quadratic, as in [BS23]) or all at once, it
  batches-and-lifts through a tower `R = R_ℓ ⊃ R_ℓ₋₁ ⊃ ... ⊃ R_0 = Z`, using a shrinking
  batching-challenge count at each level (enabled by growing subfield sizes `F_{q^{e_i}}`), which
  is what brings total communication down from `Õ(λ²)` to `Õ(λ)`.

**Concrete numbers (VERIFIED, paper Fig. 1 / §1.2):** asymptotically `Õ(λ)` vs. `Õ(λ²)` for every
compared succinct-verifier scheme (`[CLM23,BCS23,BS23,FMN24,AFLN24,CMNW24,KLNO24]`); claimed **6×**
smaller concrete proofs at 128-bit security vs. the prior state of the art [KLNO24]. No reference
implementation is described or linked in the paper — this is an asymptotic/concrete-parameter
result, not a shipped library.

## 2. Where libQ actually sits (VERIFIED — read out of the tree, `origin/main` tip)

The relevant home is `lib-q-lattice-zkp` (module-lattice, BLNS-style anonymous credentials):

- **Transparent Fiat–Shamir Σ-protocols, not a SNARK.**
  `lib-q-lattice-zkp/src/lib.rs:1`: `"Module-lattice commitments, QROM Fiat–Shamir sigma
  protocols, and BLNS-style batching hooks."` The crate proves knowledge of an Ajtai-commitment
  opening and associated linear/norm relations directly via a committed-first-message Σ-protocol
  (`DESIGN.md` §2, `SECURITY.md` §"Random Oracle Model vs Quantum Random Oracle Model"); there is
  no recursive fold, no polynomial-IOP compiler, and no split-and-fold RoK chain anywhere in the
  crate. `git grep -niE 'reduction of knowledge|split-and-fold|RoK\b'` over `lib-q-lattice-zkp`
  returns nothing.
- **Witness dimension is small and fixed, not `m`-scaling.** `src/params.rs`:
  `AjtaiParameters { module_rank, randomness_dimension }`, `witness_len() = module_rank +
  randomness_dimension`. The frozen wire v0 profiles (`DESIGN.md` §8, `src/profile.rs`) instantiate
  this at `(k, l) = (1, 1)` for PVTN membership and `(2, 1)` for token spend / selective disclosure
  — i.e. **2–3 ring elements**, a small constant, independent of any circuit or trace size. There is
  no relation in this crate whose witness length is a free asymptotic parameter `m` the way
  RoK-and-Roll's core relation `Ξ_lin` is.
- **Byte budgets are already small, and already met.** README.md: *"Byte budgets: PVTN membership
  ≤ 4096 B; presentation / token spend ≤ 125 KiB."* DESIGN.md §10: measured KATs are **2558 B**
  (PVTN, budget 4096 B), **3977 B** (token opening), **4009 B** (spending, budget 131072 B) — all
  comfortably inside budget today, with a direct (non-recursive) Σ-protocol.
- **"Structured linear relations" mapped onto crate files.** RoK-and-Roll's target relation family
  (bounded-norm, tensor-structured `F·w = y mod q`) is the same *assumption family* — Module-SIS
  binding, short-witness linear relations over `R_q` — as what this crate already proves directly,
  file-for-file:
  - `src/sigma/opening.rs` — Ajtai-commitment opening (`Π_split`'s base case: `A·(r‖m) = com`).
  - `src/sigma/linear.rs` — general `L·wit = t` linear relations (the crate's `Ξ_lin` analogue).
  - `src/sigma/norm.rs` — infinity-norm / shortness certificates (the crate's "shortness proof",
    the exact problem RoK-and-Roll's random projections target, solved here instead via a
    CRT-packed norm certificate, not a projection-and-fold chain).
  - `src/sigma/accumulator.rs`, `src/sigma/hierarchical.rs` — Merkle-membership relations, the
    closest thing this crate has to a "large structured relation" (depth-capped at 16, i.e. at most
    a few dozen ring elements on the authentication path — still `O(1)` in the RoK-and-Roll sense).
  - `src/sigma/amortise.rs` — batches a handful of independent per-attribute Σ-proofs (measured for
    a 3-attribute ≤ 125 KiB CI scenario, `DESIGN.md` §10) via a single linear-combination challenge;
    this is *aggregation* of many small proofs, not one large structured witness, so it does not
    match RoK-and-Roll's `Ξ_lin` setting either.
- **Maturity.** `README.md` "Status": *"Research-grade / pre-standard, not independently audited."*
  `SECURITY.md`: *"no published third-party security audit of the full workspace."*

## 3. Fit assessment (INFERRED — reasoned judgement)

RoK-and-Roll is topically on-radar — same assumption family (Module-SIS-hard bounded-norm linear
relations over a cyclotomic ring) and the same design lineage (LaBRADOR/BS23, which
`lib-q-lattice-zkp`'s Σ-protocols and this radar area already track via
`docs/radar-2025-2099-dv-zksnark.md` and `docs/radar-2026-1003-hidden-attr-access-control.md`) —
but it is **not an adopt / implement candidate today**, for a scale-and-purpose mismatch rather than
an assumption or relation-class mismatch:

1. **Wrong regime.** RoK-and-Roll's entire contribution is an asymptotic improvement,
   `Õ(λ²) → Õ(λ)`, that only shows up once the witness dimension `m` is large enough that a
   direct/linear-in-`m` proof would dominate proof size — its own comparison table (Fig. 1) is
   against schemes built for verifiable computation over large statements. `lib-q-lattice-zkp`'s
   relations have `witness_len() ∈ {2, 3}` ring elements (`src/params.rs`, `src/profile.rs`); at
   that size a direct Σ-protocol (what the crate already does) is already asymptotically and
   concretely smaller than paying the fixed `O(λ)`-scale overhead of a random-projection-and-fold
   RoK chain (`Π_⊗RP`/`Π_RP` both require `n_rp = Ω(λ)` projection rows *before* any compression
   pays off — the paper's own "limits of structured foldability" discussion, §2.2). Adopting it
   here would trade a working, budget-compliant 2.5–4 KB proof for new machinery whose crossover
   point the crate never reaches.
2. **No general-witness / large-`m` use case in this crate to feed it.** `DESIGN.md` §7
   ("Non-goals") already excludes replacing the STARK stack (`lib-q-zkp`) with lattice relations;
   `lib-q-lattice-zkp` proves narrow, per-credential relations by design, not general
   R1CS/circuit-trace statements. RoK-and-Roll's multilinear-polynomial-commitment application
   (its stated Polynomial-IOP/SNARK use case) has no counterpart to plug into here.
3. **No artifact, high integration cost.** The paper is asymptotic/parameter-level (Fig. 1, Table 2
   referenced but not reproduced here) with no reference implementation; the tower-of-rings lifting
   and structured/unstructured projection recursion (§2.2–2.4) is materially more complex than the
   crate's current direct Σ-protocol layer, for a crate already scoped as "research-grade,
   not independently audited" — raising, not lowering, the audit burden for no measured benefit at
   this crate's witness sizes.

This does **not** displace anything: it is a different point in the design space (asymptotically
succinct SNARK for large structured witnesses) from what `lib-q-lattice-zkp` builds (small
fixed-shape credential Σ-proofs), and it does not change the QROM Fiat–Shamir security model this
crate already commits to.

## 4. Recommendation (INFERRED)

**Track, do not action.** Close the radar item as *evaluated — not adopted*. Revisit only if libQ
takes on a genuinely large-witness lattice-SNARK use case this crate does not have today — e.g. a
general-circuit / large-batch multilinear polynomial commitment scheme built on Module-SIS — at
which point RoK-and-Roll's `Õ(λ)` structured+unstructured projection chain (and its RPS
predecessor) would be the state of the art to build on, gated on an independent proof review (the
construction is very recent, unimplemented, and has not had time to accumulate cryptanalysis).

## 5. Provenance — VERIFIED vs INFERRED

- **VERIFIED (read):** full text of ePrint 2025/1220 (Abstract, §1 Introduction incl. Fig. 1
  comparison table, §2 Technical Overview §2.1–2.4) via the IACR reader; `lib-q-lattice-zkp`
  `src/lib.rs`, `README.md`, `DESIGN.md`, `SECURITY.md`, `src/params.rs`, `src/profile.rs`,
  `src/budget.rs`, `src/sigma/mod.rs`, `src/sigma/linear.rs`, `src/sigma/amortise.rs` on this tree
  at `origin/main` tip; the `2025/1220|RoK and Roll` and `reduction of knowledge|split-and-fold|
  RoK\b` greps over `lib-q-lattice-zkp` both returning empty (positive controls proving this
  section is new, not pre-existing).
- **INFERRED (judgement):** §3 fit assessment and §4 recommendation, including the "wrong regime"
  crossover argument (that the crate's `O(1)`-sized witnesses never reach the point where
  RoK-and-Roll's asymptotic win pays for its overhead) and the "does not displace anything"
  conclusion.
- **NOT done / out of scope:** did not reproduce or re-derive any of the paper's proofs
  (Johnson–Lindenstrauss-based correctness argument, extraction/soundness reductions, the tower-of-
  rings batching bound) or its concrete parameter tables (Table 2, referenced but not transcribed
  here) — nothing here is a cryptanalytic review. No libQ code changed, so no tests were run.

Verdict: INFORMATIONAL
