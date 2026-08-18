# Radar triage: ePrint 2025/2099 — Lattice-based Designated-Verifier zkSNARK from Standard Assumptions

Board card `ENK-472` (project `iacr-radar`). Paper: *A Lattice-based Designated Verifier
zkSNARK from Standard Assumptions*, Ahmadi, Eghlidos, Abdolmaleki, Nguyen, IACR ePrint
2025/2099 (<https://eprint.iacr.org/2025/2099>). Radar relevance tag: "zero-knowledge
credentials" (high, conf 0.95).

This is a **triage note**, not a security claim. Everything below is either read out of the
paper / the tree (marked **VERIFIED**) or a fit judgement (marked **INFERRED**). Nothing here
has been reviewed by a cryptographer. No code changed on this branch.

## 1. What the paper is (VERIFIED — read end-to-end via the IACR reader)

A **designated-verifier** zkSNARK for R1CS whose only hardness assumption is **Module-SIS**.

- **Trapdoor-based Ajtai commitment (TACS, Alg. 3).** `Setup` runs `TrapGen` [MP12] `2k` times,
  splits each `A_i` into an upper/lower half, and keeps every gadget trapdoor `R_i`. `A_com`,
  `A_hide` are statistically uniform (Claim 1) so binding still reduces to MSIS and hiding to the
  regularity lemma — but the setup holder retains trapdoors. This is a **trusted setup**.
- **DV inner-product argument (`DV-LatticeIPA`, Alg. 7–9).** The verifier's secret key is a
  low-norm perturbation vector `p` plus Gaussian secrets `z_vsec, z_ksec`. Using `ChallTrap`
  (Alg. 5) + `Gaussian2Uniform` (Alg. 6, relies on `q ≡ 5 mod 8` and LPR13/FMN24 regularity),
  the verifier turns any target vector into a uniform-looking CRS challenge and checks
  `π_aux + ⟨p,c⟩ = (z_sec+1)·π_chall`. The prover never learns `z_sec`, so it cannot add a
  constant offset — this is the soundness core (Claim 2, Fig. 2).
- **Approximate range proof (Fig. 3, §4.3).** BL17/LNS21 adapted to `R_q`: `λ` binary challenge
  vectors `k_i ∈ cf⁻¹({0,1}^{2dnk})`, accept iff `‖π_chall,i + ⟨p,c⟩ − z_ksec,i·π_chall,1‖∞ < β_open/2`.
- **DV-zkSNARK (Alg. 12–14).** The LPCP compiler [ISW21] contributes a `Q_LPCP ∈ Z_q^{4×nk}`;
  its rows *replace* the range-check `k_i` and are hidden by the same challenge-randomisation, so
  **no homomorphic encryption is used** (this is the paper's headline efficiency lever). Witness /
  challenges cross the field↔ring boundary via the HSS24 ring–field isomorphism (`q ≡ 5 mod 8`).
- **Security (VERIFIED as stated, NOT independently checked):** completeness `1 − 2^-λ`;
  **adaptive** knowledge soundness via coordinate-wise special soundness (Lemma 11) with a
  **programmable random oracle** and an extractor that is *given the setup trapdoors* to rewind
  over the `U_chall/U_aux` challenges; HVZK (Lemma 12). Soundness is **ROM**, not QROM — the paper
  states the CWSS technique is "inherently confined to the random oracle model".

### Concrete numbers (VERIFIED — paper Table 2/3, §6; NOT reproduced here)

| Quantity | Value | Source |
|---|---|---|
| Assumption | Module-SIS, 128-bit (APS15 estimate) | Table 2 / §6 |
| Ring | `d = 16`, `q ≈ 2^32`, `q ≡ 5 mod 8` | Table 2 |
| Trapdoor dim / count | `n = 2,4,4` / `k = 2^9..2^11` | Table 2 |
| Witness length `N = nk` | `2^10 .. 2^13` | Table 2 |
| Norm bound `β_open` | `2^16` | Table 2 |
| Proof size | **20.75 KB** (≈ 2.5× LUNA's 8.3 KB) | Table 3 |
| Full CRS size | **1.3 GB** (≈ 10× smaller than LUNA's 11 GB) | Table 3 |
| Verifier complexity | `O(√N)` (vs LaBRADOR `O(N)`, LUNA `O(1)`) | Table 1 |
| Implementation | C, clang 14, builds on BEP+21 trapdoors; unaudited PoC | §6 |

The only prior scheme it compares against is LUNA [SSE+24]; every other lattice DV construction
in the family is broken (LOE, [DAFS24]) or non-standard (LTM).

## 2. Where libQ actually sits (VERIFIED — read out of the tree)

The relevant home is `lib-q-lattice-zkp` (module-lattice / BLNS-style anonymous credentials) and
the anon-cred wire work in `lib-q-zkp/docs/anon-cred-wire-fork-recommendation.md` (card `ENK-266`).

- **Transparent, publicly verifiable.** `lib-q-lattice-zkp` uses **uniform** Ajtai commitments and
  public-coin Fiat–Shamir Σ-protocols (`sigma/opening.rs`, `sigma/linear.rs` — `L·wit = t`,
  `sigma/norm.rs`, `sigma/hierarchical.rs`). Grepping the crate for `trapdoor|designated|SNARK|LPCP`
  returns **nothing**: there is no designated-verifier key and no trusted setup. README describes a
  "transparent … zero-knowledge stack".
- **Fiat–Shamir is QROM.** `DESIGN.md §2` / `SECURITY.md`: committed-first-message transform,
  security stated in the **quantum** ROM.
- **Wire budgets are tiny.** `README`/`DESIGN.md`: PVTN membership ≤ **4096 B**, presentation /
  token spend ≤ **125 KiB**; measured KATs 2558 B / 3977 B / 4009 B. Targets include WASM and
  `no_std`.
- **The anon-cred direction is already chosen.** `ENK-266`'s recommendation is
  **LNP22/ABDLOP for presentation (~29 KB) + LaBRADOR-class for membership (~7.56 KB)**; the
  transparent FRI/STARK arm (~1 MB) stays only as the merged Arm B membership proof. The doc
  already tracks N.K. Nguyen's line (FMN24 / GreyHound / LaBRADOR / LUNA).

## 3. Fit assessment (INFERRED — reasoned judgement)

Topically the paper lands squarely on-radar: it explicitly motivates DV-zkSNARKs with
**anonymous credentials** ([ADI25], §1), the exact domain of `lib-q-lattice-zkp`, and shares an
author with the literature libQ already tracks. But it is **not an adopt / implement candidate**
for the current direction, for four independent reasons:

1. **Trust-model mismatch.** The scheme is designated-verifier with a **trusted setup that retains
   gadget trapdoors and a secret verification key**. libQ's anon-cred *presentation* wire is
   publicly verifiable by any relying party and CRS-free. A DV scheme only fits a use case where a
   single secret-key holder does all verification (e.g. issuer-side verifiable computation), which
   libQ does not currently have on this path.
2. **Size incompatibility.** A **1.3 GB CRS** is a non-starter for libQ's WASM / embedded / `no_std`
   targets and dwarfs the 4 KB / 125 KiB wire budgets; the 20.75 KB proof is for a *general R1CS
   statement*, coarser than libQ's narrow per-relation Σ-proofs (~4 KB). The paper's headline win —
   10× smaller CRS by dropping homomorphic encryption — is **moot for libQ**, whose transparent Σ
   stack already has no CRS and no HE, so libQ is strictly ahead on that axis for its own relations.
3. **Maturity / assurance.** Unaudited academic PoC (C, single-machine, extrapolated benchmarks,
   circuits capped at `2^13`). libQ already labels its *own* lattice-zkp "research-grade …
   not independently audited"; importing a less-mature external construction would not clear the
   bar. Soundness is **ROM-only** and the extractor needs setup trapdoors — post-quantum adaptive
   soundness in the **QROM** (libQ's stated model) is not established here.
4. **No unmet need.** libQ's general-circuit proving is the transparent STARK stack (`lib-q-zkp`),
   publicly verifiable by design; its lattice path proves narrow credential relations. There is no
   open requirement for a general lattice **R1CS DV-SNARK**.

What *is* genuinely reusable is only confirmatory: the inner-product argument and the BL17/LNS21
approximate range proof (binary `{0,1}` challenge matrix, `‖MK‖∞ < β/2` check) are the same family
`sigma/norm.rs` / `sigma/linear.rs` already implement — evidence libQ is on the mainline, not a new
technique to import.

## 4. Recommendation (INFERRED)

**Track, do not action.** Close the radar item as *evaluated — not adopted*. It does **not**
displace the `ENK-266` recommendation (LNP22/ABDLOP + LaBRADOR): DV + 1.3 GB trusted-setup CRS is
the wrong trust and size model for a publicly-verifiable, budget-constrained presentation wire, and
it is an unaudited PoC.

Revisit **only** if libQ acquires a real **designated-verifier** use case — a single secret-key
verifier (issuer-side verifiable computation / private outsourced check) where a large one-time CRS
is acceptable and post-quantum public verifiability is *not* required. In that scenario the
CRS-free, HE-free inner-product + LPCP structure would be worth a second, deeper look, gated on an
independent proof review and a QROM-vs-ROM soundness reassessment.

## 5. Provenance — VERIFIED vs INFERRED

- **VERIFIED (read):** full text of 2025/2099 (abstract + Alg. 1–15, Lemmas/Claims, Tables 1–3,
  §6 evaluation) via the IACR reader; `lib-q-lattice-zkp` sources/README/DESIGN and
  `lib-q-zkp/docs/anon-cred-wire-fork-recommendation.md` in this tree; the `trapdoor|designated|
  SNARK|LPCP` grep over `lib-q-lattice-zkp` returning empty.
- **INFERRED (judgement):** §3 fit assessment, §4 recommendation, and the consequence claims
  (1.3 GB CRS incompatible with WASM/embedded; DV model vs public verifiability; does not displace
  ENK-266).
- **NOT done / out of scope:** I did **not** build or benchmark the external C PoC — the 20.75 KB /
  1.3 GB / timing figures are quoted from the paper, not independently reproduced. No security
  estimation (APS15 / lattice-estimator) was re-run. No libQ code changed, so no tests were run.
