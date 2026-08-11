//! `LatticeCheckAir` — the design's R3 AIR (`ENCRYPTION_PROOF_DESIGN.md` §2 table row: *"R3:
//! `p = B0ᵀe+f`, `v = ⟨t0,e⟩+g+encode(μ)` via random Z_q folding"*, and §6's `prove_batch` list
//! `[ShakeSpongeAir, SamplerAir, LatticeCheckAir]`).
//!
//! # Status (read before trusting the design doc's §4/§7 text verbatim)
//!
//! The design doc's §4.1–§4.3 fold (a polynomial-divisibility check with prover-witnessed quotients
//! `H_k`/`H'`, "Correction 2026-07-10, during R3 build") was **superseded** (card `t_a73aaed2`) — see
//! [`crate::relation_assembly`]'s module doc for the full story. In one line: evaluating a
//! `Z_q[X]/(X^N+1)` identity at a scalar Fiat–Shamir point `ζ` is a ring homomorphism only when
//! `ζ^N = −1`; for a generic `ζ` the reduction needs a quotient `H` that is *free* (prover-chosen,
//! committed after `ζ` is fixed), so the prover can always solve `H(ζ) := D(ζ)/(ζ^N+1)` and the check
//! is **vacuous**. Confirmed by exploit at every tier, including production FRI params. The design
//! doc's own §7 status table ("`LatticeCheckAir`: designed, not yet built") and §4 text are **STALE**
//! against that fix and against the arithmetic that was actually built afterward.
//!
//! The relation now proven is the random **additive functional** fold: test the already-reduced
//! residual `D ∈ R_q` (e.g. `D_{p_k} = Σ_r B0_{r,k}·e_r + f_k − p_k`) via `⟨D, κ⟩ = 0` for a
//! statement-derived `κ ∈ Z_q^N`. [`crate::relation_assembly::corr_negacyclic`] turns this into a
//! **public-coefficient-linear** form in the witness (no quotient anywhere), which
//! [`crate::zq::RelationCheckAir`] proves as the canonical scalar equation
//! `Σ_j a_j·w_j + c ≡ 0 (mod q)`. That AIR (§4.3c of the design doc) is **BUILT, independently
//! reviewed SOUND, and fuzzed** (`zq::tests::relation_check_*`, `fuzz::fuzz_relation_check_air`).
//!
//! `LatticeCheckAir` is the literal name the design's AIR table and `prove_batch` list use for this
//! role. This module supplies that name as a **thin newtype** over [`RelationCheckAir`], specialized
//! to the two term-count shapes `encryption_proof.rs` already instantiates for R3a/R3b
//! (`R3A_TERMS = MU + KAPPA`, `R3B_TERMS = MU + 2`, mirrored here as [`LatticeCheckAir::r3a`] /
//! [`LatticeCheckAir::r3b`]). It adds **no new constraint arithmetic** — duplicating the reviewed and
//! fuzzed `RelationCheckAir` gadget with an unreviewed copy would be strictly worse than reusing it,
//! per the "boolean-constrained is not bound" lesson (every re-implementation is a fresh, unaudited
//! surface). `Air`/`BaseAir` are forwarded verbatim to the wrapped `RelationCheckAir`, so
//! `LatticeCheckAir` inherits its soundness review, its 36k-trial mechanical fuzz census, and its
//! existing negative-control tests; this module's own tests (below) confirm the forwarding is
//! transparent — i.e. that wrapping does not accidentally widen what is provable — by tampering a
//! trace through the `LatticeCheckAir` surface exactly as `zq::tests` does through the bare
//! `RelationCheckAir`, so this specific entry point is shown to reject, not merely assumed to.
//!
//! `LatticeCheckAir` is **already composed** into the multi-AIR `prove_batch` pipeline alongside the
//! sponge and samplers — that composition lives in `encryption_proof.rs`'s
//! `assemble_full_provenance_prover`/`_verifier` (which build `RelationCheckAir { num_terms: R3A_TERMS
//! }` / `{ num_terms: R3B_TERMS }` instances — the same shapes as [`LatticeCheckAir::r3a`] /
//! [`LatticeCheckAir::r3b`]) and is exercised end-to-end by
//! `encryption_proof::tests::full_provenance_round_trip` and
//! `compose::tests::compose_full_stack_prove_batch`. **Read that evidence precisely**: only the
//! latter runs in a default `cargo test`; `full_provenance_round_trip` is `#[ignore]`d as heavy
//! (~90 KB sponge over all KAPPA R3a plus R3b in one batch), so a green default run does NOT
//! exercise it. It does pass when actually invoked — OBSERVED at the cutover commit,
//! `cargo test -p lib-q-zk-encryption-proof --release full_provenance_round_trip -- --ignored`
//! → `test result: ok. 1 passed; 0 failed`, 91.16s — but anyone citing it as evidence must run it
//! rather than infer it from the suite being green. This module does not re-route that pipeline
//! (doing so would mean re-deriving the LogUp join wiring, join-3 boundary offsets, and ρ/κ challenge
//! derivation that `encryption_proof.rs` already gets right and tests); it gives the design's name a
//! home and a directly testable, minimal surface.
//!
//! ## Remaining gap
//! None at the constraint/composition level for R3a/R3b — both are proven, LogUp-joined to the
//! sampler's coefficients (join 2) and to the fold outputs (join 3), and batched with the sponge and
//! samplers in one `prove_batch` call. What is *not* closed here (tracked at the crate level, not a
//! `LatticeCheckAir`-specific gap): the crate overall remains RED/unreviewed by a human cryptographer,
//! and the ZK/hiding-FRI path is exercised on a subset of the test matrix (see `encryption_proof.rs`'s
//! module doc for the full crate-level status).

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
};

use crate::zq::RelationCheckAir;

/// The design's R3 `LatticeCheckAir`: proves one instance of the folded `Z_q` relation
/// `Σ_j a_j·w_j + c ≡ 0 (mod q)` that [`crate::relation_assembly`] derives for an R3a column or the
/// R3b scalar (see the module doc for why this wraps, rather than reimplements,
/// [`RelationCheckAir`]).
#[derive(Debug, Clone)]
pub struct LatticeCheckAir(pub RelationCheckAir);

impl LatticeCheckAir {
    /// The R3a shape for one ρ-batched column: `mu` `e_r` folds + `kappa` `f_k`-role folds (mirrors
    /// `encryption_proof.rs`'s `R3A_TERMS = MU + KAPPA`).
    #[must_use]
    pub fn r3a(mu: usize, kappa: usize) -> Self {
        Self(RelationCheckAir {
            num_terms: mu + kappa,
        })
    }

    /// The R3b shape: `mu` `e_r` folds + the `g` fold + the `encode(μ)` fold (mirrors
    /// `encryption_proof.rs`'s `R3B_TERMS = MU + 2`).
    #[must_use]
    pub fn r3b(mu: usize) -> Self {
        Self(RelationCheckAir { num_terms: mu + 2 })
    }

    /// The wrapped relation's term count `L`.
    #[must_use]
    pub fn num_terms(&self) -> usize {
        self.0.num_terms
    }
}

impl<F> BaseAir<F> for LatticeCheckAir {
    fn width(&self) -> usize {
        BaseAir::<F>::width(&self.0)
    }

    fn num_public_values(&self) -> usize {
        BaseAir::<F>::num_public_values(&self.0)
    }
}

impl<AB: AirBuilder> Air<AB> for LatticeCheckAir {
    fn eval(&self, builder: &mut AB) {
        Air::<AB>::eval(&self.0, builder);
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_zkp::stark::{
        ConfigVal,
        StarkProver,
        StarkVerifier,
        default_config,
    };

    use super::*;
    use crate::test_macros::assert_air_rejects;
    use crate::zq::{
        Q,
        generate_relation_trace,
    };

    /// Build a genuine R3a-shaped relation (`MU = 6` `e_r` folds + `KAPPA = 9` `f`-role folds, the
    /// live `encryption_proof.rs` shape) and confirm the `LatticeCheckAir` surface proves and verifies
    /// it — i.e. the forwarding wrapper is transparent to a real witness, not just structurally
    /// well-typed.
    #[test]
    fn lattice_check_r3a_shape_proves_and_verifies() {
        const MU: usize = 6;
        const KAPPA: usize = 9;
        let l = MU + KAPPA;
        // Deterministic pseudo-random-looking public/witness values, all < Q, mirroring the shapes
        // `relation_check_proves_and_verifies` (zq.rs) already validates for the primitive itself.
        let a: Vec<u64> = (0..l as u64).map(|i| (i * 1_000_003 + 7) % Q).collect();
        let w: Vec<u64> = (0..l as u64).map(|i| (i * 998_244_353 + 11) % Q).collect();
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64;

        let air = LatticeCheckAir::r3a(MU, KAPPA);
        assert_eq!(air.num_terms(), l);
        let (trace, pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &pubs)
            .expect("prove via LatticeCheckAir");
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pubs)
            .expect("verify via LatticeCheckAir");
    }

    /// Same R3b shape (`MU = 6` `e_r` folds + `g` + `encode(μ)`, `encryption_proof.rs`'s `R3B_TERMS`)
    /// proves and verifies through the wrapper.
    #[test]
    fn lattice_check_r3b_shape_proves_and_verifies() {
        const MU: usize = 6;
        let l = MU + 2;
        let a: Vec<u64> = (0..l as u64).map(|i| (i * 5_000_011 + 3) % Q).collect();
        let w: Vec<u64> = (0..l as u64).map(|i| (i * 123_456_791 + 17) % Q).collect();
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64;

        let air = LatticeCheckAir::r3b(MU);
        assert_eq!(air.num_terms(), l);
        let (trace, pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &pubs)
            .expect("prove via LatticeCheckAir");
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pubs)
            .expect("verify via LatticeCheckAir");
    }

    /// **Negative control 1.** Tamper a witness limb (`w_0`'s low limb, cell 0) after generating a
    /// genuine R3a-shaped trace: the relation `Σ a_j w_j + c ≡ 0 (mod q)` no longer holds. Must be
    /// rejected THROUGH the `LatticeCheckAir` wrapper (not just the bare `RelationCheckAir`) — this is
    /// the check that the forwarding `Air::eval` in this module is not accidentally a no-op or a
    /// weaker relation than the one it wraps.
    #[test]
    fn lattice_check_r3a_rejects_tampered_witness_limb() {
        const MU: usize = 6;
        const KAPPA: usize = 9;
        let l = MU + KAPPA;
        let a: Vec<u64> = (0..l as u64).map(|i| (i * 1_000_003 + 7) % Q).collect();
        let w: Vec<u64> = (0..l as u64).map(|i| (i * 998_244_353 + 11) % Q).collect();
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64;

        let air = LatticeCheckAir::r3a(MU, KAPPA);
        let (mut trace, pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        // Column 0 is w_0's lowest limb (RelationCheckAir::rw_w() == 0); bump it by one.
        trace.values[0] += ConfigVal::ONE;

        assert_air_rejects!(
            &air,
            trace,
            &pubs,
            "a tampered R3a witness limb must not verify through LatticeCheckAir"
        );
    }

    /// **Negative control 2.** Tamper the *public* constant `c`'s limb after a genuine R3b-shaped
    /// trace was generated for the ORIGINAL `c` — the trace's `κ`/carry chain was built against the
    /// old `c`, so mutating the public value alone (leaving the witness trace untouched) desyncs the
    /// fused carry identity `Σ a_j w_j + c − κ·q = 0`. This is the public-input-tamper analogue of the
    /// witness-tamper control above: confirms `LatticeCheckAir` does not silently accept a proof
    /// re-bound to a different public statement.
    #[test]
    fn lattice_check_r3b_rejects_tampered_public_constant() {
        const MU: usize = 6;
        let l = MU + 2;
        let a: Vec<u64> = (0..l as u64).map(|i| (i * 5_000_011 + 3) % Q).collect();
        let w: Vec<u64> = (0..l as u64).map(|i| (i * 123_456_791 + 17) % Q).collect();
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64;

        let air = LatticeCheckAir::r3b(MU);
        let (trace, mut pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        // Bump c's lowest limb (public values are a's limbs then c's limbs, 4 limbs each; c starts at
        // index 4*l).
        pubs[4 * l] += ConfigVal::ONE;

        assert_air_rejects!(
            &air,
            trace,
            &pubs,
            "a tampered public constant must not verify through LatticeCheckAir"
        );
    }

    /// **Negative control 3.** A relation that genuinely does not hold mod q must not even reach a
    /// provable trace through the `LatticeCheckAir::r3a` shape — trace generation itself must refuse
    /// (mirrors `zq::tests::relation_check_rejects_false_relation`, exercised at the R3a term count).
    #[test]
    fn lattice_check_r3a_false_relation_has_no_trace() {
        const MU: usize = 6;
        const KAPPA: usize = 9;
        let l = MU + KAPPA;
        let a: Vec<u64> = (0..l as u64).map(|i| (i * 1_000_003 + 7) % Q).collect();
        let w: Vec<u64> = (0..l as u64).map(|i| (i * 998_244_353 + 11) % Q).collect();
        // Wrong constant: off by one from the value that would make the sum vanish mod q.
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let true_c = ((q128 - (s % q128)) % q128) as u64;
        let wrong_c = (true_c + 1) % Q;

        let air = LatticeCheckAir::r3a(MU, KAPPA);
        assert_eq!(air.num_terms(), l);
        assert!(generate_relation_trace(&a, &w, wrong_c).is_err());
    }
}
