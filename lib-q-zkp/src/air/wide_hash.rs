//! Wide-digest Poseidon-256 hashing primitive (M1, RED — ADR 113 freeze-gate).
//!
//! The unlinkable membership proof (`unlinkable-membership-v0`) pins **≥128-bit
//! collision resistance NOW** for every digest (leaf `L`, every Merkle node, nullifier
//! `N`). A sponge's collision resistance is bounded by its **capacity**, not its output
//! width: Poseidon-128 (capacity 3) caps at `3·log₂|F|/2 ≈ 93` bit over
//! `Complex<Mersenne31>` (≈62-bit elements) regardless of how wide the output is
//! truncated, so it **cannot** meet the requirement. Poseidon-256 (width 7, capacity 5)
//! caps at `5·62/2 ≈ 155` bit — hence Poseidon-256 is mandatory and the digest is
//! [`WIDE_DIGEST_ELEMS`] = 5 field elements (the truncated post-permutation state,
//! Plonky2/Poseidon2-style).
//!
//! Two layers, kept deliberately distinct:
//!
//! * **Value level (out-of-circuit / trace generation):**
//!   - [`poseidon256_perm_truncated`] — ONE Poseidon-256 permutation applied to a full
//!     width-7 state, output truncated to 5 elements. This is the per-permutation
//!     compression the multi-row sponge AIR (M2) stacks; it is the value-level companion
//!     to the in-circuit gadget path validated in this module's tests. Sound as a
//!     fixed-length compression when the adversary-controlled input occupies ≤ `rate`
//!     (= 2) state cells so capacity ≥ 5 is preserved.
//!   - [`poseidon256_wide_hash`] — the full truncated-output **sponge** (audited
//!     [`lib_q_poseidon::PoseidonSponge`] absorb + 10*1 padding, output = first 5 state
//!     cells). Handles arbitrary input length uniformly. Its **in-circuit enforcement is
//!     M2** (the multi-row sponge AIR); here it is the value-level reference only.
//!
//! * **Circuit level:** the test fixture `WideHashPermAir` exercises
//!   [`PoseidonGadget::with_params`]`(Poseidon256::params())` +
//!   [`PoseidonGadget::constrain_full_state_wide`] binding 5 outputs, proving the
//!   wide-output constraint path is sound end-to-end. The multi-row sponge AIR (M2)
//!   repeats exactly this per-row primitive with capacity carry.
//!
//! RED: the Poseidon-256 round counts are **not** independently verified for the GF(p²)
//! extension field (see `lib_q_poseidon::params`); the ~155-bit figure is a
//! capacity-based target only. The whole membership tier is gated behind the ADR-113
//! freeze review.

extern crate alloc;

use lib_q_poseidon::{
    Poseidon256,
    PoseidonField,
};

use super::compute_poseidon_row;

/// Number of `Complex<Mersenne31>` field elements in a wide digest.
///
/// Chosen so the digest carries the full capacity-bounded collision resistance of
/// Poseidon-256 (capacity 5 → ~155-bit). Applies uniformly to the leaf `L`, every
/// internal Merkle node, and the nullifier `N`.
pub const WIDE_DIGEST_ELEMS: usize = 5;

/// A wide digest: [`WIDE_DIGEST_ELEMS`] `Complex<Mersenne31>` field elements.
pub type WideDigest = [PoseidonField; WIDE_DIGEST_ELEMS];

/// Apply ONE Poseidon-256 permutation to `initial_state` and truncate the result to a
/// [`WideDigest`] (first [`WIDE_DIGEST_ELEMS`] state cells).
///
/// This is the per-permutation compression the in-circuit gadget path constrains
/// ([`PoseidonGadget::constrain_full_state_wide`]) and the unit the multi-row sponge AIR
/// (M2) stacks with capacity carry.
///
/// `initial_state` must contain at least `state_width` (= 7) elements; only the first 7
/// are used. As a fixed-length compression this is collision-resistant only when the
/// adversary-controlled portion occupies ≤ `rate` (= 2) cells (capacity ≥ 5 preserved);
/// for variable-length input use [`poseidon256_wide_hash`].
///
/// # Panics
///
/// Panics if `initial_state.len() < 7` (inherited from [`compute_poseidon_row`]).
pub fn poseidon256_perm_truncated(initial_state: &[PoseidonField]) -> WideDigest {
    let params = Poseidon256::params();
    let (final_state, _intermediates) = compute_poseidon_row(initial_state, &params);
    core::array::from_fn(|i| final_state[i])
}

/// Full truncated-output Poseidon-256 **sponge** over `input`: audited absorb + 10*1
/// padding, digest = first [`WIDE_DIGEST_ELEMS`] cells of the final permutation state.
///
/// Value-level reference used by trace generators and out-of-circuit checks. Handles
/// arbitrary `input` length; collision resistance is capacity-bounded (~155-bit). The
/// matching in-circuit AIR is the multi-row sponge AIR (M2) — until that lands, do not
/// treat a proof as enforcing this function.
pub fn poseidon256_wide_hash(input: &[PoseidonField]) -> WideDigest {
    use lib_q_poseidon::PoseidonSponge;

    let mut sponge = PoseidonSponge::new(Poseidon256::params());
    sponge.absorb(input);
    let state = sponge.finalize();
    debug_assert!(
        state.len() >= WIDE_DIGEST_ELEMS,
        "Poseidon-256 state width must be ≥ WIDE_DIGEST_ELEMS"
    );
    core::array::from_fn(|i| state[i])
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use lib_q_stark::check_constraints;
    use lib_q_stark_air::{
        Air,
        AirBuilder,
        BaseAir,
        WindowAccess,
    };
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_field::{
        BasedVectorSpace,
        Field,
    };
    use lib_q_stark_matrix::dense::RowMajorMatrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;
    use crate::air::poseidon_gadget::PoseidonGadget;

    type TestField = Complex<Mersenne31>;

    /// Poseidon-256 layout: width 7, 8 full + 60 partial rounds.
    const STATE_W: usize = 7;
    const INTERMEDIATE_COLS: usize = (8 + 60) * (STATE_W * 3); // 1428
    const DIGEST_START: usize = STATE_W + INTERMEDIATE_COLS;
    const ROW_WIDTH: usize = DIGEST_START + WIDE_DIGEST_ELEMS; // 1440

    /// Single-permutation fixture: constrains one Poseidon-256 permutation and binds the
    /// truncated wide digest. Validates the gadget's wide-output path; the per-row unit
    /// the M2 sponge AIR repeats.
    struct WideHashPermAir;

    impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for WideHashPermAir {
        fn width(&self) -> usize {
            ROW_WIDTH
        }
    }

    impl<AB: AirBuilder> Air<AB> for WideHashPermAir
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        fn eval(&self, builder: &mut AB) {
            let initial_state: Vec<AB::Expr> = {
                let main = builder.main();
                let local = main.current_slice();
                (0..STATE_W).map(|i| local[i].into()).collect()
            };
            let outputs: Vec<AB::Expr> = {
                let main = builder.main();
                let local = main.current_slice();
                (0..WIDE_DIGEST_ELEMS)
                    .map(|i| local[DIGEST_START + i].into())
                    .collect()
            };
            let gadget = PoseidonGadget::with_params(Poseidon256::params());
            if gadget
                .constrain_full_state_wide(builder, &initial_state, &outputs, STATE_W)
                .is_err()
            {
                use lib_q_stark_field::PrimeCharacteristicRing;
                builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
            }
        }
    }

    /// Build a height-2 trace (two identical valid rows; the fixture has no transition
    /// constraints) for `initial_state`, returning the matrix and the expected digest.
    fn build_trace(
        initial_state: &[TestField; STATE_W],
    ) -> (RowMajorMatrix<TestField>, WideDigest) {
        let params = Poseidon256::params();
        let (final_state, intermediates) = compute_poseidon_row(initial_state, &params);
        assert_eq!(intermediates.len(), INTERMEDIATE_COLS);
        let digest: WideDigest = core::array::from_fn(|i| final_state[i]);

        let mut row = Vec::with_capacity(ROW_WIDTH);
        row.extend_from_slice(initial_state);
        row.extend_from_slice(&intermediates);
        row.extend_from_slice(&digest);
        assert_eq!(row.len(), ROW_WIDTH);

        let mut values = row.clone();
        values.extend_from_slice(&row);
        (RowMajorMatrix::new(values, ROW_WIDTH), digest)
    }

    fn sample_state(seed: u32) -> [TestField; STATE_W] {
        core::array::from_fn(|i| TestField::from(Mersenne31::new(seed.wrapping_add(i as u32) + 1)))
    }

    #[test]
    fn columns_per_hash_matches_layout() {
        let gadget = PoseidonGadget::with_params(Poseidon256::params());
        assert_eq!(gadget.columns_per_hash(), INTERMEDIATE_COLS);
        assert_eq!(WIDE_DIGEST_ELEMS, 5);
    }

    #[test]
    fn wide_perm_digest_matches_value_helper() {
        let state = sample_state(7);
        let (_trace, digest) = build_trace(&state);
        assert_eq!(poseidon256_perm_truncated(&state), digest);
    }

    #[test]
    fn wide_hash_perm_air_round_trip() {
        let state = sample_state(42);
        let (trace, _digest) = build_trace(&state);
        let air = WideHashPermAir;
        // Panics (via DebugConstraintBuilder) on any unsatisfied constraint.
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn wide_hash_perm_air_rejects_corrupted_digest() {
        let state = sample_state(99);
        let (mut trace, _digest) = build_trace(&state);
        // Corrupt one digest cell in row 0: the wide-output binding must fail.
        let corrupt = trace.values[DIGEST_START] + TestField::from(Mersenne31::new(1));
        trace.values[DIGEST_START] = corrupt;
        let air = WideHashPermAir;
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn wide_hash_perm_air_rejects_corrupted_intermediate() {
        let state = sample_state(123);
        let (mut trace, _digest) = build_trace(&state);
        // Corrupt an interior round column: full-soundness intermediate check must fail.
        let col = STATE_W + INTERMEDIATE_COLS / 2;
        let corrupt = trace.values[col] + TestField::from(Mersenne31::new(1));
        trace.values[col] = corrupt;
        let air = WideHashPermAir;
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    fn wide_hash_sponge_deterministic_and_diffuses() {
        let a = poseidon256_wide_hash(&sample_state(1));
        let b = poseidon256_wide_hash(&sample_state(1));
        assert_eq!(a, b, "wide hash must be deterministic");
        let c = poseidon256_wide_hash(&sample_state(2));
        assert_ne!(a, c, "distinct inputs must give distinct digests");
        assert_eq!(a.len(), WIDE_DIGEST_ELEMS);
    }
}
