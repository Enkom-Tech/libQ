//! In-circuit Poseidon-256 wide sponge (M2/M3, RED — ADR 113 freeze-gate).
//!
//! ONE in-circuit implementation of the truncated-output Poseidon-256 sponge, matching the
//! value-level reference [`crate::air::wide_hash::poseidon256_wide_hash`] for **arbitrary
//! input length**. Both the wide Merkle node hash (10-input case) and the membership leaf /
//! nullifier hashes (variable-length) are expressed through this single helper, so there is
//! exactly one sponge constraint surface to audit.
//!
//! All permutations of one hash are packed into the **current trace row** (the caller owns
//! the row geometry): permutation `p`'s `(8 + 60) × (7 × 3) = 1428` round-intermediate
//! columns start at `interm_start + p × PERM_INTERM_COLS`. The number of permutations for an
//! `L`-element input is [`wide_sponge_num_perms`]`(L) = ⌊L / RATE⌋ + 1` (absorb permutes
//! once per full rate block; the `10*1` padding always permutes once more).
//!
//! Capacity carries between permutations automatically (the full width-7 state expression is
//! threaded), and the entire injection schedule (which input element is absorbed where, and
//! the padding constant) is baked into the eval *expressions* — there are no committed
//! injection columns for a prover to tamper.
//!
//! RED: Poseidon-256 round counts are NOT verified for GF(p²) — see `super::wide_hash`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_poseidon::{
    Poseidon256,
    PoseidonField,
};
use lib_q_stark_air::AirBuilder;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_mersenne31::Mersenne31;

use super::poseidon_gadget::PoseidonGadget;
use super::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
};
use super::{
    AirError,
    compute_poseidon_row,
    poseidon_to_field,
};

/// Poseidon-256 sponge geometry.
pub(crate) const STATE_W: usize = 7;
pub(crate) const RATE: usize = 2;
/// Per-permutation intermediate columns: `(8 + 60) rounds × (7 × 3)`.
pub(crate) const PERM_INTERM_COLS: usize = (8 + 60) * (STATE_W * 3); // 1428

/// Number of Poseidon-256 permutations the sponge runs for an `input_len`-element input:
/// `⌊input_len / RATE⌋ + 1` (one permute per full rate block during absorb, plus one for the
/// `10*1` padding block). Matches [`crate::air::wide_hash::poseidon256_wide_hash`].
pub const fn wide_sponge_num_perms(input_len: usize) -> usize {
    input_len / RATE + 1
}

/// Intermediate columns consumed by a sponge over an `input_len`-element input.
pub const fn wide_sponge_interm_cols(input_len: usize) -> usize {
    wide_sponge_num_perms(input_len) * PERM_INTERM_COLS
}

/// Constrain `digest = poseidon256_wide_hash(input)` within the current row and return the
/// truncated 5-element digest expression.
///
/// `input` are the preimage element expressions (any length, including 0). Permutation `p`'s
/// round intermediates occupy `[interm_start + p·PERM_INTERM_COLS, …)`; the caller must have
/// reserved [`wide_sponge_interm_cols`]`(input.len())` columns there. The returned digest is
/// NOT bound to anything — the caller wires it (running digest, public value, …).
pub fn constrain_wide_sponge<AB: AirBuilder>(
    builder: &mut AB,
    input: &[AB::Expr],
    interm_start: usize,
) -> Result<Vec<AB::Expr>, AirError>
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
    let zero = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
    let gadget = PoseidonGadget::with_params(Poseidon256::params());

    let mut state: Vec<AB::Expr> = vec![zero; STATE_W];
    let mut absorbed = 0usize;
    let mut col = interm_start;

    // Absorb: inject each element into the rate, permute on every full rate block.
    for e in input {
        state[absorbed] = state[absorbed].clone() + e.clone();
        absorbed += 1;
        if absorbed >= RATE {
            state = gadget.constrain_permutation(builder, &state, col)?;
            col += PERM_INTERM_COLS;
            absorbed = 0;
        }
    }

    // 10*1 padding, then the final permute.
    state[absorbed] = state[absorbed].clone() + one.clone();
    if absorbed + 1 < RATE {
        state[RATE - 1] = state[RATE - 1].clone() + one.clone();
    }
    state = gadget.constrain_permutation(builder, &state, col)?;

    Ok(state[..WIDE_DIGEST_ELEMS].to_vec())
}

/// Value-level companion to [`constrain_wide_sponge`]: simulate the sponge over `input`,
/// returning the concatenated round-intermediate cells (length
/// [`wide_sponge_interm_cols`]`(input.len())`) in permutation order, plus the truncated
/// digest. The digest equals [`crate::air::wide_hash::poseidon256_wide_hash`]`(input)`.
pub fn generate_wide_sponge_cells(input: &[PoseidonField]) -> (Vec<PoseidonField>, WideDigest) {
    let params = Poseidon256::params();
    let zero = PoseidonField::ZERO;
    let one = PoseidonField::ONE;

    let mut cells: Vec<PoseidonField> = Vec::with_capacity(wide_sponge_interm_cols(input.len()));
    let mut state = vec![zero; STATE_W];
    let mut absorbed = 0usize;

    for &e in input {
        state[absorbed] += e;
        absorbed += 1;
        if absorbed >= RATE {
            let (final_state, interm) = compute_poseidon_row(&state, &params);
            debug_assert_eq!(interm.len(), PERM_INTERM_COLS);
            cells.extend_from_slice(&interm);
            state.copy_from_slice(&final_state[..STATE_W]);
            absorbed = 0;
        }
    }

    state[absorbed] += one;
    if absorbed + 1 < RATE {
        state[RATE - 1] += one;
    }
    let (final_state, interm) = compute_poseidon_row(&state, &params);
    cells.extend_from_slice(&interm);

    let digest: WideDigest = core::array::from_fn(|i| final_state[i]);
    debug_assert_eq!(cells.len(), wide_sponge_interm_cols(input.len()));
    (cells, digest)
}

/// Convert a slice of [`PoseidonField`] preimage elements to trace-field elements `F`.
pub fn preimage_to_field<F: Field + BasedVectorSpace<Mersenne31>>(
    input: &[PoseidonField],
) -> Vec<F> {
    input.iter().map(poseidon_to_field).collect()
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_air::{
        Air,
        BaseAir,
        WindowAccess,
    };
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::air::wide_hash::poseidon256_wide_hash;

    type TestField = Complex<Mersenne31>;

    fn fe(x: u32) -> PoseidonField {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }

    #[test]
    fn num_perms_and_cols_match_lengths() {
        // ⌊L/2⌋ + 1.
        assert_eq!(wide_sponge_num_perms(0), 1);
        assert_eq!(wide_sponge_num_perms(1), 1);
        assert_eq!(wide_sponge_num_perms(2), 2);
        assert_eq!(wide_sponge_num_perms(3), 2);
        assert_eq!(wide_sponge_num_perms(5), 3);
        assert_eq!(wide_sponge_num_perms(7), 4);
        assert_eq!(wide_sponge_num_perms(10), 6);
        assert_eq!(wide_sponge_interm_cols(10), 6 * PERM_INTERM_COLS);
    }

    #[test]
    fn value_cells_digest_matches_reference_all_lengths() {
        for len in [0usize, 1, 2, 3, 5, 7, 10] {
            let input: Vec<PoseidonField> = (0..len as u32).map(|i| fe(i + 1)).collect();
            let (cells, digest) = generate_wide_sponge_cells(&input);
            assert_eq!(
                cells.len(),
                wide_sponge_interm_cols(len),
                "cells len for {len}"
            );
            assert_eq!(
                digest,
                poseidon256_wide_hash(&input),
                "digest must match the value-level reference for len {len}"
            );
        }
    }

    /// Test fixture: a single-row AIR that constrains `digest = H(input)` for a fixed input
    /// length, binding the digest to public values. Row layout:
    /// `[ preimage(LEN) | interm(num_perms·1428) | digest(5) ]`.
    struct SpongeFixtureAir {
        len: usize,
    }

    impl SpongeFixtureAir {
        fn interm_start(&self) -> usize {
            self.len
        }
        fn digest_start(&self) -> usize {
            self.len + wide_sponge_interm_cols(self.len)
        }
        fn row_width(&self) -> usize {
            self.digest_start() + WIDE_DIGEST_ELEMS
        }
    }

    impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for SpongeFixtureAir {
        fn width(&self) -> usize {
            self.row_width()
        }
    }

    impl<AB: AirBuilder> Air<AB> for SpongeFixtureAir
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        fn eval(&self, builder: &mut AB) {
            let input: Vec<AB::Expr> = {
                let main = builder.main();
                let local = main.current_slice();
                (0..self.len).map(|i| local[i].into()).collect()
            };
            let digest_start = self.digest_start();
            let pub_digest: Vec<AB::Expr> = {
                let main = builder.main();
                let local = main.current_slice();
                (0..WIDE_DIGEST_ELEMS)
                    .map(|i| local[digest_start + i].into())
                    .collect()
            };
            let out = match constrain_wide_sponge(builder, &input, self.interm_start()) {
                Ok(d) => d,
                Err(_) => {
                    builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
                    return;
                }
            };
            for i in 0..WIDE_DIGEST_ELEMS {
                builder.assert_eq(out[i].clone(), pub_digest[i].clone());
            }
        }
    }

    fn build_fixture_trace(len: usize) -> (SpongeFixtureAir, RowMajorMatrix<TestField>) {
        let air = SpongeFixtureAir { len };
        let input: Vec<PoseidonField> = (0..len as u32).map(|i| fe(i + 3)).collect();
        let (cells, digest) = generate_wide_sponge_cells(&input);

        let mut row: Vec<TestField> = Vec::with_capacity(air.row_width());
        row.extend(preimage_to_field::<TestField>(&input));
        row.extend(cells.iter().map(poseidon_to_field::<TestField>));
        row.extend(digest.iter().map(poseidon_to_field::<TestField>));
        assert_eq!(row.len(), air.row_width());

        // Two identical rows (the fixture has no transition constraints).
        let width = air.row_width();
        let mut values = row.clone();
        values.extend_from_slice(&row);
        (air, RowMajorMatrix::new(values, width))
    }

    #[test]
    fn sponge_fixture_round_trip_all_lengths() {
        for len in [0usize, 1, 2, 3, 5, 7, 10] {
            let (air, trace) = build_fixture_trace(len);
            check_constraints(&air, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "")]
    fn sponge_fixture_rejects_corrupted_digest() {
        let (air, mut trace) = build_fixture_trace(7);
        let ds = air.digest_start();
        trace.values[ds] += TestField::ONE;
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "")]
    fn sponge_fixture_rejects_corrupted_intermediate() {
        let (air, mut trace) = build_fixture_trace(7);
        let col = air.interm_start() + 50;
        trace.values[col] += TestField::ONE;
        check_constraints(&air, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "")]
    fn sponge_fixture_rejects_corrupted_preimage() {
        // Changing the preimage without recomputing the hash must break the digest binding.
        let (air, mut trace) = build_fixture_trace(7);
        trace.values[0] += TestField::ONE;
        check_constraints(&air, &trace, &[]);
    }
}
