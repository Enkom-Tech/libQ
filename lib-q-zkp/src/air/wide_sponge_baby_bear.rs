//! Wide Poseidon2-BabyBear sponge (Arm B, build-spec step 4) — the BabyBear analogue of
//! `wide_sponge.rs` (Poseidon256/`Complex<Mersenne31>`).
//!
//! Sponge geometry over the BabyBear base field: state width `t = 16`, **rate `r = 7`**,
//! **capacity `c = 9`**, squeeze **`w_out = 9`** cells. One permutation per full rate block
//! plus one for the `10*1` padding block; all permutations of a given input live in ONE trace
//! row, their round intermediates laid out consecutively. The injection schedule and the
//! padding constant are baked into the constraint *expressions* — no committed control columns.
//!
//! Security target (capacity-9): collision `c·log₂p / 2 = 9·30.9/2 ≈ 139 ≥ 128`; wide digest
//! `w_out·log₂p = 9·30.9 ≈ 278 ≥ 256`. (A base-field capacity of 5 would give only ~77.5 bits —
//! the reason this arm widens to capacity 9.) These are claims for the obligation packet, NOT
//! established here.
//!
//! `constrain_wide_sponge_bb` is the in-circuit form; `generate_wide_sponge_bb_cells` is its
//! value-level companion (records the same intermediate cells); `poseidon2_wide_hash_bb` is the
//! clean reference digest. Tier RED.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_poseidon::poseidon2_baby_bear::permute;
use lib_q_stark_air::AirBuilder;
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::PrimeCharacteristicRing;

use crate::air::poseidon2_gadget::{
    POSEIDON2_PERM_INTERM_COLS,
    constrain_permutation,
    generate_permutation_cells_and_output,
};

/// Sponge state width (= Poseidon2 width).
pub const STATE_W: usize = 16;
/// Sponge rate (elements absorbed per permutation).
pub const RATE: usize = 7;
/// Sponge capacity (`STATE_W - RATE`); sets the collision bound.
pub const CAPACITY: usize = STATE_W - RATE;
/// Wide digest width in cells (`w_out`).
pub const WIDE_DIGEST_ELEMS: usize = 9;
/// Intermediate columns per permutation (reused from the gadget).
pub const PERM_INTERM_COLS: usize = POSEIDON2_PERM_INTERM_COLS;

/// Number of permutations for an `input_len`-element input: `⌊L / RATE⌋ + 1`.
pub const fn wide_sponge_bb_num_perms(input_len: usize) -> usize {
    input_len / RATE + 1
}

/// Intermediate columns consumed by a sponge over an `input_len`-element input.
pub const fn wide_sponge_bb_interm_cols(input_len: usize) -> usize {
    wide_sponge_bb_num_perms(input_len) * PERM_INTERM_COLS
}

/// Constrain `digest = H(input)` within the current row; return the `WIDE_DIGEST_ELEMS`-cell
/// digest expressions (unbound — the caller wires them). Permutation `p`'s intermediates occupy
/// `[interm_start + p·PERM_INTERM_COLS, …)`; reserve [`wide_sponge_bb_interm_cols`]`(input.len())`.
pub fn constrain_wide_sponge_bb<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    input: &[AB::Expr],
    interm_start: usize,
) -> Vec<AB::Expr> {
    let one = AB::Expr::from(BabyBear::ONE);
    let zero = AB::Expr::from(BabyBear::ZERO);

    let mut state: Vec<AB::Expr> = vec![zero; STATE_W];
    let mut absorbed = 0usize;
    let mut col = interm_start;

    // Absorb: inject each element into the rate, permute on every full rate block.
    for e in input {
        state[absorbed] = state[absorbed].clone() + e.clone();
        absorbed += 1;
        if absorbed >= RATE {
            state = constrain_permutation(builder, &state, col);
            col += PERM_INTERM_COLS;
            absorbed = 0;
        }
    }

    // 10*1 padding within the final rate block, then the final permutation.
    state[absorbed] = state[absorbed].clone() + one.clone();
    if absorbed + 1 < RATE {
        state[RATE - 1] = state[RATE - 1].clone() + one.clone();
    }
    state = constrain_permutation(builder, &state, col);

    state[..WIDE_DIGEST_ELEMS].to_vec()
}

/// Value-level companion to [`constrain_wide_sponge_bb`]: simulate the sponge, returning the
/// concatenated round-intermediate cells (length [`wide_sponge_bb_interm_cols`]`(input.len())`)
/// in permutation order, plus the truncated digest (`= poseidon2_wide_hash_bb(input)`).
pub fn generate_wide_sponge_bb_cells(
    input: &[BabyBear],
) -> (Vec<BabyBear>, [BabyBear; WIDE_DIGEST_ELEMS]) {
    let one = BabyBear::ONE;
    let mut cells: Vec<BabyBear> = Vec::with_capacity(wide_sponge_bb_interm_cols(input.len()));
    let mut state = [BabyBear::ZERO; STATE_W];
    let mut absorbed = 0usize;

    for &e in input {
        state[absorbed] = state[absorbed] + e;
        absorbed += 1;
        if absorbed >= RATE {
            let (interm, output) = generate_permutation_cells_and_output(state);
            cells.extend_from_slice(&interm);
            state = output;
            absorbed = 0;
        }
    }

    state[absorbed] = state[absorbed] + one;
    if absorbed + 1 < RATE {
        state[RATE - 1] = state[RATE - 1] + one;
    }
    let (interm, output) = generate_permutation_cells_and_output(state);
    cells.extend_from_slice(&interm);

    let digest: [BabyBear; WIDE_DIGEST_ELEMS] = core::array::from_fn(|i| output[i]);
    debug_assert_eq!(cells.len(), wide_sponge_bb_interm_cols(input.len()));
    (cells, digest)
}

/// Clean value-level reference: `digest = H(input)` (no cell recording). The `generate_*` digest
/// and the `constrain_*` digest must both equal this.
pub fn poseidon2_wide_hash_bb(input: &[BabyBear]) -> [BabyBear; WIDE_DIGEST_ELEMS] {
    let one = BabyBear::ONE;
    let mut state = [BabyBear::ZERO; STATE_W];
    let mut absorbed = 0usize;
    for &e in input {
        state[absorbed] = state[absorbed] + e;
        absorbed += 1;
        if absorbed >= RATE {
            state = permute(state);
            absorbed = 0;
        }
    }
    state[absorbed] = state[absorbed] + one;
    if absorbed + 1 < RATE {
        state[RATE - 1] = state[RATE - 1] + one;
    }
    state = permute(state);
    core::array::from_fn(|i| state[i])
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::{
        Air,
        BaseAir,
        WindowAccess,
    };
    use lib_q_stark_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::check_constraints;

    const P: u32 = 2_013_265_921;

    fn fe(x: u32) -> BabyBear {
        BabyBear::new(x % P)
    }

    #[test]
    fn num_perms_and_cols_match_lengths() {
        // ⌊L/7⌋ + 1
        assert_eq!(wide_sponge_bb_num_perms(0), 1);
        assert_eq!(wide_sponge_bb_num_perms(6), 1);
        assert_eq!(wide_sponge_bb_num_perms(7), 2);
        assert_eq!(wide_sponge_bb_num_perms(13), 2);
        assert_eq!(wide_sponge_bb_num_perms(14), 3);
        assert_eq!(wide_sponge_bb_interm_cols(14), 3 * PERM_INTERM_COLS);
        assert_eq!(CAPACITY, 9);
    }

    #[test]
    fn value_cells_digest_matches_reference_all_lengths() {
        for len in [0usize, 1, 6, 7, 8, 13, 14, 20] {
            let input: Vec<BabyBear> = (0..len as u32).map(|i| fe(i + 1)).collect();
            let (cells, digest) = generate_wide_sponge_bb_cells(&input);
            assert_eq!(cells.len(), wide_sponge_bb_interm_cols(len), "cells len for {len}");
            assert_eq!(
                digest,
                poseidon2_wide_hash_bb(&input),
                "digest must match the value-level reference for len {len}"
            );
        }
    }

    /// Single-row fixture: `[ preimage(LEN) | interm | digest(9) ]`, binding the digest cells to
    /// the constrained sponge digest.
    struct SpongeFixtureBbAir {
        len: usize,
    }
    impl SpongeFixtureBbAir {
        fn interm_start(&self) -> usize {
            self.len
        }
        fn digest_start(&self) -> usize {
            self.len + wide_sponge_bb_interm_cols(self.len)
        }
    }
    impl BaseAir<BabyBear> for SpongeFixtureBbAir {
        fn width(&self) -> usize {
            self.digest_start() + WIDE_DIGEST_ELEMS
        }
        fn main_next_row_columns(&self) -> Vec<usize> {
            Vec::new()
        }
    }
    impl<AB: AirBuilder<F = BabyBear>> Air<AB> for SpongeFixtureBbAir {
        fn eval(&self, builder: &mut AB) {
            let interm_start = self.interm_start();
            let digest_start = self.digest_start();
            let input: Vec<AB::Expr> = {
                let main = builder.main();
                let local = main.current_slice();
                (0..self.len).map(|i| local[i].into()).collect()
            };
            let digest = constrain_wide_sponge_bb(builder, &input, interm_start);
            let main = builder.main();
            let local = main.current_slice();
            for i in 0..WIDE_DIGEST_ELEMS {
                builder.assert_eq(local[digest_start + i].into(), digest[i].clone());
            }
        }
    }

    fn fixture_row(input: &[BabyBear]) -> (SpongeFixtureBbAir, RowMajorMatrix<BabyBear>) {
        let air = SpongeFixtureBbAir { len: input.len() };
        let (cells, digest) = generate_wide_sponge_bb_cells(input);
        let mut row: Vec<BabyBear> = Vec::new();
        row.extend_from_slice(input);
        row.extend_from_slice(&cells);
        row.extend_from_slice(&digest);
        let w = row.len();
        (air, RowMajorMatrix::new(row, w))
    }

    #[test]
    fn fixture_roundtrip_constraints_hold() {
        for len in [0usize, 1, 7, 8, 14] {
            let input: Vec<BabyBear> = (0..len as u32).map(|i| fe(i * 7 + 3)).collect();
            let (air, trace) = fixture_row(&input);
            check_constraints(&air, &trace, &[]);
        }
    }

    fn corrupt_at(input: &[BabyBear], col: usize) -> (SpongeFixtureBbAir, RowMajorMatrix<BabyBear>) {
        let air = SpongeFixtureBbAir { len: input.len() };
        let (cells, digest) = generate_wide_sponge_bb_cells(input);
        let mut row: Vec<BabyBear> = Vec::new();
        row.extend_from_slice(input);
        row.extend_from_slice(&cells);
        row.extend_from_slice(&digest);
        row[col] = row[col] + BabyBear::ONE;
        let w = row.len();
        (air, RowMajorMatrix::new(row, w))
    }

    #[test]
    #[should_panic]
    fn corrupt_digest_rejected() {
        let input: Vec<BabyBear> = (0..8u32).map(|i| fe(i + 1)).collect();
        let air = SpongeFixtureBbAir { len: input.len() };
        let (a, t) = corrupt_at(&input, air.digest_start());
        check_constraints(&a, &t, &[]);
    }

    #[test]
    #[should_panic]
    fn corrupt_intermediate_rejected() {
        let input: Vec<BabyBear> = (0..8u32).map(|i| fe(i + 1)).collect();
        let air = SpongeFixtureBbAir { len: input.len() };
        // first intermediate cell of the first permutation
        let (a, t) = corrupt_at(&input, air.interm_start());
        check_constraints(&a, &t, &[]);
    }

    #[test]
    #[should_panic]
    fn corrupt_preimage_rejected() {
        let input: Vec<BabyBear> = (0..8u32).map(|i| fe(i + 1)).collect();
        let (a, t) = corrupt_at(&input, 0); // first preimage cell
        check_constraints(&a, &t, &[]);
    }

    /// EXHAUSTIVE under-constraint audit: mutate every column (+1) of a valid len-14 (3-permutation)
    /// sponge row and require rejection. A surviving column would be a free witness. Covers every
    /// preimage / intermediate / digest cell, not a sample. len-14 exercises multi-permutation
    /// chaining (the running capacity is carried between permutations).
    #[test]
    fn under_constraint_audit_every_column() {
        use std::panic::{
            AssertUnwindSafe,
            catch_unwind,
        };
        let input: Vec<BabyBear> = (0..14u32).map(|i| fe(i * 7 + 3)).collect();
        let (air, trace) = fixture_row(&input);
        let width = trace.values.len(); // single row
        check_constraints(&air, &trace, &[]);

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut survived = Vec::new();
        for col in 0..width {
            let mut tr = trace.clone();
            tr.values[col] = tr.values[col] + BabyBear::ONE;
            if catch_unwind(AssertUnwindSafe(|| check_constraints(&air, &tr, &[]))).is_ok() {
                survived.push(col);
            }
        }
        std::panic::set_hook(prev);
        assert!(survived.is_empty(), "UNCONSTRAINED columns: {survived:?}");
    }
}
