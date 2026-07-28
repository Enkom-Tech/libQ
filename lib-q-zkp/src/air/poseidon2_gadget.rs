//! In-circuit Poseidon2-BabyBear AIR gadget (Arm B, build-spec step 3).
//!
//! Constrains one width-16 Poseidon2 permutation (deployed Plonky3/SP1 instance:
//! `R_F = 8 = 4+4`, `R_P = 13`, S-box `x^7`) per trace row, over the BabyBear base field.
//! Mirrors the `p3-poseidon2-air` column layout but writes each S-box as a single degree-7
//! constraint (no `SBOX_REGISTERS`), as the build spec accepts a degree-7 constraint.
//!
//! Layout (`membership-arm-b-poseidon2-gadget-design.md`), 285 columns/row:
//! `inputs[16]` ‖ 4×(`sbox[16]`‖`post[16]`) ‖ 13×`post_sbox` ‖ 4×(`sbox[16]`‖`post[16]`).
//! The external (`M_E`) and internal (`1+diag(V)`) linear layers are folded into expressions;
//! only S-box outputs and post-full-round states are stored (so each full round resets to
//! trace `Var`s). Max constraint degree = 7 (the S-box rows); all others degree 1.
//!
//! Validation: `generate_poseidon2_row` replays `lib_q_poseidon::poseidon2_baby_bear::
//! permute_with_trace` (the value-level reference, itself KAT-validated). The property test
//! confirms the in-circuit output equals `permute`, `check_constraints` accepts the honest
//! trace, and four corruption cases are rejected (the under-constrained-column hunt).
//!
//! HONESTY: this proves the gadget *computes Poseidon2 correctly and is fully constrained*.
//! It does NOT establish the round-count / parameter soundness (obligation packet; tier RED).

// Column-index helpers below document the layout; some are not yet referenced (RED/WIP gadget).
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use lib_q_poseidon::poseidon2_baby_bear::{
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    RC_EXTERNAL_FINAL,
    RC_EXTERNAL_INITIAL,
    RC_INTERNAL,
    WIDTH,
    internal_diag,
    permute_with_trace,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};

// ---- Column layout ----
const FULL_ROUND_COLS: usize = 2 * WIDTH; // sbox[16] + post[16]
const BEGIN_START: usize = WIDTH;
const PARTIAL_START: usize = BEGIN_START + HALF_FULL_ROUNDS * FULL_ROUND_COLS;
const END_START: usize = PARTIAL_START + PARTIAL_ROUNDS;
/// Total columns per row for the single-permutation Poseidon2 AIR (= 285).
pub const POSEIDON2_ROW_WIDTH: usize = END_START + HALF_FULL_ROUNDS * FULL_ROUND_COLS;

#[inline]
const fn begin_sbox_col(r: usize, i: usize) -> usize {
    BEGIN_START + r * FULL_ROUND_COLS + i
}
#[inline]
const fn begin_post_col(r: usize, i: usize) -> usize {
    BEGIN_START + r * FULL_ROUND_COLS + WIDTH + i
}
#[inline]
const fn partial_col(r: usize) -> usize {
    PARTIAL_START + r
}
#[inline]
const fn end_sbox_col(r: usize, i: usize) -> usize {
    END_START + r * FULL_ROUND_COLS + i
}
#[inline]
const fn end_post_col(r: usize, i: usize) -> usize {
    END_START + r * FULL_ROUND_COLS + WIDTH + i
}

/// `x^7` (the BabyBear S-box), as `(x^2)^2 * x^2 * x`.
#[inline]
fn pow7<E: PrimeCharacteristicRing + Clone>(x: E) -> E {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x2 * x
}

/// The external linear layer `M_E` over a generic ring element (`Var`/`Expr`/field):
/// `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]` per 4-block, then the outer circulant
/// (add the four column-sums `sums[i % 4]`). Identical algebra to the value-level
/// `external_linear_layer`, expressed on `E` for constraint building.
fn external_linear_expr<E: PrimeCharacteristicRing + Clone>(state: &[E]) -> Vec<E> {
    debug_assert_eq!(state.len(), WIDTH);
    let mut s: Vec<E> = state.to_vec();
    let mut c = 0;
    while c < WIDTH {
        let x0 = s[c].clone();
        let x1 = s[c + 1].clone();
        let x2 = s[c + 2].clone();
        let x3 = s[c + 3].clone();
        let t01 = x0.clone() + x1.clone();
        let t23 = x2.clone() + x3.clone();
        let t0123 = t01.clone() + t23.clone();
        let t01123 = t0123.clone() + x1;
        let t01233 = t0123 + x3;
        s[c + 3] = t01233.clone() + x0.double();
        s[c + 1] = t01123.clone() + x2.double();
        s[c] = t01123 + t01;
        s[c + 2] = t01233 + t23;
        c += 4;
    }
    let mut sums: [E; 4] = core::array::from_fn(|_| E::ZERO);
    for (k, slot) in sums.iter_mut().enumerate() {
        let mut acc = E::ZERO;
        let mut j = 0;
        while j < WIDTH {
            acc = acc + s[j + k].clone();
            j += 4;
        }
        *slot = acc;
    }
    (0..WIDTH)
        .map(|i| s[i].clone() + sums[i % 4].clone())
        .collect()
}

/// The in-circuit Poseidon2-BabyBear AIR: one permutation per row, no cross-row constraints.
#[derive(Debug, Clone, Copy, Default)]
pub struct Poseidon2Air;

impl<F: Field> BaseAir<F> for Poseidon2Air {
    fn width(&self) -> usize {
        POSEIDON2_ROW_WIDTH
    }

    /// Single-row AIR: no constraint reads the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

/// Intermediate columns one permutation consumes (everything except the 16 initial-state
/// columns): `2·4·32 + 13 = 269`. The reuse unit for the wide sponge / Merkle AIRs.
pub const POSEIDON2_PERM_INTERM_COLS: usize =
    2 * HALF_FULL_ROUNDS * FULL_ROUND_COLS + PARTIAL_ROUNDS;

const PARTIAL_REL: usize = HALF_FULL_ROUNDS * FULL_ROUND_COLS; // 128
const END_REL: usize = PARTIAL_REL + PARTIAL_ROUNDS; // 141

/// Constrain one Poseidon2 permutation of `initial_state` (16 expressions). This permutation's
/// intermediate columns occupy `[interm_start, interm_start + POSEIDON2_PERM_INTERM_COLS)`.
/// Applies the initial external linear layer internally; returns the final-state expressions
/// (the last ending round's `post` columns). Reuse entry point for the sponge / Merkle AIRs.
pub fn constrain_permutation<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    initial_state: &[AB::Expr],
    interm_start: usize,
) -> Vec<AB::Expr> {
    let main = builder.main();
    let local = main.current_slice();

    let mut state: Vec<AB::Expr> = external_linear_expr(initial_state);

    // Beginning full rounds.
    for r in 0..HALF_FULL_ROUNDS {
        let base = interm_start + FULL_ROUND_COLS * r;
        for i in 0..WIDTH {
            let arc = state[i].clone() + AB::Expr::from(RC_EXTERNAL_INITIAL[r][i]);
            builder.assert_eq(local[base + i].into(), pow7(arc));
        }
        let sbox_state: Vec<AB::Expr> = (0..WIDTH).map(|i| local[base + i].into()).collect();
        let post = external_linear_expr(&sbox_state);
        for i in 0..WIDTH {
            builder.assert_eq(local[base + WIDTH + i].into(), post[i].clone());
        }
        state = (0..WIDTH).map(|i| local[base + WIDTH + i].into()).collect();
    }

    // Partial rounds (single S-box on lane 0; internal matmul folded).
    let diag = internal_diag();
    for r in 0..PARTIAL_ROUNDS {
        let ps = interm_start + PARTIAL_REL + r;
        let arc = state[0].clone() + AB::Expr::from(RC_INTERNAL[r]);
        builder.assert_eq(local[ps].into(), pow7(arc));

        let mut pre: Vec<AB::Expr> = Vec::with_capacity(WIDTH);
        pre.push(local[ps].into());
        for i in 1..WIDTH {
            pre.push(state[i].clone());
        }
        let mut sum = AB::Expr::ZERO;
        for e in &pre {
            sum = sum + e.clone();
        }
        state = (0..WIDTH)
            .map(|i| AB::Expr::from(diag[i]) * pre[i].clone() + sum.clone())
            .collect();
    }

    // Ending full rounds.
    for r in 0..HALF_FULL_ROUNDS {
        let base = interm_start + END_REL + FULL_ROUND_COLS * r;
        for i in 0..WIDTH {
            let arc = state[i].clone() + AB::Expr::from(RC_EXTERNAL_FINAL[r][i]);
            builder.assert_eq(local[base + i].into(), pow7(arc));
        }
        let sbox_state: Vec<AB::Expr> = (0..WIDTH).map(|i| local[base + i].into()).collect();
        let post = external_linear_expr(&sbox_state);
        for i in 0..WIDTH {
            builder.assert_eq(local[base + WIDTH + i].into(), post[i].clone());
        }
        state = (0..WIDTH).map(|i| local[base + WIDTH + i].into()).collect();
    }

    state
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        // Initial state = input columns (0..16); intermediates at [16, 285).
        let inputs: Vec<AB::Expr> = {
            let main = builder.main();
            let local = main.current_slice();
            (0..WIDTH).map(|i| local[i].into()).collect()
        };
        let _final_state = constrain_permutation(builder, &inputs, BEGIN_START);
    }
}

/// Fill one permutation's 269 intermediate cells (in `constrain_permutation` column order)
/// AND return the final-state output. Reuse unit for the sponge / Merkle generators.
pub fn generate_permutation_cells_and_output(
    initial_state: [BabyBear; WIDTH],
) -> ([BabyBear; POSEIDON2_PERM_INTERM_COLS], [BabyBear; WIDTH]) {
    let tr = permute_with_trace(initial_state);
    let mut cells = [BabyBear::ZERO; POSEIDON2_PERM_INTERM_COLS];
    for r in 0..HALF_FULL_ROUNDS {
        let base = FULL_ROUND_COLS * r;
        for i in 0..WIDTH {
            cells[base + i] = tr.begin_sbox[r][i];
            cells[base + WIDTH + i] = tr.begin_post[r][i];
        }
    }
    for r in 0..PARTIAL_ROUNDS {
        cells[PARTIAL_REL + r] = tr.partial_post_sbox[r];
    }
    for r in 0..HALF_FULL_ROUNDS {
        let base = END_REL + FULL_ROUND_COLS * r;
        for i in 0..WIDTH {
            cells[base + i] = tr.end_sbox[r][i];
            cells[base + WIDTH + i] = tr.end_post[r][i];
        }
    }
    (cells, tr.output)
}

/// Just the 269 intermediate cells (see [`generate_permutation_cells_and_output`]).
pub fn generate_permutation_cells(
    initial_state: [BabyBear; WIDTH],
) -> [BabyBear; POSEIDON2_PERM_INTERM_COLS] {
    generate_permutation_cells_and_output(initial_state).0
}

/// Fill one standalone-AIR trace row: `inputs(16) ‖ intermediates(269)`.
pub fn generate_poseidon2_row(input: [BabyBear; WIDTH]) -> [BabyBear; POSEIDON2_ROW_WIDTH] {
    let mut row = [BabyBear::ZERO; POSEIDON2_ROW_WIDTH];
    row[..WIDTH].copy_from_slice(&input);
    row[BEGIN_START..].copy_from_slice(&generate_permutation_cells(input));
    row
}

/// The 16 output (digest) columns of a row = ending full round `HALF_FULL_ROUNDS-1` post.
#[inline]
pub fn output_cols_range() -> core::ops::Range<usize> {
    let start = end_post_col(HALF_FULL_ROUNDS - 1, 0);
    start..start + WIDTH
}

#[cfg(test)]
mod tests {
    use lib_q_stark_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::check_constraints;

    const P: u32 = 2_013_265_921; // BabyBear modulus

    /// Deterministic, varied test inputs (no rng dependency).
    fn det_input(seed: u32) -> [BabyBear; WIDTH] {
        let mut x = seed.wrapping_add(0x1234_5678);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    fn trace_values(seeds: &[u32]) -> Vec<BabyBear> {
        let mut values = Vec::with_capacity(seeds.len() * POSEIDON2_ROW_WIDTH);
        for &s in seeds {
            values.extend_from_slice(&generate_poseidon2_row(det_input(s)));
        }
        values
    }

    #[test]
    fn gadget_output_matches_value_level() {
        for s in 0..32u32 {
            let input = det_input(s);
            let row = generate_poseidon2_row(input);
            let r = output_cols_range();
            let out: [BabyBear; WIDTH] = core::array::from_fn(|i| row[r.start + i]);
            assert_eq!(out, lib_q_poseidon::poseidon2_baby_bear::permute(input));
        }
    }

    #[test]
    fn constraints_hold_on_valid_trace() {
        let trace =
            RowMajorMatrix::new(trace_values(&[0, 1, 2, 3, 4, 5, 6, 7]), POSEIDON2_ROW_WIDTH);
        check_constraints(&Poseidon2Air, &trace, &[]);
    }

    /// Corrupt one cell of row 0 and confirm `check_constraints` rejects it. `col` indexes
    /// into row 0 (each test pins a different stored column class).
    fn corrupted_trace(col: usize) -> RowMajorMatrix<BabyBear> {
        let mut values = trace_values(&[0, 1, 2, 3, 4, 5, 6, 7]);
        values[col] = values[col] + BabyBear::ONE;
        RowMajorMatrix::new(values, POSEIDON2_ROW_WIDTH)
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn corrupt_input_rejected() {
        check_constraints(&Poseidon2Air, &corrupted_trace(0), &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn corrupt_begin_sbox_rejected() {
        check_constraints(&Poseidon2Air, &corrupted_trace(begin_sbox_col(0, 5)), &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn corrupt_begin_post_rejected() {
        check_constraints(&Poseidon2Air, &corrupted_trace(begin_post_col(2, 9)), &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn corrupt_partial_post_sbox_rejected() {
        check_constraints(&Poseidon2Air, &corrupted_trace(partial_col(6)), &[]);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn corrupt_end_sbox_rejected() {
        check_constraints(&Poseidon2Air, &corrupted_trace(end_sbox_col(1, 0)), &[]);
    }

    /// EXHAUSTIVE under-constraint audit: mutate every one of the 285 columns (+1, trying each
    /// row) of a valid 8-row trace and require rejection. A surviving column would be a free
    /// witness in the permutation gadget. Covers all columns, not the 5 hand-picked classes above.
    #[test]
    fn under_constraint_audit_every_column() {
        use std::panic::{
            AssertUnwindSafe,
            catch_unwind,
        };
        let trace =
            RowMajorMatrix::new(trace_values(&[0, 1, 2, 3, 4, 5, 6, 7]), POSEIDON2_ROW_WIDTH);
        let width = POSEIDON2_ROW_WIDTH;
        let height = trace.values.len() / width;
        check_constraints(&Poseidon2Air, &trace, &[]);

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut survived = Vec::new();
        for col in 0..width {
            let mut rejected = false;
            for row in 0..height {
                let mut tr = trace.clone();
                let idx = row * width + col;
                tr.values[idx] = tr.values[idx] + BabyBear::ONE;
                if catch_unwind(AssertUnwindSafe(|| {
                    check_constraints(&Poseidon2Air, &tr, &[])
                }))
                .is_err()
                {
                    rejected = true;
                    break;
                }
            }
            if !rejected {
                survived.push(col);
            }
        }
        std::panic::set_hook(prev);
        assert!(survived.is_empty(), "UNCONSTRAINED columns: {survived:?}");
    }
}
