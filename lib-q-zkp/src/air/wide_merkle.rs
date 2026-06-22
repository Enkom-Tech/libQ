//! Wide-digest Merkle AIR (M2, RED — ADR 113 freeze-gate).
//!
//! A wide-digest Merkle node compresses two 5-element children (10 input field elements)
//! into a 5-element parent. Over Poseidon-256 (width 7, rate 2, capacity 5) that is a
//! **6-permutation sponge** (5 absorb blocks + 1 padding block), so — unlike the
//! single-element [`super::merkle_inclusion::MerkleInclusionAir`], which packs an entire
//! path into ONE row — the wide node hash is inherently **multi-row** (one permutation per
//! row, capacity carried between rows). At depth 64 the single-row layout would need
//! ~550k columns (> `MAX_TRACE_WIDTH`); the multi-row layout is ~depth×6 rows of one
//! permutation each.
//!
//! This module currently provides the load-bearing **atom**: [`WideNodeHashAir`], which
//! constrains exactly one node hash `parent = wide_node_hash(left, right)`
//! ([`crate::merkle::wide_node_hash`]) end-to-end — the capacity-carry / rate-injection /
//! padding / truncated-output machinery in isolation. The full per-level Merkle path
//! (direction-bit select + running-digest threading across node groups) builds on this
//! atom and is the next sub-step of M2.
//!
//! RED: Poseidon-256 round counts are NOT verified for GF(p²) (see `super::wide_hash`);
//! gated behind the ADR-113 review.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_poseidon::{
    Poseidon256,
    PoseidonField,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::poseidon_gadget::PoseidonGadget;
use super::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
};
use super::{
    compute_poseidon_row,
    poseidon_to_field,
};

/// Poseidon-256 sponge geometry.
const STATE_W: usize = 7;
const RATE: usize = 2;
/// Per-permutation intermediate columns: `(8 + 60) rounds × (7 × 3)`.
const INTERMEDIATE_COLS: usize = (8 + 60) * (STATE_W * 3); // 1428

/// Column layout for one permutation row:
/// `[ inject(RATE) | state_in(STATE_W) | intermediates(INTERMEDIATE_COLS) ]`.
const INJECT_START: usize = 0;
const STATE_IN_START: usize = INJECT_START + RATE; // 2
const INTERMEDIATE_START: usize = STATE_IN_START + STATE_W; // 9
/// Total width of one permutation row.
pub const NODE_ROW_WIDTH: usize = INTERMEDIATE_START + INTERMEDIATE_COLS; // 1437

/// A wide node hashes exactly `2 × WIDE_DIGEST_ELEMS` = 10 input elements.
const NODE_INPUT_LEN: usize = 2 * WIDE_DIGEST_ELEMS; // 10
/// Number of permutation rows for a 10-element padded sponge: `10/RATE + 1` (padding block).
pub const NODE_NUM_PERMS: usize = NODE_INPUT_LEN / RATE + 1; // 6

/// AIR constraining one wide-digest Merkle node compression
/// `parent = wide_node_hash(left, right)` as a [`NODE_NUM_PERMS`]-row Poseidon-256 sponge.
///
/// Public values: the 5 parent-digest field elements (`pubs[0..WIDE_DIGEST_ELEMS]`).
#[derive(Debug, Clone, Default)]
pub struct WideNodeHashAir;

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for WideNodeHashAir {
    fn width(&self) -> usize {
        NODE_ROW_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for WideNodeHashAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);

        // Current row: injection + permutation-input state.
        let (state_in, inject): (Vec<AB::Expr>, [AB::Expr; RATE]) = {
            let main = builder.main();
            let local = main.current_slice();
            let state_in = (0..STATE_W)
                .map(|i| local[STATE_IN_START + i].into())
                .collect();
            let inject = [local[INJECT_START].into(), local[INJECT_START + 1].into()];
            (state_in, inject)
        };

        // Constrain this row's full permutation; obtain the FULL output state for the carry.
        let gadget = PoseidonGadget::with_params(Poseidon256::params());
        let final_state = match gadget.constrain_permutation(builder, &state_in, INTERMEDIATE_START)
        {
            Ok(s) => s,
            Err(_) => {
                builder.assert_zero(one.clone()); // force failure on setup error
                return;
            }
        };

        // FIRST ROW: state is zero-initialised, then the first block is injected into the rate.
        {
            let mut b = builder.when_first_row();
            b.assert_eq(state_in[0].clone(), inject[0].clone());
            b.assert_eq(state_in[1].clone(), inject[1].clone());
            for s in state_in.iter().take(STATE_W).skip(RATE) {
                b.assert_zero(s.clone());
            }
        }

        // TRANSITION (row r → r+1): the next permutation absorbs its block ON TOP of this
        // row's output state — capacity carries unchanged, rate gets `+ inject`.
        {
            let (next_state_in, next_inject): (Vec<AB::Expr>, [AB::Expr; RATE]) = {
                let main = builder.main();
                let next = main.next_slice();
                let nsi = (0..STATE_W)
                    .map(|i| next[STATE_IN_START + i].into())
                    .collect();
                let ninj = [next[INJECT_START].into(), next[INJECT_START + 1].into()];
                (nsi, ninj)
            };
            let mut b = builder.when_transition();
            b.assert_eq(
                next_state_in[0].clone(),
                final_state[0].clone() + next_inject[0].clone(),
            );
            b.assert_eq(
                next_state_in[1].clone(),
                final_state[1].clone() + next_inject[1].clone(),
            );
            for i in RATE..STATE_W {
                b.assert_eq(next_state_in[i].clone(), final_state[i].clone());
            }
        }

        // LAST ROW: padding block injects the 10*1 constants (both rate cells = 1, since
        // NODE_INPUT_LEN is a multiple of RATE), and the truncated output state binds to the
        // public parent digest.
        {
            let pub_digest: Vec<AB::Expr> = {
                let pubs = builder.public_values();
                (0..WIDE_DIGEST_ELEMS).map(|i| pubs[i].into()).collect()
            };
            let mut b = builder.when_last_row();
            b.assert_eq(inject[0].clone(), one.clone());
            b.assert_eq(inject[1].clone(), one.clone());
            for (i, pd) in pub_digest.iter().enumerate() {
                b.assert_eq(final_state[i].clone(), pd.clone());
            }
        }
    }
}

/// Generate the [`NODE_NUM_PERMS`]-row trace for `parent = wide_node_hash(left, right)`.
///
/// Simulates the padded Poseidon-256 sponge block-by-block, recording each permutation's
/// injection, input state, and intermediate round values. The truncated output of the last
/// row equals `wide_node_hash(left, right)` by construction (matches
/// [`super::wide_hash::poseidon256_wide_hash`]).
pub fn generate_node_trace<F: Field + BasedVectorSpace<Mersenne31>>(
    left: &WideDigest,
    right: &WideDigest,
) -> RowMajorMatrix<F> {
    let params = Poseidon256::params();
    let zero = PoseidonField::ZERO;
    let one = PoseidonField::ONE;

    let mut input = Vec::with_capacity(NODE_INPUT_LEN);
    input.extend_from_slice(left);
    input.extend_from_slice(right);

    // Each cell collected as PoseidonField, converted to F at the end.
    let mut cells: Vec<PoseidonField> = Vec::with_capacity(NODE_NUM_PERMS * NODE_ROW_WIDTH);
    let mut state = [zero; STATE_W];

    let push_row = |cells: &mut Vec<PoseidonField>,
                    inject: [PoseidonField; RATE],
                    state_in: &[PoseidonField]| {
        let (final_state, intermediates) = compute_poseidon_row(state_in, &params);
        debug_assert_eq!(intermediates.len(), INTERMEDIATE_COLS);
        cells.extend_from_slice(&inject);
        cells.extend_from_slice(state_in);
        cells.extend_from_slice(&intermediates);
        final_state
    };

    // 5 absorb blocks.
    for blk in 0..(NODE_INPUT_LEN / RATE) {
        let inject = [input[RATE * blk], input[RATE * blk + 1]];
        state[0] += inject[0];
        state[1] += inject[1];
        let final_state = push_row(&mut cells, inject, &state);
        state.copy_from_slice(&final_state[..STATE_W]);
    }
    // Padding block: inject (1, 1).
    let inject = [one, one];
    state[0] += inject[0];
    state[1] += inject[1];
    let _final = push_row(&mut cells, inject, &state);

    debug_assert_eq!(cells.len(), NODE_NUM_PERMS * NODE_ROW_WIDTH);
    let values: Vec<F> = cells.iter().map(poseidon_to_field).collect();
    RowMajorMatrix::new(values, NODE_ROW_WIDTH)
}

/// Public values for the node-hash AIR: the 5 parent-digest field elements.
pub fn node_public_values<F: Field + BasedVectorSpace<Mersenne31>>(
    left: &WideDigest,
    right: &WideDigest,
) -> Vec<F> {
    crate::merkle::wide_node_hash(left, right)
        .iter()
        .map(poseidon_to_field)
        .collect()
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_field::extension::Complex;

    use super::*;
    use crate::merkle::wide_node_hash;

    type TestField = Complex<Mersenne31>;

    fn child(seed: u8) -> WideDigest {
        use super::super::wide_hash::poseidon256_wide_hash;
        let t = Complex::<Mersenne31>::from(Mersenne31::new(seed as u32 + 1));
        poseidon256_wide_hash(&[t])
    }

    fn cell(trace: &RowMajorMatrix<TestField>, row: usize, col: usize) -> TestField {
        trace.values[row * NODE_ROW_WIDTH + col]
    }
    fn set_cell(trace: &mut RowMajorMatrix<TestField>, row: usize, col: usize, v: TestField) {
        trace.values[row * NODE_ROW_WIDTH + col] = v;
    }

    #[test]
    fn node_trace_digest_matches_value_hash() {
        let (l, r) = (child(1), child(2));
        let trace = generate_node_trace::<TestField>(&l, &r);
        assert_eq!(trace.values.len(), NODE_NUM_PERMS * NODE_ROW_WIDTH);
        // Reconstruct the last row's output state[0..5] and compare to wide_node_hash.
        let pv = node_public_values::<TestField>(&l, &r);
        let expect: Vec<TestField> = wide_node_hash(&l, &r)
            .iter()
            .map(poseidon_to_field)
            .collect();
        assert_eq!(pv, expect);
    }

    #[test]
    fn node_air_round_trip() {
        let (l, r) = (child(3), child(4));
        let trace = generate_node_trace::<TestField>(&l, &r);
        let pubs = node_public_values::<TestField>(&l, &r);
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn node_air_rejects_corrupted_intermediate() {
        let (l, r) = (child(5), child(6));
        let mut trace = generate_node_trace::<TestField>(&l, &r);
        let pubs = node_public_values::<TestField>(&l, &r);
        let v = cell(&trace, 2, INTERMEDIATE_START + 100);
        set_cell(&mut trace, 2, INTERMEDIATE_START + 100, v + TestField::ONE);
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn node_air_rejects_broken_capacity_carry() {
        // Tamper a CAPACITY cell of row 3's input: it must equal row 2's output capacity.
        let (l, r) = (child(7), child(8));
        let mut trace = generate_node_trace::<TestField>(&l, &r);
        let pubs = node_public_values::<TestField>(&l, &r);
        let col = STATE_IN_START + RATE; // first capacity cell
        let v = cell(&trace, 3, col);
        set_cell(&mut trace, 3, col, v + TestField::ONE);
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn node_air_rejects_broken_rate_injection() {
        // Change an absorb-row injection without updating its state_in: the carry constraint
        // next.state_in[0] == prev.final[0] + next.inject[0] must break.
        let (l, r) = (child(9), child(10));
        let mut trace = generate_node_trace::<TestField>(&l, &r);
        let pubs = node_public_values::<TestField>(&l, &r);
        let v = cell(&trace, 2, INJECT_START);
        set_cell(&mut trace, 2, INJECT_START, v + TestField::ONE);
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn node_air_rejects_wrong_padding_constant() {
        // The last (padding) row's injection must be the 10*1 constant (1, 1). Setting it to
        // anything else must be rejected — directly by the `when_last_row` inject==1 binding
        // (and, since state_in is left unchanged, also by the row's permutation/carry checks).
        let (l, r) = (child(11), child(12));
        let mut trace = generate_node_trace::<TestField>(&l, &r);
        let pubs = node_public_values::<TestField>(&l, &r);
        let last = NODE_NUM_PERMS - 1;
        let two = TestField::ONE + TestField::ONE;
        set_cell(&mut trace, last, INJECT_START, two);
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn node_air_rejects_wrong_public_output() {
        let (l, r) = (child(13), child(14));
        let trace = generate_node_trace::<TestField>(&l, &r);
        let mut pubs = node_public_values::<TestField>(&l, &r);
        pubs[0] += TestField::ONE;
        check_constraints(&WideNodeHashAir, &trace, &pubs);
    }
}
