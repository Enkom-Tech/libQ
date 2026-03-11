//! Poseidon AIR Gadget - Reusable constraint system for Poseidon hash
//!
//! This module provides a reusable AIR gadget for constraining Poseidon hash
//! computations in zero-knowledge proofs. It implements full soundness by
//! constraining all intermediate round states.
//!
//! # Trace Layout
//!
//! For Poseidon-128 (state width 5, rate 2):
//! - Input: 2 field elements (rate = 2)
//! - Intermediate states: 5 elements × (full_rounds + partial_rounds) rounds × 3 (ARC, Sbox, MDS)
//! - Output: 1 field element
//!
//! Total columns per hash: 64 rounds × 15 = 960 columns
//!
//! # Constraints
//!
//! For each round:
//! 1. AddRoundConstants: state[i] + rc[r][i] = intermediate_after_arc[i]
//! 2. S-box: intermediate_after_arc[i]^5 = intermediate_after_sbox[i] (full rounds)
//!    or state[0]^5 = intermediate_after_sbox[0] (partial rounds)
//! 3. MDS: sum(mds[i][j] * intermediate_after_sbox[j]) = next_state[i]

extern crate alloc;

use alloc::vec::Vec;

use lib_q_poseidon::{
    Poseidon128,
    PoseidonField,
    PoseidonParams,
};
use lib_q_stark_air::{
    AirBuilder,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
};
use lib_q_stark_mersenne31::Mersenne31;

use super::{
    AirError,
    poseidon_to_field,
};

/// Round parameters shared across full and partial round constraints (read-only).
struct PoseidonRoundParams<'a> {
    round_constants: &'a [PoseidonField],
    mds: &'a [Vec<PoseidonField>],
    n: usize,
}

/// Reusable Poseidon AIR gadget for constraining hash computations
///
/// This gadget can be embedded in other AIRs to provide full soundness
/// for Poseidon hash operations. It constrains all intermediate states
/// of the Poseidon permutation.
#[derive(Debug, Clone)]
pub struct PoseidonGadget {
    /// Poseidon-128 parameters (state_width 5 for 128-bit security)
    params: PoseidonParams,
}

impl PoseidonGadget {
    /// Number of columns required per hash computation for intermediate states
    ///
    /// For each round, we store state_width columns for ARC, Sbox, and MDS.
    /// Poseidon-128: 64 rounds × (5 × 3) = 960 columns per hash
    pub const COLUMNS_PER_HASH: usize = (8 + 56) * (5 * 3);

    /// Create a new PoseidonGadget with Poseidon-128 parameters
    pub fn new() -> Self {
        Self {
            params: Poseidon128::params(),
        }
    }

    /// Get the Poseidon parameters
    pub fn params(&self) -> &PoseidonParams {
        &self.params
    }

    /// Add constraints for a single Poseidon hash computation (2-input rate).
    ///
    /// This constrains that `Poseidon(left, right, 0, 0, 0) = output` by verifying all
    /// intermediate round states stored in the trace.
    pub fn constrain<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        left: AB::Expr,
        right: AB::Expr,
        output: AB::Expr,
        intermediate_start_col: usize,
    ) -> Result<(), AirError>
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;
        let n = self.params.state_width;
        let zero_expr = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
        let initial_state: Vec<AB::Expr> = (0..n)
            .map(|i| {
                if i == 0 {
                    left.clone()
                } else if i == 1 {
                    right.clone()
                } else {
                    zero_expr.clone()
                }
            })
            .collect();
        self.constrain_full_state(builder, &initial_state, output, intermediate_start_col)
    }

    /// Add constraints for a single Poseidon permutation with full n-element initial state.
    ///
    /// Use this for multi-row sponge traces where capacity state (positions 2..n) carries
    /// from the previous row. `initial_state` must have exactly `self.params.state_width`
    /// elements.
    pub fn constrain_full_state<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        initial_state: &[AB::Expr],
        output: AB::Expr,
        intermediate_start_col: usize,
    ) -> Result<(), AirError>
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        let main = builder.main();
        let local = main.current_slice();

        let full_rounds = self.params.full_rounds;
        let partial_rounds = self.params.partial_rounds;
        let full_rounds_half = full_rounds / 2;
        let n = self.params.state_width;
        if initial_state.len() != n {
            return Err(AirError::InvalidDimensions {
                reason: alloc::format!(
                    "initial_state must have {} elements, got {}",
                    n,
                    initial_state.len()
                ),
            });
        }
        let mds = &self.params.mds_matrix;
        let round_constants = &self.params.round_constants;

        let mut state: Vec<AB::Expr> = initial_state.to_vec();
        let mut round_const_idx = 0;
        let mut intermediate_col = intermediate_start_col;
        let round_params = PoseidonRoundParams {
            round_constants,
            mds,
            n,
        };

        for _ in 0..full_rounds_half {
            state = self.constrain_full_round(
                builder,
                &state,
                &round_params,
                &mut round_const_idx,
                &local,
                &mut intermediate_col,
            )?;
        }
        for _ in 0..partial_rounds {
            state = self.constrain_partial_round(
                builder,
                &state,
                &round_params,
                &mut round_const_idx,
                &local,
                &mut intermediate_col,
            )?;
        }
        for _ in 0..full_rounds_half {
            state = self.constrain_full_round(
                builder,
                &state,
                &round_params,
                &mut round_const_idx,
                &local,
                &mut intermediate_col,
            )?;
        }

        builder.assert_eq(state[0].clone(), output);
        Ok(())
    }

    fn constrain_full_round<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        state: &[AB::Expr],
        params: &PoseidonRoundParams<'_>,
        round_const_idx: &mut usize,
        local: &[AB::Var],
        intermediate_col: &mut usize,
    ) -> Result<Vec<AB::Expr>, AirError>
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;
        let zero = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
        let n = params.n;

        for i in 0..n {
            let rc_field =
                poseidon_to_field::<AB::F>(&params.round_constants[*round_const_idx + i]);
            let expected = state[i].clone() + AB::Expr::from(rc_field);
            builder.assert_eq(local[*intermediate_col + i].clone().into(), expected);
        }
        *round_const_idx += n;
        *intermediate_col += n;

        for i in 0..n {
            let arc_val = local[*intermediate_col - n + i].clone();
            let arc_sq = arc_val.clone() * arc_val.clone();
            let arc_quad = arc_sq.clone() * arc_sq.clone();
            let expected_sbox = arc_quad * arc_val;
            builder.assert_eq(local[*intermediate_col + i].clone().into(), expected_sbox);
        }
        *intermediate_col += n;

        let mut next_state: Vec<AB::Expr> = (0..n).map(|_| zero.clone()).collect();
        for i in 0..n {
            for j in 0..n {
                let sbox_val = local[*intermediate_col - n + j].clone();
                let mds_field = poseidon_to_field::<AB::F>(&params.mds[i][j]);
                next_state[i] = next_state[i].clone() + AB::Expr::from(mds_field) * sbox_val;
            }
            builder.assert_eq(
                local[*intermediate_col + i].clone().into(),
                next_state[i].clone(),
            );
        }
        *intermediate_col += n;

        Ok(next_state)
    }

    fn constrain_partial_round<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        state: &[AB::Expr],
        params: &PoseidonRoundParams<'_>,
        round_const_idx: &mut usize,
        local: &[AB::Var],
        intermediate_col: &mut usize,
    ) -> Result<Vec<AB::Expr>, AirError>
    where
        AB::F: Field + BasedVectorSpace<Mersenne31>,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;
        let zero = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
        let n = params.n;

        for i in 0..n {
            let rc_field =
                poseidon_to_field::<AB::F>(&params.round_constants[*round_const_idx + i]);
            let expected = state[i].clone() + AB::Expr::from(rc_field);
            builder.assert_eq(local[*intermediate_col + i].clone().into(), expected);
        }
        *round_const_idx += n;
        *intermediate_col += n;

        let arc_val_0 = local[*intermediate_col - n].clone();
        let arc_sq_0 = arc_val_0.clone() * arc_val_0.clone();
        let arc_quad_0 = arc_sq_0.clone() * arc_sq_0.clone();
        let expected_sbox_0 = arc_quad_0 * arc_val_0;
        builder.assert_eq(local[*intermediate_col].clone().into(), expected_sbox_0);
        for i in 1..n {
            builder.assert_eq(
                local[*intermediate_col + i].clone().into(),
                local[*intermediate_col - n + i].clone().into(),
            );
        }
        *intermediate_col += n;

        let mut next_state: Vec<AB::Expr> = (0..n).map(|_| zero.clone()).collect();
        for i in 0..n {
            for j in 0..n {
                let sbox_val = local[*intermediate_col - n + j].clone();
                let mds_field = poseidon_to_field::<AB::F>(&params.mds[i][j]);
                next_state[i] = next_state[i].clone() + AB::Expr::from(mds_field) * sbox_val;
            }
            builder.assert_eq(
                local[*intermediate_col + i].clone().into(),
                next_state[i].clone(),
            );
        }
        *intermediate_col += n;

        Ok(next_state)
    }
}

impl Default for PoseidonGadget {
    fn default() -> Self {
        Self::new()
    }
}
