//! Poseidon permutation implementation
//!
//! This module implements the core Poseidon permutation function,
//! which consists of:
//! 1. AddRoundConstants (ARC)
//! 2. SubWords (S-box)
//! 3. MixLayer (MDS matrix multiplication)

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;

use crate::constants::sbox;
use crate::params::PoseidonParams;

/// Field type for permutation
type F = Complex<Mersenne31>;

/// Poseidon permutation state (variable length: state_width elements)
#[cfg(feature = "alloc")]
pub type PoseidonState = Vec<F>;

/// Poseidon permutation function
///
/// This implements the full Poseidon permutation with configurable
/// round counts and state width per parameter set.
#[derive(Debug, Clone)]
pub struct PoseidonPermutation {
    params: PoseidonParams,
}

impl PoseidonPermutation {
    /// Create a new Poseidon permutation with the given parameters
    pub fn new(params: PoseidonParams) -> Self {
        let n = params.state_width;
        assert!(
            (2..=16).contains(&n),
            "state_width must be in 2..=16, got {}",
            n
        );
        let required = (params.full_rounds + params.partial_rounds) * n;
        assert!(
            params.round_constants.len() >= required,
            "Insufficient round constants: need {}, have {}",
            required,
            params.round_constants.len()
        );
        assert_eq!(
            params.mds_matrix.len(),
            n,
            "MDS matrix must have {} rows",
            n
        );
        for (i, row) in params.mds_matrix.iter().enumerate() {
            assert_eq!(row.len(), n, "MDS matrix row {} must have {} columns", i, n);
        }
        Self { params }
    }

    /// Apply the Poseidon permutation to the state
    ///
    /// # Arguments
    ///
    /// * `state` - The state to permute (state_width field elements)
    ///
    /// # Returns
    ///
    /// The permuted state
    #[cfg(feature = "alloc")]
    pub fn permute(&self, mut state: PoseidonState) -> PoseidonState {
        let full_rounds_half = self.params.full_rounds / 2;
        let mut round_const_idx = 0;

        // First half of full rounds
        for _ in 0..full_rounds_half {
            state = self.full_round(state, &mut round_const_idx);
        }

        // Partial rounds
        for _ in 0..self.params.partial_rounds {
            state = self.partial_round(state, &mut round_const_idx);
        }

        // Second half of full rounds
        for _ in 0..full_rounds_half {
            state = self.full_round(state, &mut round_const_idx);
        }

        state
    }

    /// Apply a full round (S-box on all elements)
    #[cfg(feature = "alloc")]
    fn full_round(&self, mut state: PoseidonState, round_const_idx: &mut usize) -> PoseidonState {
        let n = self.params.state_width;
        for (i, s) in state.iter_mut().enumerate().take(n) {
            *s += self.params.round_constants[*round_const_idx + i];
        }
        *round_const_idx += n;
        for s in state.iter_mut().take(n) {
            *s = sbox(*s);
        }
        self.mix_layer(state)
    }

    /// Apply a partial round (S-box only on first element)
    #[cfg(feature = "alloc")]
    fn partial_round(
        &self,
        mut state: PoseidonState,
        round_const_idx: &mut usize,
    ) -> PoseidonState {
        let n = self.params.state_width;
        for (i, s) in state.iter_mut().enumerate().take(n) {
            *s += self.params.round_constants[*round_const_idx + i];
        }
        *round_const_idx += n;
        state[0] = sbox(state[0]);
        self.mix_layer(state)
    }

    /// Apply the MDS matrix multiplication (linear layer)
    #[cfg(feature = "alloc")]
    fn mix_layer(&self, state: PoseidonState) -> PoseidonState {
        let n = self.params.state_width;
        let mds = &self.params.mds_matrix;
        let mut new_state = alloc::vec![F::ZERO; n];
        for i in 0..n {
            for j in 0..n {
                new_state[i] += mds[i][j] * state[j];
            }
        }
        new_state
    }

    /// Get a reference to the parameters
    pub fn params(&self) -> &PoseidonParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::params::Poseidon128;

    #[test]
    fn test_permutation_idempotent() {
        let perm = Poseidon128::permutation();
        let state: PoseidonState = vec![
            F::ONE,
            F::from(Mersenne31::new(2)),
            F::from(Mersenne31::new(3)),
            F::from(Mersenne31::new(4)),
            F::from(Mersenne31::new(5)),
        ];
        let permuted = perm.permute(state.clone());
        assert_ne!(state, permuted);
    }

    #[test]
    fn test_permutation_deterministic() {
        let perm = Poseidon128::permutation();
        let state: PoseidonState = vec![
            F::ONE,
            F::from(Mersenne31::new(2)),
            F::from(Mersenne31::new(3)),
            F::from(Mersenne31::new(4)),
            F::from(Mersenne31::new(5)),
        ];
        let result1 = perm.permute(state.clone());
        let result2 = perm.permute(state);
        assert_eq!(result1, result2);
    }
}
