//! Poseidon parameter sets for different security levels
//!
//! This module defines standard Poseidon parameter configurations optimized
//! for Complex<Mersenne31> field.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;

use crate::constants::{
    mds_matrix_5x5,
    mds_matrix_7x7,
    round_constants_128,
    round_constants_256,
};
use crate::permutation::PoseidonPermutation;

/// Field type used for Poseidon
pub type PoseidonField = Complex<Mersenne31>;

/// Poseidon parameter configuration
///
/// MDS matrix is stored as row-major Vec<Vec<F>> to support state widths 5 and 7
/// (128-bit and 256-bit security over Complex<Mersenne31>).
#[derive(Debug, Clone)]
pub struct PoseidonParams {
    /// State width (number of field elements)
    pub state_width: usize,
    /// Rate (number of elements absorbed per permutation)
    pub rate: usize,
    /// Capacity (security parameter)
    pub capacity: usize,
    /// Number of full rounds
    pub full_rounds: usize,
    /// Number of partial rounds
    pub partial_rounds: usize,
    /// Round constants
    pub round_constants: Vec<PoseidonField>,
    /// MDS matrix (state_width × state_width)
    pub mds_matrix: Vec<Vec<PoseidonField>>,
}

/// Poseidon-128 parameters for 128-bit security over Complex<Mersenne31>
///
/// Configuration:
/// - State width: 5 (rate=2, capacity=3) for 3×62 ≥ 128 bits
/// - Full rounds: 8 (4 before partial, 4 after)
/// - Partial rounds: 56
/// - S-box: x^5
pub struct Poseidon128;

impl Poseidon128 {
    /// Returns the Poseidon-128 permutation instance.
    pub fn permutation() -> PoseidonPermutation {
        PoseidonPermutation::new(Self::params())
    }

    /// Get Poseidon-128 parameters
    pub fn params() -> PoseidonParams {
        PoseidonParams {
            state_width: 5,
            rate: 2,
            capacity: 3,
            full_rounds: 8,
            partial_rounds: 56,
            round_constants: round_constants_128(),
            mds_matrix: mds_matrix_5x5(),
        }
    }
}

impl Default for Poseidon128 {
    fn default() -> Self {
        Self
    }
}

/// Poseidon-256 parameters for 256-bit security over Complex<Mersenne31>
///
/// Configuration:
/// - State width: 7 (rate=2, capacity=5) for 5×62 ≥ 256 bits
/// - Full rounds: 8 (4 before partial, 4 after)
/// - Partial rounds: 60
/// - S-box: x^5
pub struct Poseidon256;

impl Poseidon256 {
    /// Returns the Poseidon-256 permutation instance.
    pub fn permutation() -> PoseidonPermutation {
        PoseidonPermutation::new(Self::params())
    }

    /// Get Poseidon-256 parameters
    pub fn params() -> PoseidonParams {
        PoseidonParams {
            state_width: 7,
            rate: 2,
            capacity: 5,
            full_rounds: 8,
            partial_rounds: 60,
            round_constants: round_constants_256(),
            mds_matrix: mds_matrix_7x7(),
        }
    }
}

impl Default for Poseidon256 {
    fn default() -> Self {
        Self
    }
}
