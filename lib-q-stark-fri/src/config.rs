use alloc::vec::Vec;
use core::fmt::Debug;

use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_matrix::Matrix;
use thiserror::Error;

/// A set of parameters defining a specific instance of the FRI protocol.
#[derive(Debug)]
pub struct FriParameters<M> {
    pub log_blowup: usize,
    // TODO: This parameter and FRI early stopping are not yet implemented in `CirclePcs`.
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
    pub mmcs: M,
}

impl<M> FriParameters<M> {
    pub const fn blowup(&self) -> usize {
        1 << self.log_blowup
    }

    pub const fn final_poly_len(&self) -> usize {
        1 << self.log_final_poly_len
    }

    /// Returns the soundness bits of this FRI instance based on the
    /// [ethSTARK](https://eprint.iacr.org/2021/582) conjecture.
    ///
    /// Certain users may instead want to look at proven soundness, a more complex calculation which
    /// isn't currently supported by this crate.
    pub const fn conjectured_soundness_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.proof_of_work_bits
    }

    /// Validate FRI parameters for security and correctness.
    ///
    /// This function checks that all parameters are within acceptable ranges
    /// to ensure both security and computational feasibility.
    ///
    /// # Returns
    /// `Ok(())` if parameters are valid, `Err(FriParameterError)` otherwise.
    ///
    /// # Security
    /// Invalid parameters can lead to:
    /// - Reduced security (insufficient soundness)
    /// - Computational errors (overflow, underflow)
    /// - Performance issues (excessive memory usage)
    pub fn validate(&self) -> Result<(), FriParameterError> {
        const MIN_LOG_BLOWUP: usize = 1;
        const MAX_LOG_BLOWUP: usize = 8;
        const MIN_NUM_QUERIES: usize = 1;
        const MAX_NUM_QUERIES: usize = 1000;
        const MAX_LOG_FINAL_POLY_LEN: usize = 32;
        const MAX_PROOF_OF_WORK_BITS: usize = 64;

        if self.log_blowup < MIN_LOG_BLOWUP || self.log_blowup > MAX_LOG_BLOWUP {
            return Err(FriParameterError::InvalidLogBlowup {
                value: self.log_blowup,
                min: MIN_LOG_BLOWUP,
                max: MAX_LOG_BLOWUP,
            });
        }

        if self.num_queries < MIN_NUM_QUERIES || self.num_queries > MAX_NUM_QUERIES {
            return Err(FriParameterError::InvalidNumQueries {
                value: self.num_queries,
                min: MIN_NUM_QUERIES,
                max: MAX_NUM_QUERIES,
            });
        }

        if self.log_final_poly_len > MAX_LOG_FINAL_POLY_LEN {
            return Err(FriParameterError::InvalidLogFinalPolyLen {
                value: self.log_final_poly_len,
                max: MAX_LOG_FINAL_POLY_LEN,
            });
        }

        if self.proof_of_work_bits > MAX_PROOF_OF_WORK_BITS {
            return Err(FriParameterError::InvalidProofOfWorkBits {
                value: self.proof_of_work_bits,
                max: MAX_PROOF_OF_WORK_BITS,
            });
        }

        // Check that blowup is a power of 2 (log_blowup is already validated)
        // This is implicitly true since blowup = 1 << log_blowup

        Ok(())
    }
}

/// Errors that can occur when validating FRI parameters.
#[derive(Debug, Error)]
pub enum FriParameterError {
    /// `log_blowup` is outside the valid range.
    #[error("log_blowup ({value}) must be between {min} and {max}")]
    InvalidLogBlowup {
        value: usize,
        min: usize,
        max: usize,
    },
    /// `num_queries` is outside the valid range.
    #[error("num_queries ({value}) must be between {min} and {max}")]
    InvalidNumQueries {
        value: usize,
        min: usize,
        max: usize,
    },
    /// `log_final_poly_len` exceeds the maximum allowed value.
    #[error("log_final_poly_len ({value}) must not exceed {max}")]
    InvalidLogFinalPolyLen { value: usize, max: usize },
    /// `proof_of_work_bits` exceeds the maximum allowed value.
    #[error("proof_of_work_bits ({value}) must not exceed {max}")]
    InvalidProofOfWorkBits { value: usize, max: usize },
}

/// Whereas `FriParameters` encompasses parameters the end user can set, `FriFoldingStrategy` is
/// set by the PCS calling FRI, and abstracts over implementation details of the PCS.
pub trait FriFoldingStrategy<F: Field, EF: ExtensionField<F>> {
    type InputProof;
    type InputError: Debug;

    /// We can ask FRI to sample extra query bits (LSB) for our own purposes.
    /// They will be passed to our callbacks, but ignored (shifted off) by FRI.
    fn extra_query_index_bits(&self) -> usize;

    /// Fold a row, returning a single column.
    /// Right now the input row will always be 2 columns wide,
    /// but we may support higher folding arity in the future.
    fn fold_row(
        &self,
        index: usize,
        log_height: usize,
        beta: EF,
        evals: impl Iterator<Item = EF>,
    ) -> EF;

    /// Same as applying fold_row to every row, possibly faster.
    fn fold_matrix<M: Matrix<EF>>(&self, beta: EF, m: M) -> Vec<EF>;
}

/// Creates a minimal set of `FriParameters` for testing purposes.
/// These parameters are designed to reduce computational cost during tests.
pub const fn create_test_fri_params<Mmcs>(
    mmcs: Mmcs,
    log_final_poly_len: usize,
) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len,
        num_queries: 2,
        proof_of_work_bits: 1,
        mmcs,
    }
}

/// Creates a minimal set of `FriParameters` for testing purposes, with zk enabled.
/// These parameters are designed to reduce computational cost during tests.
pub const fn create_test_fri_params_zk<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 2,
        proof_of_work_bits: 1,
        mmcs,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking.
/// These parameters represent typical settings used in production-like scenarios.
pub const fn create_benchmark_fri_params<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking with zk enabled.
/// These parameters represent typical settings used in production-like scenarios.
pub const fn create_benchmark_fri_params_zk<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs,
    }
}
