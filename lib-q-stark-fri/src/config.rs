use alloc::vec::Vec;
use core::fmt::Debug;

use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_matrix::Matrix;
use thiserror::Error;

/// A set of parameters defining a specific instance of the FRI protocol.
#[derive(Clone, Debug)]
pub struct FriParameters<M> {
    pub log_blowup: usize,
    /// Final polynomial length (2^log_final_poly_len). TwoAdicFriPcs uses this for early stopping;
    /// CirclePcs does not yet honor it in the verify path.
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

    /// Returns the *conjectured* soundness bits of this FRI instance, i.e. the query phase priced in
    /// the capacity regime of the [ethSTARK](https://eprint.iacr.org/2021/582) conjecture: each query
    /// contributes `log_blowup` bits (per-query soundness error `rate = 2^-log_blowup`).
    ///
    /// This is the *deployed* number (Plonky3 / ethSTARK / SP1 / Risc0), but it is NOT a proven
    /// bound. The strongest up-to-capacity soundness conjectures — including the
    /// mutual-correlated-agreement conjecture behind the newest RS-proximity schemes — were
    /// **disproved over large fields in late 2025** (see SoK: Hash-Based Polynomial Commitments and
    /// Low-Degree Tests, <https://eprint.iacr.org/2026/1367>). Soundness up to the Johnson bound is
    /// unaffected. Callers that need a *proven* number should use [`Self::johnson_soundness_bits`] and
    /// price parameters against it.
    pub const fn conjectured_soundness_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.proof_of_work_bits
    }

    /// Returns the *proven* (Johnson-bound) soundness bits of this FRI instance's query phase.
    ///
    /// In the Johnson list-decoding regime the per-query soundness error is `sqrt(rate)`, so each
    /// query contributes `log_blowup / 2` bits — half the conjectured rate. This follows from the
    /// Proximity Gaps analysis (BCIKS, <https://eprint.iacr.org/2020/654>) and, unlike
    /// [`Self::conjectured_soundness_bits`], rests on a theorem rather than a conjecture; it is
    /// unaffected by the late-2025 disproof of the up-to-capacity conjectures.
    ///
    /// Precisely: BCIKS gives per-query error `sqrt(rate) * (1 + eps)` for proximity strictly below
    /// `1 - sqrt(rate)`, plus an additive field-size term, so `log_blowup / 2` bits per query is the
    /// LIMIT of that bound rather than a strict lower bound including the lower-order terms. At
    /// production parameters the slack is far below the margin, but do not read this as a rigorous
    /// floor to the last bit. The integer division also floors, which errs in the safe direction.
    pub const fn johnson_soundness_bits(&self) -> usize {
        (self.log_blowup * self.num_queries) / 2 + self.proof_of_work_bits
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

#[cfg(test)]
mod tests {
    use super::*;

    // Params with a trivial mmcs so we can exercise the soundness accounting in isolation.
    const fn params(
        log_blowup: usize,
        num_queries: usize,
        proof_of_work_bits: usize,
    ) -> FriParameters<()> {
        FriParameters {
            log_blowup,
            log_final_poly_len: 0,
            num_queries,
            proof_of_work_bits,
            mmcs: (),
        }
    }

    #[test]
    fn conjectured_is_log_blowup_times_queries_plus_pow() {
        // Arm B membership production config: log_blowup 4 / q 96 / PoW 20.
        assert_eq!(params(4, 96, 20).conjectured_soundness_bits(), 4 * 96 + 20);
        // Arm A membership production config: log_blowup 3 / q 96 / PoW 20.
        assert_eq!(params(3, 96, 20).conjectured_soundness_bits(), 3 * 96 + 20);
    }

    #[test]
    fn johnson_is_half_the_query_rate() {
        // Johnson per-query error is sqrt(rate), i.e. log_blowup/2 bits per query. Matches the
        // provable-Johnson column of lib-q-zkp/tools/fri_soundness.py (Arm A 164, Arm B 212).
        assert_eq!(params(3, 96, 20).johnson_soundness_bits(), 3 * 96 / 2 + 20); // 164
        assert_eq!(params(4, 96, 20).johnson_soundness_bits(), 4 * 96 / 2 + 20); // 212
    }

    #[test]
    fn johnson_never_exceeds_conjectured() {
        for &(lb, q, pow) in &[
            (1, 100, 16),
            (2, 64, 16),
            (3, 96, 20),
            (4, 96, 20),
            (8, 1000, 64),
        ] {
            let p = params(lb, q, pow);
            assert!(
                p.johnson_soundness_bits() <= p.conjectured_soundness_bits(),
                "Johnson bound must not exceed the conjectured bound"
            );
        }
    }

    #[test]
    fn production_membership_configs_clear_128_on_the_proven_bound() {
        // The load-bearing check the SoK (eprint 2026/1367) motivates: production configs must
        // clear 128-bit on the PROVEN Johnson query bound, not only the conjectured one, so the
        // late-2025 disproof of the up-to-capacity conjectures does not touch the claimed level.
        assert!(params(3, 96, 20).johnson_soundness_bits() >= 128); // Arm A membership
        assert!(params(4, 96, 20).johnson_soundness_bits() >= 128); // Arm B membership
    }
}
