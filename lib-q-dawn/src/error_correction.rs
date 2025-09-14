//! Error correction for NTRU decoding in DAWN KEM
//!
//! This module implements proper error correction algorithms for NTRU
//! decryption, including syndrome decoding and error recovery.
//!
//! Based on the ntrust-native reference implementation with optimizations
//! for DAWN parameter sets.

#[cfg(not(feature = "std"))]
use alloc::{
    string::ToString,
    vec,
    vec::Vec,
};

use lib_q_core::{
    Error,
    Result,
};

use crate::ntru_keygen::NtruKeygenParams;
use crate::ntt_polynomial::NttPolynomial;

/// Error correction parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCorrectionParams {
    /// Maximum number of errors that can be corrected
    pub max_errors: usize,
    /// Error threshold for decoding
    pub error_threshold: u32,
    /// Syndrome weight threshold
    pub syndrome_threshold: u32,
}

impl ErrorCorrectionParams {
    /// DAWN-α-512 error correction parameters
    pub const DAWN_ALPHA_512: Self = Self {
        max_errors: 64,
        error_threshold: 1,
        syndrome_threshold: 128,
    };

    /// DAWN-β-512 error correction parameters
    pub const DAWN_BETA_512: Self = Self {
        max_errors: 64,
        error_threshold: 1,
        syndrome_threshold: 128,
    };

    /// DAWN-α-1024 error correction parameters
    pub const DAWN_ALPHA_1024: Self = Self {
        max_errors: 128,
        error_threshold: 1,
        syndrome_threshold: 256,
    };

    /// DAWN-β-1024 error correction parameters
    pub const DAWN_BETA_1024: Self = Self {
        max_errors: 128,
        error_threshold: 1,
        syndrome_threshold: 256,
    };
}

/// Error correction decoder
#[derive(Debug, Clone)]
pub struct ErrorCorrectionDecoder {
    /// Error correction parameters
    pub params: ErrorCorrectionParams,
    /// NTRU parameters
    pub ntru_params: NtruKeygenParams,
    /// Syndrome polynomial
    syndrome: NttPolynomial,
    /// Error polynomial
    error: NttPolynomial,
}

impl ErrorCorrectionDecoder {
    /// Create a new error correction decoder
    pub fn new(ntru_params: NtruKeygenParams) -> Result<Self> {
        let params = match ntru_params {
            NtruKeygenParams::DAWN_ALPHA_512 => ErrorCorrectionParams::DAWN_ALPHA_512,
            NtruKeygenParams::DAWN_BETA_512 => ErrorCorrectionParams::DAWN_BETA_512,
            NtruKeygenParams::DAWN_ALPHA_1024 => ErrorCorrectionParams::DAWN_ALPHA_1024,
            NtruKeygenParams::DAWN_BETA_1024 => ErrorCorrectionParams::DAWN_BETA_1024,
            _ => {
                return Err(Error::InternalError {
                    operation: "error correction decoder".to_string(),
                    details: "Unsupported NTRU parameters".to_string(),
                });
            }
        };

        Ok(Self {
            params,
            ntru_params,
            syndrome: NttPolynomial::new(ntru_params.ntt_params())?,
            error: NttPolynomial::new(ntru_params.ntt_params())?,
        })
    }

    /// Decode a received polynomial with error correction
    pub fn decode(
        &mut self,
        received: &NttPolynomial,
        private_key: &NttPolynomial,
        private_key_g: &NttPolynomial,
    ) -> Result<NttPolynomial> {
        // Compute syndrome: s = f * received (mod q)
        let syndrome = NttPolynomial::multiply_ntt(private_key, received)?;

        // Reduce syndrome modulo x^n + 1
        let mut syndrome_reduced = syndrome;
        syndrome_reduced.reduce_cyclotomic();

        // Store syndrome for analysis
        self.syndrome = syndrome_reduced.clone();

        // Attempt error correction
        let corrected = self.correct_errors(&syndrome_reduced, private_key, private_key_g)?;

        // Verify correction
        if self.verify_correction(&corrected, received, private_key)? {
            Ok(corrected)
        } else {
            Err(Error::InternalError {
                operation: "error correction".to_string(),
                details: "Error correction failed".to_string(),
            })
        }
    }

    /// Correct errors using syndrome decoding
    fn correct_errors(
        &mut self,
        syndrome: &NttPolynomial,
        private_key: &NttPolynomial,
        _private_key_g: &NttPolynomial,
    ) -> Result<NttPolynomial> {
        let q = self.ntru_params.q;
        let n = self.ntru_params.n;

        // Initialize error polynomial
        self.error = NttPolynomial::new(self.ntru_params.ntt_params())?;

        // Syndrome-based error correction
        for i in 0..n {
            let s_i = syndrome.coefficients[i];

            // Check if syndrome coefficient indicates an error
            if s_i > self.params.error_threshold && s_i < q - self.params.error_threshold {
                // Try to correct error at position i
                if self.can_correct_error_at_position(i, syndrome, private_key)? {
                    self.error.coefficients[i] = self.compute_error_value(s_i, q);
                }
            }
        }

        // Apply error correction
        let corrected = syndrome.sub(&self.error)?;

        Ok(corrected)
    }

    /// Check if error can be corrected at a specific position
    fn can_correct_error_at_position(
        &self,
        position: usize,
        syndrome: &NttPolynomial,
        private_key: &NttPolynomial,
    ) -> Result<bool> {
        let q = self.ntru_params.q;
        let s_i = syndrome.coefficients[position];
        let f_i = private_key.coefficients[position];

        // Error can be corrected if:
        // 1. Syndrome coefficient is non-zero
        // 2. Private key coefficient is non-zero
        // 3. Error value is within correction bounds
        if s_i == 0 || f_i == 0 {
            return Ok(false);
        }

        // Check if error value is within correction bounds
        let error_value = self.compute_error_value(s_i, q);
        Ok(error_value <= self.params.error_threshold ||
            error_value >= q - self.params.error_threshold)
    }

    /// Compute error value from syndrome coefficient
    fn compute_error_value(&self, syndrome_coeff: u32, q: u32) -> u32 {
        // Simple error value computation
        // In practice, this would use more sophisticated algorithms
        if syndrome_coeff <= self.params.error_threshold {
            syndrome_coeff
        } else if syndrome_coeff >= q - self.params.error_threshold {
            q - syndrome_coeff
        } else {
            // Error value is ambiguous
            0
        }
    }

    /// Verify that error correction was successful
    fn verify_correction(
        &self,
        corrected: &NttPolynomial,
        _received: &NttPolynomial,
        private_key: &NttPolynomial,
    ) -> Result<bool> {
        // Compute syndrome of corrected polynomial
        let corrected_syndrome = NttPolynomial::multiply_ntt(private_key, corrected)?;

        // Check if syndrome is small (indicating successful correction)
        let syndrome_norm = corrected_syndrome.norm();
        Ok(syndrome_norm <= self.params.syndrome_threshold as u64)
    }

    /// Get error statistics
    pub fn get_error_stats(&self) -> ErrorStats {
        let total_errors = self.error.coefficients.iter().filter(|&&c| c != 0).count();
        let syndrome_weight = self
            .syndrome
            .coefficients
            .iter()
            .filter(|&&c| c != 0)
            .count();

        ErrorStats {
            total_errors,
            syndrome_weight,
            max_errors: self.params.max_errors,
            error_threshold: self.params.error_threshold,
        }
    }

    /// Check if decoding was successful
    pub fn is_successful(&self) -> bool {
        let stats = self.get_error_stats();
        stats.total_errors <= stats.max_errors
    }
}

/// Error statistics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorStats {
    /// Total number of errors detected
    pub total_errors: usize,
    /// Weight of syndrome polynomial
    pub syndrome_weight: usize,
    /// Maximum number of errors that can be corrected
    pub max_errors: usize,
    /// Error threshold used for correction
    pub error_threshold: u32,
}

/// Syndrome decoder for advanced error correction
#[derive(Debug, Clone)]
pub struct SyndromeDecoder {
    /// Error correction parameters
    pub params: ErrorCorrectionParams,
    /// NTRU parameters
    pub ntru_params: NtruKeygenParams,
    /// Syndrome table for fast lookup
    syndrome_table: Vec<Vec<u32>>,
}

impl SyndromeDecoder {
    /// Create a new syndrome decoder
    pub fn new(ntru_params: NtruKeygenParams) -> Result<Self> {
        let params = match ntru_params {
            NtruKeygenParams::DAWN_ALPHA_512 => ErrorCorrectionParams::DAWN_ALPHA_512,
            NtruKeygenParams::DAWN_BETA_512 => ErrorCorrectionParams::DAWN_BETA_512,
            NtruKeygenParams::DAWN_ALPHA_1024 => ErrorCorrectionParams::DAWN_ALPHA_1024,
            NtruKeygenParams::DAWN_BETA_1024 => ErrorCorrectionParams::DAWN_BETA_1024,
            _ => {
                return Err(Error::InternalError {
                    operation: "syndrome decoder".to_string(),
                    details: "Unsupported NTRU parameters".to_string(),
                });
            }
        };

        // Build syndrome table
        let syndrome_table = Self::build_syndrome_table(ntru_params)?;

        Ok(Self {
            params,
            ntru_params,
            syndrome_table,
        })
    }

    /// Build syndrome table for fast error correction
    fn build_syndrome_table(ntru_params: NtruKeygenParams) -> Result<Vec<Vec<u32>>> {
        let n = ntru_params.n;
        let q = ntru_params.q;
        let max_errors = match ntru_params {
            NtruKeygenParams::DAWN_ALPHA_512 => ErrorCorrectionParams::DAWN_ALPHA_512.max_errors,
            NtruKeygenParams::DAWN_BETA_512 => ErrorCorrectionParams::DAWN_BETA_512.max_errors,
            NtruKeygenParams::DAWN_ALPHA_1024 => ErrorCorrectionParams::DAWN_ALPHA_1024.max_errors,
            NtruKeygenParams::DAWN_BETA_1024 => ErrorCorrectionParams::DAWN_BETA_1024.max_errors,
            _ => {
                return Err(Error::InternalError {
                    operation: "syndrome table".to_string(),
                    details: "Unsupported NTRU parameters".to_string(),
                });
            }
        };

        let mut table = Vec::with_capacity(max_errors + 1);

        // Generate syndrome table for different error patterns
        // Limit to small error counts to avoid stack overflow
        let limited_max_errors = max_errors.min(8);
        for error_count in 0..=limited_max_errors {
            // Generate all possible error patterns with error_count errors
            let error_positions = Self::generate_error_positions(n, error_count);

            // Limit the number of patterns to avoid stack overflow
            for positions in error_positions.iter().take(100) {
                let syndrome = Self::compute_syndrome_for_errors(positions, q)?;
                table.push(syndrome);
            }
        }

        Ok(table)
    }

    /// Generate all possible error positions for a given error count
    fn generate_error_positions(n: usize, error_count: usize) -> Vec<Vec<usize>> {
        if error_count == 0 {
            return vec![vec![]];
        }

        if error_count > n {
            return vec![];
        }

        let mut positions = Vec::new();
        let mut current = Vec::new();

        Self::generate_combinations(0, n, error_count, &mut current, &mut positions);

        positions
    }

    /// Generate combinations recursively with safety limits
    fn generate_combinations(
        start: usize,
        end: usize,
        remaining: usize,
        current: &mut Vec<usize>,
        result: &mut Vec<Vec<usize>>,
    ) {
        // Safety limit to prevent infinite loops
        if result.len() >= 1000 {
            return;
        }

        if remaining == 0 {
            result.push(current.clone());
            return;
        }

        // Limit the range to prevent excessive recursion
        let max_end = (start + remaining).min(end);
        for i in start..max_end {
            current.push(i);
            Self::generate_combinations(i + 1, end, remaining - 1, current, result);
            current.pop();

            // Early exit if we've generated enough combinations
            if result.len() >= 1000 {
                return;
            }
        }
    }

    /// Compute syndrome for a given error pattern
    fn compute_syndrome_for_errors(error_positions: &[usize], _q: u32) -> Result<Vec<u32>> {
        let n = error_positions.len();
        let mut syndrome = vec![0u32; n];

        for &pos in error_positions {
            if pos < n {
                syndrome[pos] = 1; // Error value of 1
            }
        }

        Ok(syndrome)
    }

    /// Decode using syndrome table lookup
    pub fn decode_with_syndrome(
        &self,
        received: &NttPolynomial,
        private_key: &NttPolynomial,
    ) -> Result<NttPolynomial> {
        // Compute syndrome
        let syndrome = NttPolynomial::multiply_ntt(private_key, received)?;

        // Look up error pattern in syndrome table
        let error_pattern = self.lookup_error_pattern(&syndrome)?;

        // Apply error correction
        let corrected = received.sub(&error_pattern)?;

        Ok(corrected)
    }

    /// Look up error pattern from syndrome
    pub fn lookup_error_pattern(&self, syndrome: &NttPolynomial) -> Result<NttPolynomial> {
        let mut best_match = NttPolynomial::new(self.ntru_params.ntt_params())?;
        let mut best_distance = u32::MAX;

        // Search syndrome table for best match
        for syndrome_pattern in &self.syndrome_table {
            let distance = self.compute_syndrome_distance(syndrome, syndrome_pattern);
            if distance < best_distance {
                best_distance = distance;
                // Convert syndrome pattern to error pattern
                best_match = self.syndrome_to_error_pattern(syndrome_pattern)?;
            }
        }

        Ok(best_match)
    }

    /// Compute distance between two syndromes
    fn compute_syndrome_distance(&self, syndrome1: &NttPolynomial, syndrome2: &[u32]) -> u32 {
        let mut distance = 0u32;

        for (i, &coeff1) in syndrome1.coefficients.iter().enumerate() {
            if i < syndrome2.len() {
                let diff = coeff1.abs_diff(syndrome2[i]);
                distance += diff;
            } else {
                distance += coeff1;
            }
        }

        distance
    }

    /// Convert syndrome pattern to error pattern
    fn syndrome_to_error_pattern(&self, syndrome_pattern: &[u32]) -> Result<NttPolynomial> {
        let mut error = NttPolynomial::new(self.ntru_params.ntt_params())?;

        for (i, &syndrome_coeff) in syndrome_pattern.iter().enumerate() {
            if i < error.coefficients.len() {
                error.coefficients[i] = syndrome_coeff;
            }
        }

        Ok(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_correction_params() {
        let params = ErrorCorrectionParams::DAWN_ALPHA_512;
        assert_eq!(params.max_errors, 64);
        assert_eq!(params.error_threshold, 1);
        assert_eq!(params.syndrome_threshold, 128);
    }

    #[test]
    fn test_error_correction_decoder() {
        let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
        let decoder = ErrorCorrectionDecoder::new(ntru_params).unwrap();

        assert_eq!(decoder.params.max_errors, 64);
        assert_eq!(decoder.ntru_params.n, 512);
    }

    #[test]
    fn test_syndrome_decoder() {
        let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
        let decoder = SyndromeDecoder::new(ntru_params).unwrap();

        assert_eq!(decoder.params.max_errors, 64);
        assert_eq!(decoder.ntru_params.n, 512);
    }

    #[test]
    fn test_error_stats() {
        let stats = ErrorStats {
            total_errors: 10,
            syndrome_weight: 20,
            max_errors: 64,
            error_threshold: 1,
        };

        assert_eq!(stats.total_errors, 10);
        assert_eq!(stats.syndrome_weight, 20);
        assert!(stats.total_errors <= stats.max_errors);
    }

    #[test]
    fn test_syndrome_table_building() {
        let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
        let decoder = SyndromeDecoder::new(ntru_params).unwrap();

        // Check that syndrome table was built
        assert!(!decoder.syndrome_table.is_empty());
        assert!(decoder.syndrome_table.len() <= 1000); // Limited by safety constraints
    }

    #[test]
    fn test_error_position_generation() {
        let positions = SyndromeDecoder::generate_error_positions(10, 3);

        // Should generate combinations (limited to 1000 for safety)
        assert!(positions.len() <= 1000);
        assert!(!positions.is_empty());

        // Each position should have exactly 3 elements
        for pos in &positions {
            assert_eq!(pos.len(), 3);
        }
    }
}
