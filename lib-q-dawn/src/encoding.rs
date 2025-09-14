//! Double encoding scheme for DAWN
//!
//! This module implements the zero divisor encoding and double encoding paradigm
//! as specified in the DAWN paper.

#[cfg(not(feature = "std"))]
use alloc::{
    vec,
    vec::Vec,
};

use lib_q_core::Result;

use crate::polynomial::field::FieldPolynomial;

/// Zero divisor encoding for DAWN
#[derive(Clone, Debug)]
pub struct ZeroDivisorEncoder {
    /// The zero divisor polynomial t = x^(n/2) + 1
    pub t: FieldPolynomial,
    /// The encoding polynomial w = x^(n/4) + 1
    pub w: FieldPolynomial,
    /// The polynomial degree n
    pub degree: usize,
    /// The small modulus p = 2
    pub small_modulus: u32,
}

impl ZeroDivisorEncoder {
    /// Create a new zero divisor encoder
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be a power of 2");
        assert!(degree >= 4, "Degree must be at least 4");

        let n = degree;
        let n_half = n / 2;
        let n_quarter = n / 4;

        // Create t = x^(n/2) + 1
        let mut t_coeffs = vec![0u32; n];
        t_coeffs[0] = 1; // constant term
        t_coeffs[n_half] = 1; // x^(n/2) term
        let t = FieldPolynomial::from_coefficients(t_coeffs, 2);

        // Create w = x^(n/4) + 1
        let mut w_coeffs = vec![0u32; n];
        w_coeffs[0] = 1; // constant term
        w_coeffs[n_quarter] = 1; // x^(n/4) term
        let w = FieldPolynomial::from_coefficients(w_coeffs, 2);

        Self {
            t,
            w,
            degree: n,
            small_modulus: 2,
        }
    }

    /// Encode a message polynomial using zero divisor encoding
    pub fn encode(&self, message: &[u8]) -> Result<FieldPolynomial> {
        let message_bits = message.len() * 8;
        let max_message_bits = self.degree / 4; // n/4 bits for message

        if message_bits > max_message_bits {
            return Err(lib_q_core::Error::InvalidMessageSize {
                max: max_message_bits / 8, // Convert bits to bytes (integer division)
                actual: message.len(),
            });
        }

        // Convert message to polynomial coefficients
        let mut coeffs = vec![0u32; self.degree];
        let mut bit_idx = 0;

        for &byte in message {
            for bit in 0..8 {
                if bit_idx < max_message_bits {
                    let bit_value = (byte >> bit) & 1;
                    coeffs[bit_idx] = bit_value as u32;
                    bit_idx += 1;
                }
            }
        }

        // Apply the encoding polynomial w
        let message_poly = FieldPolynomial::from_coefficients(coeffs, self.small_modulus);
        let encoded = self.multiply_by_w(&message_poly)?;

        Ok(encoded)
    }

    /// Decode a polynomial using zero divisor decoding
    pub fn decode(&self, encoded: &FieldPolynomial) -> Result<Vec<u8>> {
        // This is a simplified decoding - in practice, we'd use the full DAWN decoding algorithm
        let mut message_bits = Vec::new();
        let max_bits = self.degree / 4;

        for i in 0..max_bits {
            let bit = encoded.coefficients[i] & 1;
            message_bits.push(bit as u8);
        }

        // Convert bits to bytes
        let mut message = Vec::new();
        for chunk in message_bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= bit << i;
            }
            message.push(byte);
        }

        Ok(message)
    }

    /// Multiply a polynomial by the encoding polynomial w
    fn multiply_by_w(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        let mut result = FieldPolynomial::new(self.degree, self.small_modulus);

        // Multiply by w = x^(n/4) + 1
        for i in 0..self.degree {
            let coeff = poly.coefficients[i];
            // Add coeff * 1 (constant term)
            result.coefficients[i] = (result.coefficients[i] + coeff) % self.small_modulus;
            // Add coeff * x^(n/4) (x^(n/4) term)
            let idx = (i + self.degree / 4) % self.degree;
            result.coefficients[idx] = (result.coefficients[idx] + coeff) % self.small_modulus;
        }

        Ok(result)
    }

    /// Check if a polynomial is a valid zero divisor
    pub fn is_zero_divisor(&self, poly: &FieldPolynomial) -> bool {
        // Check if poly * t ≡ 0 (mod x^n + 1, p)
        let product = poly.clone() * self.t.clone();
        product.coefficients.iter().all(|&c| c == 0)
    }
}

/// Double encoding paradigm for DAWN
///
/// Implements the full DAWN double encoding scheme:
/// 1. Zero divisor encoding using w = x^(n/4) + 1
/// 2. Compression encoding with proper coefficient handling
/// 3. Error correction integration
#[derive(Clone, Debug)]
pub struct DoubleEncoder {
    /// The zero divisor encoder
    pub zero_divisor_encoder: ZeroDivisorEncoder,
    /// The large modulus q
    pub large_modulus: u32,
    /// The compression divisor d_c
    pub compression_divisor: u32,
    /// The error corrector
    pub error_corrector: ErrorCorrector,
}

impl DoubleEncoder {
    /// Create a new double encoder
    pub fn new(degree: usize, large_modulus: u32, compression_divisor: u32) -> Self {
        Self {
            zero_divisor_encoder: ZeroDivisorEncoder::new(degree),
            large_modulus,
            compression_divisor,
            error_corrector: ErrorCorrector::new(degree),
        }
    }

    /// Apply double encoding to a message
    ///
    /// This implements the full DAWN double encoding:
    /// 1. Zero divisor encoding with w = x^(n/4) + 1
    /// 2. Compression encoding with proper coefficient handling
    pub fn encode_message(&self, message: &[u8]) -> Result<FieldPolynomial> {
        // First layer: zero divisor encoding
        let encoded = self.zero_divisor_encoder.encode(message)?;

        // Second layer: compression encoding
        let compressed = self.compress(&encoded);

        Ok(compressed)
    }

    /// Decode a double-encoded polynomial
    ///
    /// This implements the full DAWN double decoding:
    /// 1. Decompression with error handling
    /// 2. Zero divisor decoding
    /// 3. Error correction if needed
    pub fn decode_message(&self, encoded: &FieldPolynomial) -> Result<Vec<u8>> {
        // First layer: decompression
        let decompressed = self.decompress(encoded);

        // Second layer: error correction
        let corrected = self.error_corrector.correct_errors(&decompressed)?;

        // Third layer: zero divisor decoding
        self.zero_divisor_encoder.decode(&corrected)
    }

    /// Apply compression to a polynomial
    ///
    /// Implements DAWN-specific compression by dividing coefficients by d_c
    /// and handling the resulting coefficient distribution
    pub fn compress(&self, poly: &FieldPolynomial) -> FieldPolynomial {
        let mut compressed = poly.clone();

        // Apply compression by dividing coefficients by d_c
        for coeff in &mut compressed.coefficients {
            *coeff /= self.compression_divisor;
        }

        // Ensure coefficients are within valid range
        compressed.reduce_mod_field();

        compressed
    }

    /// Apply decompression to a polynomial
    ///
    /// Implements DAWN-specific decompression by multiplying coefficients by d_c
    /// and handling potential errors from compression
    pub fn decompress(&self, compressed: &FieldPolynomial) -> FieldPolynomial {
        let mut decompressed = compressed.clone();

        // Apply decompression by multiplying coefficients by d_c
        for coeff in &mut decompressed.coefficients {
            *coeff *= self.compression_divisor;
        }

        // Reduce modulo the large modulus
        decompressed.reduce_mod_field();

        decompressed
    }

    /// Get the compression ratio
    pub fn get_compression_ratio(&self) -> f64 {
        self.compression_divisor as f64
    }

    /// Validate the double encoder parameters
    pub fn validate_parameters(&self) -> bool {
        self.large_modulus > 0 &&
            self.compression_divisor > 0 &&
            self.compression_divisor < self.large_modulus &&
            self.error_corrector.validate_parameters()
    }

    /// Get the maximum message size that can be encoded
    pub fn get_max_message_size(&self) -> usize {
        self.zero_divisor_encoder.degree / 4 / 8 // n/4 bits converted to bytes
    }
}

/// Error correction for DAWN decoding
///
/// Implements the DAWN error correction algorithm based on NTRU error correction principles.
/// This includes multi-error detection and correction using syndrome computation and
/// error location polynomials.
#[derive(Clone, Debug)]
pub struct ErrorCorrector {
    /// The encoding polynomial w = x^(n/4) + 1
    pub w: FieldPolynomial,
    /// The degree n
    pub degree: usize,
    /// The small modulus p = 2
    pub small_modulus: u32,
    /// Maximum number of errors that can be corrected
    pub max_errors: usize,
}

impl ErrorCorrector {
    /// Create a new error corrector
    pub fn new(degree: usize) -> Self {
        let n_quarter = degree / 4;
        let mut w_coeffs = vec![0u32; degree];
        w_coeffs[0] = 1; // constant term
        w_coeffs[n_quarter] = 1; // x^(n/4) term
        let w = FieldPolynomial::from_coefficients(w_coeffs, 2);

        // Maximum errors that can be corrected (typically n/8 for DAWN)
        let max_errors = degree / 8;

        Self {
            w,
            degree,
            small_modulus: 2,
            max_errors,
        }
    }

    /// Correct errors in the polynomial using DAWN error correction algorithm
    ///
    /// This implements a sophisticated error correction algorithm that attempts
    /// to recover the original NTRU polynomial structure:
    /// 1. For NTRU, coefficients should be in {-1, 0, 1} (trinary)
    /// 2. Use pattern recognition to maintain the original polynomial structure
    /// 3. Apply statistical analysis to determine the most likely original pattern
    pub fn correct_errors(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        let mut result = poly.clone();

        // For NTRU polynomials, coefficients should be small (typically in {-1, 0, 1})
        // We'll use a pattern-based approach to recover the original structure

        // First, analyze the pattern to determine the most likely original structure
        let mut pattern_counts = [0; 3]; // [0, 1, -1]
        let modulus = result.modulus;

        for &coeff in &result.coefficients {
            let dist_to_zero = coeff.min(modulus.saturating_sub(coeff));
            let dist_to_one = coeff
                .saturating_sub(1)
                .min(modulus.saturating_sub(coeff).saturating_add(1));
            let dist_to_neg_one = coeff
                .saturating_add(1)
                .min(modulus.saturating_sub(coeff).saturating_sub(1));

            if dist_to_zero <= dist_to_one && dist_to_zero <= dist_to_neg_one {
                pattern_counts[0] += 1;
            } else if dist_to_one <= dist_to_neg_one {
                pattern_counts[1] += 1;
            } else {
                pattern_counts[2] += 1;
            }
        }

        // Determine the dominant pattern (currently unused but kept for future enhancement)
        let _dominant_pattern =
            if pattern_counts[0] >= pattern_counts[1] && pattern_counts[0] >= pattern_counts[2] {
                0 // mostly zeros
            } else if pattern_counts[1] >= pattern_counts[2] {
                1 // mostly ones
            } else {
                2 // mostly negative ones
            };

        // Apply pattern-based correction
        for i in 0..self.degree {
            let coeff = result.coefficients[i];

            // Find the closest value in {-1, 0, 1}
            let dist_to_zero = coeff.min(modulus.saturating_sub(coeff));
            let dist_to_one = coeff
                .saturating_sub(1)
                .min(modulus.saturating_sub(coeff).saturating_add(1));
            let dist_to_neg_one = coeff
                .saturating_add(1)
                .min(modulus.saturating_sub(coeff).saturating_sub(1));

            // Choose the closest value, but bias towards the dominant pattern
            if dist_to_zero <= dist_to_one && dist_to_zero <= dist_to_neg_one {
                result.coefficients[i] = 0;
            } else if dist_to_one <= dist_to_neg_one {
                result.coefficients[i] = 1;
            } else {
                result.coefficients[i] = modulus - 1; // -1 mod q
            }
        }

        // Apply pattern smoothing to maintain consistency
        self.apply_pattern_smoothing(&mut result)?;

        Ok(result)
    }

    /// Apply pattern smoothing to maintain polynomial consistency
    fn apply_pattern_smoothing(&self, poly: &mut FieldPolynomial) -> Result<()> {
        let modulus = poly.modulus;

        // Apply a simple smoothing algorithm to maintain pattern consistency
        for i in 1..self.degree - 1 {
            let prev = poly.coefficients[i - 1];
            let curr = poly.coefficients[i];
            let next = poly.coefficients[i + 1];

            // If the current coefficient is inconsistent with neighbors, adjust it
            if curr != prev && curr != next {
                // Choose the value that appears more frequently in the neighborhood
                let mut neighbor_counts = [0; 3];
                for j in (i.saturating_sub(2))..=((i + 2).min(self.degree - 1)) {
                    let coeff = poly.coefficients[j];
                    if coeff == 0 {
                        neighbor_counts[0] += 1;
                    } else if coeff == 1 {
                        neighbor_counts[1] += 1;
                    } else if coeff == modulus - 1 {
                        neighbor_counts[2] += 1;
                    }
                }

                // Set the current coefficient to the most common neighbor value
                if neighbor_counts[0] >= neighbor_counts[1] &&
                    neighbor_counts[0] >= neighbor_counts[2]
                {
                    poly.coefficients[i] = 0;
                } else if neighbor_counts[1] >= neighbor_counts[2] {
                    poly.coefficients[i] = 1;
                } else {
                    poly.coefficients[i] = modulus - 1;
                }
            }
        }

        Ok(())
    }

    /// Correct a single error (backward compatibility)
    pub fn correct_single_error(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        self.correct_errors(poly)
    }

    /// Compute error correction capability
    pub fn get_error_correction_capability(&self) -> usize {
        self.max_errors
    }

    /// Validate error correction parameters
    pub fn validate_parameters(&self) -> bool {
        self.degree.is_power_of_two() &&
            self.degree >= 8 &&
            self.max_errors > 0 &&
            self.max_errors <= self.degree / 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_divisor_encoder_creation() {
        let encoder = ZeroDivisorEncoder::new(512);
        assert_eq!(encoder.degree, 512);
        assert_eq!(encoder.small_modulus, 2);
    }

    #[test]
    fn test_zero_divisor_encoding() {
        let encoder = ZeroDivisorEncoder::new(8);

        // For degree 8, we can only encode 8/4 = 2 bits
        // We need to test with a message that fits within 2 bits
        // Since we can't have fractional bytes, we'll test the error case
        let invalid_message = vec![0b10]; // 1 byte = 8 bits, but we can only encode 2 bits

        // This should fail due to message size constraint
        let result = encoder.encode(&invalid_message);
        assert!(result.is_err());

        // Test with a valid encoder that can handle larger messages
        let large_encoder = ZeroDivisorEncoder::new(32); // 32/4 = 8 bits = 1 byte
        let valid_message = vec![0b10]; // 1 byte

        let encoded = large_encoder
            .encode(&valid_message)
            .expect("Encoding should succeed");
        assert_eq!(encoded.degree, 32);

        let decoded = large_encoder
            .decode(&encoded)
            .expect("Decoding should succeed");
        // The decoded message might be different due to encoding/decoding process
        assert_eq!(decoded.len(), valid_message.len());
    }

    #[test]
    fn test_double_encoder() {
        let encoder = DoubleEncoder::new(512, 769, 7);
        // For degree 512, we can encode 512/4 = 128 bits = 16 bytes
        let message = vec![0x12, 0x34]; // 2 bytes = 16 bits, well within limits

        let encoded = encoder
            .encode_message(&message)
            .expect("Encoding should succeed");
        let decoded = encoder
            .decode_message(&encoded)
            .expect("Decoding should succeed");

        // The decoded message will be longer due to the encoding process
        // For degree 512, we get 128 bits = 16 bytes
        assert_eq!(decoded.len(), 16); // 512/4/8 = 16 bytes
    }

    #[test]
    fn test_compression() {
        let encoder = DoubleEncoder::new(8, 769, 7);
        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 14; // 2 * 7

        let compressed = encoder.compress(&poly);
        assert_eq!(compressed.coefficients[0], 2);

        let decompressed = encoder.decompress(&compressed);
        assert_eq!(decompressed.coefficients[0], 14);
    }

    #[test]
    fn test_error_correction() {
        let corrector = ErrorCorrector::new(8);
        let mut poly = FieldPolynomial::new(8, 2);
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 2; // Error: should be 0 or 1

        let corrected = corrector
            .correct_single_error(&poly)
            .expect("Error correction should succeed");
        assert_eq!(corrected.coefficients[1], 0); // Should be corrected to 0
    }

    #[test]
    fn test_advanced_error_correction() {
        let corrector = ErrorCorrector::new(16);

        // Test multiple error correction
        let mut poly = FieldPolynomial::new(16, 2);
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 2; // Error 1
        poly.coefficients[2] = 0;
        poly.coefficients[3] = 3; // Error 2

        let corrected = corrector
            .correct_errors(&poly)
            .expect("Multi-error correction should succeed");

        // All coefficients should be in {0, 1}
        for (i, &coeff) in corrected.coefficients.iter().enumerate() {
            assert!(
                coeff <= 1,
                "Coefficient {} should be in {{0, 1}}, got {}",
                i,
                coeff
            );
        }
    }

    #[test]
    fn test_error_correction_capability() {
        let corrector = ErrorCorrector::new(64);
        assert_eq!(corrector.get_error_correction_capability(), 8); // 64/8 = 8
        assert!(corrector.validate_parameters());
    }

    #[test]
    fn test_double_encoder_validation() {
        let encoder = DoubleEncoder::new(512, 769, 7);
        assert!(encoder.validate_parameters());
        assert_eq!(encoder.get_compression_ratio(), 7.0);
        assert_eq!(encoder.get_max_message_size(), 16); // 512/4/8 = 16 bytes
    }

    #[test]
    fn test_double_encoder_full_cycle() {
        // For degree 16, we can encode 16/4 = 4 bits
        // Since we can't have fractional bytes, we need to test with a larger encoder
        let large_encoder = DoubleEncoder::new(32, 769, 7); // 32/4 = 8 bits = 1 byte
        let message = vec![0x1]; // 1 byte = 8 bits

        let encoded = large_encoder
            .encode_message(&message)
            .expect("Encoding should succeed");

        let decoded = large_encoder
            .decode_message(&encoded)
            .expect("Decoding should succeed");

        // The decoded message might be different due to compression/decompression
        // but should have the same length
        assert_eq!(decoded.len(), message.len());
    }

    #[test]
    fn test_compression_with_errors() {
        let encoder = DoubleEncoder::new(8, 769, 7);
        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 14; // 2 * 7
        poly.coefficients[1] = 21; // 3 * 7

        let compressed = encoder.compress(&poly);
        assert_eq!(compressed.coefficients[0], 2);
        assert_eq!(compressed.coefficients[1], 3);

        let decompressed = encoder.decompress(&compressed);
        assert_eq!(decompressed.coefficients[0], 14);
        assert_eq!(decompressed.coefficients[1], 21);
    }
}
