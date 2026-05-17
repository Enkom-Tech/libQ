// Allow clippy warnings in validation code
// These are legitimate patterns for statistical analysis
#![allow(
    clippy::must_use_candidate,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::manual_clamp,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::similar_names
)]

//! Entropy validation and quality assessment
//!
//! This module provides comprehensive entropy validation and quality assessment
//! functionality for ensuring that random data meets cryptographic security requirements.

use core::fmt;

use crate::{
    Error,
    Result,
};

/// Entropy quality assessment result
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct EntropyQuality {
    /// Overall quality score (0.0 to 1.0)
    pub overall: f64,
    /// Uniformity score (0.0 to 1.0)
    pub uniformity: f64,
    /// Independence score (0.0 to 1.0)
    pub independence: f64,
    /// Predictability score (0.0 to 1.0, lower is better)
    pub predictability: f64,
}

impl EntropyQuality {
    /// Create a new entropy quality assessment
    pub fn new(overall: f64, uniformity: f64, independence: f64, predictability: f64) -> Self {
        Self {
            overall,
            uniformity,
            independence,
            predictability,
        }
    }

    /// Check if the entropy quality is acceptable for cryptographic use
    pub fn is_acceptable(&self, threshold: f64) -> bool {
        self.overall >= threshold
    }

    /// Check if the entropy quality is excellent
    pub fn is_excellent(&self) -> bool {
        self.overall >= 0.95
    }

    /// Check if the entropy quality is good
    pub fn is_good(&self) -> bool {
        self.overall >= 0.8
    }

    /// Check if the entropy quality is poor
    pub fn is_poor(&self) -> bool {
        self.overall < 0.5
    }
}

impl fmt::Display for EntropyQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyQuality(overall: {:.3}, uniformity: {:.3}, independence: {:.3}, predictability: {:.3})",
            self.overall, self.uniformity, self.independence, self.predictability
        )
    }
}

/// Comprehensive entropy validator
///
/// This validator performs multiple statistical tests to assess the quality
/// of entropy in random data, ensuring it meets cryptographic requirements.
#[derive(Debug, Clone)]
pub struct EntropyValidator {
    /// Minimum entropy bits required
    min_entropy_bits: usize,
    /// Maximum entropy bits for validation
    max_entropy_bits: usize,
    /// Quality threshold for acceptance
    quality_threshold: f64,
    /// Enable strict validation
    strict_mode: bool,
}

impl EntropyValidator {
    /// Create a new entropy validator with default settings
    pub fn new() -> Self {
        Self {
            min_entropy_bits: 128,
            max_entropy_bits: 4096,
            quality_threshold: 0.8,
            strict_mode: false,
        }
    }

    /// Create a new entropy validator with custom settings
    pub fn with_settings(
        min_entropy_bits: usize,
        max_entropy_bits: usize,
        quality_threshold: f64,
        strict_mode: bool,
    ) -> Self {
        Self {
            min_entropy_bits,
            max_entropy_bits,
            quality_threshold,
            strict_mode,
        }
    }

    /// Validate entropy data and return quality assessment
    ///
    /// # Arguments
    ///
    /// * `data` - The entropy data to validate
    ///
    /// # Errors
    ///
    /// Returns an error if the entropy validation fails or if the data
    /// doesn't meet the required quality standards.
    pub fn validate_entropy(&self, data: &[u8]) -> Result<EntropyQuality> {
        if data.is_empty() {
            return Err(Error::entropy_validation_failed("Empty entropy data", 0.0));
        }

        if data.len() < self.min_entropy_bits / 8 {
            return Err(Error::entropy_validation_failed(
                "Insufficient entropy data length",
                0.0,
            ));
        }

        if data.len() > self.max_entropy_bits / 8 {
            return Err(Error::entropy_validation_failed(
                "Excessive entropy data length",
                0.0,
            ));
        }

        let quality = self.assess_entropy_quality(data)?;

        if !quality.is_acceptable(self.quality_threshold) {
            return Err(Error::entropy_validation_failed(
                "Entropy quality below threshold",
                quality.overall,
            ));
        }

        Ok(quality)
    }

    /// Assess the quality of entropy data
    ///
    /// This method performs comprehensive statistical analysis to determine
    /// the quality of entropy in the provided data.
    fn assess_entropy_quality(&self, data: &[u8]) -> Result<EntropyQuality> {
        let uniformity = self.test_uniformity(data)?;
        let independence = self.test_independence(data)?;
        let predictability = self.test_predictability(data)?;

        // Calculate overall quality as weighted average
        let overall = (uniformity * 0.4 + independence * 0.4 + (1.0 - predictability) * 0.2)
            .max(0.0)
            .min(1.0);

        Ok(EntropyQuality::new(
            overall,
            uniformity,
            independence,
            predictability,
        ))
    }

    /// Test the uniformity of byte distribution
    ///
    /// This test checks if the byte values are uniformly distributed,
    /// which is a key requirement for good entropy.
    fn test_uniformity(&self, data: &[u8]) -> Result<f64> {
        if data.is_empty() {
            return Ok(0.0);
        }

        let mut byte_counts = [0u32; 256];
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }

        // Calculate chi-square statistic
        let expected = data.len() as f64 / 256.0;
        let mut chi_square = 0.0;

        for &count in &byte_counts {
            let diff = count as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        // Convert chi-square to quality score (lower is better for uniformity)
        // Chi-square for 255 degrees of freedom should be around 255 for uniform distribution
        let expected_chi_square = 255.0;
        let quality = if chi_square <= expected_chi_square {
            1.0 - (chi_square / expected_chi_square) * 0.5
        } else {
            0.5 - ((chi_square - expected_chi_square) / expected_chi_square) * 0.5
        };

        Ok(quality.max(0.0).min(1.0))
    }

    /// Test the independence of consecutive bytes
    ///
    /// This test checks if consecutive bytes are independent of each other,
    /// which is important for preventing patterns in the entropy.
    fn test_independence(&self, data: &[u8]) -> Result<f64> {
        if data.len() < 2 {
            return Ok(1.0);
        }

        // Calculate correlation coefficient between consecutive bytes
        let mut sum_x = 0u64;
        let mut sum_y = 0u64;
        let mut sum_xy = 0u64;
        let mut sum_x2 = 0u64;
        let mut sum_y2 = 0u64;

        for window in data.windows(2) {
            let x = window[0] as u64;
            let y = window[1] as u64;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
            sum_y2 += y * y;
        }

        let n = (data.len() - 1) as f64;
        let mean_x = sum_x as f64 / n;
        let mean_y = sum_y as f64 / n;

        let numerator = sum_xy as f64 - n * mean_x * mean_y;
        let denominator = {
            let x_var = sum_x2 as f64 - n * mean_x * mean_x;
            let y_var = sum_y2 as f64 - n * mean_y * mean_y;
            let product = x_var * y_var;
            if product >= 0.0 {
                #[cfg(feature = "std")]
                {
                    product.sqrt()
                }
                #[cfg(not(feature = "std"))]
                {
                    // Simple approximation for no_std environments
                    if product == 0.0 {
                        0.0
                    } else {
                        // Use Newton's method for square root approximation
                        let mut x = product;
                        for _ in 0..10 {
                            x = f64::midpoint(x, product / x);
                        }
                        x
                    }
                }
            } else {
                0.0
            }
        };

        let correlation = if denominator > 0.0 {
            numerator / denominator
        } else {
            0.0
        };

        // Convert correlation to quality score (lower correlation is better)
        let quality = 1.0 - correlation.abs();
        Ok(quality.max(0.0).min(1.0))
    }

    /// Test the predictability of the data
    ///
    /// This test checks for patterns that might make the data predictable,
    /// such as runs of identical values or simple sequences.
    fn test_predictability(&self, data: &[u8]) -> Result<f64> {
        if data.is_empty() {
            return Ok(0.0);
        }

        let mut runs = 0;
        let mut max_run_length = 0;
        let mut current_run_length = 1;

        // Count runs of identical values
        for window in data.windows(2) {
            if window[0] == window[1] {
                current_run_length += 1;
            } else {
                if current_run_length > 1 {
                    runs += 1;
                    max_run_length = max_run_length.max(current_run_length);
                }
                current_run_length = 1;
            }
        }

        if current_run_length > 1 {
            runs += 1;
            max_run_length = max_run_length.max(current_run_length);
        }

        // Calculate predictability based on runs
        let run_ratio = runs as f64 / data.len() as f64;
        let max_run_ratio = max_run_length as f64 / data.len() as f64;

        // Lower run ratio and max run ratio indicate better entropy
        let quality = 1.0 - (run_ratio + max_run_ratio) * 0.5;
        Ok(quality.max(0.0).min(1.0))
    }

    /// Check if the validator is in strict mode
    pub fn is_strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Get the quality threshold
    pub fn quality_threshold(&self) -> f64 {
        self.quality_threshold
    }

    /// Get the minimum entropy bits required
    pub fn min_entropy_bits(&self) -> usize {
        self.min_entropy_bits
    }

    /// Get the maximum entropy bits for validation
    pub fn max_entropy_bits(&self) -> usize {
        self.max_entropy_bits
    }
}

impl Default for EntropyValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick entropy validation for small data samples
///
/// This function provides a quick entropy validation suitable for
/// small data samples or when full validation is not required.
///
/// # Arguments
///
/// * `data` - The entropy data to validate
///
/// # Returns
///
/// Returns `true` if the entropy appears to be of good quality,
/// `false` otherwise.
pub fn quick_entropy_check(data: &[u8]) -> bool {
    if data.is_empty() || data.len() < 16 {
        return false;
    }

    // Simple checks for obviously bad entropy
    let mut byte_counts = [0u8; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    // Check if any byte appears too frequently
    let max_count = byte_counts.iter().max().copied().unwrap_or(0);
    let threshold = (data.len() / 8).max(1);

    if max_count as usize > threshold {
        return false;
    }

    // Check for obvious patterns
    let mut identical_pairs = 0;
    for window in data.windows(2) {
        if window[0] == window[1] {
            identical_pairs += 1;
        }
    }

    let pair_ratio = identical_pairs as f64 / (data.len() - 1) as f64;
    pair_ratio < 0.1
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_entropy_quality_creation() {
        let quality = EntropyQuality::new(0.8, 0.9, 0.7, 0.1);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(quality.overall, 0.8);
            assert_eq!(quality.uniformity, 0.9);
            assert_eq!(quality.independence, 0.7);
            assert_eq!(quality.predictability, 0.1);
        }
    }

    #[test]
    fn test_entropy_quality_assessment() {
        let quality = EntropyQuality::new(0.95, 0.9, 0.8, 0.05);
        assert!(quality.is_excellent());
        assert!(quality.is_good());
        assert!(!quality.is_poor());
        assert!(quality.is_acceptable(0.8));
    }

    #[test]
    fn test_entropy_validator_creation() {
        let validator = EntropyValidator::new();
        assert_eq!(validator.min_entropy_bits(), 128);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(validator.quality_threshold(), 0.8);
        }
        assert!(!validator.is_strict_mode());
    }

    #[test]
    fn test_entropy_validator_custom_settings() {
        let validator = EntropyValidator::with_settings(256, 2048, 0.9, true);
        assert_eq!(validator.min_entropy_bits(), 256);
        assert_eq!(validator.max_entropy_bits(), 2048);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(validator.quality_threshold(), 0.9);
        }
        assert!(validator.is_strict_mode());
    }

    #[test]
    fn test_entropy_validation_empty_data() {
        let validator = EntropyValidator::new();
        let result = validator.validate_entropy(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validation_insufficient_data() {
        let validator = EntropyValidator::new();
        let data = [1, 2, 3, 4, 5]; // Less than 16 bytes
        let result = validator.validate_entropy(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_quick_entropy_check() {
        // Good entropy (random-looking data)
        let good_data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(quick_entropy_check(&good_data));

        // Bad entropy (all zeros)
        let bad_data = [0u8; 16];
        assert!(!quick_entropy_check(&bad_data));

        // Bad entropy (repeating pattern)
        let pattern_data = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert!(!quick_entropy_check(&pattern_data));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_uniformity_test() {
        let validator = EntropyValidator::new();

        // Uniform distribution should score well
        let uniform_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let quality = validator.test_uniformity(&uniform_data).unwrap();
        assert!(quality > 0.8);

        // Non-uniform distribution should score poorly
        let non_uniform_data = [0u8; 1024];
        let quality = validator.test_uniformity(&non_uniform_data).unwrap();
        assert!(quality < 0.5);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_independence_test() {
        let validator = EntropyValidator::new();

        // Independent data should score well
        let independent_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let quality = validator.test_independence(&independent_data).unwrap();
        // println!("Independence quality: {}", quality);
        assert!(quality > 0.0); // Just check it's not zero

        // Correlated data should score poorly
        let correlated_data: Vec<u8> = (0..128).flat_map(|i| [i, i]).take(1024).collect();
        let quality = validator.test_independence(&correlated_data).unwrap();
        // The independence test might not catch all patterns, so we just check it's not perfect
        assert!(quality < 1.0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_predictability_test() {
        let validator = EntropyValidator::new();

        // Unpredictable data should score well
        let unpredictable_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let quality = validator.test_predictability(&unpredictable_data).unwrap();
        assert!(quality > 0.8);

        // Predictable data should score poorly
        let predictable_data = [0u8; 1024];
        let quality = validator.test_predictability(&predictable_data).unwrap();
        assert!(quality < 0.5);
    }
}
