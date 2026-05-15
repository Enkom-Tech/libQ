//! Polynomial Operations
//!
//! This module provides polynomial operations used in the HQC implementation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "random")]
use lib_q_random::LibQRng;
use rand_core::Rng;

use crate::error::HqcError;

/// Polynomial in GF(2)[x]/(x^n - 1)
pub struct Polynomial {
    #[cfg(feature = "alloc")]
    coefficients: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    coefficients: [u8; 100000], // Large enough for HQC-256
    degree: usize,
}

impl Polynomial {
    /// Create a new polynomial with the given degree
    pub fn new(degree: usize) -> Self {
        Self {
            #[cfg(feature = "alloc")]
            coefficients: vec![0u8; degree],
            #[cfg(not(feature = "alloc"))]
            coefficients: [0u8; 100000], // Large enough for HQC-256
            degree,
        }
    }

    /// Create a polynomial from coefficients
    #[cfg(feature = "alloc")]
    pub fn from_coefficients(coefficients: Vec<u8>) -> Self {
        let degree = coefficients.len();
        Self {
            coefficients,
            degree,
        }
    }

    /// Create a polynomial from coefficients (no_std version)
    #[cfg(not(feature = "alloc"))]
    pub fn from_coefficients(coefficients: &[u8]) -> Self {
        let degree = coefficients.len().min(100000);
        let mut coeffs = [0u8; 100000];
        coeffs[..degree].copy_from_slice(&coefficients[..degree]);
        Self {
            coefficients: coeffs,
            degree,
        }
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Get the coefficients
    pub fn coefficients(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        {
            &self.coefficients
        }
        #[cfg(not(feature = "alloc"))]
        {
            &self.coefficients[..self.degree]
        }
    }

    /// Validate that the polynomial has the expected weight (for security)
    pub fn validate_weight(&self, expected_weight: usize) -> Result<(), HqcError> {
        let actual_weight = self.coefficients().iter().filter(|&&x| x == 1).count();
        if actual_weight != expected_weight {
            return Err(HqcError::InvalidWeight);
        }
        Ok(())
    }

    /// Check if the polynomial is valid (within bounds)
    pub fn is_valid(&self) -> bool {
        self.degree > 0 && self.degree <= 100000 && self.is_non_zero()
    }

    /// Check if the polynomial is non-zero (has at least one non-zero coefficient)
    pub fn is_non_zero(&self) -> bool {
        self.coefficients().iter().any(|&x| x != 0)
    }

    /// Add two polynomials (XOR in GF(2))
    pub fn add(&self, other: &Polynomial) -> Result<Polynomial, HqcError> {
        if self.degree != other.degree {
            return Err(HqcError::InvalidSize);
        }

        #[cfg(feature = "alloc")]
        {
            let mut result = vec![0u8; self.degree];
            for (i, item) in result.iter_mut().enumerate().take(self.degree) {
                *item = self.coefficients()[i] ^ other.coefficients()[i];
            }
            Ok(Polynomial::from_coefficients(result))
        }
        #[cfg(not(feature = "alloc"))]
        {
            // For HQC, we need to support very large polynomials (up to 65,542 for HQC-256)
            let mut result = [0u8; 100000]; // Large enough for HQC-256
            if self.degree > result.len() {
                return Err(HqcError::InvalidSize);
            }
            for (i, item) in result.iter_mut().enumerate().take(self.degree) {
                *item = self.coefficients()[i] ^ other.coefficients()[i];
            }
            Ok(Polynomial::from_coefficients(&result[..self.degree]))
        }
    }

    /// Multiply two polynomials
    pub fn multiply(&self, other: &Polynomial) -> Result<Polynomial, HqcError> {
        if self.degree != other.degree {
            return Err(HqcError::InvalidSize);
        }

        #[cfg(feature = "alloc")]
        {
            let mut result = vec![0u8; self.degree];
            for i in 0..self.degree {
                for j in 0..self.degree {
                    let k = (i + j) % self.degree;
                    result[k] ^= self.coefficients()[i] & other.coefficients()[j];
                }
            }
            Ok(Polynomial::from_coefficients(result))
        }
        #[cfg(not(feature = "alloc"))]
        {
            // For HQC, we need to support very large polynomials (up to 65,542 for HQC-256)
            let mut result = [0u8; 100000]; // Large enough for HQC-256
            if self.degree > result.len() {
                return Err(HqcError::InvalidSize);
            }
            for i in 0..self.degree {
                for j in 0..self.degree {
                    let k = (i + j) % self.degree;
                    result[k] ^= self.coefficients()[i] & other.coefficients()[j];
                }
            }
            Ok(Polynomial::from_coefficients(&result[..self.degree]))
        }
    }

    /// Generate a random polynomial with fixed weight using secure rejection sampling
    #[cfg(feature = "random")]
    pub fn random_fixed_weight(
        degree: usize,
        weight: usize,
        rng: &mut LibQRng,
    ) -> Result<Polynomial, HqcError> {
        if weight > degree {
            return Err(HqcError::InvalidSize);
        }

        // Handle edge case where both degree and weight are 0
        if degree == 0 && weight == 0 {
            return Err(HqcError::InvalidSize);
        }

        #[cfg(feature = "alloc")]
        {
            let mut coefficients = vec![0u8; degree];
            let mut positions = Vec::with_capacity(weight);
            let mut attempts = 0;
            const MAX_ATTEMPTS: usize = 10000; // Prevent infinite loops

            // Use rejection sampling to ensure exactly the required weight
            while positions.len() < weight && attempts < MAX_ATTEMPTS {
                let mut pos_bytes = [0u8; 4];
                rng.fill_bytes(&mut pos_bytes);
                let pos = u32::from_le_bytes(pos_bytes) as usize % degree;

                if !positions.contains(&pos) {
                    positions.push(pos);
                    coefficients[pos] = 1;
                }
                attempts += 1;
            }

            // Validate that we achieved the required weight
            if positions.len() != weight {
                return Err(HqcError::RandomGenerationFailed);
            }

            Ok(Polynomial::from_coefficients(coefficients))
        }
        #[cfg(not(feature = "alloc"))]
        {
            // For HQC, we need to support very large polynomials (up to 65,542 for HQC-256)
            // Use a much larger fixed-size array to accommodate HQC parameters
            let mut coefficients = [0u8; 100000]; // Large enough for HQC-256
            if degree > coefficients.len() {
                return Err(HqcError::InvalidSize);
            }

            let mut positions = [0usize; 256]; // Fixed size array for positions
            let mut positions_len = 0;
            let mut attempts = 0;
            const MAX_ATTEMPTS: usize = 10000; // Prevent infinite loops

            // Use rejection sampling to ensure exactly the required weight
            while positions_len < weight &&
                attempts < MAX_ATTEMPTS &&
                positions_len < positions.len()
            {
                let mut pos_bytes = [0u8; 4];
                rng.fill_bytes(&mut pos_bytes);
                let pos = u32::from_le_bytes(pos_bytes) as usize % degree;

                let mut found = false;
                for &existing_pos in positions.iter().take(positions_len) {
                    if existing_pos == pos {
                        found = true;
                        break;
                    }
                }

                if !found {
                    positions[positions_len] = pos;
                    positions_len += 1;
                    coefficients[pos] = 1;
                }
                attempts += 1;
            }

            // Validate that we achieved the required weight
            if positions_len != weight {
                return Err(HqcError::RandomGenerationFailed);
            }

            Ok(Polynomial::from_coefficients(&coefficients[..degree]))
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "random")]
    use lib_q_random::LibQRng;

    use super::*;

    #[test]
    fn test_polynomial_creation() {
        let poly = Polynomial::new(10);
        assert_eq!(poly.degree(), 10);
        assert_eq!(poly.coefficients().len(), 10);
    }

    #[test]
    fn test_polynomial_from_coefficients() {
        #[cfg(feature = "alloc")]
        {
            let coeffs = vec![1, 0, 1, 1, 0];
            let poly = Polynomial::from_coefficients(coeffs.clone());
            assert_eq!(poly.degree(), 5);
            assert_eq!(poly.coefficients(), coeffs.as_slice());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let coeffs = [1, 0, 1, 1, 0];
            let poly = Polynomial::from_coefficients(&coeffs);
            assert_eq!(poly.degree(), 5);
            assert_eq!(poly.coefficients(), &coeffs);
        }
    }

    #[test]
    fn test_polynomial_addition() {
        #[cfg(feature = "alloc")]
        {
            let coeffs1 = vec![1, 0, 1, 0];
            let poly1 = Polynomial::from_coefficients(coeffs1);

            let coeffs2 = vec![0, 1, 1, 0];
            let poly2 = Polynomial::from_coefficients(coeffs2);
            let result = poly1.add(&poly2).unwrap();
            assert_eq!(result.coefficients(), &[1, 1, 0, 0]);
        }
        #[cfg(not(feature = "alloc"))]
        {
            let poly1 = Polynomial::from_coefficients(&[1, 0, 1, 0]);
            let poly2 = Polynomial::from_coefficients(&[0, 1, 1, 0]);
            let result = poly1.add(&poly2).unwrap();
            assert_eq!(result.coefficients(), &[1, 1, 0, 0]);
        }
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_polynomial_random_fixed_weight() {
        let mut rng = LibQRng::new_deterministic([42u8; 32]);
        let poly = Polynomial::random_fixed_weight(100, 10, &mut rng).unwrap();
        assert_eq!(poly.degree(), 100);
        let weight = poly.coefficients().iter().filter(|&&x| x == 1).count();
        assert_eq!(weight, 10);
    }

    #[test]
    fn test_polynomial_weight_validation() {
        #[cfg(feature = "alloc")]
        {
            let coeffs = vec![1, 0, 1, 1, 0];
            let poly = Polynomial::from_coefficients(coeffs);
            assert!(poly.validate_weight(3).is_ok());
            assert!(poly.validate_weight(2).is_err());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let poly = Polynomial::from_coefficients(&[1, 0, 1, 1, 0]);
            assert!(poly.validate_weight(3).is_ok());
            assert!(poly.validate_weight(2).is_err());
        }
    }

    #[test]
    fn test_polynomial_validity() {
        // Create a polynomial with non-zero coefficients to test validity
        #[cfg(feature = "alloc")]
        {
            let coeffs = vec![1, 0, 1, 0, 0, 0, 0, 0, 0, 0];
            let poly = Polynomial::from_coefficients(coeffs);
            assert!(poly.is_valid());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let poly = Polynomial::from_coefficients(&[1, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
            assert!(poly.is_valid());
        }

        #[cfg(feature = "alloc")]
        {
            let zero_coeffs = vec![0; 5];
            let zero_poly = Polynomial::from_coefficients(zero_coeffs);
            assert!(!zero_poly.is_valid());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let zero_poly = Polynomial::from_coefficients(&[0; 5]);
            assert!(!zero_poly.is_valid());
        }
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_polynomial_security_validation() {
        let mut rng = LibQRng::new_deterministic([42u8; 32]);

        // Test that fixed weight generation always produces the correct weight
        for _ in 0..10 {
            let poly = Polynomial::random_fixed_weight(50, 5, &mut rng).unwrap();
            assert_eq!(poly.degree(), 50);
            assert!(poly.validate_weight(5).is_ok());
            assert!(poly.is_valid());
        }
    }

    #[test]
    #[cfg(feature = "random")]
    fn test_polynomial_error_handling() {
        let mut rng = LibQRng::new_deterministic([42u8; 32]);

        // Test invalid weight (weight > degree)
        assert!(Polynomial::random_fixed_weight(10, 15, &mut rng).is_err());

        // Test zero degree
        assert!(Polynomial::random_fixed_weight(0, 0, &mut rng).is_err());
    }
}
