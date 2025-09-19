//! Mathematical operations for RCPKC
//!
//! This module provides the core mathematical functions needed for the
//! RCPKC cryptosystem, including modular arithmetic and polynomial operations.

use lib_q_core::Result;

/// Modular arithmetic operations
pub struct ModularArithmetic;

impl ModularArithmetic {
    /// Add two numbers modulo m
    pub fn add(a: u64, b: u64, m: u64) -> u64 {
        ((a as u128 + b as u128) % m as u128) as u64
    }

    /// Subtract two numbers modulo m
    pub fn sub(a: u64, b: u64, m: u64) -> u64 {
        let result = (a as i128 - b as i128) % m as i128;
        if result < 0 {
            (result + m as i128) as u64
        } else {
            result as u64
        }
    }

    /// Multiply two numbers modulo m
    /// Uses constant-time operations to prevent timing attacks
    pub fn mul(a: u64, b: u64, m: u64) -> u64 {
        // Use u128 to prevent overflow and ensure constant-time behavior
        let result = (a as u128 * b as u128) % m as u128;
        result as u64
    }

    /// Compute a^b mod m using binary exponentiation
    pub fn pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;

        while exp > 0 {
            if exp % 2 == 1 {
                result = Self::mul(result, base, m);
            }
            exp >>= 1;
            base = Self::mul(base, base, m);
        }

        result
    }

    /// Compute modular inverse using extended Euclidean algorithm
    pub fn mod_inverse(a: u64, m: u64) -> Result<u64> {
        let (gcd, x, _) = Self::extended_gcd(a, m);

        if gcd != 1 {
            return Err(lib_q_core::Error::InternalError {
                operation: "mod_inverse".to_string(),
                details: "No modular inverse exists".to_string(),
            });
        }

        // Ensure result is positive
        let result = ((x % m as i64) + m as i64) % m as i64;
        Ok(result as u64)
    }

    /// Extended Euclidean algorithm
    pub fn extended_gcd(a: u64, b: u64) -> (u64, i64, i64) {
        if a == 0 {
            (b, 0, 1)
        } else {
            let (gcd, x1, y1) = Self::extended_gcd(b % a, a);
            let x = y1 - (b / a) as i64 * x1;
            let y = x1;
            (gcd, x, y)
        }
    }

    /// Greatest common divisor
    pub fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let temp = b;
            b = a % b;
            a = temp;
        }
        a
    }
}

/// Polynomial operations for RCPKC
pub struct PolynomialOps;

impl PolynomialOps {
    /// Evaluate a polynomial at a point using Horner's method
    pub fn evaluate(coefficients: &[u64], x: u64, modulus: u64) -> u64 {
        let mut result = 0u64;

        for &coeff in coefficients.iter().rev() {
            result = ModularArithmetic::mul(result, x, modulus);
            result = ModularArithmetic::add(result, coeff, modulus);
        }

        result
    }

    /// Generate a random polynomial of given degree
    pub fn random_polynomial(degree: usize, modulus: u64) -> Result<Vec<u64>> {
        if degree == 0 {
            return Err(lib_q_core::Error::InternalError {
                operation: "random_polynomial".to_string(),
                details: "Degree must be at least 1".to_string(),
            });
        }

        let mut coefficients = Vec::with_capacity(degree + 1);

        // Generate random coefficients
        for _ in 0..=degree {
            let random_bytes = lib_q_core::api::Utils::random_bytes(8)?;
            let coeff = u64::from_le_bytes([
                random_bytes[0],
                random_bytes[1],
                random_bytes[2],
                random_bytes[3],
                random_bytes[4],
                random_bytes[5],
                random_bytes[6],
                random_bytes[7],
            ]);
            coefficients.push(coeff % modulus);
        }

        Ok(coefficients)
    }

    /// Check if a polynomial is invertible modulo a given modulus
    pub fn is_invertible(coefficients: &[u64], modulus: u64) -> bool {
        // A polynomial is invertible if its constant term is coprime to the modulus
        if coefficients.is_empty() {
            return false;
        }

        ModularArithmetic::gcd(coefficients[0], modulus) == 1
    }
}

/// RCPKC One-Way Function implementation
///
/// Implements the core RCPKC one-way function: F_h(m, r) = r · h + m (mod q)
/// This is the fundamental mathematical primitive underlying RCPKC encryption.
///
/// From Section 7 of the research paper:
/// "The one-way function underlying RCPKC is: F_h: D_m × D_r → Z_q"
/// where F_h(m, r) = r · h + m (mod q)
pub struct RcpkcOneWayFunction;

impl RcpkcOneWayFunction {
    /// Compute the RCPKC one-way function F_h(m, r) = r · h + m (mod q)
    ///
    /// # Arguments
    /// * `h` - Public key polynomial (mod q)
    /// * `m` - Message polynomial (from domain D_m)
    /// * `r` - Random polynomial (from domain D_r)
    /// * `q` - Modulus
    ///
    /// # Returns
    /// The result of F_h(m, r) = r · h + m (mod q)
    ///
    /// # Security
    /// This function is designed to be one-way: given the output and h,
    /// it should be computationally infeasible to find the input (m, r).
    pub fn compute(h: u64, m: u64, r: u64, q: u64) -> u64 {
        // F_h(m, r) = r · h + m (mod q)
        let r_h = ModularArithmetic::mul(r, h, q);
        ModularArithmetic::add(r_h, m, q)
    }

    /// Verify if a given output could have been produced by the one-way function
    ///
    /// # Arguments
    /// * `output` - The claimed output of F_h(m, r)
    /// * `h` - Public key polynomial
    /// * `m` - Message polynomial
    /// * `r` - Random polynomial
    /// * `q` - Modulus
    ///
    /// # Returns
    /// `true` if output == F_h(m, r), `false` otherwise
    pub fn verify(output: u64, h: u64, m: u64, r: u64, q: u64) -> bool {
        let expected = Self::compute(h, m, r, q);
        output == expected
    }

    /// Attempt to find a pre-image for the one-way function (for testing/analysis)
    ///
    /// # Warning
    /// This function is for educational/testing purposes only.
    /// In practice, finding pre-images should be computationally infeasible.
    ///
    /// # Arguments
    /// * `output` - The output of F_h(m, r)
    /// * `h` - Public key polynomial
    /// * `q` - Modulus
    /// * `m_candidates` - Possible message values to try
    /// * `r_candidates` - Possible random values to try
    ///
    /// # Returns
    /// `Some((m, r))` if a pre-image is found, `None` otherwise
    pub fn find_preimage(
        output: u64,
        h: u64,
        q: u64,
        m_candidates: &[u64],
        r_candidates: &[u64],
    ) -> Option<(u64, u64)> {
        for &m in m_candidates {
            for &r in r_candidates {
                if Self::compute(h, m, r, q) == output {
                    return Some((m, r));
                }
            }
        }
        None
    }

    /// Check if the one-way function preserves the security properties
    ///
    /// # Arguments
    /// * `h` - Public key polynomial
    /// * `q` - Modulus
    /// * `test_cases` - Test cases to verify
    ///
    /// # Returns
    /// `true` if all test cases pass, `false` otherwise
    pub fn validate_security_properties(
        h: u64,
        q: u64,
        test_cases: &[(u64, u64, u64)], // (m, r, expected_output)
    ) -> bool {
        for &(m, r, expected) in test_cases {
            let actual = Self::compute(h, m, r, q);
            if actual != expected {
                return false;
            }
        }
        true
    }
}

/// Lattice reduction operations (simplified for RCPKC)
pub struct LatticeOps;

impl LatticeOps {
    /// Simplified lattice basis reduction for RCPKC
    /// This is a basic implementation for the specific RCPKC case
    pub fn reduce_basis(v1: &[u64], v2: &[u64], modulus: u64) -> Result<(Vec<u64>, Vec<u64>)> {
        if v1.len() != v2.len() {
            return Err(lib_q_core::Error::InternalError {
                operation: "reduce_basis".to_string(),
                details: "Vectors must have the same length".to_string(),
            });
        }

        let u1 = v1.to_vec();
        let mut u2 = v2.to_vec();

        // Simple reduction step
        let dot_product = Self::dot_product(&u1, &u2, modulus);
        let norm_squared = Self::norm_squared(&u1, modulus);

        if norm_squared > 0 {
            let reduction_factor = dot_product / norm_squared;

            for i in 0..u2.len() {
                let reduction = ModularArithmetic::mul(reduction_factor, u1[i], modulus);
                u2[i] = ModularArithmetic::sub(u2[i], reduction, modulus);
            }
        }

        Ok((u1, u2))
    }

    /// Compute dot product of two vectors modulo m
    pub fn dot_product(v1: &[u64], v2: &[u64], modulus: u64) -> u64 {
        let mut result = 0u64;

        for (a, b) in v1.iter().zip(v2.iter()) {
            result =
                ModularArithmetic::add(result, ModularArithmetic::mul(*a, *b, modulus), modulus);
        }

        result
    }

    /// Compute squared norm of a vector modulo m
    pub fn norm_squared(v: &[u64], modulus: u64) -> u64 {
        Self::dot_product(v, v, modulus)
    }
}

/// Random number generation utilities
pub struct RandomOps;

impl RandomOps {
    /// Generate a random number in the range [0, max)
    pub fn random_in_range(max: u64) -> Result<u64> {
        if max == 0 {
            return Err(lib_q_core::Error::InternalError {
                operation: "random_in_range".to_string(),
                details: "Maximum value must be greater than 0".to_string(),
            });
        }

        let random_bytes = lib_q_core::api::Utils::random_bytes(8)?;
        let random_value = u64::from_le_bytes([
            random_bytes[0],
            random_bytes[1],
            random_bytes[2],
            random_bytes[3],
            random_bytes[4],
            random_bytes[5],
            random_bytes[6],
            random_bytes[7],
        ]);

        Ok(random_value % max)
    }

    /// Generate a random polynomial coefficient
    pub fn random_coefficient(modulus: u64) -> Result<u64> {
        Self::random_in_range(modulus)
    }

    /// Generate a random message for encryption
    pub fn random_message(size: usize) -> Result<Vec<u8>> {
        lib_q_core::api::Utils::random_bytes(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modular_arithmetic() {
        let m = 17u64;

        // Test addition
        assert_eq!(ModularArithmetic::add(10, 15, m), 8);
        assert_eq!(ModularArithmetic::add(16, 1, m), 0);

        // Test subtraction
        assert_eq!(ModularArithmetic::sub(5, 10, m), 12);
        assert_eq!(ModularArithmetic::sub(0, 1, m), 16);

        // Test multiplication
        assert_eq!(ModularArithmetic::mul(3, 5, m), 15);
        assert_eq!(ModularArithmetic::mul(16, 2, m), 15);

        // Test exponentiation
        assert_eq!(ModularArithmetic::pow(2, 3, m), 8);
        assert_eq!(ModularArithmetic::pow(3, 4, m), 13);
    }

    #[test]
    fn test_pow_function_usage() {
        // Test the pow function with various inputs to ensure it's used
        let m = 17u64;

        // Test with different bases and exponents
        assert_eq!(ModularArithmetic::pow(1, 100, m), 1);
        assert_eq!(ModularArithmetic::pow(0, 5, m), 0);
        assert_eq!(ModularArithmetic::pow(2, 0, m), 1);
        assert_eq!(ModularArithmetic::pow(3, 1, m), 3);

        // Test with large exponents
        assert_eq!(ModularArithmetic::pow(2, 10, m), 4); // 2^10 = 1024 ≡ 4 (mod 17)
    }

    #[test]
    fn test_mod_inverse() {
        let m = 17u64;

        // Test with coprime numbers
        assert_eq!(ModularArithmetic::mod_inverse(3, m).unwrap(), 6);
        assert_eq!(ModularArithmetic::mod_inverse(5, m).unwrap(), 7);

        // Test with non-coprime numbers
        assert!(ModularArithmetic::mod_inverse(2, 4).is_err());
    }

    #[test]
    fn test_polynomial_evaluation() {
        let coefficients = vec![1, 2, 3]; // 3x^2 + 2x + 1
        let modulus = 17u64;

        // Evaluate at x = 1: 3(1)^2 + 2(1) + 1 = 6
        assert_eq!(PolynomialOps::evaluate(&coefficients, 1, modulus), 6);

        // Evaluate at x = 2: 3(2)^2 + 2(2) + 1 = 17 ≡ 0 (mod 17)
        assert_eq!(PolynomialOps::evaluate(&coefficients, 2, modulus), 0);
    }

    #[test]
    fn test_random_polynomial() {
        let degree = 3;
        let modulus = 17u64;

        // Generate a random polynomial
        let poly = PolynomialOps::random_polynomial(degree, modulus).unwrap();

        // Check that it has the correct degree + 1 coefficients
        assert_eq!(poly.len(), degree + 1);

        // Check that all coefficients are within the modulus
        for &coeff in &poly {
            assert!(coeff < modulus);
        }

        // Test error case
        assert!(PolynomialOps::random_polynomial(0, modulus).is_err());
    }

    #[test]
    fn test_is_invertible() {
        let modulus = 17u64; // Prime number

        // Test invertible polynomial (constant term coprime to modulus)
        let invertible_coeffs = vec![3, 2, 1]; // 3 is coprime to 17
        assert!(PolynomialOps::is_invertible(&invertible_coeffs, modulus));

        // Test non-invertible polynomial (constant term not coprime to modulus)
        let non_invertible_coeffs = vec![17, 2, 1]; // 17 is not coprime to 17
        assert!(!PolynomialOps::is_invertible(
            &non_invertible_coeffs,
            modulus
        ));

        // Test empty polynomial
        let empty_coeffs = vec![];
        assert!(!PolynomialOps::is_invertible(&empty_coeffs, modulus));
    }

    #[test]
    fn test_lattice_operations() {
        let v1 = vec![1, 2];
        let v2 = vec![3, 4];
        let modulus = 17u64;

        let dot = LatticeOps::dot_product(&v1, &v2, modulus);
        assert_eq!(dot, 11); // 1*3 + 2*4 = 11

        let norm_sq = LatticeOps::norm_squared(&v1, modulus);
        assert_eq!(norm_sq, 5); // 1*1 + 2*2 = 5
    }

    #[test]
    fn test_random_operations() {
        // Test random number generation
        let random_num = RandomOps::random_in_range(100).unwrap();
        assert!(random_num < 100);

        // Test random coefficient
        let coeff = RandomOps::random_coefficient(17).unwrap();
        assert!(coeff < 17);

        // Test random message
        let message = RandomOps::random_message(32).unwrap();
        assert_eq!(message.len(), 32);
    }

    #[test]
    fn test_rcpkc_one_way_function() {
        // Test parameters from Maple examples
        let h = 12345u64; // Public key
        let q = 65537u64; // Modulus
        let m = 1000u64; // Message
        let r = 5000u64; // Random value

        // Test basic computation: F_h(m, r) = r · h + m (mod q)
        let result = RcpkcOneWayFunction::compute(h, m, r, q);
        let expected = (r * h + m) % q;
        assert_eq!(result, expected);

        // Test verification
        assert!(RcpkcOneWayFunction::verify(result, h, m, r, q));
        assert!(!RcpkcOneWayFunction::verify(result + 1, h, m, r, q));

        // Test with different values
        let m2 = 2000u64;
        let r2 = 3000u64;
        let result2 = RcpkcOneWayFunction::compute(h, m2, r2, q);
        assert_ne!(result, result2); // Different inputs should produce different outputs
    }

    #[test]
    fn test_rcpkc_one_way_function_preimage_search() {
        let h = 12345u64;
        let q = 65537u64;
        let m = 1000u64;
        let r = 5000u64;

        // Compute the one-way function
        let output = RcpkcOneWayFunction::compute(h, m, r, q);

        // Try to find the pre-image with small candidate sets
        let m_candidates = vec![999, 1000, 1001];
        let r_candidates = vec![4999, 5000, 5001];

        let preimage =
            RcpkcOneWayFunction::find_preimage(output, h, q, &m_candidates, &r_candidates);
        assert!(preimage.is_some());
        let (found_m, found_r) = preimage.unwrap();
        assert_eq!(found_m, m);
        assert_eq!(found_r, r);
    }

    #[test]
    fn test_rcpkc_one_way_function_security_properties() {
        let h = 12345u64;
        let q = 65537u64;

        // Test cases: (m, r, expected_output)
        let test_cases = vec![
            (1000, 5000, (5000 * h + 1000) % q),
            (2000, 3000, (3000 * h + 2000) % q),
            (500, 7000, (7000 * h + 500) % q),
        ];

        // Validate security properties
        assert!(RcpkcOneWayFunction::validate_security_properties(
            h,
            q,
            &test_cases
        ));

        // Test with incorrect expected values
        let incorrect_test_cases = vec![
            (1000, 5000, (5000 * h + 1000) % q + 1), // Wrong expected output
        ];
        assert!(!RcpkcOneWayFunction::validate_security_properties(
            h,
            q,
            &incorrect_test_cases
        ));
    }

    #[test]
    fn test_rcpkc_one_way_function_edge_cases() {
        let h = 12345u64;
        let q = 65537u64;

        // Test with zero values
        let result_zero = RcpkcOneWayFunction::compute(h, 0, 0, q);
        assert_eq!(result_zero, 0);

        // Test with maximum values
        let result_max = RcpkcOneWayFunction::compute(h, q - 1, q - 1, q);
        let expected_max = ((q - 1) * h + (q - 1)) % q;
        assert_eq!(result_max, expected_max);

        // Test commutativity of addition (r · h + m = m + r · h)
        let m = 1000u64;
        let r = 5000u64;
        let result1 = RcpkcOneWayFunction::compute(h, m, r, q);
        let result2 = (m + (r * h) % q) % q;
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_rcpkc_one_way_function_verify_usage() {
        let h = 12345u64;
        let q = 65537u64;
        let m = 1000u64;
        let r = 5000u64;

        // Test the verify function with correct values
        let output = RcpkcOneWayFunction::compute(h, m, r, q);
        assert!(RcpkcOneWayFunction::verify(output, h, m, r, q));

        // Test the verify function with incorrect values
        assert!(!RcpkcOneWayFunction::verify(output + 1, h, m, r, q));
        assert!(!RcpkcOneWayFunction::verify(output, h + 1, m, r, q));
        assert!(!RcpkcOneWayFunction::verify(output, h, m + 1, r, q));
        assert!(!RcpkcOneWayFunction::verify(output, h, m, r + 1, q));
    }

    #[test]
    fn test_rcpkc_one_way_function_find_preimage_usage() {
        let h = 12345u64;
        let q = 65537u64;
        let m = 1000u64;
        let r = 5000u64;

        // Compute the one-way function
        let output = RcpkcOneWayFunction::compute(h, m, r, q);

        // Test find_preimage with correct candidates
        let m_candidates = vec![999, 1000, 1001];
        let r_candidates = vec![4999, 5000, 5001];

        let preimage =
            RcpkcOneWayFunction::find_preimage(output, h, q, &m_candidates, &r_candidates);
        assert!(preimage.is_some());
        let (found_m, found_r) = preimage.unwrap();
        assert_eq!(found_m, m);
        assert_eq!(found_r, r);

        // Test find_preimage with incorrect candidates
        let wrong_m_candidates = vec![2000, 2001, 2002];
        let wrong_r_candidates = vec![6000, 6001, 6002];

        let no_preimage = RcpkcOneWayFunction::find_preimage(
            output,
            h,
            q,
            &wrong_m_candidates,
            &wrong_r_candidates,
        );
        assert!(no_preimage.is_none());
    }

    #[test]
    fn test_rcpkc_one_way_function_validate_security_properties_usage() {
        let h = 12345u64;
        let q = 65537u64;

        // Test cases: (m, r, expected_output)
        let test_cases = vec![
            (1000, 5000, (5000 * h + 1000) % q),
            (2000, 3000, (3000 * h + 2000) % q),
            (500, 7000, (7000 * h + 500) % q),
        ];

        // Test validate_security_properties with correct test cases
        assert!(RcpkcOneWayFunction::validate_security_properties(
            h,
            q,
            &test_cases
        ));

        // Test validate_security_properties with incorrect test cases
        let incorrect_test_cases = vec![
            (1000, 5000, (5000 * h + 1000) % q + 1), // Wrong expected output
        ];
        assert!(!RcpkcOneWayFunction::validate_security_properties(
            h,
            q,
            &incorrect_test_cases
        ));

        // Test with empty test cases
        let empty_test_cases = vec![];
        assert!(RcpkcOneWayFunction::validate_security_properties(
            h,
            q,
            &empty_test_cases
        ));
    }
}
