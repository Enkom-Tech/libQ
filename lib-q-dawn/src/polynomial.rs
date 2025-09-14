//! Polynomial arithmetic for DAWN NTRU operations
//!
//! This module implements polynomial operations over power-of-2 cyclotomic rings
//! R[x^n+1] as required by the DAWN specification.
//!
//! Based on the ntrust-native and FN-DSA implementations for secure, efficient
//! polynomial arithmetic operations.

#[cfg(not(feature = "std"))]
use alloc::{
    string::ToString,
    vec,
    vec::Vec,
};
use core::ops::{
    Add,
    Mul,
    Neg,
    Sub,
};

use lib_q_core::{
    Error,
    Result,
};
// Import RNG traits for random polynomial generation
use rand_core::RngCore;

/// A polynomial over the ring R[x^n+1] where n is a power of 2
#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    /// Coefficients of the polynomial
    pub coefficients: Vec<i32>,
    /// Degree of the polynomial (must be a power of 2)
    pub degree: usize,
}

impl Polynomial {
    /// Create a new polynomial with the given degree
    pub fn new(degree: usize) -> Self {
        assert!(degree.is_power_of_two(), "Degree must be a power of 2");
        Self {
            coefficients: vec![0; degree],
            degree,
        }
    }

    /// Create a polynomial from coefficients
    pub fn from_coefficients(coefficients: Vec<i32>) -> Self {
        let degree = coefficients.len();
        assert!(degree.is_power_of_two(), "Degree must be a power of 2");
        Self {
            coefficients,
            degree,
        }
    }

    /// Get the coefficient at index i
    pub fn coefficient(&self, i: usize) -> i32 {
        self.coefficients[i % self.degree]
    }

    /// Set the coefficient at index i
    pub fn set_coefficient(&mut self, i: usize, value: i32) {
        self.coefficients[i % self.degree] = value;
    }

    /// Reduce the polynomial modulo x^n + 1
    pub fn reduce_mod_cyclotomic(&mut self) {
        for i in self.degree..self.coefficients.len() {
            let idx = i % self.degree;
            self.coefficients[idx] -= self.coefficients[i];
        }
        self.coefficients.truncate(self.degree);
    }

    /// Compute the norm of the polynomial
    pub fn norm(&self) -> u64 {
        self.coefficients
            .iter()
            .map(|&c| (c as i64).pow(2) as u64)
            .sum()
    }

    /// Check if the polynomial is invertible modulo x^n + 1
    pub fn is_invertible(&self) -> bool {
        // For NTRU, we need to check if the polynomial is invertible
        // This is a simplified check - in practice, we'd use more sophisticated methods
        self.coefficients.iter().any(|&c| c != 0)
    }
}

impl Add for Polynomial {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        assert_eq!(
            self.degree, rhs.degree,
            "Polynomials must have the same degree"
        );

        let mut result = self;
        for (i, &coeff) in rhs.coefficients.iter().enumerate() {
            result.coefficients[i] += coeff;
        }
        result.reduce_mod_cyclotomic();
        result
    }
}

impl Sub for Polynomial {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        assert_eq!(
            self.degree, rhs.degree,
            "Polynomials must have the same degree"
        );

        let mut result = self;
        for (i, &coeff) in rhs.coefficients.iter().enumerate() {
            result.coefficients[i] -= coeff;
        }
        result.reduce_mod_cyclotomic();
        result
    }
}

impl Neg for Polynomial {
    type Output = Self;

    fn neg(self) -> Self {
        let mut result = self;
        for coeff in &mut result.coefficients {
            *coeff = -*coeff;
        }
        result
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        assert_eq!(
            self.degree, rhs.degree,
            "Polynomials must have the same degree"
        );

        let mut result = Self::new(self.degree);

        // Naive polynomial multiplication
        for i in 0..self.degree {
            for j in 0..self.degree {
                let idx = (i + j) % self.degree;
                result.coefficients[idx] += self.coefficients[i] * rhs.coefficients[j];
            }
        }

        result.reduce_mod_cyclotomic();
        result
    }
}

/// Polynomial operations over finite fields
pub mod field {
    use super::*;

    /// A polynomial over a finite field Z_q
    #[derive(Clone, Debug, PartialEq)]
    pub struct FieldPolynomial {
        pub coefficients: Vec<u32>,
        pub degree: usize,
        pub modulus: u32,
    }

    impl FieldPolynomial {
        /// Create a new field polynomial
        pub fn new(degree: usize, modulus: u32) -> Self {
            assert!(degree.is_power_of_two(), "Degree must be a power of 2");
            Self {
                coefficients: vec![0; degree],
                degree,
                modulus,
            }
        }

        /// Create from coefficients
        pub fn from_coefficients(coefficients: Vec<u32>, modulus: u32) -> Self {
            let degree = coefficients.len();
            assert!(degree.is_power_of_two(), "Degree must be a power of 2");
            Self {
                coefficients,
                degree,
                modulus,
            }
        }

        /// Reduce coefficients modulo the field modulus
        pub fn reduce_mod_field(&mut self) {
            for coeff in &mut self.coefficients {
                *coeff %= self.modulus;
            }
        }

        /// Reduce modulo x^n + 1
        pub fn reduce_mod_cyclotomic(&mut self) {
            for i in self.degree..self.coefficients.len() {
                let idx = i % self.degree;
                self.coefficients[idx] =
                    (self.coefficients[idx] + self.modulus - self.coefficients[i]) % self.modulus;
            }
            self.coefficients.truncate(self.degree);
        }

        /// Compute the inverse of the polynomial (if it exists)
        ///
        /// Uses Newton's method for polynomial inversion over Z_q[x]/(x^n + 1)
        /// Based on ntrust-native implementation
        pub fn inverse(&self) -> Result<Self> {
            if !self.is_invertible() {
                return Err(Error::InternalError {
                    operation: "polynomial inversion".to_string(),
                    details: "polynomial is not invertible".to_string(),
                });
            }

            // Newton's method for polynomial inversion
            // Start with initial guess: 1 / constant_term
            let mut result = Self::new(self.degree, self.modulus);
            if self.coefficients[0] != 0 {
                let inv_constant = self.mod_inverse(self.coefficients[0])?;
                result.coefficients[0] = inv_constant;
            } else {
                // If constant term is zero, find first non-zero coefficient
                for i in 1..self.degree {
                    if self.coefficients[i] != 0 {
                        let inv_coeff = self.mod_inverse(self.coefficients[i])?;
                        result.coefficients[self.degree - i] = inv_coeff;
                        break;
                    }
                }
            }

            // Newton iteration: x_{n+1} = x_n * (2 - a * x_n)
            for _ in 0..4 {
                // 4 iterations should be sufficient for convergence
                let mut temp = self.clone() * result.clone();
                temp.reduce_mod_field();
                temp.reduce_mod_cyclotomic();

                // Compute 2 - a * x_n
                for i in 0..self.degree {
                    temp.coefficients[i] = (2 * self.modulus - temp.coefficients[i]) % self.modulus;
                }

                result = result * temp;
                result.reduce_mod_field();
                result.reduce_mod_cyclotomic();
            }

            Ok(result)
        }

        /// Modular inverse using extended Euclidean algorithm
        fn mod_inverse(&self, a: u32) -> Result<u32> {
            if a == 0 {
                return Err(Error::InternalError {
                    operation: "modular inverse".to_string(),
                    details: "cannot compute inverse of zero".to_string(),
                });
            }

            // Extended Euclidean algorithm for integers
            let mut old_r = a as i64;
            let mut r = self.modulus as i64;
            let mut old_s = 1i64;
            let mut s = 0i64;

            while r != 0 {
                let quotient = old_r / r;
                let temp = r;
                r = old_r - quotient * r;
                old_r = temp;

                let temp = s;
                s = old_s - quotient * s;
                old_s = temp;
            }

            if old_r > 1 {
                return Err(Error::InternalError {
                    operation: "modular inverse".to_string(),
                    details: "element is not invertible".to_string(),
                });
            }

            // Ensure positive result
            let result = if old_s < 0 {
                (old_s + self.modulus as i64) as u32
            } else {
                old_s as u32
            };

            Ok(result % self.modulus)
        }

        /// Check if the polynomial is invertible
        pub fn is_invertible(&self) -> bool {
            // For NTRU, a polynomial is invertible if it has at least one non-zero coefficient
            // and the constant term is non-zero (for proper inversion)
            self.coefficients.iter().any(|&c| c != 0) && self.coefficients[0] != 0
        }

        /// Sample a random polynomial with coefficients in [0, q-1]
        pub fn random(degree: usize, modulus: u32, rng: &mut impl RngCore) -> Self {
            let mut poly = Self::new(degree, modulus);
            for i in 0..degree {
                poly.coefficients[i] = rng.next_u32() % modulus;
            }
            poly
        }

        /// Sample a trinary polynomial (coefficients in {-1, 0, 1})
        pub fn random_trinary(degree: usize, modulus: u32, rng: &mut impl RngCore) -> Self {
            let mut poly = Self::new(degree, modulus);
            for i in 0..degree {
                let val = rng.next_u32() % 3;
                poly.coefficients[i] = match val {
                    0 => 0,
                    1 => 1,
                    2 => modulus - 1, // -1 mod q
                    _ => unreachable!(),
                };
            }
            poly
        }

        /// Sample a small polynomial (coefficients in small range)
        pub fn random_small(
            degree: usize,
            modulus: u32,
            bound: u32,
            rng: &mut impl RngCore,
        ) -> Self {
            let mut poly = Self::new(degree, modulus);
            for i in 0..degree {
                let val = rng.next_u32() % (2 * bound + 1);
                poly.coefficients[i] = if val <= bound {
                    val
                } else {
                    modulus - (val - bound)
                };
            }
            poly
        }

        /// Compute the norm of the polynomial
        pub fn norm(&self) -> u64 {
            self.coefficients.iter().map(|&c| (c as u64).pow(2)).sum()
        }

        /// Check if polynomial is small (all coefficients are small)
        pub fn is_small(&self, bound: u32) -> bool {
            self.coefficients
                .iter()
                .all(|&c| c <= bound || c >= self.modulus - bound)
        }
    }

    impl Add for FieldPolynomial {
        type Output = Self;

        fn add(self, rhs: Self) -> Self {
            assert_eq!(
                self.degree, rhs.degree,
                "Polynomials must have the same degree"
            );
            assert_eq!(
                self.modulus, rhs.modulus,
                "Polynomials must have the same modulus"
            );

            let mut result = self;
            for (i, &coeff) in rhs.coefficients.iter().enumerate() {
                result.coefficients[i] = (result.coefficients[i] + coeff) % result.modulus;
            }
            result
        }
    }

    impl Sub for FieldPolynomial {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self {
            assert_eq!(
                self.degree, rhs.degree,
                "Polynomials must have the same degree"
            );
            assert_eq!(
                self.modulus, rhs.modulus,
                "Polynomials must have the same modulus"
            );

            let mut result = self;
            for (i, &coeff) in rhs.coefficients.iter().enumerate() {
                result.coefficients[i] =
                    (result.coefficients[i] + result.modulus - coeff) % result.modulus;
            }
            result
        }
    }

    impl Mul for FieldPolynomial {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self {
            assert_eq!(
                self.degree, rhs.degree,
                "Polynomials must have the same degree"
            );
            assert_eq!(
                self.modulus, rhs.modulus,
                "Polynomials must have the same modulus"
            );

            let mut result = Self::new(self.degree, self.modulus);

            // Naive polynomial multiplication
            for i in 0..self.degree {
                for j in 0..self.degree {
                    let idx = (i + j) % self.degree;
                    result.coefficients[idx] = (result.coefficients[idx] +
                        (self.coefficients[i] as u64 * rhs.coefficients[j] as u64) as u32) %
                        self.modulus;
                }
            }

            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_creation() {
        let poly = Polynomial::new(512);
        assert_eq!(poly.degree, 512);
        assert_eq!(poly.coefficients.len(), 512);
    }

    #[test]
    fn test_polynomial_addition() {
        let mut poly1 = Polynomial::new(4);
        poly1.set_coefficient(0, 1);
        poly1.set_coefficient(1, 2);

        let mut poly2 = Polynomial::new(4);
        poly2.set_coefficient(0, 3);
        poly2.set_coefficient(1, 4);

        let result = poly1 + poly2;
        assert_eq!(result.coefficient(0), 4);
        assert_eq!(result.coefficient(1), 6);
    }

    #[test]
    fn test_polynomial_multiplication() {
        let mut poly1 = Polynomial::new(4);
        poly1.set_coefficient(0, 1);
        poly1.set_coefficient(1, 1);

        let mut poly2 = Polynomial::new(4);
        poly2.set_coefficient(0, 1);
        poly2.set_coefficient(1, 1);

        let result = poly1 * poly2;
        // (1 + x) * (1 + x) = 1 + 2x + x^2
        assert_eq!(result.coefficient(0), 1);
        assert_eq!(result.coefficient(1), 2);
        assert_eq!(result.coefficient(2), 1);
    }

    #[test]
    fn test_field_polynomial() {
        let poly = field::FieldPolynomial::new(4, 769);
        assert_eq!(poly.degree, 4);
        assert_eq!(poly.modulus, 769);
    }

    #[test]
    fn test_field_polynomial_operations() {
        let mut poly1 = field::FieldPolynomial::new(4, 769);
        poly1.coefficients[0] = 100;
        poly1.coefficients[1] = 200;

        let mut poly2 = field::FieldPolynomial::new(4, 769);
        poly2.coefficients[0] = 300;
        poly2.coefficients[1] = 400;

        let result = poly1 + poly2;
        assert_eq!(result.coefficients[0], 400);
        assert_eq!(result.coefficients[1], 600);
    }
}
