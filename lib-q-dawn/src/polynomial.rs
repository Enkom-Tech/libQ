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
use rand_core::Rng;

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

    fn poly_degree(p: &[i64]) -> usize {
        for i in (0..p.len()).rev() {
            if p[i] != 0 {
                return i;
            }
        }
        0
    }

    fn scalar_inv(a: i64, q: i64) -> Option<i64> {
        if a == 0 {
            return None;
        }
        let a = a.rem_euclid(q);
        let (mut old_r, mut r) = (a, q);
        let (mut old_s, mut s) = (1i64, 0i64);
        while r != 0 {
            let qt = old_r / r;
            (old_r, r) = (r, old_r - qt * r);
            (old_s, s) = (s, old_s - qt * s);
        }
        if old_r != 1 {
            return None;
        }
        Some(old_s.rem_euclid(q))
    }

    fn poly_div_rem_zq(dividend: &[i64], divisor: &[i64], q: i64) -> (Vec<i64>, Vec<i64>) {
        let mut rem = dividend.to_vec();
        let dd = poly_degree(divisor);
        let lead_inv = scalar_inv(divisor[dd], q).expect("divisor leading coeff not invertible");
        let mut quot = vec![0i64; dividend.len()];
        loop {
            let dr = poly_degree(&rem);
            if dr < dd || (dr == 0 && rem[0] == 0) {
                break;
            }
            let k = dr - dd;
            let scale = (rem[dr] * lead_inv).rem_euclid(q);
            quot[k] = (quot[k] + scale).rem_euclid(q);
            for j in 0..=dd {
                if j + k < rem.len() {
                    rem[j + k] = (rem[j + k] - scale * divisor[j]).rem_euclid(q);
                }
            }
        }
        (quot, rem)
    }

    fn poly_mul_zq(a: &[i64], b: &[i64], q: i64) -> Vec<i64> {
        let n = a.len() + b.len().saturating_sub(1);
        let mut res = vec![0i64; n];
        for i in 0..a.len() {
            for j in 0..b.len() {
                res[i + j] = (res[i + j] + a[i] * b[j]).rem_euclid(q);
            }
        }
        res
    }

    fn poly_sub_zq(a: &[i64], b: &[i64], q: i64, len: usize) -> Vec<i64> {
        let mut res = vec![0i64; len];
        for i in 0..len {
            let av = if i < a.len() { a[i] } else { 0 };
            let bv = if i < b.len() { b[i] } else { 0 };
            res[i] = (av - bv).rem_euclid(q);
        }
        res
    }

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

        /// Compute the inverse of the polynomial mod (x^n+1, q) using extended GCD.
        pub fn inverse(&self) -> Result<Self> {
            let n = self.degree;
            let q = self.modulus as i64;
            let cap = 2 * n + 2;

            let mut modpoly = vec![0i64; cap];
            modpoly[0] = 1;
            modpoly[n] = 1;

            let mut r0 = modpoly.clone();
            let mut r1: Vec<i64> = self.coefficients.iter().map(|&c| c as i64).collect();
            r1.resize(cap, 0);

            let mut s0 = vec![0i64; cap];
            let mut s1 = vec![0i64; cap];
            s1[0] = 1;

            loop {
                if poly_degree(&r1) == 0 && r1[0] == 0 {
                    return Err(Error::InternalError {
                        operation: "polynomial inversion".to_string(),
                        details: "polynomial is not invertible mod (x^n+1, q)".to_string(),
                    });
                }
                if poly_degree(&r1) == 0 {
                    let c_inv = scalar_inv(r1[0], q).ok_or_else(|| Error::InternalError {
                        operation: "polynomial inversion".to_string(),
                        details: "gcd leading coeff not invertible".to_string(),
                    })?;
                    let mut inv_full: Vec<i64> =
                        s1.iter().map(|&c| (c * c_inv).rem_euclid(q)).collect();
                    for i in n..inv_full.len() {
                        let idx = i - n;
                        inv_full[idx] = (inv_full[idx] - inv_full[i]).rem_euclid(q);
                    }
                    let inv_coeffs: Vec<u32> = inv_full[..n].iter().map(|&c| c as u32).collect();
                    return Ok(Self::from_coefficients(inv_coeffs, self.modulus));
                }

                let (q_poly, rem) = poly_div_rem_zq(&r0, &r1, q);
                let qs1 = poly_mul_zq(&q_poly, &s1, q);
                let new_s0 = poly_sub_zq(&s0, &qs1, q, cap);

                r0 = r1;
                r1 = rem;
                r1.resize(cap, 0);
                s0 = s1;
                s1 = new_s0;
            }
        }

        /// Check if the polynomial is invertible mod (x^n+1, q).
        pub fn is_invertible(&self) -> bool {
            self.inverse().is_ok()
        }

        /// Sample a random polynomial with coefficients in [0, q-1]
        pub fn random(degree: usize, modulus: u32, rng: &mut impl Rng) -> Self {
            let mut poly = Self::new(degree, modulus);
            for i in 0..degree {
                poly.coefficients[i] = rng.next_u32() % modulus;
            }
            poly
        }

        /// Sample a trinary polynomial (coefficients in {-1, 0, 1})
        pub fn random_trinary(degree: usize, modulus: u32, rng: &mut impl Rng) -> Self {
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
        pub fn random_small(degree: usize, modulus: u32, bound: u32, rng: &mut impl Rng) -> Self {
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

        /// Sample from T_{n,k}: exactly k coefficients equal to +1, k equal to -1 (mod q), rest zero.
        /// Uses Fisher-Yates shuffle for uniform permutation.
        pub fn random_ternary_exact(
            degree: usize,
            k: usize,
            modulus: u32,
            rng: &mut impl Rng,
        ) -> Self {
            assert!(2 * k <= degree, "T_{{n,k}} requires 2*k <= n");
            let mut poly = Self::new(degree, modulus);
            let minus_one = modulus - 1;
            for i in 0..k {
                poly.coefficients[i] = 1;
            }
            for i in k..(2 * k) {
                poly.coefficients[i] = minus_one;
            }
            for i in (2 * k)..degree {
                poly.coefficients[i] = 0;
            }
            for i in 0..degree {
                let j = i + (rng.next_u32() as usize % (degree - i));
                poly.coefficients.swap(i, j);
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

            // Polynomial multiplication in Z_q[x]/(x^n+1): x^n = -1
            for i in 0..self.degree {
                for j in 0..self.degree {
                    let idx = (i + j) % self.degree;
                    let prod = (self.coefficients[i] as u64 * rhs.coefficients[j] as u64 %
                        self.modulus as u64) as u32;
                    if i + j < self.degree {
                        result.coefficients[idx] = (result.coefficients[idx] + prod) % self.modulus;
                    } else {
                        result.coefficients[idx] =
                            (result.coefficients[idx] + self.modulus - prod) % self.modulus;
                    }
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
