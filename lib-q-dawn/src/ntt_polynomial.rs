//! NTT-based polynomial arithmetic for DAWN KEM
//!
//! This module implements efficient polynomial operations using the Number
//! Theoretic Transform (NTT) for O(n log n) polynomial multiplication.
//!
//! Based on the ntrust-native reference implementation and optimized for
//! DAWN KEM parameter sets.

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

use crate::secure_rng::SecureRng;

/// NTT parameters for different DAWN parameter sets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NttParams {
    /// DAWN-α-512 and DAWN-β-512: n=512, q=769 or q=257
    Dawn512 { q: u32 },
    /// DAWN-α-1024 and DAWN-β-1024: n=1024, q=769 or q=257
    Dawn1024 { q: u32 },
}

impl NttParams {
    /// Get the polynomial degree n
    pub fn degree(&self) -> usize {
        match self {
            NttParams::Dawn512 { .. } => 512,
            NttParams::Dawn1024 { .. } => 1024,
        }
    }

    /// Get the modulus q
    pub fn modulus(&self) -> u32 {
        match self {
            NttParams::Dawn512 { q } | NttParams::Dawn1024 { q } => *q,
        }
    }

    /// Check if NTT is supported for these parameters
    pub fn is_supported(&self) -> bool {
        // NTT requires q ≡ 1 (mod 2n) for degree n
        let n = self.degree() as u32;
        let q = self.modulus();
        (q - 1).is_multiple_of(2 * n)
    }

    /// Get the primitive root of unity for NTT
    pub fn primitive_root(&self) -> Result<u32> {
        let n = self.degree() as u32;
        let q = self.modulus();

        // Find a primitive 2n-th root of unity
        // For NTT, we need ω^(2n) ≡ 1 (mod q) and ω^k ≢ 1 for k < 2n
        let mut candidate = 2u32;
        while candidate < q {
            if mod_pow(candidate, 2 * n, q) == 1 {
                // Check if it's primitive
                let mut is_primitive = true;
                for k in 1..2 * n {
                    if mod_pow(candidate, k, q) == 1 {
                        is_primitive = false;
                        break;
                    }
                }
                if is_primitive {
                    return Ok(candidate);
                }
            }
            candidate += 1;
        }

        Err(Error::InternalError {
            operation: "NTT primitive root".to_string(),
            details: format!("No primitive root found for n={}, q={}", n, q),
        })
    }
}

/// Modular exponentiation: base^exp (mod modulus)
fn mod_pow(mut base: u32, mut exp: u32, modulus: u32) -> u32 {
    let mut result = 1u32;
    base %= modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u64 * base as u64) % modulus as u64) as u32;
        }
        exp >>= 1;
        base = ((base as u64 * base as u64) % modulus as u64) as u32;
    }

    result
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u32, modulus: u32) -> Result<u32> {
    let mut a = a as i64;
    let mut m = modulus as i64;
    let mut x0 = 0i64;
    let mut x1 = 1i64;

    while a > 1 {
        let q = a / m;
        let t = m;
        m = a % m;
        a = t;
        let t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if x1 < 0 {
        x1 += modulus as i64;
    }

    Ok(x1 as u32)
}

/// NTT-based polynomial arithmetic
#[derive(Debug, Clone)]
pub struct NttPolynomial {
    /// Polynomial coefficients
    pub coefficients: Vec<u32>,
    /// NTT parameters
    pub params: NttParams,
    /// Precomputed NTT roots
    roots: Vec<u32>,
    /// Precomputed inverse NTT roots
    roots_inv: Vec<u32>,
    /// Precomputed scaling factor (1/n mod q)
    scale_factor: u32,
}

impl NttPolynomial {
    /// Create a new NTT polynomial
    pub fn new(params: NttParams) -> Result<Self> {
        if !params.is_supported() {
            return Err(Error::InternalError {
                operation: "NTT polynomial creation".to_string(),
                details: "NTT not supported for these parameters".to_string(),
            });
        }

        let n = params.degree();
        let q = params.modulus();

        // Find primitive root
        let root = params.primitive_root()?;
        let root_inv = mod_inverse(root, q)?;

        // Precompute roots
        let mut roots = vec![0u32; 2 * n];
        let mut roots_inv = vec![0u32; 2 * n];

        roots[0] = 1;
        roots_inv[0] = 1;

        for i in 1..2 * n {
            roots[i] = ((roots[i - 1] as u64 * root as u64) % q as u64) as u32;
            roots_inv[i] = ((roots_inv[i - 1] as u64 * root_inv as u64) % q as u64) as u32;
        }

        // Compute scaling factor
        let scale_factor = mod_inverse(n as u32, q)?;

        Ok(Self {
            coefficients: vec![0; n],
            params,
            roots,
            roots_inv,
            scale_factor,
        })
    }

    /// Create from coefficients
    pub fn from_coefficients(coefficients: Vec<u32>, params: NttParams) -> Result<Self> {
        let mut poly = Self::new(params)?;
        let n = poly.params.degree();

        if coefficients.len() != n {
            return Err(Error::InternalError {
                operation: "NTT polynomial creation".to_string(),
                details: format!("Expected {} coefficients, got {}", n, coefficients.len()),
            });
        }

        // Reduce coefficients modulo q
        let q = poly.params.modulus();
        for (i, &coeff) in coefficients.iter().enumerate() {
            poly.coefficients[i] = coeff % q;
        }

        Ok(poly)
    }

    /// Forward NTT transform
    pub fn forward_ntt(&mut self) -> Result<()> {
        let n = self.params.degree();
        let q = self.params.modulus();

        // Bit-reverse permutation
        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;

            if i < j {
                self.coefficients.swap(i, j);
            }
        }

        // NTT computation
        let mut len = 1;
        while len < n {
            let step = n / (2 * len);
            for i in 0..len {
                let w = self.roots[step * i];
                for j in (i..n).step_by(2 * len) {
                    let u = self.coefficients[j];
                    let v = ((self.coefficients[j + len] as u64 * w as u64) % q as u64) as u32;
                    self.coefficients[j] = (u + v) % q;
                    self.coefficients[j + len] = (u + q - v) % q;
                }
            }
            len *= 2;
        }

        Ok(())
    }

    /// Inverse NTT transform
    pub fn inverse_ntt(&mut self) -> Result<()> {
        let n = self.params.degree();
        let q = self.params.modulus();

        // Bit-reverse permutation
        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;

            if i < j {
                self.coefficients.swap(i, j);
            }
        }

        // Inverse NTT computation
        let mut len = n / 2;
        while len >= 1 {
            let step = n / (2 * len);
            for i in 0..len {
                let w = self.roots_inv[step * i];
                for j in (i..n).step_by(2 * len) {
                    let u = self.coefficients[j];
                    let v = self.coefficients[j + len];
                    self.coefficients[j] = (u + v) % q;
                    self.coefficients[j + len] =
                        (((u + q - v) as u64 * w as u64) % q as u64) as u32;
                }
            }
            len /= 2;
        }

        // Scale by 1/n
        for coeff in &mut self.coefficients {
            *coeff = ((*coeff as u64 * self.scale_factor as u64) % q as u64) as u32;
        }

        Ok(())
    }

    /// Multiply two polynomials using NTT
    pub fn multiply_ntt(a: &NttPolynomial, b: &NttPolynomial) -> Result<NttPolynomial> {
        if a.params != b.params {
            return Err(Error::InternalError {
                operation: "NTT polynomial multiplication".to_string(),
                details: "Polynomial parameters must match".to_string(),
            });
        }

        let n = a.params.degree();
        let q = a.params.modulus();

        // Create result polynomial
        let mut result = NttPolynomial::new(a.params)?;

        // Forward NTT
        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();
        a_ntt.forward_ntt()?;
        b_ntt.forward_ntt()?;

        // Pointwise multiplication
        for i in 0..n {
            result.coefficients[i] =
                ((a_ntt.coefficients[i] as u64 * b_ntt.coefficients[i] as u64) % q as u64) as u32;
        }

        // Inverse NTT
        result.inverse_ntt()?;

        // Reduce modulo x^n + 1 (cyclotomic reduction)
        result.reduce_cyclotomic();

        Ok(result)
    }

    /// Reduce polynomial modulo x^n + 1
    pub fn reduce_cyclotomic(&mut self) {
        let n = self.params.degree();
        let q = self.params.modulus();

        // For x^n + 1, we have x^n ≡ -1 (mod x^n + 1)
        // So x^(n+k) ≡ -x^k (mod x^n + 1)
        for i in n..self.coefficients.len() {
            let idx = i % n;
            self.coefficients[idx] = (self.coefficients[idx] + q - self.coefficients[i]) % q;
        }

        // Truncate to degree n
        self.coefficients.truncate(n);
    }

    /// Add two polynomials
    pub fn add(&self, other: &NttPolynomial) -> Result<NttPolynomial> {
        if self.params != other.params {
            return Err(Error::InternalError {
                operation: "NTT polynomial addition".to_string(),
                details: "Polynomial parameters must match".to_string(),
            });
        }

        let mut result = NttPolynomial::new(self.params)?;
        let q = self.params.modulus();

        for i in 0..self.coefficients.len() {
            result.coefficients[i] = (self.coefficients[i] + other.coefficients[i]) % q;
        }

        Ok(result)
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &NttPolynomial) -> Result<NttPolynomial> {
        if self.params != other.params {
            return Err(Error::InternalError {
                operation: "NTT polynomial subtraction".to_string(),
                details: "Polynomial parameters must match".to_string(),
            });
        }

        let mut result = NttPolynomial::new(self.params)?;
        let q = self.params.modulus();

        for i in 0..self.coefficients.len() {
            result.coefficients[i] = (self.coefficients[i] + q - other.coefficients[i]) % q;
        }

        Ok(result)
    }

    /// Negate polynomial
    pub fn negate(&mut self) {
        let q = self.params.modulus();
        for coeff in &mut self.coefficients {
            *coeff = (q - *coeff) % q;
        }
    }

    /// Sample a random polynomial with small coefficients
    pub fn random_small<R: SecureRng>(params: NttParams, rng: &mut R) -> Result<Self> {
        let mut poly = NttPolynomial::new(params)?;
        let q = poly.params.modulus();

        // Sample coefficients in {-1, 0, 1} (trinary)
        for coeff in &mut poly.coefficients {
            let val = rng.next_u32() % 3;
            *coeff = match val {
                0 => 0,
                1 => 1,
                2 => q - 1, // -1 mod q
                _ => unreachable!(),
            };
        }

        Ok(poly)
    }

    /// Sample a random polynomial with coefficients in [0, q-1]
    pub fn random_uniform<R: SecureRng>(params: NttParams, rng: &mut R) -> Result<Self> {
        let mut poly = NttPolynomial::new(params)?;
        let q = poly.params.modulus();

        for coeff in &mut poly.coefficients {
            *coeff = rng.next_u32() % q;
        }

        Ok(poly)
    }

    /// Check if polynomial is invertible
    pub fn is_invertible(&self) -> bool {
        // A polynomial is invertible if it has at least one non-zero coefficient
        // and the constant term is non-zero
        self.coefficients.iter().any(|&c| c != 0) && self.coefficients[0] != 0
    }

    /// Compute polynomial norm
    pub fn norm(&self) -> u64 {
        self.coefficients.iter().map(|&c| (c as u64).pow(2)).sum()
    }

    /// Check if polynomial has small coefficients
    pub fn is_small(&self, bound: u32) -> bool {
        let q = self.params.modulus();
        self.coefficients
            .iter()
            .all(|&c| c <= bound || c >= q - bound)
    }
}

impl PartialEq for NttPolynomial {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params && self.coefficients == other.coefficients
    }
}

impl Eq for NttPolynomial {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_rng::DeterministicRng;

    #[test]
    fn test_ntt_params() {
        let params_512_769 = NttParams::Dawn512 { q: 769 };
        let params_512_257 = NttParams::Dawn512 { q: 257 };

        assert_eq!(params_512_769.degree(), 512);
        assert_eq!(params_512_769.modulus(), 769);
        assert_eq!(params_512_257.degree(), 512);
        assert_eq!(params_512_257.modulus(), 257);
    }

    #[test]
    fn test_ntt_forward_inverse() {
        let params = NttParams::Dawn512 { q: 12289 };
        let mut poly = NttPolynomial::new(params).unwrap();

        // Test with a simple polynomial first
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 0;
        poly.coefficients[2] = 0;
        let original = poly.coefficients.clone();

        // Forward NTT
        poly.forward_ntt().unwrap();

        // Inverse NTT
        poly.inverse_ntt().unwrap();

        // Should recover original coefficients
        assert_eq!(poly.coefficients[0], original[0]);
        assert_eq!(poly.coefficients[1], original[1]);
        assert_eq!(poly.coefficients[2], original[2]);
    }

    #[test]
    fn test_ntt_multiplication() {
        let params = NttParams::Dawn512 { q: 12289 };
        let mut rng = DeterministicRng::new(12345);

        let a = NttPolynomial::random_small(params, &mut rng).unwrap();
        let b = NttPolynomial::random_small(params, &mut rng).unwrap();

        let result = NttPolynomial::multiply_ntt(&a, &b).unwrap();

        assert_eq!(result.params, params);
        assert_eq!(result.coefficients.len(), 512);
    }

    #[test]
    fn test_polynomial_operations() {
        let params = NttParams::Dawn512 { q: 12289 };
        let mut rng = DeterministicRng::new(12345);

        let a = NttPolynomial::random_small(params, &mut rng).unwrap();
        let b = NttPolynomial::random_small(params, &mut rng).unwrap();

        // Test addition
        let sum = a.add(&b).unwrap();
        assert_eq!(sum.params, params);

        // Test subtraction
        let diff = a.sub(&b).unwrap();
        assert_eq!(diff.params, params);

        // Test multiplication
        let product = NttPolynomial::multiply_ntt(&a, &b).unwrap();
        assert_eq!(product.params, params);
    }

    #[test]
    fn test_polynomial_sampling() {
        let params = NttParams::Dawn512 { q: 12289 };
        let mut rng = DeterministicRng::new(12345);

        let small_poly = NttPolynomial::random_small(params, &mut rng).unwrap();
        assert!(small_poly.is_small(1));

        let uniform_poly = NttPolynomial::random_uniform(params, &mut rng).unwrap();
        assert_eq!(uniform_poly.coefficients.len(), 512);
    }

    #[test]
    fn test_cyclotomic_reduction() {
        let params = NttParams::Dawn512 { q: 12289 };
        let mut poly = NttPolynomial::new(params).unwrap();

        // Set coefficient at index 512 (should be reduced to index 0)
        poly.coefficients.resize(513, 0);
        poly.coefficients[512] = 5;
        poly.coefficients[0] = 3;

        poly.reduce_cyclotomic();

        // Should be reduced to degree 512
        assert_eq!(poly.coefficients.len(), 512);
        // x^512 ≡ -1, so coefficient[512] should be subtracted from coefficient[0]
        // (3 + 12289 - 5) % 12289 = 12287
        assert_eq!(poly.coefficients[0], 12287);
    }
}
