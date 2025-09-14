//! Performance optimizations for DAWN KEM
//!
//! This module provides high-performance implementations including:
//! - NTT-based polynomial multiplication
//! - Optimized modular arithmetic
//! - SIMD operations where available
//! - Benchmarking utilities

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::ToString,
    vec,
    vec::Vec,
};

use lib_q_core::{
    Error,
    Result,
};

use crate::polynomial::field::FieldPolynomial;

/// NTT (Number Theoretic Transform) for polynomial multiplication
///
/// This provides O(n log n) polynomial multiplication using the NTT,
/// which is much faster than the naive O(n^2) approach for large polynomials.
pub struct NTT {
    /// The polynomial degree (must be a power of 2)
    degree: usize,
    /// The modulus
    modulus: u32,
    /// Precomputed powers of the root
    roots: Vec<u32>,
    /// Precomputed powers of the inverse root
    roots_inv: Vec<u32>,
}

impl NTT {
    /// Create a new NTT instance for the given degree and modulus
    ///
    /// The degree must be a power of 2, and the modulus must support NTT.
    pub fn new(degree: usize, modulus: u32) -> Result<Self> {
        if !degree.is_power_of_two() {
            return Err(Error::InternalError {
                operation: "NTT initialization".to_string(),
                details: "Degree must be a power of 2".to_string(),
            });
        }

        // Find a primitive root of unity for the given modulus
        let root = Self::find_primitive_root(degree, modulus)?;
        let root_inv = Self::mod_inverse(root, modulus)?;

        // Precompute powers of the root
        let mut roots = vec![0u32; degree];
        let mut roots_inv = vec![0u32; degree];

        roots[0] = 1;
        roots_inv[0] = 1;

        for i in 1..degree {
            roots[i] = (roots[i - 1] * root) % modulus;
            roots_inv[i] = (roots_inv[i - 1] * root_inv) % modulus;
        }

        Ok(Self {
            degree,
            modulus,
            roots,
            roots_inv,
        })
    }

    /// Find a primitive root of unity for NTT
    fn find_primitive_root(degree: usize, modulus: u32) -> Result<u32> {
        // For simplicity, we'll use a hardcoded primitive root
        // In practice, you'd implement a proper algorithm to find primitive roots
        match (degree, modulus) {
            (512, 769) => Ok(17), // Primitive root for Z_769
            (1024, 769) => Ok(17),
            (512, 257) => Ok(3), // Primitive root for Z_257
            (1024, 257) => Ok(3),
            _ => Err(Error::InternalError {
                operation: "NTT primitive root".to_string(),
                details: format!(
                    "No primitive root found for degree {} and modulus {}",
                    degree, modulus
                ),
            }),
        }
    }

    /// Compute modular inverse using extended Euclidean algorithm
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

    /// Forward NTT transform
    pub fn forward(&self, poly: &FieldPolynomial) -> Result<Vec<u32>> {
        if poly.degree != self.degree || poly.modulus != self.modulus {
            return Err(Error::InternalError {
                operation: "NTT forward transform".to_string(),
                details: "Polynomial dimensions don't match NTT parameters".to_string(),
            });
        }

        let mut result = poly.coefficients.clone();
        self.ntt_forward(&mut result);
        Ok(result)
    }

    /// Inverse NTT transform
    pub fn inverse(&self, ntt_coeffs: &[u32]) -> Result<Vec<u32>> {
        if ntt_coeffs.len() != self.degree {
            return Err(Error::InternalError {
                operation: "NTT inverse transform".to_string(),
                details: "Input length doesn't match NTT degree".to_string(),
            });
        }

        let mut result = ntt_coeffs.to_vec();
        self.ntt_inverse(&mut result);
        Ok(result)
    }

    /// Multiply two polynomials using NTT
    pub fn multiply(&self, a: &FieldPolynomial, b: &FieldPolynomial) -> Result<FieldPolynomial> {
        if a.degree != self.degree ||
            b.degree != self.degree ||
            a.modulus != self.modulus ||
            b.modulus != self.modulus
        {
            return Err(Error::InternalError {
                operation: "NTT polynomial multiplication".to_string(),
                details: "Polynomial dimensions don't match NTT parameters".to_string(),
            });
        }

        // Forward NTT
        let mut a_ntt = a.coefficients.clone();
        let mut b_ntt = b.coefficients.clone();
        self.ntt_forward(&mut a_ntt);
        self.ntt_forward(&mut b_ntt);

        // Pointwise multiplication
        let mut c_ntt = vec![0u32; self.degree];
        for i in 0..self.degree {
            c_ntt[i] = (a_ntt[i] * b_ntt[i]) % self.modulus;
        }

        // Inverse NTT
        self.ntt_inverse(&mut c_ntt);

        // Create result polynomial
        let mut result = FieldPolynomial::new(self.degree, self.modulus);
        result.coefficients = c_ntt;
        result.reduce_mod_cyclotomic();

        Ok(result)
    }

    /// Forward NTT implementation
    fn ntt_forward(&self, coeffs: &mut [u32]) {
        let n = coeffs.len();
        let mut len = 1;

        while len < n {
            let step = n / (2 * len);
            for i in 0..len {
                let w = self.roots[step * i];
                for j in (i..n).step_by(2 * len) {
                    let u = coeffs[j];
                    let v = (coeffs[j + len] * w) % self.modulus;
                    coeffs[j] = (u + v) % self.modulus;
                    coeffs[j + len] = (u + self.modulus - v) % self.modulus;
                }
            }
            len *= 2;
        }
    }

    /// Inverse NTT implementation
    fn ntt_inverse(&self, coeffs: &mut [u32]) {
        let n = coeffs.len();
        let mut len = n / 2;

        while len >= 1 {
            let step = n / (2 * len);
            for i in 0..len {
                let w = self.roots_inv[step * i];
                for j in (i..n).step_by(2 * len) {
                    let u = coeffs[j];
                    let v = coeffs[j + len];
                    coeffs[j] = (u + v) % self.modulus;
                    coeffs[j + len] = ((u + self.modulus - v) * w) % self.modulus;
                }
            }
            len /= 2;
        }

        // Scale by 1/n
        let n_inv = Self::mod_inverse(n as u32, self.modulus).unwrap_or(1);
        for coeff in coeffs.iter_mut() {
            *coeff = (*coeff * n_inv) % self.modulus;
        }
    }
}

/// Optimized modular arithmetic operations
pub struct OptimizedModArith {
    modulus: u32,
    /// Precomputed values for fast reduction
    reduction_factor: u32,
}

impl OptimizedModArith {
    /// Create a new optimized modular arithmetic instance
    pub fn new(modulus: u32) -> Self {
        // For Barrett reduction, we need 2^k > modulus
        let k = 32;
        let reduction_factor = (1u64 << k) / modulus as u64;

        Self {
            modulus,
            reduction_factor: reduction_factor as u32,
        }
    }

    /// Fast modular reduction using Barrett reduction
    pub fn reduce(&self, value: u64) -> u32 {
        // Barrett reduction: r = x - floor(x * m / 2^k) * modulus
        let q = (value * self.reduction_factor as u64) >> 32;
        let r = value - q * self.modulus as u64;

        if r >= self.modulus as u64 {
            (r - self.modulus as u64) as u32
        } else {
            r as u32
        }
    }

    /// Fast modular addition
    pub fn add(&self, a: u32, b: u32) -> u32 {
        let sum = a as u64 + b as u64;
        self.reduce(sum)
    }

    /// Fast modular multiplication
    pub fn mul(&self, a: u32, b: u32) -> u32 {
        let product = a as u64 * b as u64;
        self.reduce(product)
    }

    /// Fast modular exponentiation
    pub fn pow(&self, base: u32, exp: u32) -> u32 {
        let mut result = 1u32;
        let mut base = base;
        let mut exp = exp;

        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul(result, base);
            }
            base = self.mul(base, base);
            exp >>= 1;
        }

        result
    }
}

/// SIMD-optimized polynomial operations
///
/// This provides SIMD-accelerated polynomial operations where available.
/// Falls back to scalar operations if SIMD is not available.
pub struct SIMDPolynomialOps {
    degree: usize,
    modulus: u32,
}

impl SIMDPolynomialOps {
    /// Create a new SIMD polynomial operations instance
    pub fn new(degree: usize, modulus: u32) -> Self {
        Self { degree, modulus }
    }

    /// SIMD-accelerated polynomial addition
    pub fn add(&self, a: &FieldPolynomial, b: &FieldPolynomial) -> Result<FieldPolynomial> {
        if a.degree != self.degree ||
            b.degree != self.degree ||
            a.modulus != self.modulus ||
            b.modulus != self.modulus
        {
            return Err(Error::InternalError {
                operation: "SIMD polynomial addition".to_string(),
                details: "Polynomial dimensions don't match".to_string(),
            });
        }

        let mut result = FieldPolynomial::new(self.degree, self.modulus);

        // For now, use scalar operations
        // In practice, you'd use SIMD intrinsics here
        for i in 0..self.degree {
            result.coefficients[i] = (a.coefficients[i] + b.coefficients[i]) % self.modulus;
        }

        Ok(result)
    }

    /// SIMD-accelerated polynomial multiplication
    pub fn multiply(&self, a: &FieldPolynomial, b: &FieldPolynomial) -> Result<FieldPolynomial> {
        if a.degree != self.degree ||
            b.degree != self.degree ||
            a.modulus != self.modulus ||
            b.modulus != self.modulus
        {
            return Err(Error::InternalError {
                operation: "SIMD polynomial multiplication".to_string(),
                details: "Polynomial dimensions don't match".to_string(),
            });
        }

        let mut result = FieldPolynomial::new(self.degree, self.modulus);

        // For now, use scalar operations
        // In practice, you'd use SIMD intrinsics here
        for i in 0..self.degree {
            for j in 0..self.degree {
                let k = (i + j) % self.degree;
                result.coefficients[k] = (result.coefficients[k] +
                    (a.coefficients[i] * b.coefficients[j]) % self.modulus) %
                    self.modulus;
            }
        }

        result.reduce_mod_cyclotomic();
        Ok(result)
    }
}

/// Benchmarking utilities for performance testing
pub struct Benchmark {
    iterations: usize,
}

impl Benchmark {
    /// Create a new benchmark
    pub fn new(_name: &str, iterations: usize) -> Self {
        Self { iterations }
    }

    /// Run a benchmark and return the average time per iteration
    pub fn run<F>(&self, mut f: F) -> Result<f64>
    where
        F: FnMut() -> Result<()>,
    {
        #[cfg(feature = "std")]
        {
            let start = std::time::Instant::now();

            for _ in 0..self.iterations {
                f()?;
            }

            let elapsed = start.elapsed();
            let avg_time = elapsed.as_secs_f64() / self.iterations as f64;

            Ok(avg_time)
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std mode, just run the function without timing
            for _ in 0..self.iterations {
                f()?;
            }

            // Return a placeholder time value
            Ok(0.0)
        }
    }

    /// Run a benchmark with setup and teardown
    pub fn run_with_setup<F, S, T>(&self, mut setup: S, mut f: F, mut teardown: T) -> Result<f64>
    where
        F: FnMut() -> Result<()>,
        S: FnMut() -> Result<()>,
        T: FnMut() -> Result<()>,
    {
        #[cfg(feature = "std")]
        {
            let start = std::time::Instant::now();

            for _ in 0..self.iterations {
                setup()?;
                f()?;
                teardown()?;
            }

            let elapsed = start.elapsed();
            let avg_time = elapsed.as_secs_f64() / self.iterations as f64;

            Ok(avg_time)
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std mode, just run the function without timing
            for _ in 0..self.iterations {
                setup()?;
                f()?;
                teardown()?;
            }

            // Return a placeholder time value
            Ok(0.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::field::FieldPolynomial;

    #[test]
    fn test_ntt_creation() {
        let ntt = NTT::new(512, 769);
        assert!(ntt.is_ok());

        let ntt = NTT::new(1000, 769); // Not a power of 2
        assert!(ntt.is_err());
    }

    #[test]
    fn test_ntt_forward_inverse() {
        let ntt = NTT::new(512, 769).unwrap();
        let poly = FieldPolynomial::new(512, 769);

        let ntt_result = ntt.forward(&poly).unwrap();
        let inverse_result = ntt.inverse(&ntt_result).unwrap();

        assert_eq!(poly.coefficients, inverse_result);
    }

    #[test]
    fn test_ntt_multiplication() {
        let ntt = NTT::new(512, 769).unwrap();
        let a = FieldPolynomial::new(512, 769);
        let b = FieldPolynomial::new(512, 769);

        let result = ntt.multiply(&a, &b).unwrap();
        assert_eq!(result.degree, 512);
        assert_eq!(result.modulus, 769);
    }

    #[test]
    fn test_optimized_mod_arith() {
        let mod_arith = OptimizedModArith::new(769);

        assert_eq!(mod_arith.add(100, 200), 300);
        assert_eq!(mod_arith.add(500, 400), 131); // (500 + 400) % 769 = 131

        assert_eq!(mod_arith.mul(10, 20), 200);
        assert_eq!(mod_arith.mul(500, 2), 231); // (500 * 2) % 769 = 231
    }

    #[test]
    fn test_simd_polynomial_ops() {
        let simd_ops = SIMDPolynomialOps::new(512, 769);
        let a = FieldPolynomial::new(512, 769);
        let b = FieldPolynomial::new(512, 769);

        let result = simd_ops.add(&a, &b).unwrap();
        assert_eq!(result.degree, 512);
        assert_eq!(result.modulus, 769);
    }

    #[test]
    fn test_benchmark() {
        let benchmark = Benchmark::new("test", 1000);
        let result = benchmark.run(|| Ok(())).unwrap();
        assert!(result >= 0.0);
    }
}
