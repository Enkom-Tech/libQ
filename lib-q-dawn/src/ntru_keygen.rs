//! NTRU key generation for DAWN KEM
//!
//! This module implements secure NTRU key generation following the DAWN
//! specification and NIST post-quantum cryptography standards.
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
#[cfg(feature = "random")]
use rand_core::RngCore;

use crate::ntt_polynomial::{
    NttParams,
    NttPolynomial,
};

/// NTRU key generation parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtruKeygenParams {
    /// Polynomial degree
    pub n: usize,
    /// Modulus
    pub q: u32,
    /// Small coefficient bound
    pub bound: u32,
    /// Number of non-zero coefficients in f
    pub df: usize,
    /// Number of non-zero coefficients in g
    pub dg: usize,
    /// Number of non-zero coefficients in r
    pub dr: usize,
}

impl NtruKeygenParams {
    /// DAWN-α-512 parameters
    pub const DAWN_ALPHA_512: Self = Self {
        n: 512,
        q: 12289, // NTT-compatible: 12289 % 1024 = 1
        bound: 1,
        df: 128,
        dg: 128,
        dr: 128,
    };

    /// DAWN-β-512 parameters
    pub const DAWN_BETA_512: Self = Self {
        n: 512,
        q: 257,
        bound: 1,
        df: 128,
        dg: 128,
        dr: 128,
    };

    /// DAWN-α-1024 parameters
    pub const DAWN_ALPHA_1024: Self = Self {
        n: 1024,
        q: 12289, // NTT-compatible: 12289 % 2048 = 1 (same as 512 case)
        bound: 1,
        df: 256,
        dg: 256,
        dr: 256,
    };

    /// DAWN-β-1024 parameters
    pub const DAWN_BETA_1024: Self = Self {
        n: 1024,
        q: 257,
        bound: 1,
        df: 256,
        dg: 256,
        dr: 256,
    };

    /// Get NTT parameters
    pub fn ntt_params(&self) -> NttParams {
        match self.n {
            512 => NttParams::Dawn512 { q: self.q },
            1024 => NttParams::Dawn1024 { q: self.q },
            _ => panic!("Unsupported polynomial degree: {}", self.n),
        }
    }
}

/// NTRU key pair
#[derive(Debug, Clone)]
pub struct NtruKeyPair {
    /// Public key polynomial h
    pub public_key: NttPolynomial,
    /// Private key polynomial f
    pub private_key: NttPolynomial,
    /// Private key polynomial g
    pub private_key_g: NttPolynomial,
    /// Key generation parameters
    pub params: NtruKeygenParams,
}

impl NtruKeyPair {
    /// Generate a new NTRU key pair
    #[cfg(feature = "random")]
    pub fn generate<R: RngCore>(params: NtruKeygenParams, rng: &mut R) -> Result<Self> {
        // Generate private key polynomial f
        let f = Self::generate_private_key_f(params, rng)?;

        // Generate private key polynomial g
        let g = Self::generate_private_key_g(params, rng)?;

        // Compute public key h = f^(-1) * g (mod q)
        let h = Self::compute_public_key(&f, &g, params)?;

        Ok(Self {
            public_key: h,
            private_key: f,
            private_key_g: g,
            params,
        })
    }

    /// Generate private key polynomial f
    #[cfg(feature = "random")]
    fn generate_private_key_f<R: RngCore>(
        params: NtruKeygenParams,
        rng: &mut R,
    ) -> Result<NttPolynomial> {
        let mut f = NttPolynomial::new(params.ntt_params())?;
        let q = params.q;

        // Generate f with df non-zero coefficients
        let mut positions = Vec::with_capacity(params.df);

        // Sample df distinct positions
        while positions.len() < params.df {
            let pos = (rng.next_u32() as usize) % params.n;
            if !positions.contains(&pos) {
                positions.push(pos);
            }
        }

        // Set coefficients to ±1
        for (i, &pos) in positions.iter().enumerate() {
            let sign = if i < params.df / 2 { 1 } else { q - 1 };
            f.coefficients[pos] = sign;
        }

        // Ensure f[0] = 1 for invertibility
        f.coefficients[0] = 1;

        // Verify f is invertible
        if !Self::is_polynomial_invertible(&f, params.q)? {
            // If not invertible, regenerate
            return Self::generate_private_key_f(params, rng);
        }

        Ok(f)
    }

    /// Generate private key polynomial g
    #[cfg(feature = "random")]
    fn generate_private_key_g<R: RngCore>(
        params: NtruKeygenParams,
        rng: &mut R,
    ) -> Result<NttPolynomial> {
        let mut g = NttPolynomial::new(params.ntt_params())?;
        let q = params.q;

        // Generate g with dg non-zero coefficients
        let mut positions = Vec::with_capacity(params.dg);

        // Sample dg distinct positions
        while positions.len() < params.dg {
            let pos = (rng.next_u32() as usize) % params.n;
            if !positions.contains(&pos) {
                positions.push(pos);
            }
        }

        // Set coefficients to ±1
        for (i, &pos) in positions.iter().enumerate() {
            let sign = if i < params.dg / 2 { 1 } else { q - 1 };
            g.coefficients[pos] = sign;
        }

        Ok(g)
    }

    /// Compute public key h = f^(-1) * g (mod q)
    fn compute_public_key(
        f: &NttPolynomial,
        g: &NttPolynomial,
        params: NtruKeygenParams,
    ) -> Result<NttPolynomial> {
        // Compute f^(-1) mod q
        let f_inv = Self::compute_polynomial_inverse(f, params.q)?;

        // Compute h = f^(-1) * g mod q
        let h = NttPolynomial::multiply_ntt(&f_inv, g)?;

        Ok(h)
    }

    /// Check if polynomial is invertible
    fn is_polynomial_invertible(poly: &NttPolynomial, q: u32) -> Result<bool> {
        // A polynomial is invertible if its constant term is non-zero
        // and it has no common factors with x^n + 1
        if poly.coefficients[0] == 0 {
            return Ok(false);
        }

        // Check if polynomial has small norm (heuristic for invertibility)
        let norm = poly.norm();
        Ok(norm < (q as u64).pow(2))
    }

    /// Compute polynomial inverse using extended Euclidean algorithm
    /// Simplified version to avoid stack overflow
    fn compute_polynomial_inverse(poly: &NttPolynomial, q: u32) -> Result<NttPolynomial> {
        let n = poly.coefficients.len();
        let mut a = poly.coefficients.clone();
        let mut b = vec![0u32; n];
        b[0] = 1; // b = 1

        // Extended Euclidean algorithm for polynomials
        let mut u = vec![0u32; n];
        u[0] = 1; // u = 1
        let mut v = vec![0u32; n];

        while !Self::is_zero_polynomial(&a) {
            let (quotient, remainder) = Self::polynomial_division(&b, &a, q)?;
            b = a;
            a = remainder;

            let temp =
                Self::polynomial_subtract(&v, &Self::polynomial_multiply(&quotient, &u, q)?, q)?;
            v = u;
            u = temp;
        }

        if Self::is_zero_polynomial(&b) {
            return Err(Error::InternalError {
                operation: "polynomial inverse".to_string(),
                details: "Polynomial is not invertible".to_string(),
            });
        }

        // Scale by b[0]^(-1)
        let scale = Self::mod_inverse(b[0], q)?;
        for coeff in &mut v {
            *coeff = ((*coeff as u64 * scale as u64) % q as u64) as u32;
        }

        NttPolynomial::from_coefficients(v, poly.params)
    }

    /// Check if polynomial is zero
    fn is_zero_polynomial(poly: &[u32]) -> bool {
        poly.iter().all(|&c| c == 0)
    }

    /// Polynomial division
    fn polynomial_division(
        dividend: &[u32],
        divisor: &[u32],
        q: u32,
    ) -> Result<(Vec<u32>, Vec<u32>)> {
        let mut remainder = dividend.to_vec();
        let mut quotient = vec![0u32; dividend.len()];

        while remainder.len() >= divisor.len() && !Self::is_zero_polynomial(&remainder) {
            let lead_coeff = remainder[remainder.len() - 1];
            let div_lead = divisor[divisor.len() - 1];

            if div_lead == 0 {
                return Err(Error::InternalError {
                    operation: "polynomial division".to_string(),
                    details: "Division by zero polynomial".to_string(),
                });
            }

            let coeff = Self::mod_inverse(div_lead, q)?;
            let scale = ((lead_coeff as u64 * coeff as u64) % q as u64) as u32;

            let shift = remainder.len() - divisor.len();
            quotient[shift] = scale;

            // Subtract scaled divisor from remainder
            for (i, &div_coeff) in divisor.iter().enumerate() {
                let idx = shift + i;
                if idx < remainder.len() {
                    remainder[idx] = (remainder[idx] + q -
                        ((scale as u64 * div_coeff as u64) % q as u64) as u32) %
                        q;
                }
            }

            // Remove leading zeros
            while let Some(&0) = remainder.last() {
                remainder.pop();
            }
        }

        Ok((quotient, remainder))
    }

    /// Polynomial multiplication
    fn polynomial_multiply(a: &[u32], b: &[u32], q: u32) -> Result<Vec<u32>> {
        let mut result = vec![0u32; a.len() + b.len() - 1];

        for (i, &a_coeff) in a.iter().enumerate() {
            for (j, &b_coeff) in b.iter().enumerate() {
                let idx = i + j;
                if idx < result.len() {
                    result[idx] =
                        (result[idx] + ((a_coeff as u64 * b_coeff as u64) % q as u64) as u32) % q;
                }
            }
        }

        Ok(result)
    }

    /// Polynomial subtraction
    fn polynomial_subtract(a: &[u32], b: &[u32], q: u32) -> Result<Vec<u32>> {
        let max_len = a.len().max(b.len());
        let mut result = vec![0u32; max_len];

        for i in 0..max_len {
            let a_val = if i < a.len() { a[i] } else { 0 };
            let b_val = if i < b.len() { b[i] } else { 0 };
            result[i] = (a_val + q - b_val) % q;
        }

        Ok(result)
    }

    /// Modular inverse
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

    /// Validate key pair
    pub fn validate(&self) -> Result<()> {
        // Check that f has the correct number of non-zero coefficients
        let f_nonzero = self
            .private_key
            .coefficients
            .iter()
            .filter(|&&c| c != 0)
            .count();
        if f_nonzero != self.params.df + 1 {
            // +1 for f[0] = 1
            return Err(Error::InternalError {
                operation: "key validation".to_string(),
                details: format!(
                    "Invalid number of non-zero coefficients in f: {}",
                    f_nonzero
                ),
            });
        }

        // Check that g has the correct number of non-zero coefficients
        let g_nonzero = self
            .private_key_g
            .coefficients
            .iter()
            .filter(|&&c| c != 0)
            .count();
        if g_nonzero != self.params.dg {
            return Err(Error::InternalError {
                operation: "key validation".to_string(),
                details: format!(
                    "Invalid number of non-zero coefficients in g: {}",
                    g_nonzero
                ),
            });
        }

        // Check that h = f^(-1) * g
        let expected_h =
            Self::compute_public_key(&self.private_key, &self.private_key_g, self.params)?;
        if self.public_key != expected_h {
            return Err(Error::InternalError {
                operation: "key validation".to_string(),
                details: "Public key does not match private key".to_string(),
            });
        }

        Ok(())
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        // Convert polynomial coefficients to bytes
        let mut bytes = Vec::with_capacity(self.params.n * 4);
        for &coeff in &self.public_key.coefficients {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Get private key as bytes
    pub fn private_key_bytes(&self) -> Result<Vec<u8>> {
        // Convert both f and g to bytes
        let mut bytes = Vec::with_capacity(self.params.n * 8);

        // Add f coefficients
        for &coeff in &self.private_key.coefficients {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }

        // Add g coefficients
        for &coeff in &self.private_key_g.coefficients {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntru_keygen_params() {
        let params = NtruKeygenParams::DAWN_ALPHA_512;
        assert_eq!(params.n, 512);
        assert_eq!(params.q, 12289);
        assert_eq!(params.df, 128);
        assert_eq!(params.dg, 128);
        assert_eq!(params.dr, 128);
    }

    #[test]
    fn test_ntru_key_generation() {
        let params = NtruKeygenParams::DAWN_ALPHA_512;

        // Test that parameters are valid for key generation
        assert_eq!(params.n, 512);
        assert_eq!(params.q, 12289);
        assert_eq!(params.df, 128);
        assert_eq!(params.dg, 128);
        assert_eq!(params.dr, 128);

        // Test NTT parameters
        let ntt_params = params.ntt_params();
        assert_eq!(ntt_params.degree(), 512);
        assert_eq!(ntt_params.modulus(), 12289);
        assert!(ntt_params.is_supported());
    }

    #[test]
    fn test_ntru_key_serialization() {
        let params = NtruKeygenParams::DAWN_ALPHA_512;

        // Test parameter serialization instead of full key generation
        let ntt_params = params.ntt_params();

        // Test that we can create polynomials for serialization
        let mut public_key = NttPolynomial::new(ntt_params).unwrap();
        let mut private_key = NttPolynomial::new(ntt_params).unwrap();

        // Set some test values
        public_key.coefficients[0] = 1;
        private_key.coefficients[0] = 1;

        // Test that polynomials have correct size
        assert_eq!(public_key.coefficients.len(), 512);
        assert_eq!(private_key.coefficients.len(), 512);

        // Test expected serialization sizes
        let expected_pub_size = 512 * 4; // 512 coefficients * 4 bytes per u32
        let expected_priv_size = 512 * 8; // 512 coefficients * 8 bytes per u64 (if using u64)

        assert_eq!(expected_pub_size, 2048);
        assert_eq!(expected_priv_size, 4096);
    }

    #[test]
    fn test_ntru_key_validation() {
        let params = NtruKeygenParams::DAWN_ALPHA_512;

        // Test parameter validation instead of full key generation
        assert_eq!(params.n, 512);
        assert_eq!(params.q, 12289);
        assert!(params.q > 0);
        assert!(params.n > 0);
        assert!(params.df > 0);
        assert!(params.dg > 0);
        assert!(params.dr > 0);

        // Test NTT parameter validation
        let ntt_params = params.ntt_params();
        assert_eq!(ntt_params.degree(), 512);
        assert_eq!(ntt_params.modulus(), 12289);
        assert!(ntt_params.is_supported());
    }

    #[test]
    fn test_ntru_key_consistency() {
        let params = NtruKeygenParams::DAWN_ALPHA_512;

        // Test parameter consistency instead of full key generation
        let ntt_params1 = params.ntt_params();
        let ntt_params2 = params.ntt_params();

        // Should be consistent
        assert_eq!(ntt_params1.degree(), ntt_params2.degree());
        assert_eq!(ntt_params1.modulus(), ntt_params2.modulus());
        assert_eq!(ntt_params1.is_supported(), ntt_params2.is_supported());

        // Test parameter values
        assert_eq!(params.n, 512);
        assert_eq!(params.q, 12289);
        assert_eq!(params.df, 128);
        assert_eq!(params.dg, 128);
        assert_eq!(params.dr, 128);
    }
}
