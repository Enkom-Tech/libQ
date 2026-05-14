//! Reed-Solomon Code Implementation
//!
//! This module implements Reed-Solomon codes over GF(2^8) as used in HQC.
//! Based on the reference implementation in the HQC specification.

use core::fmt;

use crate::params_correct::HqcParams;

/// Reed-Solomon code implementation
pub struct ReedSolomon<P: HqcParams> {
    _params: core::marker::PhantomData<P>,
    // Generator polynomial coefficients
    generator_poly: [u8; 64], // Max size for G=31 (HQC-1)
    // Galois field tables
    gf_exp: [u8; 511], // 2 * GF_MUL_ORDER + 1 (for GF(2^8))
    gf_log: [u8; 256], // GF_MUL_ORDER + 1 (for GF(2^8))
}

impl<P: HqcParams> ReedSolomon<P> {
    /// Create a new Reed-Solomon code instance
    pub fn new() -> Result<Self, ReedSolomonError> {
        let mut rs = Self {
            _params: core::marker::PhantomData,
            generator_poly: [0u8; 64], // Max size for G=59 (HQC-5)
            gf_exp: [0u8; 511],        // Size for GF(2^8) - 2 * GF_MUL_ORDER + 1
            gf_log: [0u8; 256],        // Size for GF(2^8) - GF_MUL_ORDER + 1
        };

        rs.init_gf_tables()?;
        rs.compute_generator_polynomial()?;

        Ok(rs)
    }

    /// Initialize Galois field tables
    fn init_gf_tables(&mut self) -> Result<(), ReedSolomonError> {
        let gf_poly = P::GF_POLY;
        let gf_mul_order = P::GF_MUL_ORDER;

        // Initialize gf_exp and gf_log tables
        self.gf_exp[0] = 1;
        for i in 1..gf_mul_order {
            let temp = (self.gf_exp[i - 1] as u16) << 1;
            if temp >= (1 << P::M) {
                self.gf_exp[i] = (temp ^ gf_poly) as u8;
            } else {
                self.gf_exp[i] = temp as u8;
            }
        }

        // Fill the rest of gf_exp (for multiplication)
        for i in 0..gf_mul_order {
            self.gf_exp[gf_mul_order + i] = self.gf_exp[i];
        }
        self.gf_exp[2 * gf_mul_order] = 1;

        // Initialize gf_log
        self.gf_log[0] = 0; // log(0) is undefined, but we set it to 0
        for (i, &exp_value) in self.gf_exp.iter().enumerate().take(gf_mul_order) {
            self.gf_log[exp_value as usize] = i as u8;
        }

        Ok(())
    }

    /// Compute the generator polynomial
    fn compute_generator_polynomial(&mut self) -> Result<(), ReedSolomonError> {
        let delta = P::DELTA;
        let g = P::G;

        // Initialize generator polynomial
        self.generator_poly[0] = 1;
        for i in 1..g {
            self.generator_poly[i] = 0;
        }

        // Compute generator polynomial: g(x) = (x - α^1)(x - α^2)...(x - α^(2*delta))
        for i in 1..=2 * delta {
            // Multiply by (x - α^i)
            let alpha_i = self.gf_exp[i % P::GF_MUL_ORDER];
            self.multiply_by_x_minus_alpha(alpha_i);
        }

        Ok(())
    }

    /// Multiply generator polynomial by (x - alpha)
    fn multiply_by_x_minus_alpha(&mut self, alpha: u8) {
        let g = P::G;
        let mut temp = [0u8; 64]; // Size to match generator_poly

        // temp = generator_poly * x
        temp[1..(g + 1)].copy_from_slice(&self.generator_poly[..g]);
        temp[0] = 0;

        // temp = temp - alpha * generator_poly
        for (_i, (temp_item, &gen_poly_item)) in temp
            .iter_mut()
            .zip(self.generator_poly.iter())
            .enumerate()
            .take(g)
        {
            *temp_item ^= self.gf_multiply(gen_poly_item, alpha);
        }

        // Copy back
        self.generator_poly[..g].copy_from_slice(&temp[..g]);
    }

    /// Galois field multiplication
    fn gf_multiply(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = self.gf_log[a as usize] as usize;
        let log_b = self.gf_log[b as usize] as usize;
        self.gf_exp[log_a + log_b]
    }

    /// Galois field division
    #[allow(dead_code)] // Required by HQC Reed-Solomon specification
    fn gf_divide(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        if b == 0 {
            return 0; // Division by zero
        }
        let log_a = self.gf_log[a as usize] as usize;
        let log_b = self.gf_log[b as usize] as usize;
        let result_log = (log_a + P::GF_MUL_ORDER - log_b) % P::GF_MUL_ORDER;
        self.gf_exp[result_log]
    }

    /// Encode a message using Reed-Solomon code (LFSR-based systematic encoding)
    pub fn encode(&self, message: &[u8], codeword: &mut [u8]) -> Result<(), ReedSolomonError> {
        let k = P::K;
        let n1 = P::N1;
        let g = P::G;

        if message.len() < k {
            return Err(ReedSolomonError::InvalidMessageLength);
        }
        if codeword.len() < n1 {
            return Err(ReedSolomonError::InvalidCodewordLength);
        }

        // Initialize codeword with zeros
        for item in codeword.iter_mut().take(n1) {
            *item = 0;
        }

        // Copy message to the end of codeword (systematic positions)
        for (i, &msg_byte) in message.iter().enumerate().take(k) {
            codeword[n1 - k + i] = msg_byte;
        }

        // Use LFSR to compute parity bytes
        for (i, _) in (0..k).enumerate() {
            let gate_value = message[k - 1 - i] ^ codeword[n1 - k - 1];

            // Compute tmp[j] = gate_value * PARAM_RS_POLY[j] for j = 0 to G-1
            let mut tmp = [0u8; 64]; // Max G (increased for HQC-5)
            for (j, &poly_coef) in P::RS_POLY_COEFS.iter().enumerate().take(g) {
                tmp[j] = self.gf_multiply(gate_value, poly_coef);
            }

            // Update codeword using LFSR feedback
            for k_pos in (1..(n1 - k)).rev() {
                codeword[k_pos] = codeword[k_pos - 1] ^ tmp[k_pos];
            }
            codeword[0] = tmp[0];
        }

        Ok(())
    }

    /// Decode a codeword using Reed-Solomon code
    pub fn decode(&self, codeword: &[u8], message: &mut [u8]) -> Result<(), ReedSolomonError> {
        let k = P::K;
        let n1 = P::N1;
        let delta = P::DELTA;

        if codeword.len() < n1 {
            return Err(ReedSolomonError::InvalidCodewordLength);
        }
        if message.len() < k {
            return Err(ReedSolomonError::InvalidMessageLength);
        }

        let mut syndromes = [0u16; 128]; // Max 2*delta (HQC-1: 2*60=120)
        let mut sigma = [0u16; 128]; // Max delta + 1 (HQC-1: 60+1=61)
        let mut error_positions = [0u8; 128]; // Max delta (HQC-1: 60)
        let mut z_poly = [0u16; 128]; // Max delta + 1 (HQC-1: 60+1=61)
        let mut error_values = [0u16; 128]; // Max delta (HQC-1: 60)

        // Compute syndromes
        self.compute_syndromes_u16(&mut syndromes, codeword)?;

        // Check if codeword is valid (all syndromes are zero)
        let mut is_valid = true;
        for (i, _) in (0..2 * delta).enumerate() {
            if syndromes[i] != 0 {
                is_valid = false;
                break;
            }
        }

        if is_valid {
            // No errors, copy message with proper offset
            let offset = P::G - 1;
            message[..k].copy_from_slice(&codeword[offset..(k + offset)]);
            return Ok(());
        }

        // Compute error locator polynomial using Berlekamp-Massey algorithm
        let deg_sigma = self.compute_elp_u16(&mut sigma, &syndromes)?;

        // Find error positions using Chien search
        let found_errors =
            self.find_error_positions_chien(&mut error_positions, &sigma, deg_sigma)?;

        let mut corrected_codeword = [0u8; 512]; // Max n1 (HQC-1: 287)
        corrected_codeword[..n1].copy_from_slice(&codeword[..n1]);

        // When Chien search finds fewer roots than the ELP degree, the error pattern
        // exceeds the RS correction capacity. Applying partial corrections would corrupt
        // the codeword further, so we skip corrections entirely and let the FO transform's
        // re-encryption check detect the failure via implicit rejection.
        if found_errors == deg_sigma {
            // Compute error evaluator polynomial (z polynomial)
            self.compute_z_poly(&mut z_poly, &sigma, deg_sigma, &syndromes)?;

            // Compute error values using Forney's algorithm
            self.compute_error_values_forney(
                &mut error_values,
                &z_poly,
                &error_positions,
                &sigma,
                found_errors,
            )?;

            for i in 0..found_errors {
                let pos = error_positions[i] as usize;
                if pos < n1 {
                    corrected_codeword[pos] ^= error_values[i] as u8;
                }
            }
        }

        // Extract message from corrected codeword with proper offset
        let offset = P::G - 1;
        message[..k].copy_from_slice(&corrected_codeword[offset..(k + offset)]);

        Ok(())
    }

    /// Compute syndromes using precomputed alpha_ij_pow table (u8 version for compatibility)
    #[allow(dead_code)] // Required by HQC Reed-Solomon specification
    fn compute_syndromes(
        &self,
        syndromes: &mut [u8],
        codeword: &[u8],
    ) -> Result<(), ReedSolomonError> {
        let n1 = P::N1;
        let delta = P::DELTA;

        for (i, _) in (0..2 * delta).enumerate() {
            syndromes[i] = 0;
            #[allow(clippy::needless_range_loop)]
            for j in 1..n1 {
                syndromes[i] ^= self.gf_multiply(codeword[j], P::ALPHA_IJ_POW[i][j - 1] as u8);
            }
            syndromes[i] ^= codeword[0];
        }

        Ok(())
    }

    /// Compute syndromes using precomputed alpha_ij_pow table (u16 version for main algorithm)
    fn compute_syndromes_u16(
        &self,
        syndromes: &mut [u16],
        codeword: &[u8],
    ) -> Result<(), ReedSolomonError> {
        let n1 = P::N1;
        let delta = P::DELTA;

        for (i, _) in (0..2 * delta).enumerate() {
            // Add bounds checking for syndromes array
            if i < syndromes.len() {
                syndromes[i] = 0;
                #[allow(clippy::needless_range_loop)]
                for j in 1..n1 {
                    // Add bounds checking to prevent index out of bounds
                    if i < P::ALPHA_IJ_POW.len() && (j - 1) < P::ALPHA_IJ_POW[i].len() {
                        syndromes[i] ^= self
                            .gf_multiply_u16(codeword[j], P::ALPHA_IJ_POW[i][j - 1] as u8)
                            as u16;
                    } else {
                        let alpha_power = ((i + 1) * j) % P::GF_MUL_ORDER;
                        let alpha_val = self.gf_exp[alpha_power];
                        syndromes[i] ^= self.gf_multiply_u16(codeword[j], alpha_val) as u16;
                    }
                }
                syndromes[i] ^= codeword[0] as u16;
            }
        }

        Ok(())
    }

    /// Compute error locator polynomial using constant-time Berlekamp-Massey algorithm (u16 version)
    fn compute_elp_u16(
        &self,
        sigma: &mut [u16],
        syndromes: &[u16],
    ) -> Result<usize, ReedSolomonError> {
        let delta = P::DELTA;
        let mut sigma_copy = [0u16; 64];
        let mut x_sigma_p = [0u16; 64];
        x_sigma_p[1] = 1;

        let mut deg_sigma = 0usize;
        let mut deg_sigma_p = 0usize;
        let mut pp = 0xFFFFu16; // 2*rho initialized to -1
        let mut d_p = 1u16;
        let mut d = syndromes[0];

        sigma[0] = 1;

        for mu in 0..(2 * delta) {
            // Save sigma in case we need it to update X_sigma_p
            sigma_copy[..=delta].copy_from_slice(&sigma[..=delta]);
            let deg_sigma_copy = deg_sigma;

            let dd = self.gf_multiply_u16(d as u8, self.gf_inverse_u16(d_p as u8)) as u16;

            for i in 1..=(mu + 1).min(delta) {
                sigma[i] ^= self.gf_multiply_u16(dd as u8, x_sigma_p[i] as u8) as u16;
            }

            let deg_x = (mu as u16).wrapping_sub(pp);
            let deg_x_sigma_p = deg_x + deg_sigma_p as u16;

            // mask1 = 0xffff if(d != 0) and 0 otherwise
            let mask1 = if d != 0 { 0xFFFF } else { 0 };

            // mask2 = 0xffff if(deg_x_sigma_p > deg_sigma) and 0 otherwise
            let mask2 = if deg_x_sigma_p > (deg_sigma as u16) {
                0xFFFF
            } else {
                0
            };

            // mask12 = 0xffff if the deg_sigma increased and 0 otherwise
            let mask12 = mask1 & mask2;
            deg_sigma ^= (mask12 & (deg_x_sigma_p ^ deg_sigma as u16)) as usize;

            if mu == (2 * delta - 1) {
                break;
            }

            pp ^= mask12 & ((mu as u16) ^ pp);
            d_p ^= mask12 & (d ^ d_p);

            for i in (1..=delta).rev() {
                x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (!mask12 & x_sigma_p[i - 1]);
            }
            x_sigma_p[0] = 0;

            deg_sigma_p ^= (mask12 & ((deg_sigma_copy ^ deg_sigma_p) as u16)) as usize;

            d = syndromes[mu + 1];
            for i in 1..=(mu + 1).min(delta) {
                d ^= self.gf_multiply_u16(sigma[i] as u8, syndromes[mu + 1 - i] as u8) as u16;
            }
        }

        Ok(deg_sigma)
    }

    /// Compute multiplicative inverse in GF(2^m)
    fn gf_inverse(&self, a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        self.gf_exp[(P::GF_MUL_ORDER - self.gf_log[a as usize] as usize) % P::GF_MUL_ORDER]
    }

    /// Galois field multiplication for u16 values (for internal use)
    fn gf_multiply_u16(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = self.gf_log[a as usize] as usize;
        let log_b = self.gf_log[b as usize] as usize;
        self.gf_exp[log_a + log_b]
    }

    /// Galois field inverse for u16 values (for internal use)
    fn gf_inverse_u16(&self, a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        self.gf_exp[(P::GF_MUL_ORDER - self.gf_log[a as usize] as usize) % P::GF_MUL_ORDER]
    }

    /// Find error positions using Chien search
    fn find_error_positions_chien(
        &self,
        error_positions: &mut [u8],
        sigma: &[u16],
        degree: usize,
    ) -> Result<usize, ReedSolomonError> {
        let n1 = P::N1;
        let mut found_errors = 0;

        let mut sigma_u8 = [0u8; 256];
        for (i, &sigma_value) in sigma.iter().enumerate().take(degree + 1) {
            sigma_u8[i] = sigma_value as u8;
        }

        // Chien search: evaluate σ(α^(-i)) for each codeword position i.
        // Root at α^(-pos) means error at position pos.
        for i in 0..n1 {
            let mut sum = 0u8;
            let k = (P::GF_MUL_ORDER - i) % P::GF_MUL_ORDER;
            #[allow(clippy::needless_range_loop)]
            for j in 0..=degree {
                if sigma_u8[j] != 0 {
                    let alpha_power = (k * j) % P::GF_MUL_ORDER;
                    let alpha_val = self.gf_exp[alpha_power];
                    sum ^= self.gf_multiply(sigma_u8[j], alpha_val);
                }
            }

            if sum == 0 && found_errors < error_positions.len() {
                error_positions[found_errors] = i as u8;
                found_errors += 1;
            }
        }

        Ok(found_errors)
    }

    /// Compute z polynomial (error evaluator)
    fn compute_z_poly(
        &self,
        z: &mut [u16],
        sigma: &[u16],
        degree: usize,
        syndromes: &[u16],
    ) -> Result<(), ReedSolomonError> {
        let delta = P::DELTA;

        z[0] = 1;

        for i in 1..=delta {
            z[i] = if i <= degree { sigma[i] } else { 0 };
        }

        z[1] ^= syndromes[0];

        for i in 2..=delta {
            if i <= degree {
                z[i] ^= syndromes[i - 1];

                for j in 1..i {
                    z[i] ^= self.gf_multiply_u16(sigma[j] as u8, syndromes[i - j - 1] as u8) as u16;
                }
            }
        }

        Ok(())
    }

    /// Compute error values following the HQC reference approach.
    /// For each error at position pos_j with β_j = α^pos_j:
    ///   e_j = z(β_j^{-1}) / Π_{k≠j}(1 + β_j^{-1} * β_k)
    fn compute_error_values_forney(
        &self,
        error_values: &mut [u16],
        z: &[u16],
        error_positions: &[u8],
        _sigma: &[u16],
        num_errors: usize,
    ) -> Result<(), ReedSolomonError> {
        let delta = P::DELTA;

        let mut beta = [0u8; 64];
        for i in 0..num_errors {
            beta[i] = self.gf_exp[error_positions[i] as usize];
        }

        for i in 0..num_errors {
            let inverse = self.gf_inverse(beta[i]);

            // Numerator: z(β_i^{-1}) = z[0] + z[1]*inv + z[2]*inv^2 + ...
            let mut tmp1 = 1u16; // z[0] = 1
            let mut inverse_power = 1u8;
            for j in 1..=delta {
                inverse_power = self.gf_multiply(inverse_power, inverse);
                tmp1 ^= self.gf_multiply_u16(inverse_power, z[j] as u8) as u16;
            }

            // Denominator: Π_{k≠i}(1 + β_i^{-1} * β_k)
            let mut tmp2 = 1u8;
            for k in 0..num_errors {
                if k != i {
                    let term = 1u8 ^ self.gf_multiply(inverse, beta[k]);
                    tmp2 = self.gf_multiply(tmp2, term);
                }
            }

            if tmp2 != 0 {
                error_values[i] = self.gf_multiply_u16(tmp1 as u8, self.gf_inverse(tmp2)) as u16;
            } else {
                error_values[i] = tmp1;
            }
        }

        Ok(())
    }
}

/// Reed-Solomon error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReedSolomonError {
    InvalidMessageLength,
    InvalidCodewordLength,
    DecodingFailed,
    InvalidParameters,
}

impl fmt::Display for ReedSolomonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReedSolomonError::InvalidMessageLength => write!(f, "Invalid message length"),
            ReedSolomonError::InvalidCodewordLength => write!(f, "Invalid codeword length"),
            ReedSolomonError::DecodingFailed => write!(f, "Reed-Solomon decoding failed"),
            ReedSolomonError::InvalidParameters => write!(f, "Invalid Reed-Solomon parameters"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params_correct::Hqc1Params;

    #[test]
    fn test_reed_solomon_creation() {
        let rs = ReedSolomon::<Hqc1Params>::new();
        assert!(rs.is_ok());
    }

    #[test]
    fn test_reed_solomon_encode_decode() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();

        // Test message
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 46]; // N1 for HQC-1
        rs.encode(&message, &mut codeword).unwrap();

        // Check if encoding produces valid codeword (all syndromes should be zero)
        let mut syndromes = [0u16; 32];
        rs.compute_syndromes_u16(&mut syndromes, &codeword).unwrap();

        let mut all_zero = true;
        for (i, _) in (0..30).enumerate() {
            // 2*DELTA = 30 for HQC-1
            if syndromes[i] != 0 {
                all_zero = false;
                break;
            }
        }

        // For now, just assert that all syndromes should be zero
        assert!(all_zero, "Syndromes should be zero after encoding");

        // Decode
        let mut decoded_message = [0u8; 16]; // K for HQC-1
        rs.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }

    #[test]
    fn test_reed_solomon_error_correction() {
        let rs = ReedSolomon::<Hqc1Params>::new().unwrap();

        // Test message
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 46];
        rs.encode(&message, &mut codeword).unwrap();

        // Introduce a small error at position 20
        codeword[20] ^= 0x01;

        // Debug: Check syndromes before decoding
        let mut syndromes = [0u16; 32];
        rs.compute_syndromes_u16(&mut syndromes, &codeword).unwrap();

        // Check if we have non-zero syndromes (should have errors)
        let mut has_errors = false;
        for (i, _) in (0..30).enumerate() {
            // 2*DELTA = 30 for HQC-1
            if syndromes[i] != 0 {
                has_errors = true;
                break;
            }
        }

        // For debugging, we know there should be errors
        assert!(has_errors, "Should detect errors after introducing them");

        // Decode (should correct the error)
        let mut decoded_message = [0u8; 16];
        rs.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }
}
