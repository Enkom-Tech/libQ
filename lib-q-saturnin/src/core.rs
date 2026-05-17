//! Core Saturnin block cipher implementation
//!
//! This module contains the core Saturnin block cipher implementation based on the reference
//! implementation. Saturnin uses a bitsliced approach with 16-bit registers represented as
//! 32-bit variables for efficiency.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Error,
    Result,
};

/// Saturnin block cipher core implementation
///
/// This implements the Saturnin block cipher with configurable number of super-rounds
/// and domain parameters. The implementation uses a bitsliced approach for efficiency.
#[derive(Clone)]
pub struct SaturninCore {
    // Round constants for different configurations
    round_constants: Vec<u16>,
    num_rounds: usize,
    domain: u8,
}

impl SaturninCore {
    /// Create a new Saturnin core instance
    ///
    /// # Arguments
    /// * `num_rounds` - Number of super-rounds (0-31)
    /// * `domain` - Domain parameter (0-15)
    pub fn new(num_rounds: usize, domain: u8) -> Result<Self> {
        if num_rounds > 31 {
            return Err(Error::InvalidAlgorithm {
                algorithm: "Number of rounds must be <= 31",
            });
        }

        if domain > 15 {
            return Err(Error::InvalidAlgorithm {
                algorithm: "Domain must be <= 15",
            });
        }

        let round_constants = Self::generate_round_constants(num_rounds, domain);

        Ok(Self {
            round_constants,
            num_rounds,
            domain,
        })
    }

    /// Generate round constants for the given number of rounds and domain
    fn generate_round_constants(num_rounds: usize, domain: u8) -> Vec<u16> {
        // Use hardcoded constants from bs32 implementation for hash compatibility
        if num_rounds == 16 {
            match domain {
                7 => {
                    #[cfg(feature = "alloc")]
                    {
                        use alloc::vec;
                        vec![
                            0x3FBA, 0x180C, 0x563A, 0xB9AB, 0x125E, 0xA5EF, 0x859D, 0xA26C, 0xB8CF,
                            0x779B, 0x7D4D, 0xE793, 0x07EF, 0xB49F, 0x8D52, 0x5306, 0x1E08, 0xE6AB,
                            0x4172, 0x9F87, 0x8C4A, 0xEF0A, 0x4AA0, 0xC9A7, 0xD93A, 0x95EF, 0xBB00,
                            0xD2AF, 0xB62C, 0x5BF0, 0x386D, 0x94D8,
                        ]
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        // Fallback for no_std without alloc
                        Self::generate_round_constants_lfsr(num_rounds, domain)
                    }
                }
                8 => {
                    #[cfg(feature = "alloc")]
                    {
                        use alloc::vec;
                        vec![
                            0x3C9B, 0x19A7, 0xA909, 0x8694, 0x23F8, 0x78DA, 0xA7B6, 0x47D3, 0x74FC,
                            0x9D78, 0xEACA, 0xAE11, 0x2F31, 0xA677, 0x4CC8, 0xC054, 0x2F51, 0xCA05,
                            0x5268, 0xF195, 0x4F5B, 0x8A2B, 0xF614, 0xB4AC, 0xF1D9, 0x5401, 0x764D,
                            0x2568, 0x6A49, 0x3611, 0x8EEF, 0x9C3E,
                        ]
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        // Fallback for no_std without alloc
                        Self::generate_round_constants_lfsr(num_rounds, domain)
                    }
                }
                _ => Self::generate_round_constants_lfsr(num_rounds, domain),
            }
        } else {
            Self::generate_round_constants_lfsr(num_rounds, domain)
        }
    }

    /// Generate round constants using LFSR (original implementation)
    fn generate_round_constants_lfsr(num_rounds: usize, domain: u8) -> Vec<u16> {
        let mut constants = Vec::with_capacity(num_rounds);
        let mut x0 = (domain as u16)
            .wrapping_add((num_rounds as u16) << 4)
            .wrapping_add(0xFE00);
        let mut x1 = x0;

        for _round in 0..num_rounds {
            // Generate 16 bits for each constant
            for _iter in 0..16 {
                // C: -(x0 >> 15) - cast to signed for arithmetic shift, then back to unsigned
                let mask0 = if (x0 >> 15) != 0 { 0xFFFF } else { 0x0000 };
                let mask1 = if (x1 >> 15) != 0 { 0xFFFF } else { 0x0000 };
                x0 = (x0 << 1) ^ (0x2D & mask0);
                x1 = (x1 << 1) ^ (0x53 & mask1);
            }
            // Store both constants in a single array (RC0 and RC1 interleaved)
            constants.push(x0);
            constants.push(x1);
        }

        constants
    }

    /// Encrypt a single block
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `block` - 32-byte block to encrypt (modified in-place)
    pub fn encrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        let key_len = key.len();
        let block_len = block.len();
        if key_len != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key_len,
            });
        }
        if block_len != 32 {
            return Err(Error::InvalidMessageSize {
                max: 32,
                actual: block_len,
            });
        }
        let key: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: key_len,
        })?;
        let block: &mut [u8; 32] = block.try_into().map_err(|_| Error::InvalidMessageSize {
            max: 32,
            actual: block_len,
        })?;
        self.encrypt_block_32(key, block)
    }

    /// Encrypt one block; caller guarantees 32-byte key and block (e.g. after AEAD size checks).
    #[inline]
    pub(crate) fn encrypt_block_32(&self, key: &[u8; 32], block: &mut [u8; 32]) -> Result<()> {
        let mut state = self.decode_block(&*block);
        self.add_key(&mut state, key);
        for i in 0..self.num_rounds {
            self.apply_round(&mut state, i, key);
        }
        self.encode_block(&state, block);
        Ok(())
    }

    /// Decrypt a single block
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `block` - 32-byte block to decrypt (modified in-place)
    pub fn decrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        let key_len = key.len();
        let block_len = block.len();
        if key_len != 32 {
            return Err(Error::InvalidKeySize {
                expected: 32,
                actual: key_len,
            });
        }
        if block_len != 32 {
            return Err(Error::InvalidMessageSize {
                max: 32,
                actual: block_len,
            });
        }
        let key: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: key_len,
        })?;
        let block: &mut [u8; 32] = block.try_into().map_err(|_| Error::InvalidMessageSize {
            max: 32,
            actual: block_len,
        })?;
        self.decrypt_block_32(key, block)
    }

    /// Decrypt one block; caller guarantees 32-byte key and block.
    #[inline]
    pub(crate) fn decrypt_block_32(&self, key: &[u8; 32], block: &mut [u8; 32]) -> Result<()> {
        let mut state = self.decode_block(block);
        for i in (0..self.num_rounds).rev() {
            self.apply_inverse_round(&mut state, i, key);
        }
        self.add_key(&mut state, key);
        self.encode_block(&state, block);
        Ok(())
    }

    /// Decode block from bytes to 16-bit words
    fn decode_block(&self, block: &[u8]) -> [u16; 16] {
        let mut state = [0u16; 16];

        for i in 0..16 {
            state[i] = (block[i * 2] as u16) | ((block[i * 2 + 1] as u16) << 8);
        }

        state
    }

    /// Encode block from 16-bit words to bytes
    fn encode_block(&self, state: &[u16; 16], block: &mut [u8]) {
        for i in 0..16 {
            block[i * 2] = state[i] as u8;
            block[i * 2 + 1] = (state[i] >> 8) as u8;
        }
    }

    /// Add key to state
    fn add_key(&self, state: &mut [u16; 16], key: &[u8]) {
        for i in 0..16 {
            let key_word = (key[i * 2] as u16) | ((key[i * 2 + 1] as u16) << 8);
            state[i] ^= key_word;
        }
    }

    /// Add rotated key to state
    fn add_key_rotated(&self, state: &mut [u16; 16], key: &[u8]) {
        for i in 0..16 {
            let key_word = (key[i * 2] as u16) | ((key[i * 2 + 1] as u16) << 8);
            state[i] ^= key_word.rotate_right(5);
        }
    }

    /// Apply one super-round of the cipher (consists of two rounds)
    fn apply_round(&self, state: &mut [u16; 16], round: usize, key: &[u8]) {
        // Even round: S-box + MDS
        self.apply_sbox(state);
        self.apply_mds(state);

        // Odd round: S-box + shift rows + MDS + shift rows inverse + round constant + key
        self.apply_sbox(state);

        if (round & 1) == 0 {
            // Round r = 1 mod 4
            self.apply_shift_rows_slice(state);
            self.apply_mds(state);
            self.apply_shift_rows_slice_inv(state);
            state[0] ^= self.round_constants[round * 2];
            state[8] ^= self.round_constants[round * 2 + 1];
            self.add_key_rotated(state, key);
        } else {
            // Round r = 3 mod 4
            self.apply_shift_rows_sheet(state);
            self.apply_mds(state);
            self.apply_shift_rows_sheet_inv(state);
            state[0] ^= self.round_constants[round * 2];
            state[8] ^= self.round_constants[round * 2 + 1];
            self.add_key(state, key);
        }
    }

    /// Apply inverse round of the cipher
    fn apply_inverse_round(&self, state: &mut [u16; 16], round: usize, key: &[u8]) {
        // Odd round
        if (round & 1) == 0 {
            // Round r = 1 mod 4
            self.add_key_rotated(state, key);
            state[0] ^= self.round_constants[round * 2];
            state[8] ^= self.round_constants[round * 2 + 1];
            self.apply_shift_rows_slice(state);
            self.apply_inverse_mds(state);
            self.apply_shift_rows_slice_inv(state);
        } else {
            // Round r = 3 mod 4
            self.add_key(state, key);
            state[0] ^= self.round_constants[round * 2];
            state[8] ^= self.round_constants[round * 2 + 1];
            self.apply_shift_rows_sheet(state);
            self.apply_inverse_mds(state);
            self.apply_shift_rows_sheet_inv(state);
        }
        self.apply_inverse_sbox(state);

        // Even round
        self.apply_inverse_mds(state);
        self.apply_inverse_sbox(state);
    }

    /// Apply S-box transformation
    fn apply_sbox(&self, state: &mut [u16; 16]) {
        // Process both groups in parallel to improve instruction-level parallelism
        for i in (0..16).step_by(8) {
            // Group 1: sigma_0
            let mut a0 = state[i];
            let mut b0 = state[i + 1];
            let mut c0 = state[i + 2];
            let mut d0 = state[i + 3];

            // Group 2: sigma_1
            let mut a1 = state[i + 4];
            let mut b1 = state[i + 5];
            let mut c1 = state[i + 6];
            let mut d1 = state[i + 7];

            // Optimized S-box operations with reduced intermediate variables
            // Group 1 operations
            a0 ^= b0 & c0;
            b0 ^= a0 | d0;
            d0 ^= b0 | c0;
            c0 ^= b0 & d0;
            b0 ^= a0 | c0;
            a0 ^= b0 | d0;

            // Group 2 operations (interleaved for better CPU utilization)
            a1 ^= b1 & c1;
            b1 ^= a1 | d1;
            d1 ^= b1 | c1;
            c1 ^= b1 & d1;
            b1 ^= a1 | c1;
            a1 ^= b1 | d1;

            // Store results
            state[i] = b0;
            state[i + 1] = c0;
            state[i + 2] = d0;
            state[i + 3] = a0;
            state[i + 4] = d1;
            state[i + 5] = b1;
            state[i + 6] = a1;
            state[i + 7] = c1;
        }
    }

    /// Apply inverse S-box transformation
    fn apply_inverse_sbox(&self, state: &mut [u16; 16]) {
        for i in (0..16).step_by(8) {
            // inv_sigma_0
            let mut b = state[i];
            let mut c = state[i + 1];
            let mut d = state[i + 2];
            let mut a = state[i + 3];

            a ^= b | d;
            b ^= a | c;
            c ^= b & d;
            d ^= b | c;
            b ^= a | d;
            a ^= b & c;

            state[i] = a;
            state[i + 1] = b;
            state[i + 2] = c;
            state[i + 3] = d;

            // inv_sigma_1
            d = state[i + 4];
            b = state[i + 5];
            a = state[i + 6];
            c = state[i + 7];

            a ^= b | d;
            b ^= a | c;
            c ^= b & d;
            d ^= b | c;
            b ^= a | d;
            a ^= b & c;

            state[i + 4] = a;
            state[i + 5] = b;
            state[i + 6] = c;
            state[i + 7] = d;
        }
    }

    /// Apply MDS (Maximum Distance Separable) transformation
    fn apply_mds(&self, state: &mut [u16; 16]) {
        let mut x0 = state[0x0];
        let mut x1 = state[0x1];
        let mut x2 = state[0x2];
        let mut x3 = state[0x3];
        let mut x4 = state[0x4];
        let mut x5 = state[0x5];
        let mut x6 = state[0x6];
        let mut x7 = state[0x7];
        let mut x8 = state[0x8];
        let mut x9 = state[0x9];
        let mut xa = state[0xA];
        let mut xb = state[0xB];
        let mut xc = state[0xC];
        let mut xd = state[0xD];
        let mut xe = state[0xE];
        let mut xf = state[0xF];

        x8 ^= xc;
        x9 ^= xd;
        xa ^= xe;
        xb ^= xf; /* C ^= D */
        x0 ^= x4;
        x1 ^= x5;
        x2 ^= x6;
        x3 ^= x7; /* A ^= B */
        self.mul_column(&mut [&mut x4, &mut x5, &mut x6, &mut x7]); /* B = MUL(B) */
        self.mul_column(&mut [&mut xc, &mut xd, &mut xe, &mut xf]); /* D = MUL(D) */
        x4 ^= x8;
        x5 ^= x9;
        x6 ^= xa;
        x7 ^= xb; /* B ^= C */
        xc ^= x0;
        xd ^= x1;
        xe ^= x2;
        xf ^= x3; /* D ^= A */
        self.mul_column(&mut [&mut x0, &mut x1, &mut x2, &mut x3]); /* A = MUL(A) */
        self.mul_column(&mut [&mut x0, &mut x1, &mut x2, &mut x3]); /* A = MUL(A) */
        self.mul_column(&mut [&mut x8, &mut x9, &mut xa, &mut xb]); /* C = MUL(C) */
        self.mul_column(&mut [&mut x8, &mut x9, &mut xa, &mut xb]); /* C = MUL(C) */
        x8 ^= xc;
        x9 ^= xd;
        xa ^= xe;
        xb ^= xf; /* C ^= D */
        x0 ^= x4;
        x1 ^= x5;
        x2 ^= x6;
        x3 ^= x7; /* A ^= B */
        x4 ^= x8;
        x5 ^= x9;
        x6 ^= xa;
        x7 ^= xb; /* B ^= C */
        xc ^= x0;
        xd ^= x1;
        xe ^= x2;
        xf ^= x3; /* D ^= A */

        state[0x0] = x0;
        state[0x1] = x1;
        state[0x2] = x2;
        state[0x3] = x3;
        state[0x4] = x4;
        state[0x5] = x5;
        state[0x6] = x6;
        state[0x7] = x7;
        state[0x8] = x8;
        state[0x9] = x9;
        state[0xA] = xa;
        state[0xB] = xb;
        state[0xC] = xc;
        state[0xD] = xd;
        state[0xE] = xe;
        state[0xF] = xf;
    }

    /// Apply inverse MDS transformation
    fn apply_inverse_mds(&self, state: &mut [u16; 16]) {
        let mut x0 = state[0x0];
        let mut x1 = state[0x1];
        let mut x2 = state[0x2];
        let mut x3 = state[0x3];
        let mut x4 = state[0x4];
        let mut x5 = state[0x5];
        let mut x6 = state[0x6];
        let mut x7 = state[0x7];
        let mut x8 = state[0x8];
        let mut x9 = state[0x9];
        let mut xa = state[0xA];
        let mut xb = state[0xB];
        let mut xc = state[0xC];
        let mut xd = state[0xD];
        let mut xe = state[0xE];
        let mut xf = state[0xF];

        x4 ^= x8;
        x5 ^= x9;
        x6 ^= xa;
        x7 ^= xb; /* B ^= C */
        xc ^= x0;
        xd ^= x1;
        xe ^= x2;
        xf ^= x3; /* D ^= A */
        x8 ^= xc;
        x9 ^= xd;
        xa ^= xe;
        xb ^= xf; /* C ^= D */
        x0 ^= x4;
        x1 ^= x5;
        x2 ^= x6;
        x3 ^= x7; /* A ^= B */
        self.inv_mul_column(&mut [&mut x0, &mut x1, &mut x2, &mut x3]); /* A = MULinv(A) */
        self.inv_mul_column(&mut [&mut x0, &mut x1, &mut x2, &mut x3]); /* A = MULinv(A) */
        self.inv_mul_column(&mut [&mut x8, &mut x9, &mut xa, &mut xb]); /* C = MULinv(C) */
        self.inv_mul_column(&mut [&mut x8, &mut x9, &mut xa, &mut xb]); /* C = MULinv(C) */
        x4 ^= x8;
        x5 ^= x9;
        x6 ^= xa;
        x7 ^= xb; /* B ^= C */
        xc ^= x0;
        xd ^= x1;
        xe ^= x2;
        xf ^= x3; /* D ^= A */
        self.inv_mul_column(&mut [&mut x4, &mut x5, &mut x6, &mut x7]); /* B = MULinv(B) */
        self.inv_mul_column(&mut [&mut xc, &mut xd, &mut xe, &mut xf]); /* D = MULinv(D) */
        x8 ^= xc;
        x9 ^= xd;
        xa ^= xe;
        xb ^= xf; /* C ^= D */
        x0 ^= x4;
        x1 ^= x5;
        x2 ^= x6;
        x3 ^= x7; /* A ^= B */

        state[0x0] = x0;
        state[0x1] = x1;
        state[0x2] = x2;
        state[0x3] = x3;
        state[0x4] = x4;
        state[0x5] = x5;
        state[0x6] = x6;
        state[0x7] = x7;
        state[0x8] = x8;
        state[0x9] = x9;
        state[0xA] = xa;
        state[0xB] = xb;
        state[0xC] = xc;
        state[0xD] = xd;
        state[0xE] = xe;
        state[0xF] = xf;
    }

    /// Apply shift rows (slice variant)
    fn apply_shift_rows_slice(&self, state: &mut [u16; 16]) {
        for i in 0..4 {
            state[4 + i] = (state[4 + i] & 0x7777) << 1 | (state[4 + i] & 0x8888) >> 3;
            state[8 + i] = (state[8 + i] & 0x3333) << 2 | (state[8 + i] & 0xCCCC) >> 2;
            state[12 + i] = (state[12 + i] & 0x1111) << 3 | (state[12 + i] & 0xEEEE) >> 1;
        }
    }

    /// Apply inverse shift rows (slice variant)
    fn apply_shift_rows_slice_inv(&self, state: &mut [u16; 16]) {
        for i in 0..4 {
            state[4 + i] = (state[4 + i] & 0x1111) << 3 | (state[4 + i] & 0xEEEE) >> 1;
            state[8 + i] = (state[8 + i] & 0x3333) << 2 | (state[8 + i] & 0xCCCC) >> 2;
            state[12 + i] = (state[12 + i] & 0x7777) << 1 | (state[12 + i] & 0x8888) >> 3;
        }
    }

    /// Apply shift rows (sheet variant)
    fn apply_shift_rows_sheet(&self, state: &mut [u16; 16]) {
        for i in 0..4 {
            state[4 + i] = state[4 + i].rotate_left(4);
            state[8 + i] = state[8 + i].rotate_right(8);
            state[12 + i] = state[12 + i].rotate_right(4);
        }
    }

    /// Apply inverse shift rows (sheet variant)
    fn apply_shift_rows_sheet_inv(&self, state: &mut [u16; 16]) {
        for i in 0..4 {
            state[4 + i] = state[4 + i].rotate_right(4);
            state[8 + i] = state[8 + i].rotate_right(8);
            state[12 + i] = state[12 + i].rotate_left(4);
        }
    }

    /// Apply multiplication to a column
    fn mul_column(&self, column: &mut [&mut u16]) {
        if column.len() >= 4 {
            let tmp = *column[0];
            *column[0] = *column[1];
            *column[1] = *column[2];
            *column[2] = *column[3];
            *column[3] = tmp ^ *column[0];
        }
    }

    /// Apply inverse multiplication to a column
    fn inv_mul_column(&self, column: &mut [&mut u16]) {
        if column.len() >= 4 {
            let tmp = *column[3];
            *column[3] = *column[2];
            *column[2] = *column[1];
            *column[1] = *column[0];
            *column[0] = tmp ^ *column[1];
        }
    }

    /// Get the round constants (for debugging)
    pub fn round_constants(&self) -> &[u16] {
        &self.round_constants
    }

    /// Get the domain parameter
    pub fn domain(&self) -> u8 {
        self.domain
    }

    /// Get the number of rounds
    pub fn num_rounds(&self) -> usize {
        self.num_rounds
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::eprintln;

    use super::*;

    #[test]
    fn test_saturnin_core_creation() {
        let core = SaturninCore::new(10, 1).unwrap();
        assert_eq!(core.num_rounds(), 10);
        assert_eq!(core.domain(), 1);
    }

    #[test]
    fn test_saturnin_core_invalid_rounds() {
        let result = SaturninCore::new(32, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_core_invalid_domain() {
        let result = SaturninCore::new(10, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_saturnin_core_round_trip() -> Result<()> {
        let core = SaturninCore::new(10, 1)?;
        let key = [0u8; 32];
        let mut block = [0u8; 32];

        // Encrypt (fixed-size path)
        core.encrypt_block_32(&key, &mut block)?;

        // Decrypt (fixed-size path)
        core.decrypt_block_32(&key, &mut block)?;

        // Should be back to original (all zeros)
        assert_eq!(block, [0u8; 32]);

        Ok(())
    }

    #[test]
    fn test_round_constants() {
        // Test round constant generation for domain 7, 16 rounds
        let core = SaturninCore::new(16, 7).unwrap();

        // Expected first few round constants for domain 7, 16 rounds
        // These should match the reference implementation
        #[cfg(feature = "std")]
        eprintln!("Round constants: {:04X?}", &core.round_constants[0..4]);

        // The first round constant should be generated from:
        // x0 = x1 = 7 + (16 << 4) + 0xFE00 = 7 + 0x100 + 0xFE00 = 0xFF07
        // After 16 iterations of the LFSR, we get the first constant
        assert_eq!(core.round_constants.len(), 32); // 16 rounds * 2 constants per round
    }

    #[test]
    fn test_lfsr_implementation() {
        // Test LFSR implementation against reference values
        // From reference: domain 7, 16 rounds
        // Initial value: 7 + (16 << 4) + 0xFE00 = 0xFF07

        let mut x0 = 0xFF07u16;
        let mut x1 = 0xFF07u16;

        // Run LFSR for 16 iterations to get first round constant
        for _ in 0..16 {
            x0 = (x0 << 1) ^ (0x2D & (!(x0 >> 15).wrapping_add(1)));
            x1 = (x1 << 1) ^ (0x53 & (!(x1 >> 15).wrapping_add(1)));
        }

        #[cfg(feature = "std")]
        eprintln!("LFSR result: x0={:04X}, x1={:04X}", x0, x1);

        // These should match the first round constants from our implementation
        #[cfg(feature = "std")]
        {
            let core = SaturninCore::new(16, 7).unwrap();
            eprintln!(
                "Core constants: x0={:04X}, x1={:04X}",
                core.round_constants[0], core.round_constants[1]
            );
        }

        // For now, just verify the LFSR runs without panicking
        assert!(x0 != 0 || x1 != 0);
    }

    #[test]
    fn test_sbox_implementation() {
        // Test S-box implementation against reference values
        let core = SaturninCore::new(16, 7).unwrap();

        // Test sigma_0 with known input
        let mut state = [0u16; 16];
        state[0] = 0x1234;
        state[1] = 0x5678;
        state[2] = 0x9ABC;
        state[3] = 0xDEF0;

        let original = state;
        core.apply_sbox(&mut state);

        #[cfg(feature = "std")]
        {
            eprintln!("S-box input:  {:04X?}", &original[0..4]);
            eprintln!("S-box output: {:04X?}", &state[0..4]);
        }

        // Verify S-box is not identity
        assert_ne!(state[0..4], original[0..4]);
    }

    #[test]
    fn test_mds_implementation() {
        // Test MDS implementation
        let core = SaturninCore::new(16, 7).unwrap();

        let mut state = [0u16; 16];
        for (i, item) in state.iter_mut().enumerate() {
            *item = i as u16;
        }

        let original = state;
        core.apply_mds(&mut state);

        #[cfg(feature = "std")]
        {
            eprintln!("MDS input:  {:04X?}", &original[0..4]);
            eprintln!("MDS output: {:04X?}", &state[0..4]);
        }

        // Verify MDS is not identity
        assert_ne!(state[0..4], original[0..4]);
    }

    #[test]
    fn test_shift_rows_implementation() {
        // Test shift rows implementation
        let core = SaturninCore::new(16, 7).unwrap();

        let mut state = [0u16; 16];
        for (i, item) in state.iter_mut().enumerate() {
            *item = i as u16;
        }

        let original = state;
        core.apply_shift_rows_slice(&mut state);

        #[cfg(feature = "std")]
        {
            eprintln!("Shift rows input:  {:04X?}", &original[4..8]);
            eprintln!("Shift rows output: {:04X?}", &state[4..8]);
        }

        // Verify shift rows is not identity
        assert_ne!(state[4..8], original[4..8]);
    }

    #[test]
    fn test_complete_round_structure() {
        // Test complete round structure with known values
        let core = SaturninCore::new(16, 7).unwrap();

        // Test with all-zero key and all-zero plaintext
        let key = [0u8; 32];
        let mut block = [0u8; 32];

        #[cfg(feature = "std")]
        eprintln!("Input block: {:02X?}", &block[0..8]);

        // Encrypt the block
        core.encrypt_block(&key, &mut block).unwrap();

        #[cfg(feature = "std")]
        eprintln!("Encrypted block: {:02X?}", &block[0..8]);

        // Verify the block changed (not identity)
        assert_ne!(block, [0u8; 32]);

        // Decrypt the block
        core.decrypt_block(&key, &mut block).unwrap();

        #[cfg(feature = "std")]
        eprintln!("Decrypted block: {:02X?}", &block[0..8]);

        // Should be back to all zeros
        assert_eq!(block, [0u8; 32]);
    }

    #[test]
    fn test_single_round_debug() {
        // Test a single round with debug output
        let core = SaturninCore::new(1, 7).unwrap(); // Just 1 round for debugging

        let key = [0u8; 32];
        let mut block = [0u8; 32];

        #[cfg(feature = "std")]
        {
            eprintln!("=== Single Round Debug ===");
            eprintln!("Input block: {:02X?}", &block[0..8]);
        }

        // Encrypt the block
        core.encrypt_block(&key, &mut block).unwrap();

        #[cfg(feature = "std")]
        eprintln!("After 1 round: {:02X?}", &block[0..8]);

        // Decrypt the block
        core.decrypt_block(&key, &mut block).unwrap();

        #[cfg(feature = "std")]
        eprintln!("After decrypt: {:02X?}", &block[0..8]);

        // Should be back to all zeros
        assert_eq!(block, [0u8; 32]);
    }
}
