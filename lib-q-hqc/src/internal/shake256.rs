//! SHAKE256 XOF Implementation
//!
//! This module provides SHAKE256 extendable output function operations
//! used in the HQC implementation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HqcError;

/// SHAKE256 XOF implementation
pub struct Shake256Xof {
    pub state: [u64; 25], // Keccak state
    rate: usize,
    pub position: usize,
}

impl Shake256Xof {
    /// Create a new SHAKE256 XOF
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate: 136, // SHAKE256 rate
            position: 0,
        }
    }

    /// Initialize with input data
    pub fn init(&mut self, input: &[u8]) -> Result<(), HqcError> {
        // Initialize Keccak state
        self.state.fill(0);
        self.position = 0;

        // Absorb input data
        self.absorb(input)?;

        // Finalize absorption phase
        self.finalize_absorb()?;

        Ok(())
    }

    /// Initialize with input data and domain separation (matches reference xof_init)
    pub fn init_with_domain(&mut self, input: &[u8], domain: u8) -> Result<(), HqcError> {
        // Initialize Keccak state
        self.state.fill(0);
        self.position = 0;

        // Absorb input data
        self.absorb(input)?;

        // Absorb domain separation byte
        self.absorb(&[domain])?;

        // Finalize absorption phase
        self.finalize_absorb()?;

        Ok(())
    }

    /// Generate output bytes
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), HqcError> {
        for byte in output.iter_mut() {
            if self.position >= self.rate {
                self.keccak_f();
                self.position = 0;
            }

            let lane_index = self.position / 8;
            let byte_index = self.position % 8;
            *byte = ((self.state[lane_index] >> (byte_index * 8)) & 0xFF) as u8;
            self.position += 1;
        }
        Ok(())
    }

    /// Generate a single byte
    pub fn squeeze_byte(&mut self) -> Result<u8, HqcError> {
        let mut byte = [0u8; 1];
        self.squeeze(&mut byte)?;
        Ok(byte[0])
    }

    /// Generate a 32-bit word
    pub fn squeeze_u32(&mut self) -> Result<u32, HqcError> {
        let mut bytes = [0u8; 4];
        self.squeeze(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Generate a 64-bit word
    pub fn squeeze_u64(&mut self) -> Result<u64, HqcError> {
        let mut bytes = [0u8; 8];
        self.squeeze(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Absorb input data into the state
    pub fn absorb(&mut self, input: &[u8]) -> Result<(), HqcError> {
        for &byte in input {
            if self.position >= self.rate {
                self.keccak_f();
                self.position = 0;
            }

            let lane_index = self.position / 8;
            let byte_index = self.position % 8;
            self.state[lane_index] ^= (byte as u64) << (byte_index * 8);
            self.position += 1;
        }
        Ok(())
    }

    /// Finalize the absorption phase
    pub fn finalize_absorb(&mut self) -> Result<(), HqcError> {
        if self.position >= self.rate {
            self.keccak_f();
            self.position = 0;
        }

        // Add SHAKE256 padding (0x1F at current position)
        let lane_index = self.position / 8;
        let byte_index = self.position % 8;
        self.state[lane_index] ^= 0x1F << (byte_index * 8);

        // Add final padding bit (0x80) at the last byte of the rate
        // For SHAKE256, rate = 136 bytes, so last byte is at position 135
        let last_byte_position = self.rate - 1; // 135 for SHAKE256
        let last_lane_index = last_byte_position / 8;
        let last_byte_index = last_byte_position % 8;
        self.state[last_lane_index] ^= 0x80 << (last_byte_index * 8);

        self.keccak_f();
        self.position = 0;

        Ok(())
    }

    /// Keccak-f[1600] permutation
    fn keccak_f(&mut self) {
        // Use the proper Keccak-f implementation from lib-q-keccak
        lib_q_keccak::f1600(&mut self.state);
    }

    /// Single Keccak round
    #[allow(dead_code)] // Internal implementation detail for Keccak-f
    fn keccak_round(&mut self) {
        // Simplified round function
        // In a real implementation, this would include theta, rho, pi, chi, and iota steps

        // Theta step (simplified)
        let mut c = [0u64; 5];
        for (x, c_val) in c.iter_mut().enumerate() {
            *c_val = self.state[x] ^
                self.state[x + 5] ^
                self.state[x + 10] ^
                self.state[x + 15] ^
                self.state[x + 20];
        }

        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                self.state[x + 5 * y] ^= d;
            }
        }

        // Rho and Pi steps (simplified)
        let mut temp = [0u64; 25];
        temp.copy_from_slice(&self.state);

        for x in 0..5 {
            for y in 0..5 {
                let index = x + 5 * y;
                let new_index = (y + 5 * x) % 25;
                self.state[new_index] = temp[index].rotate_left((x + y) as u32);
            }
        }

        // Chi step (simplified)
        for y in 0..5 {
            let mut temp_row = [0u64; 5];
            for (x, temp_val) in temp_row.iter_mut().enumerate() {
                *temp_val = self.state[x + 5 * y];
            }

            for x in 0..5 {
                self.state[x + 5 * y] =
                    temp_row[x] ^ (!temp_row[(x + 1) % 5] & temp_row[(x + 2) % 5]);
            }
        }

        // Iota step (simplified)
        self.state[0] ^= 0x0000000000000001;
    }
}

impl Default for Shake256Xof {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash function using SHAKE256
#[cfg(feature = "alloc")]
pub fn shake256_hash(input: &[u8], output_len: usize) -> Result<Vec<u8>, HqcError> {
    let mut xof = Shake256Xof::new();
    xof.init(input)?;
    let mut output = vec![0u8; output_len];
    xof.squeeze(&mut output[..output_len])?;
    Ok(output)
}

#[cfg(not(feature = "alloc"))]
pub fn shake256_hash(input: &[u8], output_len: usize) -> Result<[u8; 1000], HqcError> {
    let mut xof = Shake256Xof::new();
    xof.init(input)?;
    let mut output = [0u8; 1000];
    if output_len > output.len() {
        return Err(HqcError::InvalidSize);
    }
    xof.squeeze(&mut output[..output_len])?;
    Ok(output)
}

/// Generate random bytes using SHAKE256
#[cfg(feature = "alloc")]
pub fn shake256_random(seed: &[u8], output_len: usize) -> Result<Vec<u8>, HqcError> {
    shake256_hash(seed, output_len)
}

#[cfg(not(feature = "alloc"))]
pub fn shake256_random(seed: &[u8], output_len: usize) -> Result<[u8; 1000], HqcError> {
    shake256_hash(seed, output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_xof_creation() {
        let xof = Shake256Xof::new();
        assert_eq!(xof.rate, 136);
        assert_eq!(xof.position, 0);
    }

    #[test]
    fn test_xof_kat_compatibility() {
        // Test with KAT seed from HQC-1 test vector
        let seed_kem =
            hex::decode("9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e7")
                .unwrap();

        let mut xof = Shake256Xof::new();
        xof.init_with_domain(&seed_kem, 1).expect("XOF init failed");

        // Get seed_pke (32 bytes) and sigma (16 bytes)
        let mut seed_pke = [0u8; 32];
        let mut sigma = [0u8; 16];

        xof.squeeze(&mut seed_pke).expect("XOF squeeze failed");
        xof.squeeze(&mut sigma).expect("XOF squeeze failed");

        // Verify we get non-zero output
        assert!(
            seed_pke.iter().any(|&x| x != 0),
            "seed_pke should not be all zeros"
        );
        assert!(
            sigma.iter().any(|&x| x != 0),
            "sigma should not be all zeros"
        );

        // These values should match the reference implementation
        // We'll verify this once we have the reference outputs
    }

    #[test]
    fn test_shake256_xof_init() {
        let mut xof = Shake256Xof::new();
        let input = b"test input";
        xof.init(input).unwrap();
        // State should be modified after initialization
        assert!(xof.state.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_shake256_xof_squeeze() {
        let mut xof = Shake256Xof::new();
        let input = b"test input";
        xof.init(input).unwrap();

        let mut output = [0u8; 32];
        xof.squeeze(&mut output).unwrap();

        // Should not be all zeros
        assert!(output.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_shake256_hash() {
        let input = b"test input";
        let output = shake256_hash(input, 32).unwrap();
        assert_eq!(output.len(), 32);

        // Should be deterministic
        let output2 = shake256_hash(input, 32).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_shake256_random() {
        let seed = b"random seed";
        let output = shake256_random(seed, 64).unwrap();
        assert_eq!(output.len(), 64);

        // Should be deterministic for same seed
        let output2 = shake256_random(seed, 64).unwrap();
        assert_eq!(output, output2);
    }
}
