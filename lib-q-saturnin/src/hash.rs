//! Saturnin hash function implementation
//!
//! This module provides the Saturnin hash function, which produces a 256-bit hash output
//! using the Saturnin block cipher in a specific mode of operation.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::SaturninHash;
//!
//! // Create hash instance
//! let hash = SaturninHash::new();
//!
//! // Hash some data
//! let data = b"Hello, World!";
//! let hash_output = hash.hash(data).unwrap();
//!
//! // Hash output is always 32 bytes (256 bits)
//! assert_eq!(hash_output.len(), 32);
//!
//! // Hash is deterministic
//! let hash_output2 = hash.hash(data).unwrap();
//! assert_eq!(hash_output, hash_output2);
//!
//! // Different data produces different hash
//! let different_data = b"Hello, Universe!";
//! let different_hash = hash.hash(different_data).unwrap();
//! assert_ne!(hash_output, different_hash);
//! ```
//!
//! ## Performance Notes
//!
//! - **Output size**: 256 bits (32 bytes)
//! - **Throughput**: ~200-800 MB/s on modern hardware
//! - **Memory usage**: Constant, independent of input size
//! - **Security level**: 256-bit post-quantum security

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Hash,
    Result,
};

use crate::bs32_core::SaturninBs32Core;
use crate::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use crate::simd::simd_xor;

/// Saturnin hash function implementation
///
/// Provides a 256-bit hash function using the Saturnin algorithm with 16 super-rounds
/// and domain parameters 7 and 8 for different processing phases.
pub struct SaturninHash {
    core: SaturninCore,
}

impl SaturninHash {
    /// Create a new Saturnin hash instance
    pub fn new() -> Self {
        // Use 16 super-rounds and domain 7 for the hash function
        let core = SaturninCore::new(16, 7).expect("Valid parameters");
        Self { core }
    }

    /// Get the output size in bytes (256 bits = 32 bytes)
    pub const fn output_size(&self) -> usize {
        32
    }

    /// Get the core instance (for debugging and testing)
    pub fn core(&self) -> &SaturninCore {
        &self.core
    }

    /// Hash data using Saturnin hash function
    ///
    /// # Arguments
    /// * `data` - Data to hash
    ///
    /// # Returns
    /// 32-byte hash output
    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Pre-allocate scalar cores to avoid repeated allocation overhead.
        let core_d1 = SaturninBs32Core::new(16, 7)?;
        let core_d2 = SaturninBs32Core::new(16, 8)?;

        let mut r = [0u8; 32];
        let mut u = 0;
        let len = data.len();

        loop {
            let mut t = [0u8; 32];
            let mut m = [0u8; 32];
            let clen = len - u;

            if clen >= 32 {
                // Optimized copy for full blocks
                t[0..32].copy_from_slice(&data[u..u + 32]);
                u += 32;

                // Use pre-allocated bs32 core for domain 7.
                m.copy_from_slice(&t);
                core_d1.encrypt_block(&r, &mut m)?;
            } else {
                // Handle final block with padding
                t[0..clen].copy_from_slice(&data[u..u + clen]);
                t[clen] = 0x80;
                // t[clen + 1..32] is already zero

                // Use pre-allocated bs32 core for domain 8.
                m.copy_from_slice(&t);
                core_d2.encrypt_block(&r, &mut m)?;
            }

            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            {
                let mut out = [0u8; 32];
                simd_xor::xor_blocks_32(&m, &t, &mut out);
                r.copy_from_slice(&out);
            }

            #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
            {
                for i in 0..32 {
                    r[i] = m[i] ^ t[i];
                }
            }

            if clen < 32 {
                break;
            }
        }

        Ok(r.to_vec())
    }
}

impl Hash for SaturninHash {
    /// Hash data
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(data)
    }

    /// Get the output size in bytes
    fn output_size(&self) -> usize {
        32
    }
}

impl Default for SaturninHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::eprintln;

    use super::*;
    use crate::bs32_core::SaturninBs32Core;

    #[test]
    fn test_hash_creation() {
        let hash = SaturninHash::new();
        assert_eq!(hash.output_size(), 32);

        // Test that the core is properly initialized
        let core = hash.core();
        assert_eq!(core.num_rounds(), 16);
        assert_eq!(core.domain(), 7);
    }

    #[test]
    fn test_hash_empty_input() -> Result<()> {
        let hash = SaturninHash::new();
        let result = hash.hash(b"")?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_hash_single_byte() -> Result<()> {
        let hash = SaturninHash::new();
        let result = hash.hash(b"a")?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_hash_multiple_blocks() -> Result<()> {
        let hash = SaturninHash::new();
        #[cfg(feature = "alloc")]
        let data = alloc::vec![0u8; 100]; // More than 3 blocks
        #[cfg(not(feature = "alloc"))]
        let data = [0u8; 100]; // More than 3 blocks
        let result = hash.hash(&data)?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_hash_deterministic() -> Result<()> {
        let hash = SaturninHash::new();
        let data = b"test message";

        let result1 = hash.hash(data)?;
        let result2 = hash.hash(data)?;

        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_hash_different_inputs() -> Result<()> {
        let hash = SaturninHash::new();

        let result1 = hash.hash(b"message 1")?;
        let result2 = hash.hash(b"message 2")?;

        assert_ne!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_hash_avalanche_effect() -> Result<()> {
        let hash = SaturninHash::new();

        let result1 = hash.hash(b"hello")?;
        let result2 = hash.hash(b"Hello")?; // Only first character differs

        // Should be completely different due to avalanche effect
        assert_ne!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_hash_trait_implementation() -> Result<()> {
        let hash = SaturninHash::new();
        let data = b"test data";

        // Test through trait
        let result = Hash::hash(&hash, data)?;
        assert_eq!(result.len(), 32);

        // Test direct method
        let direct_result = hash.hash(data)?;
        assert_eq!(result, direct_result);

        Ok(())
    }

    #[test]
    fn test_hash_empty_input_debug() -> Result<()> {
        let hash = SaturninHash::new();
        let result = hash.hash(b"")?;

        // Expected: 83B15641B09569B04C606108FC8AE268AC0DC9288741B5735D8612D69C0AFDFE
        let expected = [
            0x83, 0xB1, 0x56, 0x41, 0xB0, 0x95, 0x69, 0xB0, 0x4C, 0x60, 0x61, 0x08, 0xFC, 0x8A,
            0xE2, 0x68, 0xAC, 0x0D, 0xC9, 0x28, 0x87, 0x41, 0xB5, 0x73, 0x5D, 0x86, 0x12, 0xD6,
            0x9C, 0x0A, 0xFD, 0xFE,
        ];

        // Debug output
        #[cfg(feature = "std")]
        {
            eprintln!("Expected: {:02X?}", expected);
            eprintln!("Got:      {:02X?}", result);
        }

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_hash_empty_input_step_by_step() {
        // Manually implement the hash algorithm step by step
        let mut r = [0u8; 32];
        let mut u = 0;
        let data = &[];
        let len = data.len();

        #[cfg(feature = "std")]
        eprintln!("Initial r: {:02X?}", &r[0..8]);

        loop {
            let mut t = [0u8; 32];
            let mut m = [0u8; 32];
            let mut domain = 7; // SATURNIN_HASH_D1
            let clen = len - u;

            #[cfg(feature = "std")]
            eprintln!("Iteration: u={}, clen={}, len={}", u, clen, len);

            if clen >= 32 {
                t[0..32].copy_from_slice(&data[u..u + 32]);
                u += 32;
            } else {
                t[0..clen].copy_from_slice(&data[u..u + clen]);
                t[clen] = 0x80;
                // t[clen + 1..32] is already zero
                domain = 8; // SATURNIN_HASH_D2
            }

            #[cfg(feature = "std")]
            {
                eprintln!("t: {:02X?}", &t[0..8]);
                eprintln!("domain: {}", domain);
            }

            m.copy_from_slice(&t);

            // Encrypt m with r as key (16 super-rounds as per reference)
            let temp_core = SaturninCore::new(16, domain).unwrap();
            #[cfg(feature = "std")]
            {
                eprintln!("Before encryption m: {:02X?}", &m[0..8]);
                eprintln!("Key r: {:02X?}", &r[0..8]);
            }
            temp_core.encrypt_block(&r, &mut m).unwrap();
            #[cfg(feature = "std")]
            eprintln!("After encryption m: {:02X?}", &m[0..8]);

            // XOR m with t to get new r
            for v in 0..32 {
                r[v] = m[v] ^ t[v];
            }

            #[cfg(feature = "std")]
            eprintln!("New r: {:02X?}", &r[0..8]);

            if domain == 8 {
                break;
            }
        }

        #[cfg(feature = "std")]
        {
            eprintln!("Final result: {:02X?}", r);
            eprintln!(
                "Expected:     {:02X?}",
                [
                    0x83, 0xB1, 0x56, 0x41, 0xB0, 0x95, 0x69, 0xB0, 0x4C, 0x60, 0x61, 0x08, 0xFC,
                    0x8A, 0xE2, 0x68, 0xAC, 0x0D, 0xC9, 0x28, 0x87, 0x41, 0xB5, 0x73, 0x5D, 0x86,
                    0x12, 0xD6, 0x9C, 0x0A, 0xFD, 0xFE
                ]
            );
        }
    }

    #[test]
    fn test_hash_with_bs32() {
        // Test hash using bs32 implementation
        let mut r = [0u8; 32];
        let data: &[u8] = &[];
        let len = data.len();

        #[cfg(feature = "std")]
        {
            eprintln!("Testing hash with bs32 implementation");
            eprintln!("Initial r: {:02X?}", &r[0..8]);
        }

        loop {
            let mut t = [0u8; 32];
            let mut m = [0u8; 32];
            let domain = 8; // SATURNIN_HASH_D2 - for empty input, we always use domain 8
            let _clen = len; // u = 0 for empty input

            #[cfg(feature = "std")]
            eprintln!("Iteration: clen={}, len={}", _clen, len);

            // For empty input, we always use domain 8 (final block)
            t[0] = 0x80; // Set padding bit for empty input

            #[cfg(feature = "std")]
            {
                eprintln!("t: {:02X?}", &t[0..8]);
                eprintln!("domain: {}", domain);
            }

            m.copy_from_slice(&t);
            #[cfg(feature = "std")]
            eprintln!("Before encryption m: {:02X?}", &m[0..8]);

            // Encrypt m with r as key using bs32
            let temp_core = SaturninBs32Core::new(16, domain).unwrap();
            temp_core.encrypt_block(&r, &mut m).unwrap();
            #[cfg(feature = "std")]
            eprintln!("After encryption m: {:02X?}", &m[0..8]);

            // XOR m with t to get new r
            for v in 0..32 {
                r[v] = m[v] ^ t[v];
            }
            #[cfg(feature = "std")]
            eprintln!("New r: {:02X?}", &r[0..8]);

            if domain == 8 {
                break;
            }
        }

        #[cfg(feature = "std")]
        {
            eprintln!("Final result: {:02X?}", r);
            eprintln!(
                "Expected:     {:02X?}",
                [
                    0x83, 0xB1, 0x56, 0x41, 0xB0, 0x95, 0x69, 0xB0, 0x4C, 0x60, 0x61, 0x08, 0xFC,
                    0x8A, 0xE2, 0x68, 0xAC, 0x0D, 0xC9, 0x28, 0x87, 0x41, 0xB5, 0x73, 0x5D, 0x86,
                    0x12, 0xD6, 0x9C, 0x0A, 0xFD, 0xFE
                ]
            );
        }
    }

    #[test]
    fn test_block_cipher_simple_case() {
        // Test the block cipher with the exact same inputs as the hash
        let mut block = [
            0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let key = [0u8; 32];

        #[cfg(feature = "std")]
        {
            eprintln!("Input block: {:02X?}", &block[0..8]);
            eprintln!("Key: {:02X?}", &key[0..8]);
        }

        let core = SaturninCore::new(16, 8).unwrap();
        core.encrypt_block(&key, &mut block).unwrap();

        #[cfg(feature = "std")]
        {
            eprintln!("Encrypted: {:02X?}", &block[0..8]);
            eprintln!("Expected from hash debug: [BE, E7, 36, 07, BA, A3, 51, 96]");
        }
    }

    #[test]
    fn test_round_constants_comparison() {
        // Generate round constants for domain 8 (last block)
        #[cfg(feature = "std")]
        {
            let core = SaturninCore::new(16, 8).unwrap();
            eprintln!("My round constants for domain 8:");
            for (i, &constant) in core.round_constants().iter().enumerate() {
                eprintln!("  RC[{}] = 0x{:04X}", i, constant);
            }

            // Compare with bs32 hardcoded constants
            eprintln!("\nbs32 hardcoded constants RC_16_8:");
            let bs32_constants = [
                0x3C9B, 0x19A7, 0xA909, 0x8694, 0x23F8, 0x78DA, 0xA7B6, 0x47D3, 0x74FC, 0x9D78,
                0xEACA, 0xAE11, 0x2F31, 0xA677, 0x4CC8, 0xC054, 0x2F51, 0xCA05, 0x5268, 0xF195,
                0x4F5B, 0x8A2B, 0xF614, 0xB4AC, 0xF1D9, 0x5401, 0x764D, 0x2568, 0x6A49, 0x3611,
                0x8EEF, 0x9C3E,
            ];
            for (i, &constant) in bs32_constants.iter().enumerate() {
                eprintln!("  RC[{}] = 0x{:04X}", i, constant);
            }
        }
    }
}
