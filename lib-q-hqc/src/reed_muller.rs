//! Reed-Muller Code Implementation
//!
//! This module implements Reed-Muller code RM(1,7) as used in HQC.
//! Based on the reference implementation in the HQC specification.
//!
//! The Reed-Muller code RM(1,7) encodes 8-bit messages into 128-bit codewords
//! and provides error correction capabilities through the Hadamard transform.

#[cfg(feature = "alloc")]
use alloc::vec;
use core::fmt;

use crate::params_correct::HqcParams;

/// Reed-Muller codeword representation (128 bits = 16 bytes = 4 32-bit words)
/// This matches the reference implementation's rm_codeword_t union
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RmCodeword {
    /// Byte-wise access (16 bytes)
    pub u8: [u8; 16],
}

impl RmCodeword {
    /// Create a new zero-initialized codeword
    pub fn new() -> Self {
        Self { u8: [0u8; 16] }
    }

    /// Get 32-bit word access (4 words) - safe version
    pub fn u32(&self) -> [u32; 4] {
        [
            u32::from_le_bytes([self.u8[0], self.u8[1], self.u8[2], self.u8[3]]),
            u32::from_le_bytes([self.u8[4], self.u8[5], self.u8[6], self.u8[7]]),
            u32::from_le_bytes([self.u8[8], self.u8[9], self.u8[10], self.u8[11]]),
            u32::from_le_bytes([self.u8[12], self.u8[13], self.u8[14], self.u8[15]]),
        ]
    }

    /// Set 32-bit word access (4 words) - safe version
    pub fn set_u32(&mut self, words: [u32; 4]) {
        let bytes0 = words[0].to_le_bytes();
        let bytes1 = words[1].to_le_bytes();
        let bytes2 = words[2].to_le_bytes();
        let bytes3 = words[3].to_le_bytes();

        self.u8[0..4].copy_from_slice(&bytes0);
        self.u8[4..8].copy_from_slice(&bytes1);
        self.u8[8..12].copy_from_slice(&bytes2);
        self.u8[12..16].copy_from_slice(&bytes3);
    }
}

impl Default for RmCodeword {
    fn default() -> Self {
        Self::new()
    }
}

/// Reed-Muller code implementation
pub struct ReedMuller<P: HqcParams> {
    _params: core::marker::PhantomData<P>,
}

impl<P: HqcParams> Default for ReedMuller<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HqcParams> ReedMuller<P> {
    /// Create a new Reed-Muller code instance
    pub fn new() -> Self {
        Self {
            _params: core::marker::PhantomData,
        }
    }

    /// Encode a message using Reed-Muller code RM(1,7) as per reference
    #[cfg(feature = "alloc")]
    pub fn encode(&self, message: &[u8], codeword: &mut [u8]) -> Result<(), ReedMullerError> {
        let n2_bits = P::N2;
        let n2_bytes = crate::params_correct::ceil_divide(n2_bits, 8);
        let multiplicity = crate::params_correct::ceil_divide(n2_bits, 128);

        if codeword.len() < n2_bytes {
            return Err(ReedMullerError::InvalidCodewordLength);
        }

        // Initialize codeword
        for item in codeword.iter_mut().take(n2_bytes) {
            *item = 0;
        }

        // Convert byte array to rm_codeword_t array for processing
        let num_codewords = P::N1 * multiplicity;
        let mut code_array = vec![RmCodeword::new(); num_codewords];

        // Encode each byte of the message as per reference implementation
        for (i, &byte) in message.iter().enumerate() {
            if i >= P::N1 {
                break;
            }

            // Fill entries i * MULTIPLICITY to (i+1) * MULTIPLICITY
            let pos = i * multiplicity;

            // Encode first word - pass as i32 to match reference
            self.encode_byte(byte as i32, &mut code_array[pos]);

            // Copy to other identical codewords
            for copy in 1..multiplicity {
                if pos + copy < code_array.len() {
                    code_array[pos + copy] = code_array[pos];
                }
            }
        }

        // Convert back to byte array
        for (i, codeword_struct) in code_array.iter().enumerate() {
            let start_pos = i * 16;
            if start_pos + 15 < codeword.len() {
                codeword[start_pos..(16 + start_pos)].copy_from_slice(&codeword_struct.u8);
            }
        }

        Ok(())
    }

    /// Decode a codeword using Reed-Muller code RM(1,7) as per reference
    #[cfg(feature = "alloc")]
    pub fn decode(&self, codeword: &[u8], message: &mut [u8]) -> Result<(), ReedMullerError> {
        let n2_bits = P::N2;
        let n2_bytes = crate::params_correct::ceil_divide(n2_bits, 8);
        let multiplicity = crate::params_correct::ceil_divide(n2_bits, 128);

        if codeword.len() < n2_bytes {
            return Err(ReedMullerError::InvalidCodewordLength);
        }
        if message.len() < P::N1 {
            return Err(ReedMullerError::InvalidMessageLength);
        }

        // Convert byte array to rm_codeword_t array for processing
        let num_codewords = P::N1 * multiplicity;
        let mut code_array = vec![RmCodeword::new(); num_codewords];

        // Convert from byte array
        for (i, codeword_struct) in code_array.iter_mut().enumerate() {
            let start_pos = i * 16;
            if start_pos + 15 < codeword.len() {
                codeword_struct
                    .u8
                    .copy_from_slice(&codeword[start_pos..(16 + start_pos)]);
            }
        }

        // Decode each byte as per reference implementation
        for i in 0..P::N1 {
            // Collect the codewords
            let mut expanded = [0i16; 128];
            let start_idx = i * multiplicity;
            let end_idx = start_idx + multiplicity;
            if end_idx <= code_array.len() {
                self.expand_and_sum(&mut expanded, &code_array[start_idx..end_idx], multiplicity);
            } else {
                return Err(ReedMullerError::InvalidCodewordLength);
            }

            // Apply hadamard transform - exact match to reference
            let mut transform = [0i16; 128];
            self.hadamard_transform(&expanded, &mut transform);

            // Fix the first entry to get the half Hadamard transform
            transform[0] -= 64 * multiplicity as i16;

            // Finish the decoding - only write to message buffer if within bounds
            let decoded_byte = self.find_peaks(&transform) as u8;
            if i < message.len() {
                message[i] = decoded_byte;
            }
        }

        Ok(())
    }

    /// Encode a message using Reed-Muller code RM(1,7) as per reference (no_std version)
    #[cfg(not(feature = "alloc"))]
    pub fn encode(&self, message: &[u8], codeword: &mut [u8]) -> Result<(), ReedMullerError> {
        let n2_bits = P::N2;
        let n2_bytes = crate::params_correct::ceil_divide(n2_bits, 8);
        let multiplicity = crate::params_correct::ceil_divide(n2_bits, 128);

        if codeword.len() < n2_bytes {
            return Err(ReedMullerError::InvalidCodewordLength);
        }

        // Initialize codeword
        for item in codeword.iter_mut().take(n2_bytes) {
            *item = 0;
        }

        // For no_std, we need to use fixed-size arrays
        // This is a simplified version that works with the available memory
        let num_codewords = P::N1 * multiplicity;
        let mut code_array = [RmCodeword::new(); 1000]; // Fixed size array

        if num_codewords > code_array.len() {
            return Err(ReedMullerError::InvalidCodewordLength);
        }

        // Encode each byte of the message as per reference implementation
        for (i, &byte) in message.iter().enumerate() {
            if i >= P::N1 {
                break;
            }

            // Fill entries i * MULTIPLICITY to (i+1) * MULTIPLICITY
            let pos = i * multiplicity;

            // Encode first word - pass as i32 to match reference
            self.encode_byte(byte as i32, &mut code_array[pos]);

            // Copy to other identical codewords
            for copy in 1..multiplicity {
                if pos + copy < code_array.len() {
                    code_array[pos + copy] = code_array[pos];
                }
            }
        }

        // Convert back to byte array
        for (i, codeword_struct) in code_array.iter().enumerate() {
            if i >= num_codewords {
                break;
            }
            let start_pos = i * 16;
            if start_pos + 15 < codeword.len() {
                codeword[start_pos..(16 + start_pos)].copy_from_slice(&codeword_struct.u8);
            }
        }

        Ok(())
    }

    /// Decode a codeword using Reed-Muller code RM(1,7) as per reference (no_std version)
    #[cfg(not(feature = "alloc"))]
    pub fn decode(&self, codeword: &[u8], message: &mut [u8]) -> Result<(), ReedMullerError> {
        let n2_bits = P::N2;
        let n2_bytes = crate::params_correct::ceil_divide(n2_bits, 8);
        let multiplicity = crate::params_correct::ceil_divide(n2_bits, 128);

        if codeword.len() < n2_bytes {
            return Err(ReedMullerError::InvalidCodewordLength);
        }
        if message.len() < P::N1 {
            return Err(ReedMullerError::InvalidMessageLength);
        }

        // For no_std, we need to use fixed-size arrays
        let num_codewords = P::N1 * multiplicity;
        let mut code_array = [RmCodeword::new(); 1000]; // Fixed size array

        if num_codewords > code_array.len() {
            return Err(ReedMullerError::InvalidCodewordLength);
        }

        // Convert from byte array
        for (i, codeword_struct) in code_array.iter_mut().enumerate() {
            if i >= num_codewords {
                break;
            }
            let start_pos = i * 16;
            if start_pos + 15 < codeword.len() {
                codeword_struct
                    .u8
                    .copy_from_slice(&codeword[start_pos..(16 + start_pos)]);
            }
        }

        // Decode each byte as per reference implementation
        for i in 0..P::N1 {
            // Collect the codewords
            let mut expanded = [0i16; 128];
            let start_idx = i * multiplicity;
            let end_idx = start_idx + multiplicity;
            if end_idx <= num_codewords {
                self.expand_and_sum(&mut expanded, &code_array[start_idx..end_idx], multiplicity);
            } else {
                return Err(ReedMullerError::InvalidCodewordLength);
            }

            // Apply hadamard transform - exact match to reference
            let mut transform = [0i16; 128];
            self.hadamard_transform(&expanded, &mut transform);

            // Fix the first entry to get the half Hadamard transform
            transform[0] -= 64 * multiplicity as i16;

            // Finish the decoding - only write to message buffer if within bounds
            let decoded_byte = self.find_peaks(&transform) as u8;
            if i < message.len() {
                message[i] = decoded_byte;
            }
        }

        Ok(())
    }

    /// Encode a single byte using RM(1,7) as per reference implementation
    /// Takes i32 message to match reference signature exactly
    fn encode_byte(&self, message: i32, codeword: &mut RmCodeword) {
        // Initialize codeword to 0
        codeword.u8.fill(0);

        // Apply encoding as per reference implementation using BIT0MASK
        // The reference uses int32_t for first_word, so we need to be careful with the casting
        let mut first_word: i32 = self.bit0mask(message >> 7);

        // The reference uses lowercase hex literals, which are treated as unsigned in C
        // but then cast to int32_t. We need to match this behavior exactly.
        first_word ^= self.bit0mask(message) & 0xAAAAAAAA_u32 as i32;
        first_word ^= self.bit0mask(message >> 1) & 0xCCCCCCCC_u32 as i32;
        first_word ^= self.bit0mask(message >> 2) & 0xF0F0F0F0_u32 as i32;
        first_word ^= self.bit0mask(message >> 3) & 0xFF00FF00_u32 as i32;
        first_word ^= self.bit0mask(message >> 4) & 0xFFFF0000_u32 as i32;

        // Set word[0] - cast to u32 for storage
        let mut words = codeword.u32();
        words[0] = first_word as u32;

        first_word ^= self.bit0mask(message >> 5);
        words[1] = first_word as u32;
        first_word ^= self.bit0mask(message >> 6);
        words[3] = first_word as u32;
        first_word ^= self.bit0mask(message >> 5);
        words[2] = first_word as u32;

        codeword.set_u32(words);
    }

    /// Broadcast the least significant bit of x to a 32-bit mask (BIT0MASK from reference)
    /// Returns -1 if bit 0 is set, 0 otherwise (as int32_t)
    fn bit0mask(&self, x: i32) -> i32 {
        if (x & 1) == 1 { -1i32 } else { 0i32 }
    }

    /// Expand and sum duplicated codewords as per reference implementation
    fn expand_and_sum(&self, dest: &mut [i16; 128], src: &[RmCodeword], multiplicity: usize) {
        // Initialize destination to 0
        for item in dest.iter_mut() {
            *item = 0;
        }

        // Start with the first copy - exact match to reference
        if !src.is_empty() {
            let first_codeword = &src[0];
            for part in 0..4 {
                for bit in 0..32 {
                    dest[part * 32 + bit] = ((first_codeword.u32()[part] >> bit) & 1) as i16;
                }
            }
        }

        // Sum the rest of the copies - exact match to reference
        for copy in 1..multiplicity {
            if copy < src.len() {
                let copy_codeword = &src[copy];
                for part in 0..4 {
                    for bit in 0..32 {
                        dest[part * 32 + bit] += ((copy_codeword.u32()[part] >> bit) & 1) as i16;
                    }
                }
            }
        }
    }

    /// Apply Hadamard transform as per reference implementation
    /// This is the critical fix - the reference alternates between src and dst pointers
    fn hadamard_transform(&self, src: &[i16; 128], dest: &mut [i16; 128]) {
        // Copy source to destination initially
        dest.copy_from_slice(src);

        // Apply Hadamard transform using the reference algorithm
        // The passes move data: src -> dest -> src -> dest -> src -> dest -> src -> dest
        // We need to alternate between two buffers
        let p1 = dest;
        let mut p2 = [0i16; 128];

        for _pass in 0..7 {
            for (i, _) in (0..64).enumerate() {
                p2[i] = p1[2 * i] + p1[2 * i + 1];
                p2[i + 64] = p1[2 * i] - p1[2 * i + 1];
            }
            // Swap p1 and p2 for next round
            p1.copy_from_slice(&p2);
        }
    }

    /// Find peaks in the transformed codeword to decode the message as per reference
    fn find_peaks(&self, transform: &[i16; 128]) -> i32 {
        let mut peak_abs_value = 0i32;
        let mut peak_value = 0i32;
        let mut peak_pos = 0i32;

        // Find the peak with highest absolute value - exact match to reference
        for (i, &t) in transform.iter().enumerate() {
            let t = t as i32;
            let pos_mask = if t > 0 { -1i32 } else { 0i32 };
            let absolute = (pos_mask & t) | (!pos_mask & -t);

            peak_value = if absolute > peak_abs_value {
                t
            } else {
                peak_value
            };
            peak_pos = if absolute > peak_abs_value {
                i as i32
            } else {
                peak_pos
            };
            peak_abs_value = if absolute > peak_abs_value {
                absolute
            } else {
                peak_abs_value
            };
        }

        // Set bit 7 if peak is positive - exact match to reference
        peak_pos |= 128 * (peak_value > 0) as i32;

        peak_pos
    }
}

/// Reed-Muller error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReedMullerError {
    InvalidMessageLength,
    InvalidCodewordLength,
    DecodingFailed,
}

impl fmt::Display for ReedMullerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReedMullerError::InvalidMessageLength => write!(f, "Invalid message length"),
            ReedMullerError::InvalidCodewordLength => write!(f, "Invalid codeword length"),
            ReedMullerError::DecodingFailed => write!(f, "Reed-Muller decoding failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params_correct::Hqc1Params;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_reed_muller_creation() {
        let _rm = ReedMuller::<Hqc1Params>::new();
        // Should not panic
    }

    #[test]
    fn test_bit0mask() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test BIT0MASK function - should match C reference exactly
        assert_eq!(rm.bit0mask(0), 0);
        assert_eq!(rm.bit0mask(1), -1);
        assert_eq!(rm.bit0mask(2), 0);
        assert_eq!(rm.bit0mask(3), -1);
        assert_eq!(rm.bit0mask(255), -1);
    }

    #[test]
    fn test_encode_byte_single() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test encoding a single byte
        let mut codeword = RmCodeword::new();
        rm.encode_byte(0x01, &mut codeword);

        // The codeword should not be all zeros
        let words = codeword.u32();
        assert_ne!(words, [0u32; 4]);
    }

    #[test]
    fn test_hadamard_transform() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test Hadamard transform with simple input
        let mut src = [0i16; 128];
        src[0] = 1;
        src[1] = 1;

        let mut dest = [0i16; 128];
        rm.hadamard_transform(&src, &mut dest);

        // After Hadamard transform, dest should be different from src
        assert_ne!(dest, src);
    }

    #[test]
    fn test_find_peaks() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test find_peaks with simple input
        let mut transform = [0i16; 128];
        transform[0] = 10;
        transform[1] = -5;

        let peak = rm.find_peaks(&transform);
        // Peak at position 0 with positive value should return 0 | 128 = 128
        assert_eq!(peak, 128);

        // Test with negative peak
        let mut transform2 = [0i16; 128];
        transform2[1] = -10;
        transform2[0] = 5;

        let peak2 = rm.find_peaks(&transform2);
        // Peak at position 1 with negative value should return 1 | 0 = 1
        assert_eq!(peak2, 1);
    }

    #[test]
    fn test_debug_single_byte_encoding() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Debug: Let's see what happens when we encode 0x01
        let mut codeword = RmCodeword::new();
        rm.encode_byte(0x01, &mut codeword);

        let words = codeword.u32();
        // The codeword should not be all zeros
        assert_ne!(words, [0u32; 4]);

        // Now let's decode it step by step
        let mut expanded = [0i16; 128];
        rm.expand_and_sum(&mut expanded, &[codeword], 1);

        let mut transform = [0i16; 128];
        rm.hadamard_transform(&expanded, &mut transform);

        // Fix the first entry
        transform[0] -= 64;

        let peak = rm.find_peaks(&transform);

        // This should be 1, but we're getting 191
        // Let's check what we actually get
        assert_eq!(peak, 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_debug_two_bytes() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test encoding two bytes: [0x01, 0x02]
        let message = [0x01, 0x02];

        // For HQC-1: N1=46, N2=384, multiplicity=3
        // Total codeword size = N1 * multiplicity * 16 bytes = 46 * 3 * 16 = 2208 bytes
        let mut codeword = vec![0u8; 46 * 3 * 16];
        rm.encode(&message, &mut codeword).unwrap();

        let mut decoded_message = [0u8; 46];
        rm.decode(&codeword, &mut decoded_message).unwrap();

        // Both bytes should be decoded correctly
        assert_eq!(message[0], decoded_message[0]);
        assert_eq!(message[1], decoded_message[1]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_reed_muller_encode_decode_single_byte() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test with a simple single byte first
        let message = [0x01];
        let mut codeword = vec![0u8; 46 * 3 * 16]; // Correct size for HQC-1
        rm.encode(&message, &mut codeword).unwrap();

        let mut decoded_message = [0u8; 46]; // Must be N1 bytes for HQC-1
        rm.decode(&codeword, &mut decoded_message).unwrap();

        // This should now work correctly with proper integer handling
        assert_eq!(message[0], decoded_message[0]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_reed_muller_encode_decode_multiple_bytes() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test with N1 bytes (Reed-Solomon output size for HQC-1)
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E,
        ];

        // Encode - use correct buffer size
        let mut codeword = vec![0u8; 46 * 3 * 16]; // N1 * multiplicity * 16 bytes
        rm.encode(&message, &mut codeword).unwrap();

        // Decode
        let mut decoded_message = [0u8; 46]; // N1 for HQC-1
        rm.decode(&codeword, &mut decoded_message).unwrap();

        // Verify full N1 bytes roundtrip correctly
        for i in 0..46 {
            assert_eq!(
                message[i], decoded_message[i],
                "Mismatch at byte {i}: expected 0x{:02X}, got 0x{:02X}",
                message[i], decoded_message[i]
            );
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_reed_muller_error_correction() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test message (N1 bytes - Reed-Solomon output size for HQC-1)
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E,
        ];

        // Encode - use correct buffer size
        let mut codeword = vec![0u8; 46 * 3 * 16]; // N1 * multiplicity * 16 bytes
        rm.encode(&message, &mut codeword).unwrap();

        // Introduce a small error
        codeword[100] ^= 0x01; // Introduce error at position 100

        // Decode (should correct the error)
        let mut decoded_message = [0u8; 46];
        rm.decode(&codeword, &mut decoded_message).unwrap();

        // RM(1,7) corrects this single-bit error; the full 46-byte block must round-trip.
        assert_eq!(message, decoded_message);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_reed_muller_error_handling() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test invalid codeword length
        let message = [0x01];
        let mut codeword = [0u8; 10]; // Too small
        assert!(rm.encode(&message, &mut codeword).is_err());

        // Test invalid message length
        let mut decoded_message = [0u8; 10]; // Too small
        let codeword = vec![0u8; 46 * 3 * 16]; // Correct size
        assert!(rm.decode(&codeword, &mut decoded_message).is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_reed_muller_edge_cases() {
        let rm = ReedMuller::<Hqc1Params>::new();

        // Test with all zeros
        let message = [0x00];
        let mut codeword = vec![0u8; 46 * 3 * 16]; // Correct size
        rm.encode(&message, &mut codeword).unwrap();

        let mut decoded_message = [0u8; 46];
        rm.decode(&codeword, &mut decoded_message).unwrap();

        assert_eq!(message[0], decoded_message[0]);

        // Test with all ones
        let message = [0xFF];
        let mut codeword = vec![0u8; 46 * 3 * 16]; // Correct size
        rm.encode(&message, &mut codeword).unwrap();

        let mut decoded_message = [0u8; 46];
        rm.decode(&codeword, &mut decoded_message).unwrap();

        assert_eq!(message[0], decoded_message[0]);
    }
}
