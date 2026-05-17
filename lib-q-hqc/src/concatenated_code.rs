//! Concatenated Code Implementation
//!
//! This module implements the concatenated code used in HQC, which combines
//! Reed-Solomon and Reed-Muller codes as specified in the HQC reference.

use core::fmt;

use crate::params_correct::HqcParams;
use crate::reed_muller::{
    ReedMuller,
    ReedMullerError,
};
use crate::reed_solomon::{
    ReedSolomon,
    ReedSolomonError,
};

/// Concatenated code implementation
pub struct ConcatenatedCode<P: HqcParams> {
    reed_solomon: ReedSolomon<P>,
    reed_muller: ReedMuller<P>,
}

impl<P: HqcParams> ConcatenatedCode<P> {
    /// Create a new concatenated code instance
    pub fn new() -> Result<Self, ConcatenatedCodeError> {
        let reed_solomon = ReedSolomon::new().map_err(ConcatenatedCodeError::ReedSolomonError)?;
        let reed_muller = ReedMuller::new();

        Ok(Self {
            reed_solomon,
            reed_muller,
        })
    }

    /// Encode a message using the concatenated code
    ///
    /// The encoding process:
    /// 1. First encode the message using Reed-Solomon code
    /// 2. Then encode the Reed-Solomon codeword using Reed-Muller code
    pub fn encode(&self, message: &[u8], codeword: &mut [u8]) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let n1 = P::N1;
        let _n2 = P::N2;
        let n1n2 = P::N1N2;

        if message.len() < k {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }
        if codeword.len() < n1n2.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }

        // Step 1: Reed-Solomon encoding
        let mut rs_codeword = [0u8; 128]; // Max N1 for HQC variants (HQC-5: N1=90)
        self.reed_solomon
            .encode(&message[..k], &mut rs_codeword[..n1])
            .map_err(ConcatenatedCodeError::ReedSolomonError)?;

        // Step 2: Reed-Muller encoding
        self.reed_muller
            .encode(&rs_codeword[..n1], codeword)
            .map_err(ConcatenatedCodeError::ReedMullerError)?;

        Ok(())
    }

    /// Encode a message using the concatenated code (u64 array version)
    ///
    /// This version works directly with u64 arrays to avoid conversion errors
    pub fn encode_u64(
        &self,
        message: &[u64],
        codeword: &mut [u64],
    ) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let _n1 = P::N1;
        let _n2 = P::N2;
        let n1n2 = P::N1N2;

        if message.len() < k.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }
        if codeword.len() < n1n2.div_ceil(64) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }

        // Convert message from u64 array to bytes
        let mut message_bytes = alloc::vec![0u8; k];
        for (i, &word) in message.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= message_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < message_bytes.len() {
                        message_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Convert codeword from u64 array to bytes
        let mut codeword_bytes = alloc::vec![0u8; n1n2 / 8];
        for (i, &word) in codeword.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= codeword_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < codeword_bytes.len() {
                        codeword_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Encode using the byte version
        self.encode(&message_bytes, &mut codeword_bytes)?;

        // Convert result back to u64 array
        for (i, word) in codeword.iter_mut().enumerate() {
            let start = i * 8;
            if start + 8 <= codeword_bytes.len() {
                let mut bytes = [0u8; 8];
                for (j, &byte) in codeword_bytes[start..start + 8].iter().enumerate() {
                    bytes[j] = byte;
                }
                *word = u64::from_le_bytes(bytes);
            }
        }

        Ok(())
    }

    /// Decode a codeword using the concatenated code
    ///
    /// The decoding process:
    /// 1. First decode the codeword using Reed-Muller code
    /// 2. Then decode the Reed-Muller result using Reed-Solomon code
    pub fn decode(&self, codeword: &[u8], message: &mut [u8]) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let n1 = P::N1;
        let _n2 = P::N2;
        let n1n2 = P::N1N2;

        if codeword.len() < n1n2.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }
        if message.len() < k {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }

        // Step 1: Reed-Muller decoding
        let mut rm_result = [0u8; 128]; // Max N1 for HQC variants (HQC-5: N1=90)
        self.reed_muller
            .decode(codeword, &mut rm_result[..n1])
            .map_err(ConcatenatedCodeError::ReedMullerError)?;

        // Step 2: Reed-Solomon decoding
        self.reed_solomon
            .decode(&rm_result[..n1], &mut message[..k])
            .map_err(ConcatenatedCodeError::ReedSolomonError)?;

        Ok(())
    }

    /// Get the Reed-Solomon code instance
    pub fn reed_solomon(&self) -> &ReedSolomon<P> {
        &self.reed_solomon
    }

    /// Get the Reed-Muller code instance
    pub fn reed_muller(&self) -> &ReedMuller<P> {
        &self.reed_muller
    }

    /// Decode a codeword using the concatenated code (u64 array version)
    ///
    /// This version works directly with u64 arrays to avoid conversion errors
    pub fn decode_u64(
        &self,
        codeword: &[u64],
        message: &mut [u64],
    ) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let _n1 = P::N1;
        let _n2 = P::N2;
        let n1n2 = P::N1N2;

        if codeword.len() < n1n2.div_ceil(64) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }
        if message.len() < k.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }

        // Convert codeword from u64 array to bytes
        let mut codeword_bytes = alloc::vec![0u8; n1n2 / 8];
        for (i, &word) in codeword.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= codeword_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < codeword_bytes.len() {
                        codeword_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Convert message from u64 array to bytes
        let mut message_bytes = alloc::vec![0u8; k];
        for (i, &word) in message.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= message_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < message_bytes.len() {
                        message_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Decode using the byte version
        self.decode(&codeword_bytes, &mut message_bytes)?;

        // Convert result back to u64 array
        for (i, word) in message.iter_mut().enumerate() {
            let start = i * 8;
            if start + 8 <= message_bytes.len() {
                let mut bytes = [0u8; 8];
                for (j, &byte) in message_bytes[start..start + 8].iter().enumerate() {
                    bytes[j] = byte;
                }
                *word = u64::from_le_bytes(bytes);
            }
        }

        Ok(())
    }

    /// Encode a message using the concatenated code (direct u64 array version)
    ///
    /// This matches the reference implementation's code_encode function exactly
    pub fn code_encode(&self, em: &mut [u64], m: &[u64]) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let n1 = P::N1;
        let n1n2 = P::N1N2;

        if m.len() < k.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }
        if em.len() < n1n2.div_ceil(64) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }

        // Convert message from u64 array to bytes
        let mut message_bytes = alloc::vec![0u8; k];
        for (i, &word) in m.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= message_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < message_bytes.len() {
                        message_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Encode using Reed-Solomon first
        let mut rs_codeword = alloc::vec![0u8; n1];
        self.reed_solomon.encode(&message_bytes, &mut rs_codeword)?;

        // Then encode using Reed-Muller
        let mut rm_codeword = alloc::vec![0u8; n1n2 / 8];
        self.reed_muller.encode(&rs_codeword, &mut rm_codeword)?;

        // Convert result to u64 array
        for (i, word) in em.iter_mut().enumerate() {
            let start = i * 8;
            if start + 8 <= rm_codeword.len() {
                let mut bytes = [0u8; 8];
                for (j, &byte) in rm_codeword[start..start + 8].iter().enumerate() {
                    bytes[j] = byte;
                }
                *word = u64::from_le_bytes(bytes);
            }
        }

        Ok(())
    }

    /// Decode a codeword using the concatenated code (direct u64 array version)
    ///
    /// This matches the reference implementation's code_decode function exactly
    pub fn code_decode(&self, m: &mut [u64], em: &[u64]) -> Result<(), ConcatenatedCodeError> {
        let k = P::K;
        let n1 = P::N1;
        let n1n2 = P::N1N2;

        if em.len() < n1n2.div_ceil(64) {
            return Err(ConcatenatedCodeError::InvalidCodewordLength);
        }
        if m.len() < k.div_ceil(8) {
            return Err(ConcatenatedCodeError::InvalidMessageLength);
        }

        // Convert codeword from u64 array to bytes
        let mut codeword_bytes = alloc::vec![0u8; n1n2 / 8];
        for (i, &word) in em.iter().enumerate() {
            let start = i * 8;
            if start + 8 <= codeword_bytes.len() {
                let bytes = word.to_le_bytes();
                for (j, &byte) in bytes.iter().enumerate() {
                    if start + j < codeword_bytes.len() {
                        codeword_bytes[start + j] = byte;
                    }
                }
            }
        }

        // Decode using Reed-Muller first
        let mut rm_result = alloc::vec![0u8; n1];
        self.reed_muller.decode(&codeword_bytes, &mut rm_result)?;

        // Then decode using Reed-Solomon
        let mut message_bytes = alloc::vec![0u8; k];
        self.reed_solomon.decode(&rm_result, &mut message_bytes)?;

        // Convert result to u64 array
        for (i, word) in m.iter_mut().enumerate() {
            let start = i * 8;
            if start + 8 <= message_bytes.len() {
                let mut bytes = [0u8; 8];
                for (j, &byte) in message_bytes[start..start + 8].iter().enumerate() {
                    bytes[j] = byte;
                }
                *word = u64::from_le_bytes(bytes);
            }
        }

        Ok(())
    }
}

/// Concatenated code error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcatenatedCodeError {
    ReedSolomonError(ReedSolomonError),
    ReedMullerError(ReedMullerError),
    InvalidMessageLength,
    InvalidCodewordLength,
    DecodingFailed,
}

impl fmt::Display for ConcatenatedCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConcatenatedCodeError::ReedSolomonError(e) => write!(f, "Reed-Solomon error: {}", e),
            ConcatenatedCodeError::ReedMullerError(e) => write!(f, "Reed-Muller error: {}", e),
            ConcatenatedCodeError::InvalidMessageLength => write!(f, "Invalid message length"),
            ConcatenatedCodeError::InvalidCodewordLength => write!(f, "Invalid codeword length"),
            ConcatenatedCodeError::DecodingFailed => write!(f, "Concatenated code decoding failed"),
        }
    }
}

impl From<ReedSolomonError> for ConcatenatedCodeError {
    fn from(error: ReedSolomonError) -> Self {
        ConcatenatedCodeError::ReedSolomonError(error)
    }
}

impl From<ReedMullerError> for ConcatenatedCodeError {
    fn from(error: ReedMullerError) -> Self {
        ConcatenatedCodeError::ReedMullerError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params_correct::Hqc1Params;

    #[test]
    fn test_concatenated_code_creation() {
        let code = ConcatenatedCode::<Hqc1Params>::new();
        assert!(code.is_ok());
    }

    #[test]
    fn test_concatenated_code_encode_decode() {
        let code = ConcatenatedCode::<Hqc1Params>::new().unwrap();

        // Test message (K bytes for HQC-1)
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 3680]; // N1N2/8 for HQC-1 (29440/8 = 3680)
        code.encode(&message, &mut codeword).unwrap();

        // Decode
        let mut decoded_message = [0u8; 16]; // K for HQC-1
        code.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }

    #[test]
    fn test_concatenated_code_error_correction() {
        let code = ConcatenatedCode::<Hqc1Params>::new().unwrap();

        // Test message
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Encode
        let mut codeword = [0u8; 3680]; // N1N2/8 for HQC-1 (29440/8 = 3680)
        code.encode(&message, &mut codeword).unwrap();

        // Introduce a small error
        codeword[100] ^= 0x01;

        // Decode (should correct the error)
        let mut decoded_message = [0u8; 16];
        code.decode(&codeword, &mut decoded_message).unwrap();

        // Verify
        assert_eq!(message, decoded_message);
    }

    #[test]
    fn test_concatenated_code_parameters() {
        let code = ConcatenatedCode::<Hqc1Params>::new().unwrap();

        // Test that we can access the underlying codes
        let _rs = code.reed_solomon();
        let _rm = code.reed_muller();

        // This test just ensures the methods work
        // Test passes - no assertion needed
    }

    #[test]
    fn test_concatenated_code_error_handling() {
        let code = ConcatenatedCode::<Hqc1Params>::new().unwrap();

        // Test invalid message length
        let short_message = [0x01, 0x02]; // Too short
        let mut codeword = [0u8; 2208];
        let result = code.encode(&short_message, &mut codeword);
        assert!(result.is_err());

        // Test invalid codeword length
        let message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let mut short_codeword = [0u8; 100]; // Too short
        let result = code.encode(&message, &mut short_codeword);
        assert!(result.is_err());
    }
}
