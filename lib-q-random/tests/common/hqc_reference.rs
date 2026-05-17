//! HQC Reference Implementation for Testing
//!
//! **TEST INFRASTRUCTURE ONLY - NOT FOR PRODUCTION USE**
//!
//! This module contains simplified reference implementations of HQC cryptographic
//! primitives. These are used **exclusively** for:
//!
//! - Testing `lib-q-random` RNG integration with HQC-style operations
//! - Demonstrating the RNG API usage patterns
//! - Providing consistent test vectors for validation
//!
//! ## ⚠️ Critical Warning
//!
//! **DO NOT USE THESE IMPLEMENTATIONS FOR ANY CRYPTOGRAPHIC PURPOSE**
//!
//! These implementations are intentionally simplified and lack:
//! - Proper BCH codes (uses simple repetition)
//! - Full error correction capabilities
//! - Validated security parameters
//! - Side-channel attack protections
//! - Security auditing
//!
//! ## For Production HQC
//!
//! Use one of these instead:
//! - NIST PQC HQC reference implementation
//! - PQClean HQC implementation
//! - Other audited and verified HQC libraries
//!
//! ## Purpose in lib-q-random
//!
//! This module exists to verify that `lib-q-random` can correctly supply
//! random numbers to polynomial operations and cryptographic primitives.
//! It is NOT a complete or secure HQC implementation.

use rand_core::Rng;

/// Result type for HQC reference operations
pub type Result<T> = core::result::Result<T, HqcError>;

/// Errors for HQC reference implementation
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum HqcError {
    /// Invalid buffer size
    InvalidBufferSize,
    /// Operation failed
    OperationFailed,
}

impl core::fmt::Display for HqcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBufferSize => write!(f, "Invalid buffer size"),
            Self::OperationFailed => write!(f, "Operation failed"),
        }
    }
}

/// HQC polynomial operations in GF(2)
pub mod polynomial {
    use super::{
        Result,
        Rng,
    };

    /// Multiply two polynomials in GF(2)
    ///
    /// **TEST HELPER ONLY** - Reference implementation for testing
    pub fn polynomial_multiply(result: &mut [u8], a: &[u8], b: &[u8]) -> Result<()> {
        if result.is_empty() || a.is_empty() || b.is_empty() {
            return Ok(());
        }

        result.fill(0);

        for (i, &a_coeff) in a.iter().enumerate() {
            for (j, &b_coeff) in b.iter().enumerate() {
                let result_idx = i + j;
                if result_idx < result.len() {
                    let product = a_coeff & b_coeff;
                    result[result_idx] ^= product;
                }
            }
        }

        Ok(())
    }

    /// Generate a random polynomial with specified weight
    ///
    /// **TEST HELPER ONLY** - Reference implementation for testing
    pub fn polynomial_random_weight<R: Rng + ?Sized>(
        result: &mut [u8],
        weight: usize,
        rng: &mut R,
    ) -> Result<()> {
        const MAX_ATTEMPTS: usize = 1000;

        if result.is_empty() {
            return Ok(());
        }

        result.fill(0);

        let total_bits = result.len() * 8;
        let actual_weight = weight.min(total_bits);

        if actual_weight == 0 {
            return Ok(());
        }

        #[cfg(feature = "alloc")]
        {
            extern crate alloc;
            use alloc::vec::Vec;

            let mut positions = Vec::with_capacity(actual_weight);
            let mut attempts = 0;

            while positions.len() < actual_weight && attempts < MAX_ATTEMPTS {
                let mut pos_bytes = [0u8; 4];
                rng.fill_bytes(&mut pos_bytes);
                let pos = u32::from_le_bytes(pos_bytes) as usize % total_bits;

                if !positions.contains(&pos) {
                    positions.push(pos);
                }
                attempts += 1;
            }

            for &pos in &positions {
                let byte_idx = pos / 8;
                let bit_idx = pos % 8;
                if byte_idx < result.len() {
                    result[byte_idx] |= 1 << bit_idx;
                }
            }
        }

        Ok(())
    }
}

/// HQC matrix operations
pub mod matrix {
    use super::Result;

    /// Multiply a matrix by a vector
    ///
    /// **TEST HELPER ONLY** - Reference implementation for testing
    pub fn matrix_vector_multiply(
        result: &mut [u8],
        matrix: &[Vec<u8>],
        vector: &[u8],
    ) -> Result<()> {
        if result.is_empty() || matrix.is_empty() || vector.is_empty() {
            return Ok(());
        }

        result.fill(0);

        for (i, row) in matrix.iter().enumerate() {
            if i >= result.len() {
                break;
            }

            let mut sum = 0u8;
            for (j, &row_val) in row.iter().enumerate() {
                if j < vector.len() {
                    sum ^= row_val & vector[j];
                }
            }
            result[i] = sum;
        }

        Ok(())
    }
}

/// HQC tensor code operations (simplified for testing)
pub mod codec {
    use super::Result;

    /// Encode a message using simplified tensor code
    ///
    /// **TEST HELPER ONLY** - Uses simple repetition, not proper BCH codes
    pub fn tensor_code_encode(codeword: &mut [u8], message: &[u8]) -> Result<()> {
        if codeword.is_empty() {
            return Ok(());
        }

        codeword.fill(0);
        let message_len = message.len().min(codeword.len());
        codeword[..message_len].copy_from_slice(&message[..message_len]);

        let mut pos = message_len;
        while pos < codeword.len() {
            let copy_len = (codeword.len() - pos).min(message_len);
            if copy_len > 0 {
                codeword[pos..pos + copy_len].copy_from_slice(&message[..copy_len]);
                pos += copy_len;
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Decode a codeword using simplified tensor code
    ///
    /// **TEST HELPER ONLY** - Simplified decoding for testing
    pub fn tensor_code_decode(message: &mut [u8], codeword: &[u8]) -> Result<()> {
        if message.is_empty() || codeword.is_empty() {
            return Ok(());
        }

        message.fill(0);
        let message_len = message.len().min(codeword.len());
        message[..message_len].copy_from_slice(&codeword[..message_len]);

        Ok(())
    }
}

/// HQC key generation operations (simplified for testing)
pub mod keygen {
    use super::{
        Result,
        Rng,
    };

    /// Generate HQC key pair using RNG
    ///
    /// **TEST HELPER ONLY** - Simplified key generation for testing RNG integration
    pub fn hqc_keygen<R: Rng + ?Sized>(
        public_key: &mut [u8],
        secret_key: &mut [u8],
        rng: &mut R,
    ) -> Result<()> {
        if public_key.is_empty() || secret_key.is_empty() {
            return Ok(());
        }

        rng.fill_bytes(public_key);
        rng.fill_bytes(secret_key);

        if public_key.iter().all(|&x| x == 0) {
            public_key[0] = 1;
        }
        if secret_key.iter().all(|&x| x == 0) {
            secret_key[0] = 1;
        }

        Ok(())
    }
}

/// HQC encryption operations (simplified for testing)
pub mod encrypt {
    use super::{
        Result,
        Rng,
    };

    /// Encrypt a message (simplified for testing)
    ///
    /// **TEST HELPER ONLY** - Not secure HQC encryption
    pub fn hqc_encrypt<R: Rng + ?Sized>(
        ciphertext: &mut [u8],
        message: &[u8],
        public_key: &[u8],
        rng: &mut R,
    ) -> Result<()> {
        if ciphertext.is_empty() {
            return Ok(());
        }

        rng.fill_bytes(ciphertext);

        for (i, &msg_byte) in message.iter().enumerate() {
            if i < ciphertext.len() {
                ciphertext[i] ^= msg_byte;
            }
        }

        for (i, &pk_byte) in public_key.iter().enumerate() {
            if i < ciphertext.len() {
                ciphertext[i] ^= pk_byte;
            }
        }

        Ok(())
    }
}

/// HQC decryption operations (simplified for testing)
pub mod decrypt {
    use super::Result;

    /// Decrypt a ciphertext (simplified for testing)
    ///
    /// **TEST HELPER ONLY** - Not secure HQC decryption
    pub fn hqc_decrypt(message: &mut [u8], ciphertext: &[u8], secret_key: &[u8]) -> Result<()> {
        if message.is_empty() || ciphertext.is_empty() || secret_key.is_empty() {
            return Ok(());
        }

        message.fill(0);

        for (i, &ct_byte) in ciphertext.iter().enumerate() {
            if i < message.len() {
                message[i] = ct_byte;
            }
        }

        for (i, &sk_byte) in secret_key.iter().enumerate() {
            if i < message.len() {
                message[i] ^= sk_byte;
            }
        }

        Ok(())
    }
}

// Re-export for convenience in tests
pub use codec::{
    tensor_code_decode,
    tensor_code_encode,
};
pub use decrypt::hqc_decrypt;
pub use encrypt::hqc_encrypt;
pub use keygen::hqc_keygen;
pub use matrix::matrix_vector_multiply;
pub use polynomial::{
    polynomial_multiply,
    polynomial_random_weight,
};
