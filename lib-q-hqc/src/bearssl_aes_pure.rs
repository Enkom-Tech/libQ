//! Pure Rust implementation of BearSSL AES-256-ECB
//!
//! This module provides a pure Rust AES-256-ECB implementation using the `aes` crate
//! as a replacement for the BearSSL C implementation, maintaining the same interface.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{
    BlockEncrypt,
    KeyInit,
};

/// AES-256 context for pure Rust implementation
#[derive(Clone)]
pub struct Aes256CtxPure {
    cipher: Aes256,
}

impl Aes256CtxPure {
    /// Create a new AES-256 context with the given key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        Self { cipher }
    }

    /// Encrypt a single 16-byte block using AES-256-ECB
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut block = GenericArray::clone_from_slice(input);
        self.cipher.encrypt_block(&mut block);
        block.into()
    }

    /// Encrypt multiple blocks using AES-256-ECB
    pub fn encrypt_blocks(&self, output: &mut [u8], input: &[u8], nblocks: usize) {
        for i in 0..nblocks {
            let start = i * 16;
            let end = start + 16;
            let input_block = &input[start..end];
            let output_block = &mut output[start..end];

            let mut block = GenericArray::clone_from_slice(input_block);
            self.cipher.encrypt_block(&mut block);
            output_block.copy_from_slice(&block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_encrypt_block() {
        // Test vector from NIST SP 800-38A
        let key = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D,
            0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3,
            0x09, 0x14, 0xDF, 0xF4,
        ];
        let plaintext = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let expected = [
            0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1,
            0x81, 0xF8,
        ];

        let ctx = Aes256CtxPure::new(&key);
        let result = ctx.encrypt_block(&plaintext);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_aes256_encrypt_blocks() {
        let key = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D,
            0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3,
            0x09, 0x14, 0xDF, 0xF4,
        ];
        let plaintext = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let expected = [
            0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1,
            0x81, 0xF8,
        ];

        let ctx = Aes256CtxPure::new(&key);
        let mut output = [0u8; 16];
        ctx.encrypt_blocks(&mut output, &plaintext, 1);
        assert_eq!(output, expected);
    }
}
