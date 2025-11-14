//! lib-Q FN-DSA - Post-Quantum Digital Signatures
//!
//! This crate provides a libQ-compatible wrapper around the FN-DSA (FIPS 206)
//! post-quantum digital signature algorithm, which is based on FALCON with
//! enhanced performance and compact signature sizes.

// Suppress clippy warnings in reference implementation code
// These are external implementations that shouldn't be modified
#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::uninlined_format_args,
    clippy::must_use_candidate,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::manual_clamp,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::let_and_return,
    clippy::identity_op,
    clippy::erasing_op,
    clippy::struct_excessive_bools,
    clippy::doc_markdown
)]
//!
//! # Features
//!
//! - **NIST-Approved**: Implements the upcoming FN-DSA standard (FIPS 206)
//! - **High Performance**: Optimized for both x86_64 and ARM64 architectures
//! - **Compact Signatures**: Smaller signature sizes compared to other post-quantum schemes
//! - **Security Levels**: Supports Level 1 (128-bit) and Level 5 (256-bit) security
//! - **Memory Safe**: Zero unsafe code, automatic memory zeroization
//! - **Constant-Time**: Operations designed to prevent timing attacks
//!
//! # Security Levels
//!
//! FN-DSA provides two main security levels:
//!
//! - **Level 1 (128-bit security)**: n=512, suitable for most applications
//! - **Level 5 (256-bit security)**: n=1024, for high-security applications
//!
//! # Example Usage
//!
//! ```rust
//! use lib_q_core::{
//!     SigKeypair,
//!     SigPublicKey,
//!     SigSecretKey,
//!     Signature,
//! };
//! use lib_q_fn_dsa::{
//!     FnDsa,
//!     FnDsa512,
//!     FnDsa1024,
//! };
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an FN-DSA instance
//!     let fn_dsa = FnDsa512::new();
//!
//!     // Generate a keypair
//!     let keypair = fn_dsa.generate_keypair()?;
//!
//!     // Sign a message
//!     let message = b"Hello, FN-DSA!";
//!     let signature = fn_dsa.sign(&keypair.secret_key, message)?;
//!
//!     // Verify the signature
//!     let is_valid =
//!         fn_dsa.verify(&keypair.public_key, message, &signature)?;
//!     assert!(is_valid);
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

extern crate alloc;

// Re-export core types for public use
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::marker::PhantomData;

// Re-export FN-DSA types and constants
pub use fn_dsa::{
    DOMAIN_NONE,
    FN_DSA_LOGN_512,
    FN_DSA_LOGN_1024,
    HASH_ID_RAW,
    KeyPairGenerator,
    KeyPairGeneratorStandard,
    SigningKey,
    SigningKeyStandard,
    VerifyingKey,
    VerifyingKeyStandard,
    sign_key_size,
    signature_size,
    vrfy_key_size,
};
pub use lib_q_core::{
    Error,
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
// Import RNG traits and implementations
use rand_core::CryptoRng;

/// Get an appropriate RNG for the current environment
fn get_rng() -> impl CryptoRng {
    lib_q_random::FnDsaRng::new()
}

/// FN-DSA security level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FnDsaSecurityLevel {
    /// Level 1: 128-bit security (n=512)
    Level1,
    /// Level 5: 256-bit security (n=1024)
    Level5,
}

impl FnDsaSecurityLevel {
    /// Get the logn value for this security level
    pub fn logn(&self) -> u32 {
        match self {
            FnDsaSecurityLevel::Level1 => FN_DSA_LOGN_512,
            FnDsaSecurityLevel::Level5 => FN_DSA_LOGN_1024,
        }
    }

    /// Get the key sizes for this security level
    pub fn key_sizes(&self) -> (usize, usize, usize) {
        let logn = self.logn();
        (
            sign_key_size(logn),
            vrfy_key_size(logn),
            signature_size(logn),
        )
    }
}

/// Base FN-DSA implementation trait
pub trait FnDsaImpl {
    /// Get the security level
    fn security_level(&self) -> FnDsaSecurityLevel;

    /// Get the logn value
    fn logn(&self) -> u32;
}

/// FN-DSA Level 1 (128-bit security) implementation
pub struct FnDsa512 {
    _phantom: PhantomData<()>,
}

impl FnDsa512 {
    /// Create a new FN-DSA Level 1 instance
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl FnDsaImpl for FnDsa512 {
    fn security_level(&self) -> FnDsaSecurityLevel {
        FnDsaSecurityLevel::Level1
    }

    fn logn(&self) -> u32 {
        FN_DSA_LOGN_512
    }
}

impl Signature for FnDsa512 {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        // Generate keypair using the underlying FN-DSA implementation
        let mut kg = KeyPairGeneratorStandard::default();
        let mut sign_key = {
            let v = vec![0; sign_key_size(self.logn())];
            v
        };
        let mut vrfy_key = {
            let v = vec![0; vrfy_key_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        kg.keygen(self.logn(), &mut rng, &mut sign_key, &mut vrfy_key);

        Ok(SigKeypair::new(vrfy_key, sign_key))
    }

    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        // Decode the signing key
        let mut sk = SigningKeyStandard::decode(secret_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: sign_key_size(self.logn()),
                actual: secret_key.as_bytes().len(),
            }
        })?;

        // Create signature buffer
        let mut signature = {
            let v = vec![0; signature_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        // Sign the message
        sk.sign(
            &mut rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message,
            &mut signature,
        );

        Ok(signature)
    }

    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Validate signature size first
        let expected_sig_size = signature_size(self.logn());
        if signature.len() != expected_sig_size {
            return Err(Error::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: signature.len(),
            });
        }

        // Decode the verifying key
        let vk = VerifyingKeyStandard::decode(public_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: vrfy_key_size(self.logn()),
                actual: public_key.as_bytes().len(),
            }
        })?;

        // Verify the signature
        let is_valid = vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message);

        Ok(is_valid)
    }
}

impl Default for FnDsa512 {
    fn default() -> Self {
        Self::new()
    }
}

/// FN-DSA Level 5 (256-bit security) implementation
pub struct FnDsa1024 {
    _phantom: PhantomData<()>,
}

impl FnDsa1024 {
    /// Create a new FN-DSA Level 5 instance
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl FnDsaImpl for FnDsa1024 {
    fn security_level(&self) -> FnDsaSecurityLevel {
        FnDsaSecurityLevel::Level5
    }

    fn logn(&self) -> u32 {
        FN_DSA_LOGN_1024
    }
}

impl Signature for FnDsa1024 {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        // Generate keypair using the underlying FN-DSA implementation
        let mut kg = KeyPairGeneratorStandard::default();
        let mut sign_key = {
            let v = vec![0; sign_key_size(self.logn())];
            v
        };
        let mut vrfy_key = {
            let v = vec![0; vrfy_key_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        kg.keygen(self.logn(), &mut rng, &mut sign_key, &mut vrfy_key);

        Ok(SigKeypair::new(vrfy_key, sign_key))
    }

    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        // Decode the signing key
        let mut sk = SigningKeyStandard::decode(secret_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: sign_key_size(self.logn()),
                actual: secret_key.as_bytes().len(),
            }
        })?;

        // Create signature buffer
        let mut signature = {
            let v = vec![0; signature_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        // Sign the message
        sk.sign(
            &mut rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message,
            &mut signature,
        );

        Ok(signature)
    }

    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Validate signature size first
        let expected_sig_size = signature_size(self.logn());
        if signature.len() != expected_sig_size {
            return Err(Error::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: signature.len(),
            });
        }

        // Decode the verifying key
        let vk = VerifyingKeyStandard::decode(public_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: vrfy_key_size(self.logn()),
                actual: public_key.as_bytes().len(),
            }
        })?;

        // Verify the signature
        let is_valid = vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message);

        Ok(is_valid)
    }
}

impl Default for FnDsa1024 {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic FN-DSA implementation that can work with any security level
pub struct FnDsa {
    security_level: FnDsaSecurityLevel,
}

impl FnDsa {
    /// Create a new FN-DSA instance with the specified security level
    pub fn new(security_level: FnDsaSecurityLevel) -> Self {
        Self { security_level }
    }

    /// Create a new FN-DSA Level 1 instance
    pub fn level1() -> Self {
        Self::new(FnDsaSecurityLevel::Level1)
    }

    /// Create a new FN-DSA Level 5 instance
    pub fn level5() -> Self {
        Self::new(FnDsaSecurityLevel::Level5)
    }

    /// Get the security level
    pub fn security_level(&self) -> FnDsaSecurityLevel {
        self.security_level
    }

    /// Get the logn value
    pub fn logn(&self) -> u32 {
        self.security_level.logn()
    }
}

impl Signature for FnDsa {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        // Generate keypair using the underlying FN-DSA implementation
        let mut kg = KeyPairGeneratorStandard::default();
        let mut sign_key = {
            let v = vec![0; sign_key_size(self.logn())];
            v
        };
        let mut vrfy_key = {
            let v = vec![0; vrfy_key_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        kg.keygen(self.logn(), &mut rng, &mut sign_key, &mut vrfy_key);

        Ok(SigKeypair::new(vrfy_key, sign_key))
    }

    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        // Decode the signing key
        let mut sk = SigningKeyStandard::decode(secret_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: sign_key_size(self.logn()),
                actual: secret_key.as_bytes().len(),
            }
        })?;

        // Create signature buffer
        let mut signature = {
            let v = vec![0; signature_size(self.logn())];
            v
        };

        // Use a secure random number generator
        let mut rng = get_rng();

        // Sign the message
        sk.sign(
            &mut rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message,
            &mut signature,
        );

        Ok(signature)
    }

    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Validate signature size first
        let expected_sig_size = signature_size(self.logn());
        if signature.len() != expected_sig_size {
            return Err(Error::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: signature.len(),
            });
        }

        // Decode the verifying key
        let vk = VerifyingKeyStandard::decode(public_key.as_bytes()).ok_or_else(|| {
            Error::InvalidKeySize {
                expected: vrfy_key_size(self.logn()),
                actual: public_key.as_bytes().len(),
            }
        })?;

        // Verify the signature
        let is_valid = vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message);

        Ok(is_valid)
    }
}

impl Default for FnDsa {
    fn default() -> Self {
        Self::level1()
    }
}

/// Utility functions for FN-DSA
pub mod utils {
    use super::*;

    /// Get the key sizes for a given security level
    pub fn get_key_sizes(security_level: FnDsaSecurityLevel) -> (usize, usize, usize) {
        security_level.key_sizes()
    }

    /// Validate key sizes for a given security level
    pub fn validate_key_sizes(
        security_level: FnDsaSecurityLevel,
        sign_key_size: usize,
        vrfy_key_size: usize,
        signature_size: usize,
    ) -> Result<()> {
        let (expected_sign, expected_vrfy, expected_sig) = security_level.key_sizes();

        if sign_key_size != expected_sign {
            return Err(Error::InvalidKeySize {
                expected: expected_sign,
                actual: sign_key_size,
            });
        }

        if vrfy_key_size != expected_vrfy {
            return Err(Error::InvalidKeySize {
                expected: expected_vrfy,
                actual: vrfy_key_size,
            });
        }

        if signature_size != expected_sig {
            return Err(Error::InvalidKeySize {
                expected: expected_sig,
                actual: signature_size,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn_dsa512_creation() {
        let fn_dsa = FnDsa512::new();
        assert_eq!(fn_dsa.security_level(), FnDsaSecurityLevel::Level1);
        assert_eq!(fn_dsa.logn(), FN_DSA_LOGN_512);
    }

    #[test]
    fn test_fn_dsa1024_creation() {
        let fn_dsa = FnDsa1024::new();
        assert_eq!(fn_dsa.security_level(), FnDsaSecurityLevel::Level5);
        assert_eq!(fn_dsa.logn(), FN_DSA_LOGN_1024);
    }

    #[test]
    fn test_fn_dsa_generic_creation() {
        let fn_dsa1 = FnDsa::level1();
        assert_eq!(fn_dsa1.security_level(), FnDsaSecurityLevel::Level1);

        let fn_dsa5 = FnDsa::level5();
        assert_eq!(fn_dsa5.security_level(), FnDsaSecurityLevel::Level5);
    }

    #[test]
    fn test_key_sizes() {
        let (sign_size_512, vrfy_size_512, sig_size_512) = FnDsaSecurityLevel::Level1.key_sizes();
        let (sign_size_1024, vrfy_size_1024, sig_size_1024) =
            FnDsaSecurityLevel::Level5.key_sizes();

        // Verify that 1024-bit keys are larger than 512-bit keys
        assert!(sign_size_1024 > sign_size_512);
        assert!(vrfy_size_1024 > vrfy_size_512);
        assert!(sig_size_1024 > sig_size_512);

        // Verify expected sizes (from FN-DSA specification)
        assert_eq!(sign_size_512, 1281);
        assert_eq!(vrfy_size_512, 897);
        assert_eq!(sig_size_512, 666);

        assert_eq!(sign_size_1024, 2305);
        assert_eq!(vrfy_size_1024, 1793);
        assert_eq!(sig_size_1024, 1280);
    }

    #[test]
    fn test_utils_validation() {
        // Test valid key sizes
        let result = utils::validate_key_sizes(FnDsaSecurityLevel::Level1, 1281, 897, 666);
        assert!(result.is_ok());

        // Test invalid key sizes
        let result = utils::validate_key_sizes(
            FnDsaSecurityLevel::Level1,
            1280,
            897,
            666, // Wrong sign key size
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_generation() {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa
            .generate_keypair()
            .expect("Keypair generation should succeed");

        // Verify key sizes
        assert_eq!(
            keypair.public_key().as_bytes().len(),
            vrfy_key_size(FN_DSA_LOGN_512)
        );
        assert_eq!(
            keypair.secret_key().as_bytes().len(),
            sign_key_size(FN_DSA_LOGN_512)
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa
            .generate_keypair()
            .expect("Keypair generation should succeed");

        let message = b"Hello, FN-DSA!";
        let signature = fn_dsa
            .sign(&keypair.secret_key, message)
            .expect("Signing should succeed");

        // Verify the signature
        let is_valid = fn_dsa
            .verify(&keypair.public_key, message, &signature)
            .expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_valid = fn_dsa
            .verify(&keypair.public_key, wrong_message, &signature)
            .expect("Verification should succeed");
        assert!(!is_valid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_sign_and_verify_1024() {
        let fn_dsa = FnDsa1024::new();
        let keypair = fn_dsa
            .generate_keypair()
            .expect("Keypair generation should succeed");

        let message = b"Hello, FN-DSA 1024!";
        let signature = fn_dsa
            .sign(&keypair.secret_key, message)
            .expect("Signing should succeed");

        // Verify the signature
        let is_valid = fn_dsa
            .verify(&keypair.public_key, message, &signature)
            .expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");
    }
}
