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
//! - **NIST-Approved**: Implements NIST FIPS 206 (FN-DSA)
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
//! ```rust,no_run
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

#[cfg(not(feature = "std"))]
use alloc::vec;
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

// KangarooTwelve-backed deterministic CSPRNG (seedable). Used by the `*_from_seed` entry points so
// FN-DSA key generation and signing are reproducible from a fixed seed (KAT / conformance vectors),
// while remaining cryptographically secure when the seed is fresh CSPRNG entropy.
use lib_q_random::Kt128Rng;

/// Get an appropriate RNG for the current environment
fn get_rng() -> impl CryptoRng {
    lib_q_random::FnDsaRng::new()
}

/// Deterministic FN-DSA key generation from a 32-byte seed.
///
/// The seed is expanded through the KangarooTwelve XOF ([`Kt128Rng`]) to supply the key-generation
/// randomness, so a fixed seed yields a fixed keypair. This is exactly equivalent, security-wise, to
/// seeding any CSPRNG from a hardware entropy source: production callers MUST pass fresh 256-bit
/// CSPRNG entropy as `seed`. A fixed seed is intended only for reproducible KAT / conformance
/// vectors and deterministic identity derivation.
fn keygen_from_seed_bytes(logn: u32, seed: &[u8; 32]) -> Result<SigKeypair> {
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sign_key = vec![0u8; sign_key_size(logn)];
    let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];
    let mut rng = Kt128Rng::from_seed_bytes(*seed);
    kg.keygen(logn, &mut rng, &mut sign_key, &mut vrfy_key);
    Ok(SigKeypair::new(vrfy_key, sign_key))
}

/// Deterministic FN-DSA signing from a 32-byte seed.
///
/// See [`keygen_from_seed_bytes`] for the seed security requirements. FN-DSA signing is randomized
/// (Gaussian sampling); production callers pass fresh CSPRNG entropy per signature so signatures
/// stay randomized, whereas a fixed seed reproduces a single KAT signature.
fn sign_from_seed_bytes(
    logn: u32,
    secret_key: &SigSecretKey,
    message: &[u8],
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut sk = SigningKeyStandard::decode(secret_key.as_bytes()).ok_or_else(|| {
        Error::InvalidKeySize {
            expected: sign_key_size(logn),
            actual: secret_key.as_bytes().len(),
        }
    })?;
    let mut signature = vec![0u8; signature_size(logn)];
    let mut rng = Kt128Rng::from_seed_bytes(*seed);
    sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut signature);
    Ok(signature)
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

    /// Deterministically generate a keypair from a 32-byte seed (reproducible KAT / identity
    /// derivation). The seed MUST be fresh CSPRNG entropy in production; see
    /// [`keygen_from_seed_bytes`].
    pub fn generate_keypair_from_seed(&self, seed: &[u8; 32]) -> Result<SigKeypair> {
        keygen_from_seed_bytes(FN_DSA_LOGN_512, seed)
    }

    /// Deterministically sign `message` from a 32-byte seed. Production callers pass fresh CSPRNG
    /// entropy per signature; a fixed seed reproduces a KAT signature. See [`sign_from_seed_bytes`].
    pub fn sign_from_seed(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        seed: &[u8; 32],
    ) -> Result<Vec<u8>> {
        sign_from_seed_bytes(FN_DSA_LOGN_512, secret_key, message, seed)
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

    /// Deterministically generate a keypair from a 32-byte seed (reproducible KAT / identity
    /// derivation). The seed MUST be fresh CSPRNG entropy in production; see
    /// [`keygen_from_seed_bytes`].
    pub fn generate_keypair_from_seed(&self, seed: &[u8; 32]) -> Result<SigKeypair> {
        keygen_from_seed_bytes(FN_DSA_LOGN_1024, seed)
    }

    /// Deterministically sign `message` from a 32-byte seed. Production callers pass fresh CSPRNG
    /// entropy per signature; a fixed seed reproduces a KAT signature. See [`sign_from_seed_bytes`].
    pub fn sign_from_seed(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        seed: &[u8; 32],
    ) -> Result<Vec<u8>> {
        sign_from_seed_bytes(FN_DSA_LOGN_1024, secret_key, message, seed)
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

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

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
    fn test_keypair_generation() -> TestResult {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair()?;

        assert_eq!(
            keypair.public_key().as_bytes().len(),
            vrfy_key_size(FN_DSA_LOGN_512)
        );
        assert_eq!(
            keypair.secret_key().as_bytes().len(),
            sign_key_size(FN_DSA_LOGN_512)
        );

        // Exercise signing and verification success path.
        let message = b"coverage keypair generation message";
        let signature = fn_dsa.sign(&keypair.secret_key, message)?;
        assert_eq!(signature.len(), signature_size(FN_DSA_LOGN_512));
        assert!(fn_dsa.verify(&keypair.public_key, message, &signature)?);

        // Exercise invalid signature length error branch.
        let invalid_signature = vec![0_u8; signature.len().saturating_sub(1)];
        let verify_err = fn_dsa.verify(&keypair.public_key, message, &invalid_signature);
        assert!(matches!(
            verify_err,
            Err(Error::InvalidSignatureSize {
                expected,
                actual
            }) if expected == signature_size(FN_DSA_LOGN_512) && actual + 1 == expected
        ));

        // Exercise invalid secret key length error branch.
        let invalid_secret_key = SigSecretKey::new(vec![0_u8; sign_key_size(FN_DSA_LOGN_512) - 1]);
        let sign_err = fn_dsa.sign(&invalid_secret_key, b"invalid secret key");
        assert!(matches!(
            sign_err,
            Err(Error::InvalidKeySize {
                expected,
                actual
            }) if expected == sign_key_size(FN_DSA_LOGN_512)
                && actual == sign_key_size(FN_DSA_LOGN_512) - 1
        ));

        // Exercise invalid public key length error branch.
        let invalid_public_key = SigPublicKey::new(vec![0_u8; vrfy_key_size(FN_DSA_LOGN_512) - 1]);
        let verify_key_err = fn_dsa.verify(&invalid_public_key, message, &signature);
        assert!(matches!(
            verify_key_err,
            Err(Error::InvalidKeySize {
                expected,
                actual
            }) if expected == vrfy_key_size(FN_DSA_LOGN_512)
                && actual == vrfy_key_size(FN_DSA_LOGN_512) - 1
        ));
        Ok(())
    }

    #[test]
    fn test_sign_and_verify() -> TestResult {
        let fn_dsa = FnDsa512::new();
        let keypair = fn_dsa.generate_keypair()?;

        let message = b"Hello, FN-DSA!";
        let signature = fn_dsa.sign(&keypair.secret_key, message)?;

        let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
        assert!(is_valid, "Signature should be valid");

        let wrong_message = b"Wrong message";
        let is_valid = fn_dsa.verify(&keypair.public_key, wrong_message, &signature)?;
        assert!(!is_valid, "Signature should be invalid for wrong message");
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_1024() -> TestResult {
        let fn_dsa = FnDsa1024::new();
        let keypair = fn_dsa.generate_keypair()?;

        let message = b"Hello, FN-DSA 1024!";
        let signature = fn_dsa.sign(&keypair.secret_key, message)?;

        let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
        assert!(is_valid, "Signature should be valid");
        Ok(())
    }

    // --- Deterministic seed-based keygen/sign (KAT reproducibility) ---

    #[test]
    fn seeded_keygen_is_deterministic_512() -> TestResult {
        let fn_dsa = FnDsa512::new();
        let seed = [0x11u8; 32];
        let kp_a = fn_dsa.generate_keypair_from_seed(&seed)?;
        let kp_b = fn_dsa.generate_keypair_from_seed(&seed)?;
        assert_eq!(
            kp_a.public_key.as_bytes(),
            kp_b.public_key.as_bytes(),
            "same seed => same verifying key"
        );
        assert_eq!(
            kp_a.secret_key.as_bytes(),
            kp_b.secret_key.as_bytes(),
            "same seed => same signing key"
        );
        // A different seed must yield a different key.
        let kp_c = fn_dsa.generate_keypair_from_seed(&[0x22u8; 32])?;
        assert_ne!(
            kp_a.public_key.as_bytes(),
            kp_c.public_key.as_bytes(),
            "different seed => different key"
        );
        Ok(())
    }

    #[test]
    fn seeded_keygen_is_deterministic_1024() -> TestResult {
        let fn_dsa = FnDsa1024::new();
        let seed = [0x33u8; 32];
        let kp_a = fn_dsa.generate_keypair_from_seed(&seed)?;
        let kp_b = fn_dsa.generate_keypair_from_seed(&seed)?;
        assert_eq!(kp_a.public_key.as_bytes(), kp_b.public_key.as_bytes());
        assert_eq!(kp_a.secret_key.as_bytes(), kp_b.secret_key.as_bytes());
        Ok(())
    }

    #[test]
    fn seeded_sign_is_deterministic_and_verifies_512() -> TestResult {
        let fn_dsa = FnDsa512::new();
        let kp = fn_dsa.generate_keypair_from_seed(&[0x44u8; 32])?;
        let message = b"seeded FN-DSA-512 KAT";
        let sig_seed = [0x55u8; 32];
        let sig_a = fn_dsa.sign_from_seed(&kp.secret_key, message, &sig_seed)?;
        let sig_b = fn_dsa.sign_from_seed(&kp.secret_key, message, &sig_seed)?;
        assert_eq!(sig_a, sig_b, "same (key, msg, seed) => same signature");
        // A different signing seed yields a different (still valid) signature.
        let sig_c = fn_dsa.sign_from_seed(&kp.secret_key, message, &[0x66u8; 32])?;
        assert_ne!(sig_a, sig_c, "different seed => different signature");
        // Both signatures verify under the seed-derived key.
        assert!(fn_dsa.verify(&kp.public_key, message, &sig_a)?);
        assert!(fn_dsa.verify(&kp.public_key, message, &sig_c)?);
        Ok(())
    }

    #[test]
    fn seeded_sign_verifies_1024() -> TestResult {
        let fn_dsa = FnDsa1024::new();
        let kp = fn_dsa.generate_keypair_from_seed(&[0x77u8; 32])?;
        let message = b"seeded FN-DSA-1024 KAT";
        let sig = fn_dsa.sign_from_seed(&kp.secret_key, message, &[0x88u8; 32])?;
        assert!(fn_dsa.verify(&kp.public_key, message, &sig)?);
        // Cross-check: a signature over the seeded key must fail for a tampered message.
        assert!(!fn_dsa.verify(&kp.public_key, b"tampered", &sig)?);
        Ok(())
    }
}
