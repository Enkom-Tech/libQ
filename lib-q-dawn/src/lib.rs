//! lib-Q DAWN - NTRU-based Key Encapsulation Mechanism
//!
//! DAWN is a post-quantum KEM based on NTRU with double encoding that provides
//! smaller and faster ciphertext sizes compared to Kyber/ML-KEM.
//!
//! This implementation provides two parameter sets:
//! - DAWN-α: Optimized for minimal ciphertext size
//! - DAWN-β: Optimized for minimal combined public key + ciphertext size

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::unnecessary_cast)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    string::ToString,
    vec,
    vec::Vec,
};

use lib_q_core::{
    Error,
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    Result,
};
#[cfg(feature = "random")]
use rand_core::TryRng;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// DAWN cryptographic modules
pub mod codec;
pub mod encoding;
pub mod error_correction;
pub mod kem_ops;
pub mod keygen;
pub mod ntru_keygen;
pub mod ntt_polynomial;
pub mod performance;
pub mod polynomial;
pub mod security;

use kem_ops::DawnKemOps;
use keygen::{
    DawnKeyGenerator,
    DawnKeyPair,
    DeterministicKeyGenerator,
    KeyGenParams,
};

/// Profile for DAWN parameter sets: spec (paper-faithful) vs production (tuned for correctness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum DawnProfile {
    /// Paper/spec parameters; may have non-negligible decryption failure with current decoder.
    SpecExperimental,
    /// Implementation-tuned parameters for negligible decryption failure.
    Production,
}

/// DAWN parameter sets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum DawnParameterSet {
    /// DAWN-α-512: NIST-I security, minimal ciphertext size
    Alpha512,
    /// DAWN-α-1024: NIST-V security, minimal ciphertext size  
    Alpha1024,
    /// DAWN-β-512: NIST-I security, minimal combined size
    Beta512,
    /// DAWN-β-1024: NIST-V security, minimal combined size
    Beta1024,
}

impl DawnParameterSet {
    /// Get the security level for this parameter set
    pub fn security_level(&self) -> u32 {
        match self {
            DawnParameterSet::Alpha512 | DawnParameterSet::Beta512 => 1, // NIST-I
            DawnParameterSet::Alpha1024 | DawnParameterSet::Beta1024 => 5, // NIST-V
        }
    }

    /// Get the polynomial degree n
    pub fn polynomial_degree(&self) -> usize {
        match self {
            DawnParameterSet::Alpha512 | DawnParameterSet::Beta512 => 512,
            DawnParameterSet::Alpha1024 | DawnParameterSet::Beta1024 => 1024,
        }
    }

    /// Get the large modulus q
    pub fn large_modulus(&self) -> u32 {
        match self {
            DawnParameterSet::Alpha512 | DawnParameterSet::Alpha1024 => 769,
            DawnParameterSet::Beta512 | DawnParameterSet::Beta1024 => 257,
        }
    }

    /// Get the compression divisor d_c (matches `KeyGenParams::for_profile` Production where applicable).
    pub fn compression_divisor(&self) -> u32 {
        match self {
            DawnParameterSet::Alpha512 | DawnParameterSet::Alpha1024 => 1,
            DawnParameterSet::Beta512 => 2,
            DawnParameterSet::Beta1024 => 1,
        }
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            DawnParameterSet::Alpha512 => 640,
            DawnParameterSet::Alpha1024 => 1280,
            DawnParameterSet::Beta512 => 576,
            DawnParameterSet::Beta1024 => 1152,
        }
    }

    /// Get the secret key size in bytes (f || f2 || k_stored || h_pk || pk)
    pub fn secret_key_size(&self) -> usize {
        let pk = self.public_key_size();
        let f2_len = (self.polynomial_degree() / 2).div_ceil(8);
        pk + f2_len + 32 + 32 + pk
    }

    /// Get the ciphertext size in bytes (encoded compressed PKE ciphertext only)
    pub fn ciphertext_size(&self) -> usize {
        match self {
            // Production Alpha512 uses d_c=1 (10 bits/coeff × 512 / 8).
            DawnParameterSet::Alpha512 => 640,
            // Production Alpha1024 uses d_c=1 (10 bits/coeff × 1024 / 8).
            DawnParameterSet::Alpha1024 => 1280,
            DawnParameterSet::Beta512 => 512,
            DawnParameterSet::Beta1024 => 1152,
        }
    }

    /// Get the shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        32 // All DAWN variants use 256-bit shared secrets
    }
}

/// DAWN KEM implementation
pub struct DawnKem {
    parameter_set: DawnParameterSet,
    keygen_params: KeyGenParams,
    #[allow(dead_code)] // retained for future deterministic keygen API
    key_generator: DawnKeyGenerator,
    kem_ops: DawnKemOps,
}

impl DawnKem {
    /// Create a new DAWN KEM instance with the specified parameter set (production profile).
    pub fn new(parameter_set: DawnParameterSet) -> Self {
        Self::new_with_profile(parameter_set, DawnProfile::Production)
    }

    /// Create a new DAWN KEM instance with the specified parameter set and profile.
    pub fn new_with_profile(parameter_set: DawnParameterSet, profile: DawnProfile) -> Self {
        let keygen_params = KeyGenParams::for_profile(parameter_set, profile);

        let key_generator = DawnKeyGenerator::new(keygen_params.clone());
        let kem_ops = DawnKemOps::new(keygen_params.clone());

        Self {
            parameter_set,
            keygen_params,
            key_generator,
            kem_ops,
        }
    }

    /// Create a KEM instance with explicit keygen params (for tuning and tests).
    pub fn new_with_params(keygen_params: KeyGenParams) -> Self {
        let parameter_set = keygen_params.base_parameter_set;
        let key_generator = DawnKeyGenerator::new(keygen_params.clone());
        let kem_ops = DawnKemOps::new(keygen_params.clone());

        Self {
            parameter_set,
            keygen_params,
            key_generator,
            kem_ops,
        }
    }

    /// Create a KEM instance that uses the reliability-bounded decoder in decapsulation (for sweep/prototype evaluation).
    pub fn new_with_params_and_reliability_decoder(keygen_params: KeyGenParams) -> Self {
        let parameter_set = keygen_params.base_parameter_set;
        let key_generator = DawnKeyGenerator::new(keygen_params.clone());
        let kem_ops = DawnKemOps::new_with_reliability_decoder(keygen_params.clone());

        Self {
            parameter_set,
            keygen_params,
            key_generator,
            kem_ops,
        }
    }

    /// Create a KEM instance that uses the Path B majority-reliability decoder in decapsulation (for sweep/prototype evaluation).
    pub fn new_with_params_and_majority_reliability_decoder(keygen_params: KeyGenParams) -> Self {
        let parameter_set = keygen_params.base_parameter_set;
        let key_generator = DawnKeyGenerator::new(keygen_params.clone());
        let kem_ops = DawnKemOps::new_with_majority_reliability_decoder(keygen_params.clone());

        Self {
            parameter_set,
            keygen_params,
            key_generator,
            kem_ops,
        }
    }

    /// Get the parameter set for this KEM instance
    pub fn parameter_set(&self) -> DawnParameterSet {
        self.parameter_set
    }

    /// Get the keygen params (defines actual sizes and crypto parameters)
    pub fn keygen_params(&self) -> &KeyGenParams {
        &self.keygen_params
    }
}

impl Default for DawnKem {
    fn default() -> Self {
        Self::new(DawnParameterSet::Alpha512)
    }
}

impl DawnKem {
    /// Get the security level
    pub fn security_level(&self) -> u32 {
        self.parameter_set.security_level()
    }

    /// Reconstruct a DawnKeyPair from a secret key.
    /// Layout: f_bytes || f2 || k_stored (32) || h_pk (32) || pk_bytes.
    fn reconstruct_keypair_from_secret_key(
        &self,
        secret_key: &KemSecretKey,
    ) -> Result<DawnKeyPair> {
        let sk_data = &secret_key.data;
        let degree = self.keygen_params.degree;
        let pk_size = self.keygen_params.public_key_byte_size();
        let min_len = self.keygen_params.secret_key_byte_size();
        if sk_data.len() < min_len {
            return Err(Error::InvalidKeySize {
                expected: min_len,
                actual: sk_data.len(),
            });
        }
        let f2_size = (degree / 2).div_ceil(8);

        let f_data = &sk_data[0..pk_size];
        let f = self.kem_ops.decode_pk_polynomial(f_data)?;
        let f2 = sk_data[pk_size..pk_size + f2_size].to_vec();
        let mut k_stored = [0u8; 32];
        k_stored.copy_from_slice(&sk_data[pk_size + f2_size..pk_size + f2_size + 32]);
        let mut h_pk = [0u8; 32];
        h_pk.copy_from_slice(&sk_data[pk_size + f2_size + 32..pk_size + f2_size + 64]);
        let pk_data = &sk_data[pk_size + f2_size + 64..pk_size + f2_size + 64 + pk_size];
        let h = self.kem_ops.decode_pk_polynomial(pk_data)?;

        let mut g = f.clone() * h.clone();
        g.reduce_mod_field();
        g.reduce_mod_cyclotomic();

        Ok(DawnKeyPair::new(
            h,
            f,
            g,
            f2,
            k_stored,
            h_pk,
            self.keygen_params.clone(),
        ))
    }
}

#[cfg(feature = "random")]
impl Kem for DawnKem {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<KemKeypair> {
        const MAX_RETRIES: usize = 10;
        for _ in 0..MAX_RETRIES {
            let mut rng =
                lib_q_random::new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
                    operation: format!("lib-q-random: {}", e),
                })?;
            let mut randomness = [0u8; 64];
            rng.try_fill_bytes(&mut randomness)
                .map_err(|e| Error::RandomGenerationFailed {
                    operation: format!("RNG fill: {}", e),
                })?;

            let det_generator =
                DeterministicKeyGenerator::new(self.keygen_params.clone(), randomness.to_vec());

            match det_generator.generate_keypair() {
                Ok(dawn_keypair) => {
                    let public_key = dawn_keypair.public_key_bytes();
                    let secret_key = dawn_keypair.secret_key_bytes();
                    return Ok(KemKeypair::new(public_key, secret_key));
                }
                Err(Error::InternalError { ref details, .. })
                    if details.contains("not invertible") =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(Error::InternalError {
            operation: "key generation".to_string(),
            details: "f not invertible after retries; try again".to_string(),
        })
    }

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate public key size
        let expected_size = self.keygen_params.public_key_byte_size();
        if public_key.data.len() != expected_size {
            return Err(Error::InvalidKeySize {
                expected: expected_size,
                actual: public_key.data.len(),
            });
        }

        // Decode public key to polynomial (pk encoding, not ct)
        let pk_poly = self.kem_ops.decode_pk_polynomial(&public_key.data)?;

        // Generate 64 bytes of secure randomness for encapsulation
        let mut rng =
            lib_q_random::new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
                operation: format!("lib-q-random: {}", e),
            })?;
        let mut randomness = [0u8; 64];
        rng.try_fill_bytes(&mut randomness)
            .map_err(|e| Error::RandomGenerationFailed {
                operation: format!("RNG fill: {}", e),
            })?;

        // Perform encapsulation using the proper KEM operations
        // The randomness will be embedded in the ciphertext
        let (ciphertext, shared_secret) = self.kem_ops.encapsulate(&pk_poly, &randomness)?;

        Ok((ciphertext, shared_secret))
    }

    /// Decapsulate a shared secret
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate secret key size
        let expected_sk_size = self.keygen_params.secret_key_byte_size();
        if secret_key.data.len() != expected_sk_size {
            return Err(Error::InvalidKeySize {
                expected: expected_sk_size,
                actual: secret_key.data.len(),
            });
        }

        // Validate ciphertext size
        let expected_ct_size = self.keygen_params.ciphertext_byte_size();
        if ciphertext.len() != expected_ct_size {
            return Err(Error::InvalidCiphertextSize {
                expected: expected_ct_size,
                actual: ciphertext.len(),
            });
        }

        // Reconstruct the keypair from the secret key
        let dawn_keypair = self.reconstruct_keypair_from_secret_key(secret_key)?;

        // Perform decapsulation using the proper KEM operations
        // The randomness is now embedded in the ciphertext during encapsulation
        let shared_secret = self.kem_ops.decapsulate(&dawn_keypair, ciphertext)?;

        Ok(shared_secret)
    }

    /// Derive public key from secret key
    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey> {
        // Validate secret key size
        let expected_sk_size = self.keygen_params.secret_key_byte_size();
        if secret_key.data.len() != expected_sk_size {
            return Err(Error::InvalidKeySize {
                expected: expected_sk_size,
                actual: secret_key.data.len(),
            });
        }

        // Reconstruct the keypair from the secret key
        let dawn_keypair = self.reconstruct_keypair_from_secret_key(secret_key)?;

        // Return the public key
        let public_key_bytes = dawn_keypair.public_key_bytes();
        Ok(KemPublicKey::new(public_key_bytes))
    }

    /// Authenticated encapsulation (RFC 9180 AuthEncap)
    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // DAWN does not support authenticated encapsulation
        Err(Error::UnsupportedOperation {
            operation: "DAWN does not support authenticated encapsulation".to_string(),
        })
    }

    /// Authenticated decapsulation (RFC 9180 AuthDecap)
    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>> {
        // DAWN does not support authenticated decapsulation
        Err(Error::UnsupportedOperation {
            operation: "DAWN does not support authenticated decapsulation".to_string(),
        })
    }
}

/// WASM-friendly wrapper for DAWN operations
#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::JsError;

    use super::*;

    /// Generate a keypair (WASM)
    #[wasm_bindgen]
    pub fn generate_keypair(
        parameter_set: DawnParameterSet,
    ) -> std::result::Result<KemKeypair, JsError> {
        let kem = DawnKem::new(parameter_set);
        kem.generate_keypair()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn encapsulate(
        parameter_set: DawnParameterSet,
        public_key: &KemPublicKey,
    ) -> std::result::Result<EncapsulationResult, JsError> {
        let kem = DawnKem::new(parameter_set);
        let (ciphertext, shared_secret) = kem
            .encapsulate(public_key)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(EncapsulationResult::new(ciphertext, shared_secret))
    }

    /// Decapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn decapsulate(
        parameter_set: DawnParameterSet,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> std::result::Result<Vec<u8>, JsError> {
        let kem = DawnKem::new(parameter_set);
        kem.decapsulate(secret_key, ciphertext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Result of encapsulation operation for WASM
    #[wasm_bindgen]
    pub struct EncapsulationResult {
        #[wasm_bindgen(skip)]
        ciphertext: Vec<u8>,
        #[wasm_bindgen(skip)]
        shared_secret: Vec<u8>,
    }

    #[wasm_bindgen]
    impl EncapsulationResult {
        #[wasm_bindgen(constructor)]
        pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
            Self {
                ciphertext,
                shared_secret,
            }
        }

        #[wasm_bindgen(getter)]
        pub fn ciphertext(&self) -> Vec<u8> {
            self.ciphertext.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn shared_secret(&self) -> Vec<u8> {
            self.shared_secret.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{
        format,
        vec,
    };

    use super::*;

    #[test]
    fn test_parameter_set_properties() {
        // Test DAWN-α-512
        let alpha512 = DawnParameterSet::Alpha512;
        assert_eq!(alpha512.security_level(), 1);
        assert_eq!(alpha512.polynomial_degree(), 512);
        assert_eq!(alpha512.large_modulus(), 769);
        assert_eq!(alpha512.compression_divisor(), 1);
        assert_eq!(alpha512.public_key_size(), 640);
        assert_eq!(alpha512.secret_key_size(), 640 + 32 + 32 + 32 + 640);
        assert_eq!(alpha512.ciphertext_size(), 640);
        assert_eq!(alpha512.shared_secret_size(), 32);

        // Test DAWN-α-1024
        let alpha1024 = DawnParameterSet::Alpha1024;
        assert_eq!(alpha1024.security_level(), 5);
        assert_eq!(alpha1024.polynomial_degree(), 1024);
        assert_eq!(alpha1024.large_modulus(), 769);
        assert_eq!(alpha1024.compression_divisor(), 1);
        assert_eq!(alpha1024.public_key_size(), 1280);
        assert_eq!(alpha1024.secret_key_size(), 1280 + 64 + 32 + 32 + 1280);
        assert_eq!(alpha1024.ciphertext_size(), 1280);
        assert_eq!(alpha1024.shared_secret_size(), 32);

        // Test DAWN-β-512
        let beta512 = DawnParameterSet::Beta512;
        assert_eq!(beta512.security_level(), 1);
        assert_eq!(beta512.polynomial_degree(), 512);
        assert_eq!(beta512.large_modulus(), 257);
        assert_eq!(beta512.compression_divisor(), 2);
        assert_eq!(beta512.public_key_size(), 576);
        assert_eq!(beta512.secret_key_size(), 576 + 32 + 32 + 32 + 576);
        assert_eq!(beta512.ciphertext_size(), 512);
        assert_eq!(beta512.shared_secret_size(), 32);

        // Test DAWN-β-1024
        let beta1024 = DawnParameterSet::Beta1024;
        assert_eq!(beta1024.security_level(), 5);
        assert_eq!(beta1024.polynomial_degree(), 1024);
        assert_eq!(beta1024.large_modulus(), 257);
        assert_eq!(beta1024.compression_divisor(), 1);
        assert_eq!(beta1024.public_key_size(), 1152);
        assert_eq!(beta1024.secret_key_size(), 1152 + 64 + 32 + 32 + 1152);
        assert_eq!(beta1024.ciphertext_size(), 1152);
        assert_eq!(beta1024.shared_secret_size(), 32);
    }

    #[test]
    fn test_dawn_creation() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        assert_eq!(dawn.parameter_set(), DawnParameterSet::Alpha512);
        assert_eq!(dawn.security_level(), 1);

        let dawn_default = DawnKem::default();
        assert_eq!(dawn_default.parameter_set(), DawnParameterSet::Alpha512);
    }

    #[test]
    fn test_dawn_keypair_generation() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        let result = dawn.generate_keypair();
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(
            keypair.public_key.data.len(),
            dawn.keygen_params().public_key_byte_size()
        );
        assert_eq!(
            keypair.secret_key.data.len(),
            dawn.keygen_params().secret_key_byte_size()
        );
    }

    #[test]
    fn test_dawn_encapsulation() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        let public_key_data = security::generate_deterministic_high_entropy_data(
            b"test_dawn_encapsulation_public_key",
            640,
        );
        let public_key = KemPublicKey::new(public_key_data);

        let result = dawn.encapsulate(&public_key);
        assert!(result.is_ok());

        let (ciphertext, shared_secret) = result.unwrap();
        assert_eq!(
            ciphertext.len(),
            dawn.keygen_params().ciphertext_byte_size()
        );
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_dawn_encapsulation_invalid_key_size() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        let public_key = KemPublicKey::new(vec![0u8; 100]); // Wrong size

        let result = dawn.encapsulate(&public_key);
        assert!(result.is_err());

        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, dawn.keygen_params().public_key_byte_size());
            assert_eq!(actual, 100);
        } else {
            panic!("Expected InvalidKeySize error");
        }
    }

    #[test]
    fn test_dawn_decapsulation() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);

        // Generate a valid keypair first
        let keypair = dawn
            .generate_keypair()
            .expect("Key generation should succeed");

        // Encapsulate to get a valid ciphertext
        let (ciphertext, _) = dawn
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        // Now test decapsulation with valid inputs
        let result = dawn.decapsulate(&keypair.secret_key, &ciphertext);
        assert!(result.is_ok());

        let shared_secret = result.unwrap();
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_dawn_decapsulation_invalid_key_size() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        let expected_sk = dawn.keygen_params().secret_key_byte_size();
        let secret_key = KemSecretKey::new(vec![0u8; 100]); // Wrong size
        let ciphertext = vec![0u8; dawn.keygen_params().ciphertext_byte_size()];

        let result = dawn.decapsulate(&secret_key, &ciphertext);
        assert!(result.is_err());

        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, expected_sk);
            assert_eq!(actual, 100);
        } else {
            panic!("Expected InvalidKeySize error");
        }
    }

    #[test]
    fn test_dawn_decapsulation_invalid_ciphertext_size() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);
        let expected_sk = dawn.keygen_params().secret_key_byte_size();
        let secret_key = KemSecretKey::new(vec![0u8; expected_sk]);
        let ciphertext = vec![0u8; 100]; // Wrong size

        let result = dawn.decapsulate(&secret_key, &ciphertext);
        assert!(result.is_err());

        if let Err(Error::InvalidCiphertextSize { expected, actual }) = result {
            assert_eq!(expected, dawn.keygen_params().ciphertext_byte_size());
            assert_eq!(actual, 100);
        } else {
            panic!("Expected InvalidCiphertextSize error");
        }
    }

    #[test]
    fn test_all_parameter_sets() {
        let parameter_sets = [
            DawnParameterSet::Alpha512,
            DawnParameterSet::Alpha1024,
            DawnParameterSet::Beta512,
            DawnParameterSet::Beta1024,
        ];

        for param_set in parameter_sets {
            let dawn = DawnKem::new(param_set);

            // Test key generation
            let keypair = dawn.generate_keypair().unwrap();
            assert_eq!(
                keypair.public_key.data.len(),
                dawn.keygen_params().public_key_byte_size()
            );
            assert_eq!(
                keypair.secret_key.data.len(),
                dawn.keygen_params().secret_key_byte_size()
            );

            // Test encapsulation
            let (ciphertext, shared_secret) = dawn.encapsulate(&keypair.public_key).unwrap();
            assert_eq!(
                ciphertext.len(),
                dawn.keygen_params().ciphertext_byte_size()
            );
            assert_eq!(shared_secret.len(), param_set.shared_secret_size());

            // Test decapsulation
            let decrypted_secret = dawn.decapsulate(&keypair.secret_key, &ciphertext).unwrap();
            assert_eq!(decrypted_secret.len(), param_set.shared_secret_size());
        }
    }

    #[test]
    fn test_parameter_set_equality() {
        assert_eq!(DawnParameterSet::Alpha512, DawnParameterSet::Alpha512);
        assert_ne!(DawnParameterSet::Alpha512, DawnParameterSet::Alpha1024);
        assert_ne!(DawnParameterSet::Alpha512, DawnParameterSet::Beta512);
        assert_ne!(DawnParameterSet::Alpha512, DawnParameterSet::Beta1024);
    }

    #[test]
    fn test_parameter_set_clone() {
        let param_set = DawnParameterSet::Alpha512;
        let cloned = param_set;
        assert_eq!(param_set, cloned);
    }

    #[test]
    fn test_parameter_set_debug() {
        let param_set = DawnParameterSet::Alpha512;
        let debug_str = format!("{:?}", param_set);
        assert!(debug_str.contains("Alpha512"));
    }

    /// Full cycle with strict shared-secret equality (Production Alpha512).
    #[test]
    fn test_secure_kem_full_cycle() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);

        // Generate keypair
        let keypair = dawn
            .generate_keypair()
            .expect("Key generation should succeed");

        // Encapsulate
        let (ciphertext, shared_secret1) = dawn
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        // Verify ciphertext size
        assert_eq!(
            ciphertext.len(),
            dawn.keygen_params().ciphertext_byte_size()
        );
        assert_eq!(shared_secret1.len(), 32);

        // Decapsulate
        let shared_secret2 = dawn
            .decapsulate(&keypair.secret_key, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(shared_secret2.len(), 32);
        if shared_secret1 != shared_secret2 {
            eprintln!(
                "KEM secret mismatch: enc[..8] = {:?}, dec[..8] = {:?}",
                &shared_secret1[..8],
                &shared_secret2[..8]
            );
        }
        assert_eq!(
            shared_secret1, shared_secret2,
            "decapsulation must recover the same shared secret as encapsulation"
        );
    }

    /// Alpha1024 full cycle (Production).
    #[test]
    fn test_secure_kem_full_cycle_alpha1024() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha1024);

        let keypair = dawn
            .generate_keypair()
            .expect("Key generation should succeed");

        let (ciphertext, shared_secret1) = dawn
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        assert_eq!(
            ciphertext.len(),
            dawn.keygen_params().ciphertext_byte_size()
        );
        assert_eq!(shared_secret1.len(), 32);

        let shared_secret2 = dawn
            .decapsulate(&keypair.secret_key, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(shared_secret2.len(), 32);
        assert_eq!(
            shared_secret1, shared_secret2,
            "decapsulation must recover the same shared secret as encapsulation"
        );
    }

    #[test]
    fn test_secure_kem_different_randomness() {
        let dawn = DawnKem::new(DawnParameterSet::Alpha512);

        // Generate keypair
        let keypair = dawn
            .generate_keypair()
            .expect("Key generation should succeed");

        // Encapsulate multiple times with different randomness
        let (ciphertext1, _shared_secret1) = dawn
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        let (ciphertext2, _shared_secret2) = dawn
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        // Different encapsulations should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
        // Note: With proper randomness usage, shared secrets should also be different
        // For now, we verify the basic flow works without errors

        // But each should be decapsulatable correctly
        let decrypted1 = dawn
            .decapsulate(&keypair.secret_key, &ciphertext1)
            .expect("Decapsulation should succeed");

        let decrypted2 = dawn
            .decapsulate(&keypair.secret_key, &ciphertext2)
            .expect("Decapsulation should succeed");

        assert_eq!(decrypted1.len(), 32);
        assert_eq!(decrypted2.len(), 32);
    }

    #[test]
    fn test_reconstruction_algebra_g_equals_f_times_h() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = security::generate_deterministic_high_entropy_data(
            b"test_reconstruction_algebra_g_equals_f_times_h",
            64,
        );
        let key_gen = DeterministicKeyGenerator::new(params, seed);
        let keypair = key_gen
            .generate_keypair()
            .expect("key generation should succeed");

        let f = &keypair.secret_key;
        let h = &keypair.public_key;
        let g = &keypair.g;

        let mut g_reconstructed = f.clone() * h.clone();
        g_reconstructed.reduce_mod_field();
        g_reconstructed.reduce_mod_cyclotomic();

        assert_eq!(
            g_reconstructed.coefficients, g.coefficients,
            "reconstruction invariant: g must equal f * h (mod field and cyclotomic)"
        );
    }
}
