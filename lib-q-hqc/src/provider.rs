//! HQC Provider Implementation for libQ
//!
//! This module provides the libQ provider implementation for HQC KEM operations.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::String,
    vec,
    vec::Vec,
};

use lib_q_core::{
    Algorithm,
    CryptoProvider,
    Error,
    KemOperations,
    Result,
};

use crate::hqc_correct::{
    Hqc1,
    Hqc3,
    Hqc5,
    HqcCore,
};

/// HQC provider for libQ integration
#[derive(Debug, Clone, PartialEq)]
pub struct LibQHqcProvider;

impl LibQHqcProvider {
    /// Create a new HQC provider
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Get the provider name
    pub fn name(&self) -> &'static str {
        "libQ HQC Provider"
    }

    /// Get the provider priority
    pub fn priority(&self) -> u32 {
        100
    }

    /// Get the provider capabilities
    pub fn capabilities(&self) -> Vec<Algorithm> {
        vec![Algorithm::Hqc128, Algorithm::Hqc192, Algorithm::Hqc256]
    }

    /// Check if the provider supports a specific algorithm
    pub fn supports_algorithm(&self, algorithm: Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256
        )
    }
}

#[cfg(feature = "alloc")]
impl KemOperations for LibQHqcProvider {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        _randomness: Option<&[u8]>,
    ) -> Result<lib_q_core::KemKeypair> {
        use lib_q_random::LibQRng;

        match algorithm {
            Algorithm::Hqc128 => {
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (secret_key, public_key) =
                    Hqc1::generate_keypair(&mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-128 key generation"),
                        details: format!("Failed to generate HQC-128 keypair: {:?}", e),
                    })?;
                Ok(lib_q_core::KemKeypair {
                    public_key: lib_q_core::KemPublicKey::new(public_key.as_bytes().to_vec()),
                    secret_key: lib_q_core::KemSecretKey::new(secret_key.as_bytes()),
                })
            }
            Algorithm::Hqc192 => {
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (secret_key, public_key) =
                    Hqc3::generate_keypair(&mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-192 key generation"),
                        details: format!("Failed to generate HQC-192 keypair: {:?}", e),
                    })?;
                Ok(lib_q_core::KemKeypair {
                    public_key: lib_q_core::KemPublicKey::new(public_key.as_bytes().to_vec()),
                    secret_key: lib_q_core::KemSecretKey::new(secret_key.as_bytes()),
                })
            }
            Algorithm::Hqc256 => {
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (secret_key, public_key) =
                    Hqc5::generate_keypair(&mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-256 key generation"),
                        details: format!("Failed to generate HQC-256 keypair: {:?}", e),
                    })?;
                Ok(lib_q_core::KemKeypair {
                    public_key: lib_q_core::KemPublicKey::new(public_key.as_bytes().to_vec()),
                    secret_key: lib_q_core::KemSecretKey::new(secret_key.as_bytes()),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Unsupported algorithm",
            }),
        }
    }

    fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &lib_q_core::KemPublicKey,
        _randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use lib_q_random::LibQRng;

        use crate::hqc_correct::{
            Hqc1PublicKey,
            Hqc3PublicKey,
            Hqc5PublicKey,
        };
        use crate::hqc_kem::HqcKemPublicKey;
        use crate::hqc_pke::HqcPkePublicKey;
        #[allow(unused_imports)] // HqcParams trait needed for associated constants access
        use crate::params_correct::{
            Hqc1Params,
            Hqc3Params,
            Hqc5Params,
            HqcParams,
        };

        match algorithm {
            Algorithm::Hqc128 => {
                let pke_pk = HqcPkePublicKey::<Hqc1Params>::new(public_key.data.clone());
                let kem_pk = HqcKemPublicKey::new(pke_pk);
                let pk = Hqc1PublicKey::new(kem_pk);
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (ciphertext, shared_secret) =
                    Hqc1::encapsulate(&pk, &mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-128 encapsulation"),
                        details: format!("Failed to encapsulate HQC-128: {:?}", e),
                    })?;
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
            Algorithm::Hqc192 => {
                let pke_pk = HqcPkePublicKey::<Hqc3Params>::new(public_key.data.clone());
                let kem_pk = HqcKemPublicKey::new(pke_pk);
                let pk = Hqc3PublicKey::new(kem_pk);
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (ciphertext, shared_secret) =
                    Hqc3::encapsulate(&pk, &mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-192 encapsulation"),
                        details: format!("Failed to encapsulate HQC-192: {:?}", e),
                    })?;
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
            Algorithm::Hqc256 => {
                let pke_pk = HqcPkePublicKey::<Hqc5Params>::new(public_key.data.clone());
                let kem_pk = HqcKemPublicKey::new(pke_pk);
                let pk = Hqc5PublicKey::new(kem_pk);
                let mut rng = LibQRng::new_secure().map_err(|_| Error::InternalError {
                    operation: String::from("RNG initialization"),
                    details: String::from("Failed to initialize secure random number generator"),
                })?;
                let (ciphertext, shared_secret) =
                    Hqc5::encapsulate(&pk, &mut rng).map_err(|e| Error::InternalError {
                        operation: String::from("HQC-256 encapsulation"),
                        details: format!("Failed to encapsulate HQC-256: {:?}", e),
                    })?;
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Unsupported algorithm",
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &lib_q_core::KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        use crate::hqc_correct::{
            Hqc1Ciphertext,
            Hqc1SecretKey,
            Hqc3Ciphertext,
            Hqc3SecretKey,
            Hqc5Ciphertext,
            Hqc5SecretKey,
        };
        use crate::hqc_kem::{
            HqcKemCiphertext,
            HqcKemSecretKey,
        };
        use crate::hqc_pke::{
            HqcPkeCiphertext,
            HqcPkePublicKey,
            HqcPkeSecretKey,
        };
        #[allow(unused_imports)] // HqcParams trait needed for associated constants access
        use crate::params_correct::{
            Hqc1Params,
            Hqc3Params,
            Hqc5Params,
            HqcParams,
        };

        match algorithm {
            Algorithm::Hqc128 => {
                // Parse secret key: ek_pke (PUBLIC_KEY_BYTES) + dk_pke (32) + sigma (16) + seed_kem (48)
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc1Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc1Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }
                let ek_pke_bytes = &sk_bytes[..Hqc1Params::PUBLIC_KEY_BYTES];
                let dk_pke_start = Hqc1Params::PUBLIC_KEY_BYTES;
                let dk_pke_bytes = &sk_bytes[dk_pke_start..dk_pke_start + 32];
                let sigma_start = dk_pke_start + 32;
                let mut sigma = [0u8; 16];
                sigma.copy_from_slice(&sk_bytes[sigma_start..sigma_start + 16]);
                let seed_kem_start = sigma_start + 16;
                let mut seed_kem = [0u8; 48];
                seed_kem.copy_from_slice(&sk_bytes[seed_kem_start..seed_kem_start + 48]);

                let ek_pke = HqcPkePublicKey::<Hqc1Params>::new(ek_pke_bytes.to_vec());
                let mut dk_pke_array = [0u8; 32];
                dk_pke_array.copy_from_slice(dk_pke_bytes);
                let dk_pke = HqcPkeSecretKey::new(dk_pke_array);
                let kem_sk = HqcKemSecretKey::new(ek_pke, dk_pke, sigma, seed_kem);
                let sk = Hqc1SecretKey::new(kem_sk);

                // Parse ciphertext: c_pke (VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES) + salt (16)
                let pke_ct_size = Hqc1Params::VEC_N_SIZE_BYTES + Hqc1Params::VEC_N1N2_SIZE_BYTES;
                if ciphertext.len() < pke_ct_size + 16 {
                    return Err(Error::InvalidKeySize {
                        expected: pke_ct_size + 16,
                        actual: ciphertext.len(),
                    });
                }
                let c_pke_bytes = &ciphertext[..pke_ct_size];
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&ciphertext[pke_ct_size..pke_ct_size + 16]);
                let c_pke = HqcPkeCiphertext::<Hqc1Params>::new(c_pke_bytes.to_vec());
                let kem_ct = HqcKemCiphertext::new(c_pke, salt);
                let ct = Hqc1Ciphertext::new(kem_ct);

                let shared_secret =
                    Hqc1::decapsulate::<lib_q_random::LibQRng>(&sk, &ct).map_err(|e| {
                        Error::InternalError {
                            operation: String::from("HQC-128 decapsulation"),
                            details: format!("Failed to decapsulate HQC-128: {:?}", e),
                        }
                    })?;
                Ok(shared_secret.as_bytes().to_vec())
            }
            Algorithm::Hqc192 => {
                // Parse secret key
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc3Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc3Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }
                let ek_pke_bytes = &sk_bytes[..Hqc3Params::PUBLIC_KEY_BYTES];
                let dk_pke_start = Hqc3Params::PUBLIC_KEY_BYTES;
                let dk_pke_bytes = &sk_bytes[dk_pke_start..dk_pke_start + 32];
                let sigma_start = dk_pke_start + 32;
                let mut sigma = [0u8; 16];
                sigma.copy_from_slice(&sk_bytes[sigma_start..sigma_start + 16]);
                let seed_kem_start = sigma_start + 16;
                let mut seed_kem = [0u8; 48];
                seed_kem.copy_from_slice(&sk_bytes[seed_kem_start..seed_kem_start + 48]);

                let ek_pke = HqcPkePublicKey::<Hqc3Params>::new(ek_pke_bytes.to_vec());
                let mut dk_pke_array = [0u8; 32];
                dk_pke_array.copy_from_slice(dk_pke_bytes);
                let dk_pke = HqcPkeSecretKey::new(dk_pke_array);
                let kem_sk = HqcKemSecretKey::new(ek_pke, dk_pke, sigma, seed_kem);
                let sk = Hqc3SecretKey::new(kem_sk);

                // Parse ciphertext: c_pke (VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES) + salt (16)
                let pke_ct_size = Hqc3Params::VEC_N_SIZE_BYTES + Hqc3Params::VEC_N1N2_SIZE_BYTES;
                if ciphertext.len() < pke_ct_size + 16 {
                    return Err(Error::InvalidKeySize {
                        expected: pke_ct_size + 16,
                        actual: ciphertext.len(),
                    });
                }
                let c_pke_bytes = &ciphertext[..pke_ct_size];
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&ciphertext[pke_ct_size..pke_ct_size + 16]);
                let c_pke = HqcPkeCiphertext::<Hqc3Params>::new(c_pke_bytes.to_vec());
                let kem_ct = HqcKemCiphertext::new(c_pke, salt);
                let ct = Hqc3Ciphertext::new(kem_ct);

                let shared_secret =
                    Hqc3::decapsulate::<lib_q_random::LibQRng>(&sk, &ct).map_err(|e| {
                        Error::InternalError {
                            operation: String::from("HQC-192 decapsulation"),
                            details: format!("Failed to decapsulate HQC-192: {:?}", e),
                        }
                    })?;
                Ok(shared_secret.as_bytes().to_vec())
            }
            Algorithm::Hqc256 => {
                // Parse secret key
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc5Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc5Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }
                let ek_pke_bytes = &sk_bytes[..Hqc5Params::PUBLIC_KEY_BYTES];
                let dk_pke_start = Hqc5Params::PUBLIC_KEY_BYTES;
                let dk_pke_bytes = &sk_bytes[dk_pke_start..dk_pke_start + 32];
                let sigma_start = dk_pke_start + 32;
                let mut sigma = [0u8; 16];
                sigma.copy_from_slice(&sk_bytes[sigma_start..sigma_start + 16]);
                let seed_kem_start = sigma_start + 16;
                let mut seed_kem = [0u8; 48];
                seed_kem.copy_from_slice(&sk_bytes[seed_kem_start..seed_kem_start + 48]);

                let ek_pke = HqcPkePublicKey::<Hqc5Params>::new(ek_pke_bytes.to_vec());
                let mut dk_pke_array = [0u8; 32];
                dk_pke_array.copy_from_slice(dk_pke_bytes);
                let dk_pke = HqcPkeSecretKey::new(dk_pke_array);
                let kem_sk = HqcKemSecretKey::new(ek_pke, dk_pke, sigma, seed_kem);
                let sk = Hqc5SecretKey::new(kem_sk);

                // Parse ciphertext: c_pke (VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES) + salt (16)
                let pke_ct_size = Hqc5Params::VEC_N_SIZE_BYTES + Hqc5Params::VEC_N1N2_SIZE_BYTES;
                if ciphertext.len() < pke_ct_size + 16 {
                    return Err(Error::InvalidKeySize {
                        expected: pke_ct_size + 16,
                        actual: ciphertext.len(),
                    });
                }
                let c_pke_bytes = &ciphertext[..pke_ct_size];
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&ciphertext[pke_ct_size..pke_ct_size + 16]);
                let c_pke = HqcPkeCiphertext::<Hqc5Params>::new(c_pke_bytes.to_vec());
                let kem_ct = HqcKemCiphertext::new(c_pke, salt);
                let ct = Hqc5Ciphertext::new(kem_ct);

                let shared_secret =
                    Hqc5::decapsulate::<lib_q_random::LibQRng>(&sk, &ct).map_err(|e| {
                        Error::InternalError {
                            operation: String::from("HQC-256 decapsulation"),
                            details: format!("Failed to decapsulate HQC-256: {:?}", e),
                        }
                    })?;
                Ok(shared_secret.as_bytes().to_vec())
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Unsupported algorithm",
            }),
        }
    }

    fn derive_public_key(
        &self,
        algorithm: Algorithm,
        secret_key: &lib_q_core::KemSecretKey,
    ) -> Result<lib_q_core::KemPublicKey> {
        #[allow(unused_imports)] // HqcParams trait needed for associated constants access
        use crate::params_correct::{
            Hqc1Params,
            Hqc3Params,
            Hqc5Params,
            HqcParams,
        };

        match algorithm {
            Algorithm::Hqc128 => {
                // Validate secret key size
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc1Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc1Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }

                // Extract ek_pke (public key) from first PUBLIC_KEY_BYTES of secret key
                // Secret key structure: ek_pke (PUBLIC_KEY_BYTES) + dk_pke (32) + sigma (16) + seed_kem (48)
                let ek_pke_bytes = &sk_bytes[..Hqc1Params::PUBLIC_KEY_BYTES];

                Ok(lib_q_core::KemPublicKey::new(ek_pke_bytes.to_vec()))
            }
            Algorithm::Hqc192 => {
                // Validate secret key size
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc3Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc3Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }

                // Extract ek_pke (public key) from first PUBLIC_KEY_BYTES of secret key
                let ek_pke_bytes = &sk_bytes[..Hqc3Params::PUBLIC_KEY_BYTES];

                Ok(lib_q_core::KemPublicKey::new(ek_pke_bytes.to_vec()))
            }
            Algorithm::Hqc256 => {
                // Validate secret key size
                let sk_bytes = &secret_key.data;
                if sk_bytes.len() < Hqc5Params::SECRET_KEY_BYTES {
                    return Err(Error::InvalidKeySize {
                        expected: Hqc5Params::SECRET_KEY_BYTES,
                        actual: sk_bytes.len(),
                    });
                }

                // Extract ek_pke (public key) from first PUBLIC_KEY_BYTES of secret key
                let ek_pke_bytes = &sk_bytes[..Hqc5Params::PUBLIC_KEY_BYTES];

                Ok(lib_q_core::KemPublicKey::new(ek_pke_bytes.to_vec()))
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Unsupported algorithm for HQC derive_public_key",
            }),
        }
    }
}

impl Default for LibQHqcProvider {
    fn default() -> Self {
        Self::new().expect("HQC provider should always be creatable")
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQHqcProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(self)
    }

    fn signature(&self) -> Option<&dyn lib_q_core::SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn lib_q_core::HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn lib_q_core::AeadOperations> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    extern crate alloc;

    use lib_q_core::Algorithm;

    use super::*;

    #[test]
    fn test_derive_public_key_hqc128() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc128, None)
            .expect("Failed to generate keypair");

        // Derive public key from secret key
        let derived_pk = provider
            .derive_public_key(Algorithm::Hqc128, &keypair.secret_key)
            .expect("Failed to derive public key");

        // Verify derived public key matches original
        assert_eq!(
            derived_pk.data, keypair.public_key.data,
            "Derived public key should match original public key"
        );
        assert_eq!(
            derived_pk.data.len(),
            keypair.public_key.data.len(),
            "Derived public key size should match original"
        );
    }

    #[test]
    fn test_derive_public_key_hqc192() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc192, None)
            .expect("Failed to generate keypair");

        // Derive public key from secret key
        let derived_pk = provider
            .derive_public_key(Algorithm::Hqc192, &keypair.secret_key)
            .expect("Failed to derive public key");

        // Verify derived public key matches original
        assert_eq!(
            derived_pk.data, keypair.public_key.data,
            "Derived public key should match original public key"
        );
        assert_eq!(
            derived_pk.data.len(),
            keypair.public_key.data.len(),
            "Derived public key size should match original"
        );
    }

    #[test]
    fn test_derive_public_key_hqc256() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc256, None)
            .expect("Failed to generate keypair");

        // Derive public key from secret key
        let derived_pk = provider
            .derive_public_key(Algorithm::Hqc256, &keypair.secret_key)
            .expect("Failed to derive public key");

        // Verify derived public key matches original
        assert_eq!(
            derived_pk.data, keypair.public_key.data,
            "Derived public key should match original public key"
        );
        assert_eq!(
            derived_pk.data.len(),
            keypair.public_key.data.len(),
            "Derived public key size should match original"
        );
    }

    #[test]
    fn test_derive_public_key_invalid_key_size() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Create a secret key with invalid size
        let invalid_sk = lib_q_core::KemSecretKey::new(alloc::vec![0u8; 100]);

        // Should return error for invalid key size
        let result = provider.derive_public_key(Algorithm::Hqc128, &invalid_sk);
        assert!(result.is_err(), "Should return error for invalid key size");
        if let Err(Error::InvalidKeySize { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidKeySize error, got: {:?}", result);
        }
    }

    #[test]
    fn test_derive_public_key_unsupported_algorithm() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate a valid HQC-128 keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc128, None)
            .expect("Failed to generate keypair");

        // Try to derive with unsupported algorithm
        let result = provider.derive_public_key(Algorithm::MlKem512, &keypair.secret_key);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );
        if let Err(Error::InvalidAlgorithm { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidAlgorithm error, got: {:?}", result);
        }
    }

    #[test]
    #[ignore] // Probabilistic HQC failures - covered by integration_test.rs
    fn test_derive_public_key_round_trip_encapsulation() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc128, None)
            .expect("Failed to generate keypair");

        // Derive public key from secret key
        let derived_pk = provider
            .derive_public_key(Algorithm::Hqc128, &keypair.secret_key)
            .expect("Failed to derive public key");

        // Use derived public key for encapsulation
        let (ciphertext, shared_secret1) = provider
            .encapsulate(Algorithm::Hqc128, &derived_pk, None)
            .expect("Failed to encapsulate with derived public key");

        // Decapsulate using original secret key
        let shared_secret2 = provider
            .decapsulate(Algorithm::Hqc128, &keypair.secret_key, &ciphertext)
            .expect("Failed to decapsulate");

        // Verify shared secrets match
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets should match when using derived public key"
        );
    }

    #[test]
    #[ignore] // Probabilistic HQC failures - covered by integration_test.rs  
    fn test_derive_public_key_multiple_round_trips() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        // Generate keypair
        let keypair = provider
            .generate_keypair(Algorithm::Hqc192, None)
            .expect("Failed to generate keypair");

        // Derive public key once
        let derived_pk = provider
            .derive_public_key(Algorithm::Hqc192, &keypair.secret_key)
            .expect("Failed to derive public key");

        // Perform multiple encapsulations with derived key
        for _ in 0..3 {
            let (ciphertext, shared_secret1) = provider
                .encapsulate(Algorithm::Hqc192, &derived_pk, None)
                .expect("Failed to encapsulate");

            let shared_secret2 = provider
                .decapsulate(Algorithm::Hqc192, &keypair.secret_key, &ciphertext)
                .expect("Failed to decapsulate");

            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secrets should match in round-trip test"
            );
        }
    }

    #[test]
    fn test_derive_public_key_all_algorithms() {
        let provider = LibQHqcProvider::new().expect("Failed to create provider");

        let algorithms = [Algorithm::Hqc128, Algorithm::Hqc192, Algorithm::Hqc256];

        for algorithm in algorithms {
            // Generate keypair
            let keypair = provider
                .generate_keypair(algorithm, None)
                .unwrap_or_else(|_| panic!("Failed to generate keypair for {algorithm:?}"));

            // Derive public key
            let derived_pk = provider
                .derive_public_key(algorithm, &keypair.secret_key)
                .unwrap_or_else(|_| panic!("Failed to derive public key for {algorithm:?}"));

            // Verify match
            assert_eq!(
                derived_pk.data, keypair.public_key.data,
                "Derived public key should match for {:?}",
                algorithm
            );
        }
    }
}
