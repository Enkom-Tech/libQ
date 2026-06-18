//! ML-KEM implementations using lib-q-kem

#[cfg(all(feature = "alloc", feature = "ml-kem"))]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "ml-kem")]
use lib_q_core::{
    Algorithm,
    KemOperations,
};
#[cfg(feature = "ml-kem")]
use lib_q_kem::{
    LibQKemProvider,
    available_algorithms,
};
#[cfg(feature = "alloc")]
use zeroize::Zeroizing;

use crate::error::{
    HpkeError,
    KemOperation,
};
use crate::kem::traits::Kem;
use crate::types::*;

/// ML-KEM implementation using lib-q-kem
pub struct MlKemImpl {
    variant: HpkeKem,
    #[cfg(feature = "ml-kem")]
    provider: LibQKemProvider,
}

impl MlKemImpl {
    /// Create a new ML-KEM implementation
    pub fn new(variant: HpkeKem) -> Result<Self, HpkeError> {
        #[cfg(feature = "ml-kem")]
        {
            let provider = LibQKemProvider::new().map_err(|e| {
                HpkeError::kem_error(
                    variant,
                    KemOperation::KeyGeneration,
                    format!("Failed to create KEM provider: {}", e),
                )
            })?;

            Ok(Self { variant, provider })
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            Err(HpkeError::feature_not_enabled("ML-KEM support"))
        }
    }

    /// Get the HPKE KEM variant
    pub fn variant(&self) -> HpkeKem {
        self.variant
    }
}

impl Kem for MlKemImpl {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        #[cfg(feature = "ml-kem")]
        {
            let algorithm = match self.variant {
                HpkeKem::MlKem512 => Algorithm::MlKem512,
                HpkeKem::MlKem768 => Algorithm::MlKem768,
                HpkeKem::MlKem1024 => Algorithm::MlKem1024,
            };

            let keypair = self
                .provider
                .generate_keypair(algorithm, None)
                .map_err(|e| {
                    HpkeError::kem_error(
                        self.variant,
                        KemOperation::KeyGeneration,
                        format!("Key generation failed: {}", e),
                    )
                })?;

            Ok((
                keypair.public_key().as_bytes().to_vec(),
                Zeroizing::new(keypair.secret_key().as_bytes().to_vec()),
            ))
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            Err(HpkeError::feature_not_enabled("ML-KEM support"))
        }
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError> {
        #[cfg(feature = "ml-kem")]
        {
            let algorithm = match self.variant {
                HpkeKem::MlKem512 => Algorithm::MlKem512,
                HpkeKem::MlKem768 => Algorithm::MlKem768,
                HpkeKem::MlKem1024 => Algorithm::MlKem1024,
            };

            let pk = lib_q_core::KemPublicKey::new(public_key.to_vec());
            let (ciphertext, shared_secret) = self
                .provider
                .encapsulate(algorithm, &pk, None)
                .map_err(|e| {
                    HpkeError::kem_error(
                        self.variant,
                        KemOperation::Encapsulation,
                        format!("Encapsulation failed: {}", e),
                    )
                })?;

            Ok((ciphertext, Zeroizing::new(shared_secret)))
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            Err(HpkeError::feature_not_enabled("ML-KEM support"))
        }
    }

    fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        #[cfg(feature = "ml-kem")]
        {
            let algorithm = match self.variant {
                HpkeKem::MlKem512 => Algorithm::MlKem512,
                HpkeKem::MlKem768 => Algorithm::MlKem768,
                HpkeKem::MlKem1024 => Algorithm::MlKem1024,
            };

            let sk = lib_q_core::KemSecretKey::new(secret_key.to_vec());
            let shared_secret = self
                .provider
                .decapsulate(algorithm, &sk, ciphertext)
                .map_err(|e| {
                    HpkeError::kem_error(
                        self.variant,
                        KemOperation::Decapsulation,
                        format!("Decapsulation failed: {}", e),
                    )
                })?;

            Ok(Zeroizing::new(shared_secret))
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            Err(HpkeError::feature_not_enabled("ML-KEM support"))
        }
    }
}

/// Create an ML-KEM implementation for the given variant
pub fn create_ml_kem(variant: HpkeKem) -> Result<MlKemImpl, HpkeError> {
    MlKemImpl::new(variant)
}

/// Check if ML-KEM is available
pub fn is_ml_kem_available() -> bool {
    #[cfg(feature = "ml-kem")]
    {
        !available_algorithms().is_empty()
    }
    #[cfg(not(feature = "ml-kem"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_availability() {
        let available = is_ml_kem_available();
        #[cfg(feature = "ml-kem")]
        assert!(available);
        #[cfg(not(feature = "ml-kem"))]
        assert!(!available);
    }

    #[test]
    fn test_ml_kem_creation() {
        let result = MlKemImpl::new(HpkeKem::MlKem512);
        #[cfg(feature = "ml-kem")]
        assert!(result.is_ok());
        #[cfg(not(feature = "ml-kem"))]
        assert!(result.is_err());
    }

    #[cfg(feature = "ml-kem")]
    #[test]
    fn test_ml_kem_operations() {
        let kem = MlKemImpl::new(HpkeKem::MlKem512).unwrap();

        // Generate keypair
        let (public_key, secret_key) = kem.generate_keypair().unwrap();
        assert!(!public_key.is_empty());
        assert!(!secret_key.is_empty());

        // Encapsulate
        let (ciphertext, shared_secret) = kem.encapsulate(&public_key).unwrap();
        assert!(!ciphertext.is_empty());
        assert!(!shared_secret.is_empty());

        // Decapsulate
        let decapsulated_secret = kem.decapsulate(&secret_key, &ciphertext).unwrap();
        assert_eq!(*shared_secret, *decapsulated_secret);
    }
}
