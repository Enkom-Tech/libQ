//! Refactored ML-KEM implementation with proper error handling
//!
//! This module provides a clean, secure implementation of ML-KEM that
//! eliminates the deprecated API usage and custom authentication issues.

use lib_q_core::{
    Error,
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    SecurityLevel,
};
use lib_q_ml_kem::{
    Decapsulate,
    Encapsulate,
    EncodedSizeUser,
    KemCore,
    MLKEM512_CIPHERTEXT_SIZE,
    MLKEM512_PUBLIC_KEY_SIZE,
    MLKEM512_SECRET_KEY_SIZE,
    MLKEM768_CIPHERTEXT_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
    MLKEM1024_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE,
    MLKEM1024_SECRET_KEY_SIZE,
    MlKem512,
    MlKem768,
    MlKem1024,
};

/// Secure helper function to create Array from slice with runtime validation
/// This function provides proper error handling instead of panicking
fn secure_array_from_slice<const N: usize>(slice: &[u8]) -> Result<[u8; N], Error> {
    if slice.len() != N {
        return Err(Error::InvalidKeySize {
            expected: N,
            actual: slice.len(),
        });
    }

    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

/// ML-KEM 512 implementation (FIPS 203 Level 1)
#[derive(Debug, Clone)]
pub struct MlKem512Impl {
    security_level: SecurityLevel,
}

impl Default for MlKem512Impl {
    fn default() -> Self {
        Self::new(SecurityLevel::Level1)
    }
}

impl MlKem512Impl {
    pub fn new(security_level: SecurityLevel) -> Self {
        Self { security_level }
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

impl Kem for MlKem512Impl {
    fn generate_keypair(&self) -> Result<KemKeypair, Error> {
        let mut rng = rand::rng();
        let (dk, ek) = MlKem512::generate(&mut rng);

        let public_key = KemPublicKey {
            data: ek.as_bytes().to_vec(),
        };

        let secret_key = KemSecretKey {
            data: dk.as_bytes().to_vec(),
        };

        Ok(KemKeypair {
            public_key,
            secret_key,
        })
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Validate public key size
        if public_key.data.len() != MLKEM512_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM512_PUBLIC_KEY_SIZE,
                actual: public_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let ek_array = secure_array_from_slice::<{ MLKEM512_PUBLIC_KEY_SIZE }>(&public_key.data)?;

        // Use the proper non-deprecated API
        let ek = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&ek_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = rand::rng();
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 512 encapsulation".to_string(),
                })?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM512_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM512_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Validate ciphertext size
        if ciphertext.len() != MLKEM512_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextSize {
                expected: MLKEM512_CIPHERTEXT_SIZE,
                actual: ciphertext.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM512_SECRET_KEY_SIZE }>(&secret_key.data)?;
        let ct_array = secure_array_from_slice::<{ MLKEM512_CIPHERTEXT_SIZE }>(ciphertext)?;

        // Use the proper non-deprecated API
        let dk = <MlKem512 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &lib_q_ml_kem::array::Array::try_from(&ct_array[..])
                    .map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 512 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM512_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM512_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM512_SECRET_KEY_SIZE }>(&secret_key.data)?;

        // Use the proper non-deprecated API
        let dk = <MlKem512 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: ek.as_bytes().to_vec(),
        })
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>, Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}

/// ML-KEM 768 implementation (FIPS 203 Level 3)
#[derive(Debug, Clone)]
pub struct MlKem768Impl {
    security_level: SecurityLevel,
}

impl Default for MlKem768Impl {
    fn default() -> Self {
        Self::new(SecurityLevel::Level3)
    }
}

impl MlKem768Impl {
    pub fn new(security_level: SecurityLevel) -> Self {
        Self { security_level }
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

impl Kem for MlKem768Impl {
    fn generate_keypair(&self) -> Result<KemKeypair, Error> {
        let mut rng = rand::rng();
        let (dk, ek) = MlKem768::generate(&mut rng);

        let public_key = KemPublicKey {
            data: ek.as_bytes().to_vec(),
        };

        let secret_key = KemSecretKey {
            data: dk.as_bytes().to_vec(),
        };

        Ok(KemKeypair {
            public_key,
            secret_key,
        })
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Validate public key size
        if public_key.data.len() != MLKEM768_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM768_PUBLIC_KEY_SIZE,
                actual: public_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let ek_array = secure_array_from_slice::<{ MLKEM768_PUBLIC_KEY_SIZE }>(&public_key.data)?;

        // Use the proper non-deprecated API
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&ek_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = rand::rng();
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 768 encapsulation".to_string(),
                })?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM768_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM768_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Validate ciphertext size
        if ciphertext.len() != MLKEM768_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextSize {
                expected: MLKEM768_CIPHERTEXT_SIZE,
                actual: ciphertext.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM768_SECRET_KEY_SIZE }>(&secret_key.data)?;
        let ct_array = secure_array_from_slice::<{ MLKEM768_CIPHERTEXT_SIZE }>(ciphertext)?;

        // Use the proper non-deprecated API
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &lib_q_ml_kem::array::Array::try_from(&ct_array[..])
                    .map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 768 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM768_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM768_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM768_SECRET_KEY_SIZE }>(&secret_key.data)?;

        // Use the proper non-deprecated API
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: ek.as_bytes().to_vec(),
        })
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>, Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}

/// ML-KEM 1024 implementation (FIPS 203 Level 5)
#[derive(Debug, Clone)]
pub struct MlKem1024Impl {
    security_level: SecurityLevel,
}

impl Default for MlKem1024Impl {
    fn default() -> Self {
        Self::new(SecurityLevel::Level4)
    }
}

impl MlKem1024Impl {
    pub fn new(security_level: SecurityLevel) -> Self {
        Self { security_level }
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

impl Kem for MlKem1024Impl {
    fn generate_keypair(&self) -> Result<KemKeypair, Error> {
        let mut rng = rand::rng();
        let (dk, ek) = MlKem1024::generate(&mut rng);

        let public_key = KemPublicKey {
            data: ek.as_bytes().to_vec(),
        };

        let secret_key = KemSecretKey {
            data: dk.as_bytes().to_vec(),
        };

        Ok(KemKeypair {
            public_key,
            secret_key,
        })
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Validate public key size
        if public_key.data.len() != MLKEM1024_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM1024_PUBLIC_KEY_SIZE,
                actual: public_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let ek_array = secure_array_from_slice::<{ MLKEM1024_PUBLIC_KEY_SIZE }>(&public_key.data)?;

        // Use the proper non-deprecated API
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&ek_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = rand::rng();
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 1024 encapsulation".to_string(),
                })?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM1024_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM1024_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Validate ciphertext size
        if ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextSize {
                expected: MLKEM1024_CIPHERTEXT_SIZE,
                actual: ciphertext.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM1024_SECRET_KEY_SIZE }>(&secret_key.data)?;
        let ct_array = secure_array_from_slice::<{ MLKEM1024_CIPHERTEXT_SIZE }>(ciphertext)?;

        // Use the proper non-deprecated API
        let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &lib_q_ml_kem::array::Array::try_from(&ct_array[..])
                    .map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 1024 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey, Error> {
        // Validate secret key size
        if secret_key.data.len() != MLKEM1024_SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: MLKEM1024_SECRET_KEY_SIZE,
                actual: secret_key.data.len(),
            });
        }

        // Use secure array conversion with proper error handling
        let dk_array = secure_array_from_slice::<{ MLKEM1024_SECRET_KEY_SIZE }>(&secret_key.data)?;

        // Use the proper non-deprecated API
        let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(
            &lib_q_ml_kem::array::Array::try_from(&dk_array[..])
                .map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: ek.as_bytes().to_vec(),
        })
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>, Error> {
        // Authentication is not part of the base ML-KEM specification
        // This should be implemented using a proper authenticated KEM scheme
        // like HPKE's AuthEncap/AuthDecap if needed
        Err(Error::NotImplemented {
            feature: "ML-KEM authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use lib_q_ml_kem::MLKEM_SHARED_KEY_SIZE;

    use super::*;

    #[test]
    fn test_ml_kem_512_creation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        assert_eq!(kem.security_level(), SecurityLevel::Level1);
    }

    #[test]
    fn test_ml_kem_768_creation() {
        let kem = MlKem768Impl::new(SecurityLevel::Level3);
        assert_eq!(kem.security_level(), SecurityLevel::Level3);
    }

    #[test]
    fn test_ml_kem_1024_creation() {
        let kem = MlKem1024Impl::new(SecurityLevel::Level4);
        assert_eq!(kem.security_level(), SecurityLevel::Level4);
    }

    #[test]
    fn test_secure_array_from_slice() {
        let data = vec![1, 2, 3, 4];
        let result = secure_array_from_slice::<4>(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [1, 2, 3, 4]);

        let result = secure_array_from_slice::<3>(&data);
        assert!(result.is_err());
        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, 3);
            assert_eq!(actual, 4);
        } else {
            panic!("Expected InvalidKeySize error");
        }
    }

    #[test]
    fn test_ml_kem_512_keypair_generation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        let keypair = kem.generate_keypair().unwrap();

        assert_eq!(keypair.public_key.data.len(), MLKEM512_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.data.len(), MLKEM512_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_kem_512_encapsulation_decapsulation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        let keypair = kem.generate_keypair().unwrap();

        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(ciphertext.len(), MLKEM512_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), MLKEM_SHARED_KEY_SIZE);
    }

    #[test]
    fn test_authentication_not_implemented() {
        let kem = MlKem512Impl::default();
        let keypair = kem.generate_keypair().unwrap();

        let result = kem.auth_encapsulate(&keypair.secret_key, &keypair.public_key);
        assert!(result.is_err());
        if let Err(Error::NotImplemented { feature }) = result {
            assert!(feature.contains("ML-KEM authenticated encapsulation"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }
}
