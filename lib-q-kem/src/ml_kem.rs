//! Refactored ML-KEM implementation with proper error handling
//!
//! This module provides a clean, secure implementation of ML-KEM that
//! eliminates the deprecated API usage and custom authentication issues.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::ToString,
    vec::Vec,
};

use lib_q_core::{
    Error,
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    SecurityLevel,
};
use lib_q_ml_kem::array::Array;
use lib_q_ml_kem::{
    ArraySize,
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
    Zeroizing,
};
use lib_q_random::new_secure_rng;

/// Copy a [`Zeroizing`] ML-KEM wire encoding (e.g. from [`EncodedSizeUser::as_bytes`]) into a `Vec`.
#[inline]
fn kem_zeroizing_encoding_to_vec<S: ArraySize>(encoded: Zeroizing<Array<u8, S>>) -> Vec<u8> {
    Vec::from(encoded.as_slice())
}

/// Copy a plain [`Array`] encoding into a `Vec`, wrapping the value in [`Zeroizing`] so the stack
/// buffer is cleared after the copy (used for ciphertexts and shared secrets from encapsulate).
#[inline]
fn kem_array_soft_zero_to_vec<S: ArraySize>(encoded: Array<u8, S>) -> Vec<u8> {
    let enc = Zeroizing::new(encoded);
    Vec::from(enc.as_slice())
}

/// Copy validated fixed-length material into a [`Zeroizing`] stack buffer (plain `[u8; N]` does not
/// clear on drop).
fn secure_array_from_slice<const N: usize>(slice: &[u8]) -> Result<Zeroizing<[u8; N]>, Error> {
    if slice.len() != N {
        return Err(Error::InvalidKeySize {
            expected: N,
            actual: slice.len(),
        });
    }

    let mut array = Zeroizing::new([0u8; N]);
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
        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (dk, ek) = MlKem512::generate(&mut rng);

        let public_key = KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
        };

        let secret_key = KemSecretKey {
            data: kem_zeroizing_encoding_to_vec(dk.as_bytes()),
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
            &Array::try_from(ek_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 512 encapsulation".to_string(),
                })?;

        Ok((
            kem_array_soft_zero_to_vec(ciphertext),
            kem_array_soft_zero_to_vec(shared_secret),
        ))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &Array::try_from(ct_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 512 decapsulation".to_string(),
            })?;

        Ok(kem_array_soft_zero_to_vec(shared_secret))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
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
        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (dk, ek) = MlKem768::generate(&mut rng);

        let public_key = KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
        };

        let secret_key = KemSecretKey {
            data: kem_zeroizing_encoding_to_vec(dk.as_bytes()),
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
            &Array::try_from(ek_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 768 encapsulation".to_string(),
                })?;

        Ok((
            kem_array_soft_zero_to_vec(ciphertext),
            kem_array_soft_zero_to_vec(shared_secret),
        ))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &Array::try_from(ct_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 768 decapsulation".to_string(),
            })?;

        Ok(kem_array_soft_zero_to_vec(shared_secret))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
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
        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (dk, ek) = MlKem1024::generate(&mut rng);

        let public_key = KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
        };

        let secret_key = KemSecretKey {
            data: kem_zeroizing_encoding_to_vec(dk.as_bytes()),
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
            &Array::try_from(ek_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let mut rng = new_secure_rng().map_err(|e| Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        let (ciphertext, shared_secret) =
            ek.encapsulate(&mut rng)
                .map_err(|_| Error::EncryptionFailed {
                    operation: "ML-KEM 1024 encapsulation".to_string(),
                })?;

        Ok((
            kem_array_soft_zero_to_vec(ciphertext),
            kem_array_soft_zero_to_vec(shared_secret),
        ))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        let shared_secret = dk
            .decapsulate(
                &Array::try_from(ct_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
            )
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 1024 decapsulation".to_string(),
            })?;

        Ok(kem_array_soft_zero_to_vec(shared_secret))
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
            &Array::try_from(dk_array.as_slice()).map_err(|_| Error::InvalidKeyFormat)?,
        );

        // Derive public key from secret key
        let ek = dk.encapsulation_key();

        Ok(KemPublicKey {
            data: kem_zeroizing_encoding_to_vec(ek.as_bytes()),
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
        let data = alloc::vec![1, 2, 3, 4];
        let result = secure_array_from_slice::<4>(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_slice(), &[1, 2, 3, 4]);

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

    #[test]
    fn test_ml_kem_768_and_1024_roundtrip_and_derive() {
        let kem768 = MlKem768Impl::default();
        let keypair768 = kem768.generate_keypair().unwrap();
        let (ct768, ss768_a) = kem768.encapsulate(&keypair768.public_key).unwrap();
        let ss768_b = kem768.decapsulate(&keypair768.secret_key, &ct768).unwrap();
        assert_eq!(ss768_a, ss768_b);
        assert_eq!(ct768.len(), MLKEM768_CIPHERTEXT_SIZE);
        assert_eq!(ss768_a.len(), MLKEM_SHARED_KEY_SIZE);
        let derived768 = kem768.derive_public_key(&keypair768.secret_key).unwrap();
        assert_eq!(derived768.data, keypair768.public_key.data);

        let kem1024 = MlKem1024Impl::default();
        let keypair1024 = kem1024.generate_keypair().unwrap();
        let (ct1024, ss1024_a) = kem1024.encapsulate(&keypair1024.public_key).unwrap();
        let ss1024_b = kem1024
            .decapsulate(&keypair1024.secret_key, &ct1024)
            .unwrap();
        assert_eq!(ss1024_a, ss1024_b);
        assert_eq!(ct1024.len(), MLKEM1024_CIPHERTEXT_SIZE);
        assert_eq!(ss1024_a.len(), MLKEM_SHARED_KEY_SIZE);
        let derived1024 = kem1024.derive_public_key(&keypair1024.secret_key).unwrap();
        assert_eq!(derived1024.data, keypair1024.public_key.data);
    }

    #[test]
    fn test_ml_kem_768_and_1024_error_paths_and_auth_decapsulate() {
        let kem768 = MlKem768Impl::default();
        let keypair768 = kem768.generate_keypair().unwrap();
        let bad_pk768 = KemPublicKey::new(alloc::vec![0u8; MLKEM768_PUBLIC_KEY_SIZE - 1]);
        let encapsulate_err = kem768.encapsulate(&bad_pk768);
        assert!(matches!(
            encapsulate_err,
            Err(Error::InvalidKeySize { expected, actual })
                if expected == MLKEM768_PUBLIC_KEY_SIZE && actual == MLKEM768_PUBLIC_KEY_SIZE - 1
        ));
        let bad_sk768 = KemSecretKey::new(alloc::vec![0u8; MLKEM768_SECRET_KEY_SIZE - 1]);
        let bad_ct768 = alloc::vec![0u8; MLKEM768_CIPHERTEXT_SIZE];
        let decapsulate_err = kem768.decapsulate(&bad_sk768, &bad_ct768);
        assert!(matches!(
            decapsulate_err,
            Err(Error::InvalidKeySize { expected, actual })
                if expected == MLKEM768_SECRET_KEY_SIZE && actual == MLKEM768_SECRET_KEY_SIZE - 1
        ));
        let auth_decap_err_768 =
            kem768.auth_decapsulate(&keypair768.secret_key, &bad_ct768, &keypair768.public_key);
        assert!(matches!(
            auth_decap_err_768,
            Err(Error::NotImplemented { .. })
        ));

        let kem1024 = MlKem1024Impl::default();
        let keypair1024 = kem1024.generate_keypair().unwrap();
        let bad_pk1024 = KemPublicKey::new(alloc::vec![0u8; MLKEM1024_PUBLIC_KEY_SIZE - 1]);
        let encapsulate_err = kem1024.encapsulate(&bad_pk1024);
        assert!(matches!(
            encapsulate_err,
            Err(Error::InvalidKeySize { expected, actual })
                if expected == MLKEM1024_PUBLIC_KEY_SIZE && actual == MLKEM1024_PUBLIC_KEY_SIZE - 1
        ));
        let bad_ct1024 = alloc::vec![0u8; MLKEM1024_CIPHERTEXT_SIZE - 1];
        let decapsulate_err = kem1024.decapsulate(&keypair1024.secret_key, &bad_ct1024);
        assert!(matches!(
            decapsulate_err,
            Err(Error::InvalidCiphertextSize { expected, actual })
                if expected == MLKEM1024_CIPHERTEXT_SIZE && actual == MLKEM1024_CIPHERTEXT_SIZE - 1
        ));
        let auth_decap_err_1024 = kem1024.auth_decapsulate(
            &keypair1024.secret_key,
            &bad_ct1024,
            &keypair1024.public_key,
        );
        assert!(matches!(
            auth_decap_err_1024,
            Err(Error::NotImplemented { .. })
        ));
    }
}
