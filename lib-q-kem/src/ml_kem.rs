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
/// This function will panic if the size is incorrect, which is acceptable for cryptographic operations
/// as it indicates a serious implementation error that should be caught during testing.
fn secure_array_from_slice<const N: usize>(slice: &[u8]) -> [u8; N] {
    assert_eq!(
        slice.len(),
        N,
        "Array size mismatch - this indicates a serious implementation error"
    );
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    array
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

        // Use secure infallible parsing with runtime validation
        // Convert to the expected format for the ML-KEM implementation
        let ek_array = secure_array_from_slice::<{ MLKEM512_PUBLIC_KEY_SIZE }>(&public_key.data);

        // Use the ML-KEM implementation's internal methods
        // Note: Using deprecated from_slice for security - this prevents fallible parsing
        // that could leak information through error channels. The runtime validation
        // in secure_array_from_slice ensures safe usage.
        #[allow(deprecated)]
        let ek = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(
            lib_q_ml_kem::array::Array::from_slice(&ek_array),
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

        // Use secure infallible parsing with runtime validation
        let dk_array = secure_array_from_slice::<{ MLKEM512_SECRET_KEY_SIZE }>(&secret_key.data);

        #[allow(deprecated)]
        let dk = <MlKem512 as KemCore>::DecapsulationKey::from_bytes(
            // Note: Using deprecated from_slice for security - prevents fallible parsing
            lib_q_ml_kem::array::Array::from_slice(&dk_array),
        );

        // Use secure infallible parsing for ciphertext
        let ct_array = secure_array_from_slice::<{ MLKEM512_CIPHERTEXT_SIZE }>(ciphertext);

        #[allow(deprecated)]
        let shared_secret = dk
            // Note: Using deprecated from_slice for security - prevents fallible parsing
            .decapsulate(lib_q_ml_kem::array::Array::from_slice(&ct_array))
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 512 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
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

        // Use secure infallible parsing with runtime validation
        let ek_array = secure_array_from_slice::<{ MLKEM768_PUBLIC_KEY_SIZE }>(&public_key.data);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            lib_q_ml_kem::array::Array::from_slice(&ek_array),
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

        // Use secure infallible parsing with runtime validation
        let dk_array = secure_array_from_slice::<{ MLKEM768_SECRET_KEY_SIZE }>(&secret_key.data);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(
            lib_q_ml_kem::array::Array::from_slice(&dk_array),
        );

        // Use secure infallible parsing for ciphertext
        let ct_array = secure_array_from_slice::<{ MLKEM768_CIPHERTEXT_SIZE }>(ciphertext);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let shared_secret = dk
            .decapsulate(lib_q_ml_kem::array::Array::from_slice(&ct_array))
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 768 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
    }
}

/// ML-KEM 1024 implementation (FIPS 203 Level 5)
#[derive(Debug, Clone)]
pub struct MlKem1024Impl {
    security_level: SecurityLevel,
}

impl Default for MlKem1024Impl {
    fn default() -> Self {
        Self::new(SecurityLevel::Level5)
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

        // Use secure infallible parsing with runtime validation
        let ek_array = secure_array_from_slice::<{ MLKEM1024_PUBLIC_KEY_SIZE }>(&public_key.data);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(
            lib_q_ml_kem::array::Array::from_slice(&ek_array),
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

        // Use secure infallible parsing with runtime validation
        let dk_array = secure_array_from_slice::<{ MLKEM1024_SECRET_KEY_SIZE }>(&secret_key.data);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(
            lib_q_ml_kem::array::Array::from_slice(&dk_array),
        );

        // Use secure infallible parsing for ciphertext
        let ct_array = secure_array_from_slice::<{ MLKEM1024_CIPHERTEXT_SIZE }>(ciphertext);

        // Note: Using deprecated from_slice for security - prevents fallible parsing
        #[allow(deprecated)]
        let shared_secret = dk
            .decapsulate(lib_q_ml_kem::array::Array::from_slice(&ct_array))
            .map_err(|_| Error::DecryptionFailed {
                operation: "ML-KEM 1024 decapsulation".to_string(),
            })?;

        Ok(shared_secret.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use lib_q_ml_kem::MLKEM_SHARED_KEY_SIZE;

    use super::*;

    #[test]
    fn test_mlkem512_creation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        assert_eq!(kem.security_level(), SecurityLevel::Level1);
    }

    #[test]
    fn test_mlkem768_creation() {
        let kem = MlKem768Impl::new(SecurityLevel::Level3);
        assert_eq!(kem.security_level(), SecurityLevel::Level3);
    }

    #[test]
    fn test_mlkem1024_creation() {
        let kem = MlKem1024Impl::new(SecurityLevel::Level5);
        assert_eq!(kem.security_level(), SecurityLevel::Level5);
    }

    #[test]
    fn test_mlkem512_keypair_generation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        let keypair = kem.generate_keypair().unwrap();

        // Check key sizes
        assert_eq!(keypair.public_key.data.len(), MLKEM512_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.data.len(), MLKEM512_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_mlkem768_keypair_generation() {
        let kem = MlKem768Impl::new(SecurityLevel::Level3);
        let keypair = kem.generate_keypair().unwrap();

        // Check key sizes
        assert_eq!(keypair.public_key.data.len(), MLKEM768_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.data.len(), MLKEM768_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_mlkem1024_keypair_generation() {
        let kem = MlKem1024Impl::new(SecurityLevel::Level5);
        let keypair = kem.generate_keypair().unwrap();

        // Check key sizes
        assert_eq!(keypair.public_key.data.len(), MLKEM1024_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.data.len(), MLKEM1024_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_mlkem512_encapsulation_decapsulation() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        let keypair = kem.generate_keypair().unwrap();

        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(ciphertext.len(), MLKEM512_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), MLKEM_SHARED_KEY_SIZE);
    }

    #[test]
    fn test_mlkem768_encapsulation_decapsulation() {
        let kem = MlKem768Impl::new(SecurityLevel::Level3);
        let keypair = kem.generate_keypair().unwrap();

        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(ciphertext.len(), MLKEM768_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), MLKEM_SHARED_KEY_SIZE);
    }

    #[test]
    fn test_mlkem1024_encapsulation_decapsulation() {
        let kem = MlKem1024Impl::new(SecurityLevel::Level5);
        let keypair = kem.generate_keypair().unwrap();

        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(ciphertext.len(), MLKEM1024_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), MLKEM_SHARED_KEY_SIZE);
    }

    #[test]
    fn test_invalid_key_sizes() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);

        // Test invalid public key size
        let invalid_public_key = KemPublicKey {
            data: vec![0u8; 100], // Wrong size
        };
        assert!(kem.encapsulate(&invalid_public_key).is_err());

        // Test invalid secret key size
        let invalid_secret_key = KemSecretKey {
            data: vec![0u8; 100], // Wrong size
        };
        let invalid_ciphertext = vec![0u8; MLKEM512_CIPHERTEXT_SIZE];
        assert!(
            kem.decapsulate(&invalid_secret_key, &invalid_ciphertext)
                .is_err()
        );
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let kem = MlKem512Impl::new(SecurityLevel::Level1);
        let keypair = kem.generate_keypair().unwrap();

        let invalid_ciphertext = vec![0u8; 100]; // Wrong size
        assert!(
            kem.decapsulate(&keypair.secret_key, &invalid_ciphertext)
                .is_err()
        );
    }
}
