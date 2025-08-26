//! lib-Q KEM - Post-quantum Key Encapsulation Mechanisms
//!
//! This crate provides implementations of post-quantum key encapsulation mechanisms.

use lib_q_core::{
    Algorithm,
    Error,
    Kem,
};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "ml-kem")]
pub mod ml_kem;

/// Get a list of available KEM algorithms
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn available_algorithms() -> Vec<Algorithm> {
    #[allow(unused_mut)]
    let mut algorithms = Vec::new();
    #[cfg(feature = "ml-kem")]
    {
        algorithms.push(Algorithm::MlKem512);
        algorithms.push(Algorithm::MlKem768);
        algorithms.push(Algorithm::MlKem1024);
    }
    algorithms
}

/// Create a KEM instance for the specified algorithm
pub fn create_kem(algorithm: Algorithm) -> Result<Box<dyn Kem>, Error> {
    match algorithm {
        #[cfg(feature = "ml-kem")]
        Algorithm::MlKem512 => Ok(Box::new(ml_kem::MlKem512Impl::default())),
        #[cfg(feature = "ml-kem")]
        Algorithm::MlKem768 => Ok(Box::new(ml_kem::MlKem768Impl::default())),
        #[cfg(feature = "ml-kem")]
        Algorithm::MlKem1024 => Ok(Box::new(ml_kem::MlKem1024Impl::default())),
        _ => Err(Error::InvalidAlgorithm {
            algorithm: "Unknown KEM algorithm",
        }),
    }
}

/// WASM-friendly wrapper for KEM operations
#[cfg(feature = "wasm")]
pub mod wasm {
    use lib_q_core::{
        KemKeypair,
        KemPublicKey,
        KemSecretKey,
    };
    #[allow(unused_imports)]
    use wasm_bindgen::{
        JsError,
        prelude::*,
    };

    use super::*;

    /// Generate a keypair for the specified algorithm (WASM)
    #[wasm_bindgen]
    pub fn generate_keypair(algorithm: Algorithm) -> Result<KemKeypair, JsError> {
        let kem = create_kem(algorithm).map_err(|e| JsError::new(&e.to_string()))?;
        kem.generate_keypair()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn encapsulate(
        algorithm: Algorithm,
        public_key: &KemPublicKey,
    ) -> Result<EncapsulationResult, JsError> {
        let kem = create_kem(algorithm).map_err(|e| JsError::new(&e.to_string()))?;
        let (ciphertext, shared_secret) = kem
            .encapsulate(public_key)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(EncapsulationResult::new(ciphertext, shared_secret))
    }

    /// Decapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn decapsulate(
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let kem = create_kem(algorithm).map_err(|e| JsError::new(&e.to_string()))?;
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
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        assert!(
            !algorithms.is_empty(),
            "Should have at least one algorithm available"
        );
        for algorithm in algorithms {
            let kem = create_kem(algorithm);
            assert!(
                kem.is_ok(),
                "Should be able to create KEM for {:?}",
                algorithm
            );
        }
    }

    #[test]
    fn test_create_kem_instances() {
        let algorithms = available_algorithms();
        for algorithm in algorithms {
            let kem = create_kem(algorithm).unwrap();
            let keypair = kem.generate_keypair();
            assert!(
                keypair.is_ok(),
                "Should be able to generate keypair for {:?}",
                algorithm
            );
        }
    }

    #[test]
    fn test_unsupported_algorithm() {
        let result = create_kem(Algorithm::MlDsa65);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );
    }
}
