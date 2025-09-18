//! Tests for WASM support in lib-q-sig
//!
//! These tests verify that the signature implementations work correctly
//! in WASM environments with JavaScript bindings.

#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[cfg(feature = "wasm")]
wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(all(feature = "ml-dsa", feature = "wasm"))]
use lib_q_sig::ml_dsa::{
    MlDsa,
    WasmMlDsaKeyPair,
};
#[cfg(all(feature = "slh-dsa", feature = "wasm"))]
use lib_q_sig::slh_dsa::{
    SlhDsa,
    WasmSlhDsaKeyPair,
};

#[cfg(feature = "slh-dsa")]
#[cfg(feature = "wasm")]
mod slh_dsa_wasm_tests {
    use super::*;

    /// Test SLH-DSA key generation in WASM environment
    #[wasm_bindgen_test]
    fn test_slh_dsa_key_generation_wasm() {
        let slh_dsa = SlhDsa::new();

        // Generate deterministic randomness
        let mut randomness = [0u8; 32];
        for i in 0..32 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let randomness_uint8 = Uint8Array::from(&randomness[..]);

        let keypair = slh_dsa
            .generate_keypair_wasm("SlhDsaShake256128fRobust", Some(randomness_uint8))
            .expect("Key generation should succeed");

        // Verify key sizes are reasonable
        assert!(keypair.public_key().length() > 0);
        assert!(keypair.secret_key().length() > 0);

        // Test that same randomness produces same keys
        let mut randomness2 = [0u8; 32];
        for i in 0..32 {
            randomness2[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let randomness2_uint8 = Uint8Array::from(&randomness2[..]);

        let keypair2 = slh_dsa
            .generate_keypair_wasm("SlhDsaShake256128fRobust", Some(randomness2_uint8))
            .expect("Key generation should succeed");

        // Convert to vectors for comparison
        let pk1: Vec<u8> = keypair.public_key().to_vec();
        let pk2: Vec<u8> = keypair2.public_key().to_vec();
        let sk1: Vec<u8> = keypair.secret_key().to_vec();
        let sk2: Vec<u8> = keypair2.secret_key().to_vec();

        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    /// Test SLH-DSA signing in WASM environment
    #[wasm_bindgen_test]
    fn test_slh_dsa_signing_wasm() {
        let slh_dsa = SlhDsa::new();

        // Generate keypair
        let mut key_randomness = [0u8; 32];
        for i in 0..32 {
            key_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

        let keypair = slh_dsa
            .generate_keypair_wasm("SlhDsaShake256128fRobust", Some(key_randomness_uint8))
            .expect("Key generation should succeed");

        // Sign message
        let message = b"Hello, WASM SLH-DSA!";
        let message_uint8 = Uint8Array::from(&message[..]);

        let mut signing_randomness = [0u8; 16];
        for i in 0..16 {
            signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

        let signature = slh_dsa
            .sign_wasm(
                "SlhDsaShake256128fRobust",
                keypair.secret_key(),
                message_uint8,
                Some(signing_randomness_uint8),
            )
            .expect("Signing should succeed");

        // Verify signature
        let is_valid = slh_dsa
            .verify_wasm(
                "SlhDsaShake256128fRobust",
                keypair.public_key(),
                message_uint8,
                signature,
            )
            .expect("Verification should succeed");

        assert!(is_valid);
    }

    /// Test SLH-DSA error handling in WASM environment
    #[wasm_bindgen_test]
    fn test_slh_dsa_wasm_error_handling() {
        let slh_dsa = SlhDsa::new();

        // Test with invalid algorithm
        let result = slh_dsa.generate_keypair_wasm("InvalidAlgorithm", None);
        assert!(result.is_err());

        // Test with invalid randomness size
        let small_randomness = Uint8Array::from(&[0u8; 8][..]);
        let result =
            slh_dsa.generate_keypair_wasm("SlhDsaShake256128fRobust", Some(small_randomness));
        // This should still work as we handle size mismatches gracefully
    }

    /// Test all SLH-DSA parameter sets in WASM environment
    #[wasm_bindgen_test]
    fn test_all_slh_dsa_parameter_sets_wasm() {
        let slh_dsa = SlhDsa::new();
        let algorithms = [
            "SlhDsaSha256128fRobust",
            "SlhDsaSha256192fRobust",
            "SlhDsaSha256256fRobust",
            "SlhDsaShake256128fRobust",
            "SlhDsaShake256192fRobust",
            "SlhDsaShake256256fRobust",
        ];

        for algorithm in algorithms {
            // Generate deterministic randomness
            let mut randomness = [0u8; 32];
            for i in 0..32 {
                randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }
            let randomness_uint8 = Uint8Array::from(&randomness[..]);

            let keypair = slh_dsa
                .generate_keypair_wasm(algorithm, Some(randomness_uint8))
                .expect("Key generation should succeed");

            let message = b"Test message for WASM";
            let message_uint8 = Uint8Array::from(&message[..]);

            let mut signing_randomness = [0u8; 16];
            for i in 0..16 {
                signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }
            let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

            let signature = slh_dsa
                .sign_wasm(
                    algorithm,
                    keypair.secret_key(),
                    message_uint8,
                    Some(signing_randomness_uint8),
                )
                .expect("Signing should succeed");

            let is_valid = slh_dsa
                .verify_wasm(algorithm, keypair.public_key(), message_uint8, signature)
                .expect("Verification should succeed");

            assert!(
                is_valid,
                "Signature should be valid for algorithm: {}",
                algorithm
            );
        }
    }
}

#[cfg(feature = "ml-dsa")]
#[cfg(feature = "wasm")]
mod ml_dsa_wasm_tests {
    use super::*;

    /// Test ML-DSA key generation in WASM environment
    #[wasm_bindgen_test]
    fn test_ml_dsa_key_generation_wasm() {
        let ml_dsa = MlDsa::ml_dsa_65();

        // Generate deterministic randomness
        let mut randomness = [0u8; 32]; // KEY_GENERATION_RANDOMNESS_SIZE
        for i in 0..32 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let randomness_uint8 = Uint8Array::from(&randomness[..]);

        let keypair = ml_dsa
            .generate_keypair_wasm(Some(randomness_uint8))
            .expect("Key generation should succeed");

        // Verify key sizes are reasonable
        assert!(keypair.public_key().length() > 0);
        assert!(keypair.secret_key().length() > 0);

        // Test that same randomness produces same keys
        let mut randomness2 = [0u8; 32];
        for i in 0..32 {
            randomness2[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let randomness2_uint8 = Uint8Array::from(&randomness2[..]);

        let keypair2 = ml_dsa
            .generate_keypair_wasm(Some(randomness2_uint8))
            .expect("Key generation should succeed");

        // Convert to vectors for comparison
        let pk1: Vec<u8> = keypair.public_key().to_vec();
        let pk2: Vec<u8> = keypair2.public_key().to_vec();
        let sk1: Vec<u8> = keypair.secret_key().to_vec();
        let sk2: Vec<u8> = keypair2.secret_key().to_vec();

        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    /// Test ML-DSA signing in WASM environment
    #[wasm_bindgen_test]
    fn test_ml_dsa_signing_wasm() {
        let ml_dsa = MlDsa::ml_dsa_65();

        // Generate keypair
        let mut key_randomness = [0u8; 32];
        for i in 0..32 {
            key_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

        let keypair = ml_dsa
            .generate_keypair_wasm(Some(key_randomness_uint8))
            .expect("Key generation should succeed");

        // Sign message
        let message = b"Hello, WASM ML-DSA!";
        let message_uint8 = Uint8Array::from(&message[..]);

        let mut signing_randomness = [0u8; 32]; // SIGNING_RANDOMNESS_SIZE
        for i in 0..32 {
            signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

        let signature = ml_dsa
            .sign_wasm(
                keypair.secret_key(),
                message_uint8,
                Some(signing_randomness_uint8),
            )
            .expect("Signing should succeed");

        // Verify signature
        let is_valid = ml_dsa
            .verify_wasm(keypair.public_key(), message_uint8, signature)
            .expect("Verification should succeed");

        assert!(is_valid);
    }

    /// Test all ML-DSA variants in WASM environment
    #[wasm_bindgen_test]
    fn test_all_ml_dsa_variants_wasm() {
        let variants = [MlDsa::ml_dsa_44(), MlDsa::ml_dsa_65(), MlDsa::ml_dsa_87()];

        for ml_dsa in variants {
            // Generate deterministic randomness
            let mut key_randomness = [0u8; 32];
            for i in 0..32 {
                key_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }
            let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

            let keypair = ml_dsa
                .generate_keypair_wasm(Some(key_randomness_uint8))
                .expect("Key generation should succeed");

            let message = b"Test message for WASM ML-DSA";
            let message_uint8 = Uint8Array::from(&message[..]);

            let mut signing_randomness = [0u8; 32];
            for i in 0..32 {
                signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }
            let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

            let signature = ml_dsa
                .sign_wasm(
                    keypair.secret_key(),
                    message_uint8,
                    Some(signing_randomness_uint8),
                )
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify_wasm(keypair.public_key(), message_uint8, signature)
                .expect("Verification should succeed");

            assert!(is_valid, "Signature should be valid");
        }
    }
}
