//! Tests for WASM support in lib-q-sig
//!
//! These tests verify that the signature implementations work correctly
//! in WASM environments with JavaScript bindings.

#![allow(clippy::needless_range_loop)]

#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[cfg(feature = "wasm")]
wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(all(feature = "ml-dsa", feature = "wasm"))]
use lib_q_sig::ml_dsa::MlDsa;
#[cfg(all(feature = "slh-dsa", feature = "wasm"))]
use lib_q_sig::slh_dsa::SlhDsa;

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
        for (i, byte) in randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
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
        for (i, byte) in randomness2.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
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
        for (i, byte) in key_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

        let keypair = slh_dsa
            .generate_keypair_wasm("SlhDsaShake256128fRobust", Some(key_randomness_uint8))
            .expect("Key generation should succeed");

        // Sign message
        let message = b"Hello, WASM SLH-DSA!";
        let message_uint8 = Uint8Array::from(&message[..]);

        let mut signing_randomness = [0u8; 16];
        for (i, byte) in signing_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

        let signature = slh_dsa
            .sign_wasm(
                "SlhDsaShake256128fRobust",
                keypair.secret_key(),
                message_uint8.clone(),
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

        // verify_wasm with wrong algorithm string must error
        let mut key_randomness = [0u8; 32];
        for (i, byte) in key_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let kp = slh_dsa
            .generate_keypair_wasm(
                "SlhDsaShake256128fRobust",
                Some(Uint8Array::from(&key_randomness[..])),
            )
            .expect("keygen");
        let msg = Uint8Array::from(b"m".as_slice());
        let mut signing_randomness = [0u8; 16];
        for (i, byte) in signing_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let sig = slh_dsa
            .sign_wasm(
                "SlhDsaShake256128fRobust",
                kp.secret_key(),
                msg.clone(),
                Some(Uint8Array::from(&signing_randomness[..])),
            )
            .expect("sign");
        let bad_alg = slh_dsa.verify_wasm("WrongAlgName", kp.public_key(), msg, sig);
        assert!(
            bad_alg.is_err(),
            "invalid algorithm in verify_wasm must error"
        );

        // Test with invalid randomness size
        let small_randomness = Uint8Array::from(&[0u8; 8][..]);
        let _result =
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
            for (i, byte) in randomness.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }
            let randomness_uint8 = Uint8Array::from(&randomness[..]);

            let keypair = slh_dsa
                .generate_keypair_wasm(algorithm, Some(randomness_uint8))
                .expect("Key generation should succeed");

            let message = b"Test message for WASM";
            let message_uint8 = Uint8Array::from(&message[..]);

            let mut signing_randomness = [0u8; 16];
            for (i, byte) in signing_randomness.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }
            let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

            let signature = slh_dsa
                .sign_wasm(
                    algorithm,
                    keypair.secret_key(),
                    message_uint8.clone(),
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
        for (i, byte) in randomness2.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
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
        for (i, byte) in key_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

        let keypair = ml_dsa
            .generate_keypair_wasm(Some(key_randomness_uint8))
            .expect("Key generation should succeed");

        // Sign message
        let message = b"Hello, WASM ML-DSA!";
        let message_uint8 = Uint8Array::from(&message[..]);

        let mut signing_randomness = [0u8; 32]; // SIGNING_RANDOMNESS_SIZE
        for (i, byte) in signing_randomness.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

        let signature = ml_dsa
            .sign_wasm(
                keypair.secret_key(),
                message_uint8.clone(),
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
            for (i, byte) in key_randomness.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }
            let key_randomness_uint8 = Uint8Array::from(&key_randomness[..]);

            let keypair = ml_dsa
                .generate_keypair_wasm(Some(key_randomness_uint8))
                .expect("Key generation should succeed");

            let message = b"Test message for WASM ML-DSA";
            let message_uint8 = Uint8Array::from(&message[..]);

            let mut signing_randomness = [0u8; 32];
            for (i, byte) in signing_randomness.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }
            let signing_randomness_uint8 = Uint8Array::from(&signing_randomness[..]);

            let signature = ml_dsa
                .sign_wasm(
                    keypair.secret_key(),
                    message_uint8.clone(),
                    Some(signing_randomness_uint8),
                )
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify_wasm(keypair.public_key(), message_uint8, signature)
                .expect("Verification should succeed");

            assert!(is_valid, "Signature should be valid");
        }
    }

    /// Wrong public key must not verify as valid.
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_wrong_public_key() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp_a = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen a");
        let kp_b = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32_b()[..],
            )))
            .expect("keygen b");

        let message = Uint8Array::from(b"same message".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let sig = ml_dsa
            .sign_wasm(kp_a.secret_key(), message.clone(), Some(signing_r))
            .expect("sign");

        let ok = ml_dsa
            .verify_wasm(kp_b.public_key(), message, sig)
            .expect("verify call completes");
        assert!(!ok, "wrong public key must yield false");
    }

    /// Tampered message must not verify.
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_tampered_message() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"original msg".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let sig = ml_dsa
            .sign_wasm(kp.secret_key(), message.clone(), Some(signing_r))
            .expect("sign");

        let mut tampered = message.to_vec();
        tampered[0] ^= 1;
        let tampered_u8 = Uint8Array::from(&tampered[..]);

        let ok = ml_dsa
            .verify_wasm(kp.public_key(), tampered_u8, sig)
            .expect("verify");
        assert!(!ok, "tampered message must yield false");
    }

    /// One flipped bit in signature must not verify.
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_flipped_signature_bit() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"msg".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let mut sig_vec = ml_dsa
            .sign_wasm(kp.secret_key(), message.clone(), Some(signing_r))
            .expect("sign")
            .to_vec();
        sig_vec[0] ^= 0xFF;
        let bad_sig = Uint8Array::from(&sig_vec[..]);

        let ok = ml_dsa
            .verify_wasm(kp.public_key(), message, bad_sig)
            .expect("verify");
        assert!(!ok, "corrupted signature must yield false");
    }

    /// Random signature of correct length must not verify (whp).
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_random_signature_same_length() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"hello wasm".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let good_len = ml_dsa
            .sign_wasm(kp.secret_key(), message.clone(), Some(signing_r))
            .expect("sign")
            .length() as usize;
        let mut random_sig = vec![0u8; good_len];
        for (i, b) in random_sig.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let random_u8 = Uint8Array::from(&random_sig[..]);

        let ok = ml_dsa
            .verify_wasm(kp.public_key(), message, random_u8)
            .expect("verify");
        assert!(!ok, "random signature must yield false");
    }

    /// Signature for a different message must not verify.
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_signature_for_other_message() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let msg_a = Uint8Array::from(b"message A".as_slice());
        let msg_b = Uint8Array::from(b"message B".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let sig_b = ml_dsa
            .sign_wasm(kp.secret_key(), msg_b, Some(signing_r))
            .expect("sign b");

        let ok = ml_dsa
            .verify_wasm(kp.public_key(), msg_a, sig_b)
            .expect("verify");
        assert!(!ok, "sig for message B must not verify message A");
    }

    /// Empty signature is an error, not Ok(true).
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_empty_signature_errors() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"x".as_slice());
        let empty = Uint8Array::new_with_length(0);
        let result = ml_dsa.verify_wasm(kp.public_key(), message, empty);
        assert!(result.is_err(), "empty signature must error");
    }

    /// Truncated signature is an error.
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_truncated_signature_errors() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"y".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let mut v = ml_dsa
            .sign_wasm(kp.secret_key(), message.clone(), Some(signing_r))
            .expect("sign")
            .to_vec();
        v.pop();
        let truncated = Uint8Array::from(&v[..]);
        let result = ml_dsa.verify_wasm(kp.public_key(), message, truncated);
        assert!(result.is_err(), "truncated signature must error");
    }

    /// Oversized signature is an error (no panic in WASM).
    #[wasm_bindgen_test]
    fn test_ml_dsa_verify_wasm_oversized_signature_errors() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let kp = ml_dsa
            .generate_keypair_wasm(Some(Uint8Array::from(
                &generate_deterministic_seed_32()[..],
            )))
            .expect("keygen");
        let message = Uint8Array::from(b"z".as_slice());
        let signing_r = Uint8Array::from(&generate_deterministic_signing_32()[..]);
        let mut v = ml_dsa
            .sign_wasm(kp.secret_key(), message.clone(), Some(signing_r))
            .expect("sign")
            .to_vec();
        v.push(0u8);
        let oversized = Uint8Array::from(&v[..]);
        let result = ml_dsa.verify_wasm(kp.public_key(), message, oversized);
        assert!(result.is_err(), "oversized signature must error");
    }

    fn generate_deterministic_seed_32() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        r
    }

    fn generate_deterministic_seed_32_b() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x3D).wrapping_add(0x11);
        }
        r
    }

    fn generate_deterministic_signing_32() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        r
    }
}
