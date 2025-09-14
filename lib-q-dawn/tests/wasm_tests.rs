//! WASM-specific tests for lib-q-dawn
//!
//! These tests verify the WASM bindings work correctly.

#[cfg(feature = "wasm")]
mod wasm_tests {
    use lib_q_core::{
        KemPublicKey,
        KemSecretKey,
    };
    use lib_q_dawn::{
        DawnParameterSet,
        wasm,
    };

    #[test]
    fn test_wasm_generate_keypair() {
        let result = wasm::generate_keypair(DawnParameterSet::Alpha512);
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair.public_key_bytes().len(), 615);
        assert_eq!(keypair.secret_key_bytes().len(), 1319);
    }

    #[test]
    fn test_wasm_encapsulate() {
        let public_key = KemPublicKey::new(vec![0u8; 615]);
        let result = wasm::encapsulate(DawnParameterSet::Alpha512, &public_key);
        assert!(result.is_ok());

        let encap_result = result.unwrap();
        assert_eq!(encap_result.ciphertext().len(), 436);
        assert_eq!(encap_result.shared_secret().len(), 32);
    }

    #[test]
    fn test_wasm_decapsulate() {
        let secret_key = KemSecretKey::new(vec![0u8; 1319]);
        let ciphertext = vec![0u8; 436];
        let result = wasm::decapsulate(DawnParameterSet::Alpha512, &secret_key, &ciphertext);
        assert!(result.is_ok());

        let shared_secret = result.unwrap();
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_wasm_encapsulation_result() {
        let ciphertext = vec![1u8; 436];
        let shared_secret = vec![2u8; 32];

        let result = wasm::EncapsulationResult::new(ciphertext.clone(), shared_secret.clone());
        assert_eq!(result.ciphertext(), ciphertext);
        assert_eq!(result.shared_secret(), shared_secret);
    }

    #[test]
    fn test_wasm_all_parameter_sets() {
        let parameter_sets = [
            DawnParameterSet::Alpha512,
            DawnParameterSet::Alpha1024,
            DawnParameterSet::Beta512,
            DawnParameterSet::Beta1024,
        ];

        for param_set in parameter_sets {
            // Test key generation
            let keypair = wasm::generate_keypair(param_set).expect("Key generation should succeed");

            // Test encapsulation
            let public_key = KemPublicKey::new(keypair.public_key_bytes());
            let encap_result =
                wasm::encapsulate(param_set, &public_key).expect("Encapsulation should succeed");

            // Test decapsulation
            let secret_key = KemSecretKey::new(keypair.secret_key_bytes());
            let decap_result =
                wasm::decapsulate(param_set, &secret_key, &encap_result.ciphertext())
                    .expect("Decapsulation should succeed");

            assert_eq!(encap_result.shared_secret(), decap_result);
        }
    }
}

#[cfg(not(feature = "wasm"))]
mod wasm_tests {
    #[test]
    fn test_wasm_feature_disabled() {
        // This test ensures that WASM tests are only run when the wasm feature is enabled
        // The test passes by simply existing - no assertion needed
    }
}
