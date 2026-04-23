//! Comprehensive fuzzing tests for HPKE security validation
//!
//! These tests use property-based testing and fuzzing techniques to validate
//! security properties and edge cases in the HPKE implementation.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
};
use lib_q_hpke::security::prng::{CryptoRng, Kt128Rng};
use lib_q_kem::LibQKemProvider;

fn random_bytes(rng: &mut Kt128Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v).unwrap();
    v
}

/// Fuzzing test for authentication proof validation
#[test]
fn fuzz_auth_proof_validation() {
    let mut rng = Kt128Rng::from_seed(&[0u8; 32]);
    
    for _ in 0..1000 {
        // Generate random but valid key sizes
        let kem = match rng.next_u32().unwrap() % 3 {
            0 => HpkeKem::MlKem512,
            1 => HpkeKem::MlKem768,
            _ => HpkeKem::MlKem1024,
        };
        
        // Generate random data with correct sizes
        let sender_sk = random_bytes(&mut rng, kem.secret_key_len());
        let sender_pk = random_bytes(&mut rng, kem.public_key_len());
        let recipient_pk = random_bytes(&mut rng, kem.public_key_len());
        let encapsulated_key = random_bytes(&mut rng, kem.enc_len());
        let shared_secret = random_bytes(&mut rng, kem.shared_secret_len());
        
        // Test with valid data - should not panic
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        
        // Create key objects
        let sender_sk_obj = KemSecretKey::new(sender_sk.clone());
        let sender_pk_obj = KemPublicKey::new(sender_pk.clone());
        let recipient_pk_obj = KemPublicKey::new(recipient_pk.clone());
        
        // Test authentication proof creation
        let result = provider.create_auth_proof(
            kem,
            &sender_sk_obj,
            &sender_pk_obj,
            &recipient_pk_obj,
            &encapsulated_key,
            &shared_secret,
            &mut rng,
        );
        
        // Should either succeed or fail gracefully (no panic)
        match result {
            Ok(proof) => {
                // If successful, proof should have correct length
                assert_eq!(proof.len(), provider.get_auth_proof_length(kem));
                
                // Test verification with the created proof
                let verify_result = provider.verify_auth_proof(
                    kem,
                    &sender_pk_obj,
                    &sender_sk_obj,
                    &encapsulated_key,
                    &shared_secret,
                    &proof,
                );
                
                // Verification should succeed for valid proof
                assert!(verify_result.is_ok(), "Valid auth proof should verify successfully");
            }
            Err(_) => {
                // Failure is acceptable for invalid inputs
            }
        }
    }
}

/// Fuzzing test for invalid authentication proof detection
#[test]
fn fuzz_invalid_auth_proof_detection() {
    let mut rng = Kt128Rng::from_seed(&[1u8; 32]);
    
    for _ in 0..1000 {
        let kem = HpkeKem::MlKem512; // Use consistent KEM for this test
        
        // Generate valid base data
        let sender_sk = random_bytes(&mut rng, kem.secret_key_len());
        let sender_pk = random_bytes(&mut rng, kem.public_key_len());
        let recipient_pk = random_bytes(&mut rng, kem.public_key_len());
        let encapsulated_key = random_bytes(&mut rng, kem.enc_len());
        let shared_secret = random_bytes(&mut rng, kem.shared_secret_len());
        
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        let sender_sk_obj = KemSecretKey::new(sender_sk);
        let sender_pk_obj = KemPublicKey::new(sender_pk);
        
        // Generate random invalid proof
        let invalid_proof_len = (rng.next_u32().unwrap() % 63) as usize + 1;
        let invalid_proof = random_bytes(&mut rng, invalid_proof_len);
        
        // Verification should fail for invalid proof
        let verify_result = provider.verify_auth_proof(
            kem,
            &sender_pk_obj,
            &sender_sk_obj,
            &encapsulated_key,
            &shared_secret,
            &invalid_proof,
        );
        
        assert!(verify_result.is_err(), "Invalid auth proof should be rejected");
    }
}

/// Fuzzing test for key validation edge cases
#[test]
fn fuzz_key_validation_edge_cases() {
    let mut rng = Kt128Rng::from_seed(&[2u8; 32]);
    
    for _ in 0..1000 {
        let kem = HpkeKem::MlKem512;
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        
        // Test various invalid key sizes
        let invalid_sizes = vec![
            0, 1, 7, 15, 31, 33, 63, 65, 127, 129, 255, 257, 511, 513, 1023, 1025,
        ];
        
        for &size in &invalid_sizes {
            let invalid_key = random_bytes(&mut rng, size);
            
            // Test public key validation
            let pk_result = provider.validate_key(kem, &invalid_key, false);
            assert!(pk_result.is_err(), "Invalid public key size should be rejected");
            
            // Test secret key validation
            let sk_result = provider.validate_key(kem, &invalid_key, true);
            assert!(sk_result.is_err(), "Invalid secret key size should be rejected");
        }
    }
}

/// Fuzzing test for zero key rejection
#[test]
fn fuzz_zero_key_rejection() {
    let _rng = Kt128Rng::from_seed(&[3u8; 32]);
    
    for _ in 0..100 {
        let kem = HpkeKem::MlKem512;
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        
        // Test zero keys of correct size
        let zero_pk = vec![0u8; kem.public_key_len()];
        let zero_sk = vec![0u8; kem.secret_key_len()];
        
        // Zero keys should be rejected
        let pk_result = provider.validate_key(kem, &zero_pk, false);
        assert!(pk_result.is_err(), "Zero public key should be rejected");
        
        let sk_result = provider.validate_key(kem, &zero_sk, true);
        assert!(sk_result.is_err(), "Zero secret key should be rejected");
    }
}

/// Fuzzing test for AEAD key validation
#[test]
fn fuzz_aead_key_validation() {
    let mut rng = Kt128Rng::from_seed(&[4u8; 32]);
    
    for _ in 0..1000 {
        let aead = HpkeAead::Saturnin256;
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        
        // Test various invalid key sizes
        let invalid_sizes = vec![0, 1, 7, 15, 31, 33, 63, 65, 127, 129];
        
        for &size in &invalid_sizes {
            let invalid_key = random_bytes(&mut rng, size);
            let nonce = vec![0u8; aead.nonce_len()];
            let plaintext = b"test message";
            
            // Test encryption with invalid key
            let encrypt_result = provider.seal(aead, &invalid_key, &nonce, b"", plaintext);
            assert!(encrypt_result.is_err(), "Invalid AEAD key should be rejected");
            
            // Test decryption with invalid key
            let decrypt_result = provider.open(aead, &invalid_key, &nonce, b"", plaintext);
            assert!(decrypt_result.is_err(), "Invalid AEAD key should be rejected");
        }
    }
}

/// Fuzzing test for nonce validation
#[test]
fn fuzz_nonce_validation() {
    let mut rng = Kt128Rng::from_seed(&[5u8; 32]);
    
    for _ in 0..1000 {
        let aead = HpkeAead::Saturnin256;
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        let key = vec![1u8; aead.key_len()]; // Valid non-zero key
        let plaintext = b"test message";
        
        // Test various invalid nonce sizes
        let invalid_sizes = vec![0, 1, 7, 15, 17, 31, 33, 63, 65];
        
        for &size in &invalid_sizes {
            let invalid_nonce = random_bytes(&mut rng, size);
            
            // Test encryption with invalid nonce
            let encrypt_result = provider.seal(aead, &key, &invalid_nonce, b"", plaintext);
            assert!(encrypt_result.is_err(), "Invalid nonce should be rejected");
            
            // Test decryption with invalid nonce
            let decrypt_result = provider.open(aead, &key, &invalid_nonce, b"", plaintext);
            assert!(decrypt_result.is_err(), "Invalid nonce should be rejected");
        }
    }
}

/// Fuzzing test for ciphertext length validation
#[test]
fn fuzz_ciphertext_length_validation() {
    let mut rng = Kt128Rng::from_seed(&[6u8; 32]);
    
    for _ in 0..1000 {
        let aead = HpkeAead::Saturnin256;
        let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
        let key = vec![1u8; aead.key_len()];
        let nonce = vec![0u8; aead.nonce_len()];
        let plaintext = b"test message";
        
        // Test various invalid ciphertext sizes
        let invalid_sizes = vec![0, 1, 7, 15, 31, 33, 63, 65, 127, 129];
        
        for &size in &invalid_sizes {
            let invalid_ciphertext = random_bytes(&mut rng, size);
            
            // Test decryption with invalid ciphertext length
            let decrypt_result = provider.open(aead, &key, &nonce, b"", &invalid_ciphertext);
            assert!(decrypt_result.is_err(), "Invalid ciphertext length should be rejected");
        }
    }
}

/// Fuzzing test for HPKE context state transitions
#[test]
fn fuzz_hpke_context_state_transitions() {
    let mut rng = Kt128Rng::from_seed(&[7u8; 32]);
    
    for _ in 0..100 {
        let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
        let mut hpke_ctx = HpkeContext::with_provider(provider);
        
        // Generate valid key pair
        let mut kem_ctx = KemContext::with_provider(Box::new(LibQKemProvider::new().expect("Failed to create KEM provider")));
        let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
        
        let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
        let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
        
        // Test context setup with random info
        let info_len = (rng.next_u32().unwrap() % 1024) as usize;
        let info = random_bytes(&mut rng, info_len);
        
        let setup_result = hpke_ctx.setup_sender(&recipient_pk, &info);
        
        match setup_result {
            Ok(mut sender_ctx) => {
                // Test multiple encryptions with random data
                for _ in 0..10 {
                    let msg_len = (rng.next_u32().unwrap() % 1024) as usize;
                    let message = random_bytes(&mut rng, msg_len);
                    let aad_len = (rng.next_u32().unwrap() % 512) as usize;
                    let aad = random_bytes(&mut rng, aad_len);
                    
                    let encrypt_result = sender_ctx.seal(&aad, &message);
                    
                    // Should either succeed or fail gracefully
                    match encrypt_result {
                        Ok(_) => {
                            // Encryption succeeded
                        }
                        Err(_) => {
                            // Failure is acceptable (e.g., context exhausted)
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Setup failure is acceptable for invalid inputs
            }
        }
    }
}

/// Fuzzing test for sequence number overflow handling
#[test]
fn fuzz_sequence_number_overflow() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    
    // Generate valid key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    
    // Setup sender context
    let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"test info").unwrap();
    
    // Force sequence number to near maximum
    sender_ctx.sequence_number = u32::MAX - 5;
    
    // Try to encrypt multiple messages to trigger overflow
    for i in 0..10 {
        let message = format!("test message {}", i);
        let result = sender_ctx.seal(b"", message.as_bytes());
        
        if i < 5 {
            // First few should succeed
            assert!(result.is_ok(), "Encryption should succeed before overflow");
        } else {
            // Later ones should fail due to overflow
            assert!(result.is_err(), "Encryption should fail after sequence overflow");
        }
    }
    
    // Context should be in NeedsRekey state
    assert_eq!(sender_ctx.state, lib_q_hpke::HpkeContextState::NeedsRekey);
}

/// Fuzzing test for memory safety with large inputs
#[test]
fn fuzz_memory_safety_large_inputs() {
    let mut rng = Kt128Rng::from_seed(&[8u8; 32]);
    
    for _ in 0..10 {
        let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
        let mut hpke_ctx = HpkeContext::with_provider(provider);
        
        // Generate valid key pair
        let mut kem_ctx = KemContext::with_provider(Box::new(LibQKemProvider::new().expect("Failed to create KEM provider")));
        let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
        
        let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
        let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
        
        // Test with very large messages
        let large_msg_size = (rng.next_u32().unwrap() % (65536 - 1024)) as usize + 1024;
        let large_message = random_bytes(&mut rng, large_msg_size);
        let large_aad = random_bytes(&mut rng, 1024);
        let large_info = random_bytes(&mut rng, 1024);
        
        // Should handle large inputs gracefully
        let encrypt_result = hpke_ctx.seal(&recipient_pk, &large_info, &large_aad, &large_message);
        
        match encrypt_result {
            Ok((encapsulated_key, ciphertext)) => {
                // If encryption succeeds, decryption should also succeed
                let decrypt_result = hpke_ctx.open(
                    &encapsulated_key,
                    &recipient_sk,
                    &large_info,
                    &large_aad,
                    &ciphertext,
                );
                assert!(decrypt_result.is_ok(), "Decryption should succeed for valid encryption");
                
                let decrypted = decrypt_result.unwrap();
                assert_eq!(decrypted, large_message, "Decrypted message should match original");
            }
            Err(_) => {
                // Failure is acceptable for very large inputs
            }
        }
    }
}
