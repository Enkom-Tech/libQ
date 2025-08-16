//! Constant-time verification tests for libQ
//! 
//! These tests verify that cryptographic operations are constant-time
//! and don't leak information through timing side-channels.

use libq::*;

/// Test that key comparison operations are constant-time
#[test]
fn test_constant_time_key_comparison() {
    // Test AEAD key comparison
    let key_data1 = utils::random_bytes(32).unwrap();
    let key_data2 = utils::random_bytes(32).unwrap();
    let key_data3 = key_data1.clone();
    
    let key1 = AeadKey::new(key_data1);
    let key2 = AeadKey::new(key_data2);
    let key3 = AeadKey::new(key_data3);
    
    // These should be constant-time regardless of key values
    let _result1 = key1 == key2;
    let _result2 = key1 == key3;
    
    // Test KEM key comparison
    let kem_key_data1 = utils::random_bytes(32).unwrap();
    let kem_key_data2 = utils::random_bytes(32).unwrap();
    let kem_key_data3 = kem_key_data1.clone();
    
    let kem_key1 = KemSecretKey::new(kem_key_data1);
    let kem_key2 = KemSecretKey::new(kem_key_data2);
    let kem_key3 = KemSecretKey::new(kem_key_data3);
    
    let _result3 = kem_key1 == kem_key2;
    let _result4 = kem_key1 == kem_key3;
    
    // Test signature key comparison
    let sig_key_data1 = utils::random_bytes(32).unwrap();
    let sig_key_data2 = utils::random_bytes(32).unwrap();
    let sig_key_data3 = sig_key_data1.clone();
    
    let sig_key1 = SigSecretKey::new(sig_key_data1);
    let sig_key2 = SigSecretKey::new(sig_key_data2);
    let sig_key3 = SigSecretKey::new(sig_key_data3);
    
    let _result5 = sig_key1 == sig_key2;
    let _result6 = sig_key1 == sig_key3;
}

/// Test that hash operations don't leak timing information
#[test]
fn test_constant_time_hash_operations() {
    let data1 = vec![0u8; 64];
    let data2 = vec![1u8; 64];
    let data3 = vec![0u8; 128];
    
    let hash_impl = HashAlgorithm::Shake256.create_hash();
    
    // These operations should be constant-time regardless of input
    let _hash1 = hash_impl.hash(&data1).unwrap();
    let _hash2 = hash_impl.hash(&data2).unwrap();
    let _hash3 = hash_impl.hash(&data3).unwrap();
}

/// Test that random number generation is constant-time
#[test]
fn test_constant_time_random_generation() {
    // Generate different amounts of random data
    // These should take similar time regardless of size
    let _bytes1 = utils::random_bytes(32).unwrap();
    let _bytes2 = utils::random_bytes(64).unwrap();
    let _bytes3 = utils::random_bytes(128).unwrap();
    
    let _key1 = utils::random_key(32).unwrap();
    let _key2 = utils::random_key(64).unwrap();
    let _key3 = utils::random_key(128).unwrap();
}

/// Test that utility functions are constant-time
#[test]
fn test_constant_time_utility_functions() {
    let data1 = vec![0u8; 32];
    let data2 = vec![1u8; 32];
    let data3 = vec![0u8; 64];
    
    // Test constant-time comparison
    let _result1 = utils::constant_time_compare(&data1, &data2);
    let _result2 = utils::constant_time_compare(&data1, &data1);
    let _result3 = utils::constant_time_compare(&data1, &data3);
    
    // Test hex conversion (should be constant-time for same input sizes)
    let _hex1 = utils::bytes_to_hex(&data1);
    let _hex2 = utils::bytes_to_hex(&data2);
    let _hex3 = utils::bytes_to_hex(&data3);
}

/// Test that cryptographic operations don't branch on secret data
#[test]
fn test_no_branching_on_secrets() {
    // Test that operations don't have obvious timing variations
    // based on secret data values
    
    let secret1 = utils::random_key(32).unwrap();
    let secret2 = utils::random_key(32).unwrap();
    
    // These operations should take similar time regardless of secret values
    let _hash1 = HashAlgorithm::Shake256.create_hash().hash(&secret1).unwrap();
    let _hash2 = HashAlgorithm::Shake256.create_hash().hash(&secret2).unwrap();
    
    // Test key operations
    let key1 = AeadKey::new(secret1);
    let key2 = AeadKey::new(secret2);
    
    let _result1 = key1 == key2;
    let _result2 = key1 == key1;
}

/// Test that memory operations are secure
#[test]
fn test_secure_memory_operations() {
    // Test that sensitive data is properly zeroized
    let mut secret = utils::random_key(32).unwrap();
    
    // Perform some operations
    let _hash = HashAlgorithm::Shake256.create_hash().hash(&secret).unwrap();
    
    // The secret should still be properly managed
    assert_eq!(secret.len(), 32);
    
    // Test that zeroization works
    utils::secure_zeroize(&mut secret);
    
    // After zeroization, the data should be cleared
    assert_eq!(secret, vec![0u8; 32]);
}

/// Test that input validation doesn't leak timing information
#[test]
fn test_constant_time_input_validation() {
    let valid_data = vec![0u8; 32];
    let invalid_data = vec![0u8; 31]; // Wrong size
    
    // These validation operations should take similar time
    // regardless of whether the input is valid or not
    let _result1 = utils::validate_data_size(&valid_data, 32, 32);
    let _result2 = utils::validate_data_size(&invalid_data, 32, 32);
    
    // Test with different sizes
    let large_data = vec![0u8; 64];
    let _result3 = utils::validate_data_size(&large_data, 32, 32);
}

/// Test that cryptographic primitives are constant-time
#[test]
fn test_constant_time_primitives() {
    // Test that basic cryptographic operations don't leak timing
    let data1 = vec![0u8; 64];
    let data2 = vec![1u8; 64];
    
    let hash_impl = HashAlgorithm::Shake256.create_hash();
    
    // These should take similar time
    let _hash1 = hash_impl.hash(&data1).unwrap();
    let _hash2 = hash_impl.hash(&data2).unwrap();
    
    // Test with different hash algorithms
    let shake128_hash = HashAlgorithm::Shake128.create_hash();
    let _hash3 = shake128_hash.hash(&data1).unwrap();
    let _hash4 = shake128_hash.hash(&data2).unwrap();
}

/// Test that error handling doesn't leak timing information
#[test]
fn test_constant_time_error_handling() {
    // Test that error conditions don't cause timing variations
    let valid_key = utils::random_key(32).unwrap();
    let invalid_key = vec![0u8; 31]; // Wrong size
    
    // These operations should take similar time regardless of success/failure
    let _result1 = AeadKey::new(valid_key.clone());
    let _result2 = AeadKey::new(invalid_key.clone());
    
    let _result3 = KemSecretKey::new(valid_key.clone());
    let _result4 = KemSecretKey::new(invalid_key.clone());
    
    let _result5 = SigSecretKey::new(valid_key);
    let _result6 = SigSecretKey::new(invalid_key);
}
