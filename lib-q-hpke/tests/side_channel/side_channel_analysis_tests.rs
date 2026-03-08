//! Side-channel analysis validation tests for HPKE implementation
//!
//! These tests validate that the HPKE implementation is resistant to
//! timing attacks and other side-channel vulnerabilities.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::security::prng::{CryptoRng, KangarooTwelveRng};
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
};
use lib_q_kem::LibQKemProvider;
use std::time::{Duration, Instant};

/// Test constant-time key comparison
#[test]
fn test_constant_time_key_comparison() {
    use lib_q_hpke::security::constant_time::constant_time_eq;
    
    // Test equal keys
    let key1 = vec![1u8, 2u8, 3u8, 4u8];
    let key2 = vec![1u8, 2u8, 3u8, 4u8];
    assert!(constant_time_eq(&key1, &key2));
    
    // Test different keys
    let key3 = vec![1u8, 2u8, 3u8, 5u8];
    assert!(!constant_time_eq(&key1, &key3));
    
    // Test different lengths
    let key4 = vec![1u8, 2u8, 3u8];
    assert!(!constant_time_eq(&key1, &key4));
    
    // Test empty keys
    assert!(constant_time_eq(&[], &[]));
    assert!(!constant_time_eq(&[], &[1u8]));
}

/// Test timing consistency for key validation
#[test]
fn test_timing_consistency_key_validation() {
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let kem = HpkeKem::MlKem512;
    
    // Generate test keys
    let valid_key = vec![1u8; kem.public_key_len()];
    let invalid_key_short = vec![1u8; kem.public_key_len() - 1];
    let invalid_key_long = vec![1u8; kem.public_key_len() + 1];
    let zero_key = vec![0u8; kem.public_key_len()];
    
    // Measure timing for different validation scenarios
    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();
    
    // Warm up
    for _ in 0..10 {
        let _ = provider.validate_key(kem, &valid_key, false);
        let _ = provider.validate_key(kem, &invalid_key_short, false);
    }
    
    // Measure valid key validation timing
    for _ in 0..100 {
        let start = Instant::now();
        let _ = provider.validate_key(kem, &valid_key, false);
        valid_times.push(start.elapsed());
    }
    
    // Measure invalid key validation timing
    for _ in 0..100 {
        let start = Instant::now();
        let _ = provider.validate_key(kem, &invalid_key_short, false);
        invalid_times.push(start.elapsed());
    }
    
    // Calculate average times
    let avg_valid_time: Duration = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let avg_invalid_time: Duration = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;
    
    // Times should be similar (within reasonable tolerance)
    let time_diff = if avg_valid_time > avg_invalid_time {
        avg_valid_time - avg_invalid_time
    } else {
        avg_invalid_time - avg_valid_time
    };
    
    // Allow up to 10% difference in timing
    let max_allowed_diff = avg_valid_time / 10;
    assert!(
        time_diff <= max_allowed_diff,
        "Key validation timing should be consistent: valid={:?}, invalid={:?}, diff={:?}",
        avg_valid_time,
        avg_invalid_time,
        time_diff
    );
    
    // Test zero key rejection timing
    let mut zero_times = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        let _ = provider.validate_key(kem, &zero_key, false);
        zero_times.push(start.elapsed());
    }
    
    let avg_zero_time: Duration = zero_times.iter().sum::<Duration>() / zero_times.len() as u32;
    let zero_time_diff = if avg_valid_time > avg_zero_time {
        avg_valid_time - avg_zero_time
    } else {
        avg_zero_time - avg_valid_time
    };
    
    assert!(
        zero_time_diff <= max_allowed_diff,
        "Zero key rejection timing should be consistent: valid={:?}, zero={:?}, diff={:?}",
        avg_valid_time,
        avg_zero_time,
        zero_time_diff
    );
}

/// Test timing consistency for AEAD operations
#[test]
fn test_timing_consistency_aead_operations() {
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let aead = HpkeAead::Saturnin256;
    
    let valid_key = vec![1u8; aead.key_len()];
    let valid_nonce = vec![0u8; aead.nonce_len()];
    let plaintext = b"test message";
    
    let invalid_key_short = vec![1u8; aead.key_len() - 1];
    let invalid_nonce_short = vec![0u8; aead.nonce_len() - 1];
    
    // Measure timing for valid operations
    let mut valid_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = provider.seal(aead, &valid_key, &valid_nonce, b"", plaintext);
        valid_times.push(start.elapsed());
    }
    
    // Measure timing for invalid key operations
    let mut invalid_key_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = provider.seal(aead, &invalid_key_short, &valid_nonce, b"", plaintext);
        invalid_key_times.push(start.elapsed());
    }
    
    // Measure timing for invalid nonce operations
    let mut invalid_nonce_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = provider.seal(aead, &valid_key, &invalid_nonce_short, b"", plaintext);
        invalid_nonce_times.push(start.elapsed());
    }
    
    // Calculate average times
    let avg_valid_time: Duration = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let avg_invalid_key_time: Duration = invalid_key_times.iter().sum::<Duration>() / invalid_key_times.len() as u32;
    let avg_invalid_nonce_time: Duration = invalid_nonce_times.iter().sum::<Duration>() / invalid_nonce_times.len() as u32;
    
    // All times should be similar (within reasonable tolerance)
    let max_time = avg_valid_time.max(avg_invalid_key_time).max(avg_invalid_nonce_time);
    let min_time = avg_valid_time.min(avg_invalid_key_time).min(avg_invalid_nonce_time);
    let time_range = max_time - min_time;
    
    // Allow up to 20% difference in timing for AEAD operations
    let max_allowed_range = avg_valid_time / 5;
    assert!(
        time_range <= max_allowed_range,
        "AEAD operation timing should be consistent: valid={:?}, invalid_key={:?}, invalid_nonce={:?}, range={:?}",
        avg_valid_time,
        avg_invalid_key_time,
        avg_invalid_nonce_time,
        time_range
    );
}

/// Test timing consistency for authentication proof operations
#[test]
fn test_timing_consistency_auth_proof_operations() {
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let kem = HpkeKem::MlKem512;
    
    // Generate test data
    let sender_sk = vec![1u8; kem.secret_key_len()];
    let sender_pk = vec![2u8; kem.public_key_len()];
    let recipient_pk = vec![3u8; kem.public_key_len()];
    let encapsulated_key = vec![4u8; kem.enc_len()];
    let shared_secret = vec![5u8; kem.shared_secret_len()];
    
    let invalid_sender_sk = vec![1u8; kem.secret_key_len() - 1];
    let invalid_sender_pk = vec![2u8; kem.public_key_len() - 1];
    
    // Create key objects
    let sender_sk_obj = KemSecretKey::new(sender_sk.clone());
    let sender_pk_obj = KemPublicKey::new(sender_pk.clone());
    let recipient_pk_obj = KemPublicKey::new(recipient_pk.clone());
    
    let invalid_sender_sk_obj = KemSecretKey::new(invalid_sender_sk);
    let invalid_sender_pk_obj = KemPublicKey::new(invalid_sender_pk);

    let mut rng = KangarooTwelveRng::new().expect("K12 RNG");
    
    // Measure timing for valid proof creation
    let mut valid_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = provider.create_auth_proof(
            kem,
            &sender_sk_obj,
            &sender_pk_obj,
            &recipient_pk_obj,
            &encapsulated_key,
            &shared_secret,
            &mut rng,
        );
        valid_times.push(start.elapsed());
    }
    
    // Measure timing for invalid proof creation
    let mut invalid_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = provider.create_auth_proof(
            kem,
            &invalid_sender_sk_obj,
            &invalid_sender_pk_obj,
            &recipient_pk_obj,
            &encapsulated_key,
            &shared_secret,
            &mut rng,
        );
        invalid_times.push(start.elapsed());
    }
    
    // Calculate average times
    let avg_valid_time: Duration = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let avg_invalid_time: Duration = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;
    
    // Times should be similar (within reasonable tolerance)
    let time_diff = if avg_valid_time > avg_invalid_time {
        avg_valid_time - avg_invalid_time
    } else {
        avg_invalid_time - avg_valid_time
    };
    
    // Allow up to 15% difference in timing
    let max_allowed_diff = avg_valid_time / 7;
    assert!(
        time_diff <= max_allowed_diff,
        "Auth proof creation timing should be consistent: valid={:?}, invalid={:?}, diff={:?}",
        avg_valid_time,
        avg_invalid_time,
        time_diff
    );
}

/// Test memory access patterns for constant-time operations
#[test]
fn test_memory_access_patterns() {
    use lib_q_hpke::security::constant_time::constant_time_eq;
    
    // Test that constant-time comparison doesn't leak information about key differences
    let key1 = vec![1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8];
    let key2 = vec![1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 9u8]; // Different at end
    let key3 = vec![9u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8]; // Different at start
    
    // Measure timing for different positions of differences
    let mut end_diff_times = Vec::new();
    let mut start_diff_times = Vec::new();
    
    for _ in 0..100 {
        let start = Instant::now();
        let _ = constant_time_eq(&key1, &key2);
        end_diff_times.push(start.elapsed());
        
        let start = Instant::now();
        let _ = constant_time_eq(&key1, &key3);
        start_diff_times.push(start.elapsed());
    }
    
    let avg_end_diff_time: Duration = end_diff_times.iter().sum::<Duration>() / end_diff_times.len() as u32;
    let avg_start_diff_time: Duration = start_diff_times.iter().sum::<Duration>() / start_diff_times.len() as u32;
    
    // Times should be very similar regardless of where the difference occurs
    let time_diff = if avg_end_diff_time > avg_start_diff_time {
        avg_end_diff_time - avg_start_diff_time
    } else {
        avg_start_diff_time - avg_end_diff_time
    };
    
    // Allow very small difference (microseconds)
    let max_allowed_diff = Duration::from_micros(10);
    assert!(
        time_diff <= max_allowed_diff,
        "Constant-time comparison should not leak position information: end_diff={:?}, start_diff={:?}, diff={:?}",
        avg_end_diff_time,
        avg_start_diff_time,
        time_diff
    );
}

/// Test power analysis resistance (simulated)
#[test]
fn test_power_analysis_resistance() {
    // This test simulates power analysis resistance by ensuring that
    // operations consume similar amounts of computational resources
    // regardless of input values
    
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let kem = HpkeKem::MlKem512;
    
    // Test with different key patterns that might cause different power consumption
    let patterns = vec![
        vec![0x00u8; kem.public_key_len()], // All zeros
        vec![0xFFu8; kem.public_key_len()], // All ones
        vec![0xAAu8; kem.public_key_len()], // Alternating pattern
        vec![0x55u8; kem.public_key_len()], // Alternating pattern (inverted)
    ];
    
    let mut times = Vec::new();
    
    for pattern in &patterns {
        let mut pattern_times = Vec::new();
        
        for _ in 0..50 {
            let start = Instant::now();
            let _ = provider.validate_key(kem, pattern, false);
            pattern_times.push(start.elapsed());
        }
        
        let avg_time: Duration = pattern_times.iter().sum::<Duration>() / pattern_times.len() as u32;
        times.push(avg_time);
    }
    
    // All patterns should have similar execution times
    let max_time = *times.iter().max().unwrap();
    let min_time = *times.iter().min().unwrap();
    let time_range = max_time - min_time;
    
    // Allow up to 10% difference
    let max_allowed_range = max_time / 10;
    assert!(
        time_range <= max_allowed_range,
        "Power analysis resistance: max={:?}, min={:?}, range={:?}",
        max_time,
        min_time,
        time_range
    );
}

/// Test cache timing attack resistance
#[test]
fn test_cache_timing_attack_resistance() {
    // This test ensures that memory access patterns don't leak information
    // about secret data through cache timing
    
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let aead = HpkeAead::Saturnin256;
    
    // Test with keys that have different cache line alignments
    let mut keys = Vec::new();
    for i in 0..16 {
        let mut key = vec![0u8; aead.key_len() + i];
        key[i..i + aead.key_len()].fill(1u8);
        keys.push(key[i..i + aead.key_len()].to_vec());
    }
    
    let nonce = vec![0u8; aead.nonce_len()];
    let plaintext = b"test message";
    
    let mut times = Vec::new();
    
    for key in &keys {
        let mut key_times = Vec::new();
        
        for _ in 0..20 {
            let start = Instant::now();
            let _ = provider.seal(aead, key, &nonce, b"", plaintext);
            key_times.push(start.elapsed());
        }
        
        let avg_time: Duration = key_times.iter().sum::<Duration>() / key_times.len() as u32;
        times.push(avg_time);
    }
    
    // All keys should have similar execution times regardless of alignment
    let max_time = *times.iter().max().unwrap();
    let min_time = *times.iter().min().unwrap();
    let time_range = max_time - min_time;
    
    // Allow up to 15% difference for cache effects
    let max_allowed_range = max_time / 7;
    assert!(
        time_range <= max_allowed_range,
        "Cache timing attack resistance: max={:?}, min={:?}, range={:?}",
        max_time,
        min_time,
        time_range
    );
}
