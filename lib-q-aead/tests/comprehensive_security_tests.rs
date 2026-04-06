//! Comprehensive Security Tests
//!
//! This module provides comprehensive security tests including timing attack resistance,
//! fault injection resistance, and other security properties.

use std::time::{
    Duration,
    Instant,
};

use lib_q_aead::security::constant_time::constant_time_eq;
use lib_q_aead::security::memory::secure_zero_slice;
use lib_q_aead::security::timing::protect_timing;
use lib_q_aead::security::validation::validate_plaintext;
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

/// Generate a proper test key with good entropy
fn create_test_key() -> AeadKey {
    AeadKey::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ])
}

/// Generate a proper test nonce with good entropy
fn create_test_nonce() -> Nonce {
    Nonce::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ])
}

fn median_nanos(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    let mid = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        (samples[mid - 1] + samples[mid]) / 2
    } else {
        samples[mid]
    }
}

fn collect_timing_samples_ns<F>(warmup_iters: usize, measure_iters: usize, mut op: F) -> Vec<u128>
where
    F: FnMut(),
{
    for _ in 0..warmup_iters {
        op();
    }

    let mut samples_ns = Vec::with_capacity(measure_iters);
    for _ in 0..measure_iters {
        let start = Instant::now();
        op();
        samples_ns.push(start.elapsed().as_nanos());
    }
    samples_ns
}

#[cfg(feature = "shake256")]
#[test]
fn test_timing_attack_resistance() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Encrypt the message
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Interleave valid/invalid measurements and compare medians to reduce scheduler jitter.
    const WARMUP_ITERS: usize = 16;
    const MEASURE_ITERS: usize = 128;
    let mut valid_samples_ns = Vec::with_capacity(MEASURE_ITERS);
    let mut invalid_samples_ns = Vec::with_capacity(MEASURE_ITERS);

    for i in 0..(WARMUP_ITERS + MEASURE_ITERS) {
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF; // Tamper with first byte

        let measure_valid = || {
            let start = Instant::now();
            let result = aead.decrypt(&key, &nonce, &ciphertext, Some(aad));
            let duration = start.elapsed().as_nanos();
            assert!(result.is_ok(), "Valid decryption should succeed");
            duration
        };
        let measure_invalid = || {
            let start = Instant::now();
            let result = aead.decrypt(&key, &nonce, &tampered, Some(aad));
            let duration = start.elapsed().as_nanos();
            assert!(result.is_err(), "Tampered decryption should fail");
            duration
        };

        let valid_duration = if i % 2 == 0 {
            let valid = measure_valid();
            let invalid = measure_invalid();
            (valid, invalid)
        } else {
            let invalid = measure_invalid();
            let valid = measure_valid();
            (valid, invalid)
        };

        if i >= WARMUP_ITERS {
            valid_samples_ns.push(valid_duration.0);
            invalid_samples_ns.push(valid_duration.1);
        }
    }

    let valid_median_ns = median_nanos(&mut valid_samples_ns);
    let invalid_median_ns = median_nanos(&mut invalid_samples_ns);
    let timing_ratio = valid_median_ns as f64 / invalid_median_ns as f64;
    assert!(
        timing_ratio > 0.5 && timing_ratio < 2.0,
        "Timing difference too large: valid_median={}ns, invalid_median={}ns, ratio={}",
        valid_median_ns,
        invalid_median_ns,
        timing_ratio
    );
}

#[cfg(feature = "shake256")]
#[test]
fn test_constant_time_operations() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Encrypt the message
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Interleave valid/invalid measurements and compare medians to reduce scheduler jitter.
    const WARMUP_ITERS: usize = 16;
    const MEASURE_ITERS: usize = 128;
    let mut valid_samples_ns = Vec::with_capacity(MEASURE_ITERS);
    let mut invalid_samples_ns = Vec::with_capacity(MEASURE_ITERS);

    for i in 0..(WARMUP_ITERS + MEASURE_ITERS) {
        let mut tampered = ciphertext.clone();
        let last_idx = tampered.len() - 1;
        tampered[last_idx] ^= 0xFF;

        let measure_valid = || {
            let start = Instant::now();
            let result = aead.decrypt(&key, &nonce, &ciphertext, Some(aad));
            let duration = start.elapsed().as_nanos();
            assert!(result.is_ok(), "Valid decryption should succeed");
            duration
        };
        let measure_invalid = || {
            let start = Instant::now();
            let result = aead.decrypt(&key, &nonce, &tampered, Some(aad));
            let duration = start.elapsed().as_nanos();
            assert!(result.is_err(), "Tampered decryption should fail");
            duration
        };

        let valid_duration = if i % 2 == 0 {
            let valid = measure_valid();
            let invalid = measure_invalid();
            (valid, invalid)
        } else {
            let invalid = measure_invalid();
            let valid = measure_valid();
            (valid, invalid)
        };

        if i >= WARMUP_ITERS {
            valid_samples_ns.push(valid_duration.0);
            invalid_samples_ns.push(valid_duration.1);
        }
    }

    let valid_median_ns = median_nanos(&mut valid_samples_ns);
    let invalid_median_ns = median_nanos(&mut invalid_samples_ns);
    let timing_ratio = valid_median_ns as f64 / invalid_median_ns as f64;
    assert!(
        timing_ratio > 0.5 && timing_ratio < 2.0,
        "Constant-time operations failed: valid_median={}ns, invalid_median={}ns, ratio={}",
        valid_median_ns,
        invalid_median_ns,
        timing_ratio
    );
}

#[cfg(feature = "shake256")]
#[test]
fn test_fault_injection_resistance() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Encrypt the message
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Test fault injection resistance by corrupting various parts of the ciphertext
    let mut corruption_tests = Vec::new();

    // Test corruption at different positions
    for i in 0..ciphertext.len() {
        let mut corrupted = ciphertext.clone();
        corrupted[i] ^= 0xFF; // Flip all bits

        let result = aead.decrypt(&key, &nonce, &corrupted, Some(aad));
        assert!(
            result.is_err(),
            "Corrupted ciphertext at position {} should fail",
            i
        );

        corruption_tests.push((i, result.is_err()));
    }

    // All corruption tests should fail
    assert_eq!(corruption_tests.len(), ciphertext.len());
    assert!(
        corruption_tests.iter().all(|(_, failed)| *failed),
        "All corruption tests should fail"
    );
}

#[cfg(feature = "shake256")]
#[test]
fn test_key_material_protection() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    // Test that key material is properly protected
    let key_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];
    let key = AeadKey::new(key_data.clone());
    let nonce = Nonce::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Encrypt the message
    let _ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Verify that the key data is still intact (not zeroed during encryption)
    assert_eq!(
        key.as_bytes(),
        key_data,
        "Key data should not be modified during encryption"
    );

    // Test that zero keys are rejected
    let zero_key = AeadKey::new(vec![0u8; 32]);
    let result = aead.encrypt(&zero_key, &nonce, plaintext, Some(aad));
    assert!(result.is_err(), "Zero key should be rejected");

    // Test that all-ones keys are rejected
    let ones_key = AeadKey::new(vec![0xFFu8; 32]);
    let result = aead.encrypt(&ones_key, &nonce, plaintext, Some(aad));
    assert!(result.is_err(), "All-ones key should be rejected");
}

#[cfg(feature = "shake256")]
#[test]
fn test_nonce_uniqueness_requirements() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = AeadKey::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ]);
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Test that different nonces produce different ciphertexts
    let nonce1 = Nonce::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    let nonce2 = Nonce::new(vec![
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ]);

    let ciphertext1 = aead
        .encrypt(&key, &nonce1, plaintext, Some(aad))
        .expect("Encryption with nonce1 failed");
    let ciphertext2 = aead
        .encrypt(&key, &nonce2, plaintext, Some(aad))
        .expect("Encryption with nonce2 failed");

    // Different nonces should produce different ciphertexts
    assert_ne!(
        ciphertext1, ciphertext2,
        "Different nonces should produce different ciphertexts"
    );

    // Test that zero nonces are rejected
    let zero_nonce = Nonce::new(vec![0u8; 16]);
    let result = aead.encrypt(&key, &zero_nonce, plaintext, Some(aad));
    assert!(result.is_err(), "Zero nonce should be rejected");

    // Test that all-ones nonces are rejected
    let ones_nonce = Nonce::new(vec![0xFFu8; 16]);
    let result = aead.encrypt(&key, &ones_nonce, plaintext, Some(aad));
    assert!(result.is_err(), "All-ones nonce should be rejected");
}

#[cfg(feature = "shake256")]
#[test]
fn test_domain_separation_security() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";

    // Test that different associated data produces different ciphertexts
    let aad1 = b"context1";
    let aad2 = b"context2";

    let ciphertext1 = aead
        .encrypt(&key, &nonce, plaintext, Some(aad1))
        .expect("Encryption with aad1 failed");
    let ciphertext2 = aead
        .encrypt(&key, &nonce, plaintext, Some(aad2))
        .expect("Encryption with aad2 failed");

    // Different AAD should produce different ciphertexts
    assert_ne!(
        ciphertext1, ciphertext2,
        "Different AAD should produce different ciphertexts"
    );

    // Test that ciphertexts are context-specific
    let decrypted1 = aead
        .decrypt(&key, &nonce, &ciphertext1, Some(aad1))
        .expect("Decryption with aad1 failed");
    let decrypted2 = aead
        .decrypt(&key, &nonce, &ciphertext2, Some(aad2))
        .expect("Decryption with aad2 failed");

    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);

    // Test that wrong AAD fails
    let result = aead.decrypt(&key, &nonce, &ciphertext1, Some(aad2));
    assert!(result.is_err(), "Wrong AAD should fail");
}

#[cfg(feature = "shake256")]
#[test]
fn test_memory_safety() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Test that sensitive data is properly handled
    let mut sensitive_data = vec![0x42u8; 64];

    // Encrypt the message
    let _ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Test that we can securely zero sensitive data
    secure_zero_slice(&mut sensitive_data);
    assert!(
        sensitive_data.iter().all(|&b| b == 0),
        "Sensitive data should be zeroed"
    );

    // Test that the encryption still works after zeroing sensitive data
    let decrypted = aead
        .decrypt(&key, &nonce, &_ciphertext, Some(aad))
        .expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[cfg(feature = "shake256")]
#[test]
fn test_input_validation_security() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();

    // Test that invalid plaintext is rejected
    let invalid_plaintext = vec![0u8; 2 * 1024 * 1024]; // 2MB plaintext (exceeds 1MB limit)
    let result = validate_plaintext(&invalid_plaintext);
    assert!(result.is_err(), "Very large plaintext should be rejected");

    // Test that empty plaintext is handled correctly
    let empty_plaintext = b"";
    let ciphertext = aead
        .encrypt(&key, &nonce, empty_plaintext, None)
        .expect("Empty plaintext encryption failed");

    let decrypted = aead
        .decrypt(&key, &nonce, &ciphertext, None)
        .expect("Empty plaintext decryption failed");
    assert_eq!(decrypted, empty_plaintext);

    // Test that invalid key sizes are rejected
    let invalid_key = AeadKey::new(vec![1u8; 16]); // Wrong size
    let result = aead.encrypt(&invalid_key, &nonce, b"test", None);
    assert!(result.is_err(), "Invalid key size should be rejected");

    // Test that invalid nonce sizes are rejected
    let invalid_nonce = Nonce::new(vec![2u8; 12]); // Wrong size
    let result = aead.encrypt(&key, &invalid_nonce, b"test", None);
    assert!(result.is_err(), "Invalid nonce size should be rejected");
}

#[cfg(feature = "shake256")]
#[test]
fn test_side_channel_resistance() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, World!";
    let aad = b"metadata";

    // Encrypt the message
    let _ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Test side-channel resistance by measuring execution times for different input patterns.
    // Use warmup + repeated sampling and compare medians to reduce CI scheduler jitter.
    let mut pattern_medians_ns = Vec::new();

    // Test with different plaintext patterns
    let patterns = [
        vec![0u8; 16],     // All zeros
        vec![0xFFu8; 16],  // All ones
        vec![0x55u8; 16],  // Alternating pattern
        vec![0xAAu8; 16],  // Alternating pattern (inverted)
        (0..16).collect(), // Sequential pattern
    ];

    const WARMUP_ITERS: usize = 16;
    const MEASURE_ITERS: usize = 64;
    for pattern in &patterns {
        let mut samples_ns = collect_timing_samples_ns(WARMUP_ITERS, MEASURE_ITERS, || {
            let result = aead.encrypt(&key, &nonce, pattern, Some(aad));
            assert!(result.is_ok(), "Encryption should succeed for pattern");
        });
        let median_ns = median_nanos(&mut samples_ns);
        pattern_medians_ns.push(median_ns);
    }

    let min_median_ns = *pattern_medians_ns.iter().min().unwrap();
    let max_median_ns = *pattern_medians_ns.iter().max().unwrap();
    let timing_ratio = max_median_ns as f64 / min_median_ns as f64;

    assert!(
        timing_ratio < 3.0,
        "Timing variation too large: min_median={}ns, max_median={}ns, ratio={}, medians={:?}",
        min_median_ns,
        max_median_ns,
        timing_ratio,
        pattern_medians_ns
    );
}

#[cfg(feature = "shake256")]
#[test]
fn test_protect_timing_functionality() {
    // Test that the protect_timing function works correctly
    let result = protect_timing(|| {
        // Simulate some work
        std::thread::sleep(Duration::from_millis(1));
        42
    });

    assert_eq!(result, 42, "protect_timing should return the correct value");
}

#[cfg(feature = "shake256")]
#[test]
fn test_constant_time_comparison() {
    // Test constant-time comparison function
    let a = vec![1u8, 2u8, 3u8, 4u8];
    let b = vec![1u8, 2u8, 3u8, 4u8];
    let c = vec![1u8, 2u8, 3u8, 5u8];
    let d = vec![1u8, 2u8, 3u8];

    assert!(
        constant_time_eq(&a, &b),
        "Equal slices should compare equal"
    );
    assert!(
        !constant_time_eq(&a, &c),
        "Different slices should not compare equal"
    );
    assert!(
        !constant_time_eq(&a, &d),
        "Different length slices should not compare equal"
    );
}
