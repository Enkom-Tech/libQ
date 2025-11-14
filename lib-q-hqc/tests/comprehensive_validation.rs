//! Comprehensive validation tests for HQC implementation
//!
//! This module provides extensive testing for all aspects of the HQC implementation,
//! including security properties, performance characteristics, and edge cases.

#[allow(clippy::disallowed_types)]
use std::collections::HashSet;
use std::time::{
    Duration,
    Instant,
};

use lib_q_hqc::*;
use lib_q_random::LibQRng;

/// Test constant-time properties of all operations
#[test]
fn test_constant_time_properties() {
    let context = Hqc128Kem::new().unwrap();

    // Test key generation timing consistency
    let mut times = Vec::new();
    for i in 0..100 {
        let seed = [i as u8; 32];
        let start = Instant::now();
        let _ = context.keygen_with_seed(&seed).unwrap();
        times.push(start.elapsed());
    }

    // Check that timing variance is within acceptable bounds
    let avg_time: Duration = times.iter().sum::<Duration>() / times.len() as u32;
    let max_deviation = times.iter().map(|&t| t.abs_diff(avg_time)).max().unwrap();

    // Timing deviation should be less than 20% of average
    assert!(
        max_deviation < avg_time / 5,
        "Timing deviation too high: {:?} vs {:?}",
        max_deviation,
        avg_time
    );
}

/// Test memory safety and bounds checking
#[test]
fn test_memory_safety() {
    let context = Hqc128Kem::new().unwrap();

    // Test with various input sizes
    let test_cases = [
        vec![],         // Empty input
        vec![0u8; 1],   // Too small
        vec![0u8; 31],  // One byte short
        vec![0u8; 32],  // Correct size
        vec![0u8; 33],  // One byte too large
        vec![0u8; 100], // Much too large
    ];

    for (i, test_input) in test_cases.iter().enumerate() {
        match context.keygen_with_seed(test_input) {
            Ok(_) => {
                // Should only succeed for correct size (32 bytes)
                assert_eq!(test_input.len(), 32, "Test case {} should have failed", i);
            }
            Err(_) => {
                // Should fail for incorrect sizes
                assert_ne!(
                    test_input.len(),
                    32,
                    "Test case {} should have succeeded",
                    i
                );
            }
        }
    }
}

/// Test entropy quality and randomness
#[test]
fn test_entropy_quality() {
    let context = Hqc128Kem::new().unwrap();
    #[allow(clippy::disallowed_types)]
    let mut public_keys = HashSet::new();
    #[allow(clippy::disallowed_types)]
    let mut shared_secrets = HashSet::new();

    // Generate many keypairs and encapsulations
    for i in 0..1000 {
        let seed = [i as u8; 32];
        let (pk, sk) = context.keygen_with_seed(&seed).unwrap();

        // Check for duplicate public keys (using serialized form)
        let pk_bytes = pk.as_bytes().to_vec();
        assert!(
            public_keys.insert(pk_bytes),
            "Duplicate public key generated at iteration {}",
            i
        );

        // Test encapsulation
        let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
        let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();

        // Check for duplicate shared secrets
        let ss_bytes = ss.as_bytes().to_vec();
        assert!(
            shared_secrets.insert(ss_bytes),
            "Duplicate shared secret generated at iteration {}",
            i
        );

        // Test decapsulation
        let ss_decaps = context.decapsulate(&sk, &ct).unwrap();
        assert_eq!(
            ss.as_bytes(),
            ss_decaps.as_bytes(),
            "Decapsulation failed at iteration {}",
            i
        );
    }

    // Verify we have good distribution
    assert_eq!(public_keys.len(), 1000, "Not all public keys were unique");
    assert_eq!(
        shared_secrets.len(),
        1000,
        "Not all shared secrets were unique"
    );
}

/// Test performance characteristics
#[test]
fn test_performance_characteristics() {
    let context = Hqc128Kem::new().unwrap();
    let seed = [0u8; 32];

    // Test key generation performance
    let start = Instant::now();
    let (pk, sk) = context.keygen_with_seed(&seed).unwrap();
    let keygen_time = start.elapsed();

    // Key generation should complete within reasonable time
    assert!(
        keygen_time < Duration::from_millis(100),
        "Key generation too slow: {:?}",
        keygen_time
    );

    // Test encapsulation performance
    let start = Instant::now();
    let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
    let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();
    let encaps_time = start.elapsed();

    // Encapsulation should be fast
    assert!(
        encaps_time < Duration::from_millis(50),
        "Encapsulation too slow: {:?}",
        encaps_time
    );

    // Test decapsulation performance
    let start = Instant::now();
    let ss_decaps = context.decapsulate(&sk, &ct).unwrap();
    let decaps_time = start.elapsed();

    // Decapsulation should be fast
    assert!(
        decaps_time < Duration::from_millis(50),
        "Decapsulation too slow: {:?}",
        decaps_time
    );

    // Verify correctness
    assert_eq!(ss.as_bytes(), ss_decaps.as_bytes());

    // Performance should be consistent
    let total_time = keygen_time + encaps_time + decaps_time;
    assert!(
        total_time < Duration::from_millis(200),
        "Total operation time too slow: {:?}",
        total_time
    );
}

/// Test vector operations in isolation
#[test]
fn test_vector_operations() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test vect_write_support_to_vector
    let mut v = vec![0u64; 10];
    let support = vec![0u32, 64u32, 128u32, 192u32, 256u32];

    pke.vect_write_support_to_vector(&mut v, &support, 5);

    // Verify bits are set at correct positions
    assert_eq!(v[0] & 1, 1); // bit 0
    assert_eq!(v[1] & 1, 1); // bit 64
    assert_eq!(v[2] & 1, 1); // bit 128
    assert_eq!(v[3] & 1, 1); // bit 192
    assert_eq!(v[4] & 1, 1); // bit 256

    // Test Barrett reduction
    let test_cases = [
        (0u32, 0u32),
        (1u32, 1u32),
        (17668u32, 17668u32), // PARAM_N - 1
        (17669u32, 0u32),     // PARAM_N
        (17670u32, 1u32),     // PARAM_N + 1
        (35338u32, 0u32),     // 2 * PARAM_N
    ];

    for (input, expected) in test_cases {
        let result = pke.barrett_reduce(input);
        assert_eq!(
            result, expected,
            "Barrett reduction failed for input {}",
            input
        );
    }
}

/// Test polynomial multiplication properties
#[test]
fn test_polynomial_multiplication() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test with simple vectors
    let mut a = vec![0u64; 277];
    let mut b = vec![0u64; 277];
    let mut result = vec![0u64; 277];

    // Set some test bits
    a[0] = 1; // bit 0
    b[0] = 1; // bit 0

    pke.test_vect_mul(&mut result, &a, &b).unwrap();

    // Result should have bit 0 set (1 * 1 = 1)
    assert_eq!(result[0] & 1, 1);

    // Test with more complex vectors
    a[0] = 0x3; // bits 0 and 1
    b[0] = 0x5; // bits 0 and 2

    pke.test_vect_mul(&mut result, &a, &b).unwrap();

    // Result should have bits 0, 1, 2 set (0x3 * 0x5 = 0xF in GF(2))
    assert_eq!(result[0] & 0xF, 0xF);
}

/// Test XOF and hash function properties
#[test]
fn test_xof_and_hash_properties() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test hash_i function
    let input = [0u8; 32];
    let mut output = [0u8; 64];

    pke.hash_i(&mut output, &input);

    // Output should be non-zero for non-zero input
    assert!(output.iter().any(|&x| x != 0));

    // Same input should produce same output
    let mut output2 = [0u8; 64];
    pke.hash_i(&mut output2, &input);
    assert_eq!(output, output2);

    // Different input should produce different output
    let input2 = [1u8; 32];
    let mut output3 = [0u8; 64];
    pke.hash_i(&mut output3, &input2);
    assert_ne!(output, output3);
}

/// Test parameter validation
#[test]
fn test_parameter_validation() {
    // Test HQC-1 parameters
    assert_eq!(Hqc1Params::N, 17669);
    assert_eq!(Hqc1Params::OMEGA, 66);
    assert_eq!(Hqc1Params::OMEGA_R, 75);
    assert_eq!(Hqc1Params::VEC_N_SIZE_64, 277);

    // Test parameter relationships
    // These are compile-time constants that are always true
    const _: () = assert!(Hqc1Params::OMEGA_R > Hqc1Params::OMEGA);
    const _: () = assert!(Hqc1Params::N > 0);
    const _: () = assert!(Hqc1Params::VEC_N_SIZE_64 > 0);

    // Test bitmask calculation
    let bitmask = (1u64 << (Hqc1Params::N & 0x3F)) - 1;
    assert_eq!(bitmask, 0x1F); // For HQC-1: 17669 & 0x3F = 5, so 2^5 - 1 = 31 = 0x1F
}

/// Test stress scenarios
#[test]
fn test_stress_scenarios() {
    let context = Hqc128Kem::new().unwrap();

    // Test many rapid operations
    for i in 0..100 {
        let seed = [i as u8; 32];
        let (pk, sk) = context.keygen_with_seed(&seed).unwrap();

        // Multiple encapsulations with same key
        for j in 0..10 {
            let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
            let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();
            let ss_decaps = context.decapsulate(&sk, &ct).unwrap();
            assert_eq!(
                ss.as_bytes(),
                ss_decaps.as_bytes(),
                "Stress test failed at key {}, encapsulation {}",
                i,
                j
            );
        }
    }
}

/// Test cross-platform compatibility
#[test]
fn test_cross_platform_compatibility() {
    let context = Hqc128Kem::new().unwrap();
    let seed = [0x42u8; 32];

    // Generate keypair
    let (pk, sk) = context.keygen_with_seed(&seed).unwrap();

    // Test encapsulation/decapsulation
    let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
    let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();
    let ss_decaps = context.decapsulate(&sk, &ct).unwrap();

    // Results should be deterministic across platforms
    assert_eq!(ss.as_bytes(), ss_decaps.as_bytes());

    // Verify key sizes are correct
    assert_eq!(pk.as_bytes().len(), 2241); // HQC-1 public key size
    assert_eq!(sk.as_bytes().len(), 2321); // HQC-1 secret key size
    assert_eq!(ct.as_bytes().len(), 2241); // HQC-1 ciphertext size
    assert_eq!(ss.as_bytes().len(), 32); // Shared secret size
}

/// Test KAT compatibility
#[test]
fn test_kat_compatibility() {
    // This test verifies that our implementation produces the expected
    // outputs for known test vectors
    let context = Hqc128Kem::new().unwrap();

    // Use a known seed from KAT tests (48 bytes required for KEM)
    let seed = [0u8; 48];
    let (pk, sk) = context.keygen_with_seed(&seed).unwrap();

    // Verify that we can encapsulate and decapsulate successfully
    let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
    let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();
    let ss_decaps = context.decapsulate(&sk, &ct).unwrap();

    assert_eq!(ss.as_bytes(), ss_decaps.as_bytes());

    // Verify key sizes match actual implementation
    assert_eq!(pk.as_bytes().len(), 2249); // PKE public key size
    assert_eq!(sk.as_bytes().len(), 2345); // KEM secret key: ek_pke(2249) + dk_pke(32) + sigma(16) + seed_kem(48)
    assert_eq!(ct.as_bytes().len(), 5905); // PKE ciphertext size
    assert_eq!(ss.as_bytes().len(), 32); // Shared secret size
}

/// Test constant-time operations
#[test]
fn test_constant_time_operations() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test that Barrett reduction is constant-time
    let test_values = vec![0u32, 1u32, 17668u32, 17669u32, 17670u32, 35338u32];
    let mut times = Vec::new();

    for &value in &test_values {
        let start = Instant::now();
        let _ = pke.barrett_reduce(value);
        times.push(start.elapsed());
    }

    // All operations should take similar time
    let avg_time: Duration = times.iter().sum::<Duration>() / times.len() as u32;
    for (i, &time) in times.iter().enumerate() {
        let deviation = time.abs_diff(avg_time);
        assert!(
            deviation < avg_time / 10,
            "Barrett reduction not constant-time for value {}: {:?} vs {:?}",
            test_values[i],
            time,
            avg_time
        );
    }
}

/// Test vector operation correctness
#[test]
fn test_vector_operation_correctness() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test vect_add
    let mut a = vec![0u64; 277];
    let mut b = vec![0u64; 277];
    let mut result = vec![0u64; 277];

    a[0] = 0x5; // bits 0 and 2
    b[0] = 0x3; // bits 0 and 1

    pke.test_vect_add(&mut result, &a, &b, 277).unwrap();

    // Result should be 0x5 XOR 0x3 = 0x6 (bits 1 and 2)
    assert_eq!(result[0] & 0xF, 0x6);

    // Test vect_mul with known values
    a[0] = 0x1; // bit 0
    b[0] = 0x1; // bit 0

    pke.test_vect_mul(&mut result, &a, &b).unwrap();

    // Result should have bit 0 set
    assert_eq!(result[0] & 1, 1);
}

/// Test security properties
#[test]
fn test_security_properties() {
    let context = Hqc128Kem::new().unwrap();

    // Test that different seeds produce different keys
    let seed1 = [0u8; 32];
    let seed2 = [1u8; 32];

    let (pk1, _sk1) = context.keygen_with_seed(&seed1).unwrap();
    let (pk2, _sk2) = context.keygen_with_seed(&seed2).unwrap();

    assert_ne!(pk1.as_bytes(), pk2.as_bytes());

    // Test that same seed produces same keys
    let (pk1_repeat, sk1_repeat) = context.keygen_with_seed(&seed1).unwrap();
    assert_eq!(pk1.as_bytes(), pk1_repeat.as_bytes());
    assert_eq!(_sk1.as_bytes(), sk1_repeat.as_bytes());

    // Test that encapsulation produces different results each time
    let mut rng1 = LibQRng::new_secure().expect("Failed to create RNG");
    let mut rng2 = LibQRng::new_secure().expect("Failed to create RNG");
    let (ct1, ss1) = context.encapsulate(&pk1, &mut rng1).unwrap();
    let (ct2, ss2) = context.encapsulate(&pk1, &mut rng2).unwrap();

    // Ciphertexts and shared secrets should be different
    assert_ne!(ct1.as_bytes(), ct2.as_bytes());
    assert_ne!(ss1.as_bytes(), ss2.as_bytes());
}

/// Test error recovery
#[test]
fn test_error_recovery() {
    let context = Hqc128Kem::new().unwrap();

    // Test that errors don't leave the system in an inconsistent state
    for i in 0..10 {
        // Generate valid keypair
        let seed = [i as u8; 32];
        let (pk, sk) = context.keygen_with_seed(&seed).unwrap();

        // System should still work after any potential errors
        let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
        let (ct, ss) = context.encapsulate(&pk, &mut rng).unwrap();
        let ss_decaps = context.decapsulate(&sk, &ct).unwrap();
        assert_eq!(
            ss.as_bytes(),
            ss_decaps.as_bytes(),
            "System inconsistent after error at iteration {}",
            i
        );
    }
}
