//! Comprehensive validation tests for HQC implementation
//!
//! This module provides focused testing for HQC implementation correctness.

use lib_q_hqc::*;

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
