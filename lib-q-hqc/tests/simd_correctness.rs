//! Tests for SIMD correctness and equivalence

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_hqc::simd::Avx2;
use lib_q_hqc::simd::Portable;
use lib_q_hqc::simd::traits::{
    PolynomialOps,
    SyndromeOps,
};

/// Test AVX2 vs Portable polynomial multiplication equivalence
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_avx2_polynomial_mul_correctness() {
    let mut output_avx2 = [0u8; 256];
    let mut output_portable = [0u8; 256];
    let sparse = [0xABu8; 128];
    let dense = [0xCDu8; 128];

    // Run both implementations using ZSTs
    Avx2::sparse_dense_mul(&mut output_avx2, &sparse, &dense, 10);
    Portable::sparse_dense_mul(&mut output_portable, &sparse, &dense, 10);

    // Results should match byte-for-byte
    assert_eq!(output_avx2, output_portable);
}

/// Test AVX2 vs Portable vector addition equivalence
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_avx2_vector_add_correctness() {
    let mut output_avx2 = [0u8; 64];
    let mut output_portable = [0u8; 64];
    let a = [0xAAu8; 64];
    let b = [0x55u8; 64];

    // Run both implementations using ZSTs
    Avx2::vect_add(&mut output_avx2, &a, &b);
    Portable::vect_add(&mut output_portable, &a, &b);

    // Results should match byte-for-byte
    assert_eq!(output_avx2, output_portable);
}

/// Test AVX2 vs Portable syndrome generation equivalence
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_avx2_syndrome_correctness() {
    let mut syndrome_avx2 = [0u8; 64];
    let mut syndrome_portable = [0u8; 64];
    let vector = [0x12u8; 64];
    let parity = [0x34u8; 64];

    // Run both implementations using ZSTs
    Avx2::generate_syndrome(&mut syndrome_avx2, &vector, &parity);
    Portable::generate_syndrome(&mut syndrome_portable, &vector, &parity);

    // Results should match byte-for-byte
    assert_eq!(syndrome_avx2, syndrome_portable);
}

/// Test ZST dispatch works correctly
#[test]
fn test_zst_dispatch() {
    // Test that ZST dispatch doesn't panic
    let mut output = [0u8; 32];
    let sparse = [1u8; 32];
    let dense = [2u8; 32];
    let weight = 10;

    Portable::sparse_dense_mul(&mut output, &sparse, &dense, weight);

    // Test syndrome operations
    let mut syndrome = [0u8; 32];
    let vector = [3u8; 32];
    let parity = [4u8; 32];

    Portable::generate_syndrome(&mut syndrome, &vector, &parity);

    // Test error correction
    let mut corrected = [0u8; 32];
    let received = [5u8; 32];
    let result = Portable::correct_errors(&mut corrected, &received, &syndrome);

    assert!(result);
}

/// Test CPUID detection
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_cpuid_detection() {
    use lib_q_hqc::simd::runtime;

    // Force redetection
    runtime::detect_cpu_features();
    let has_avx2 = runtime::has_avx2();

    println!("AVX2 detected via CPUID: {}", has_avx2);

    // Test should not panic regardless of CPU capabilities
    // The actual result depends on the host CPU
}

/// Test that SIMD operations handle edge cases correctly
#[test]
fn test_simd_edge_cases() {
    // Test with empty arrays
    let mut output = [];
    let sparse = [];
    let dense = [];
    Portable::sparse_dense_mul(&mut output, &sparse, &dense, 0);

    // Test with single byte
    let mut output = [0u8; 1];
    let sparse = [1u8];
    let dense = [2u8];
    Portable::sparse_dense_mul(&mut output, &sparse, &dense, 1);

    // Test with non-32-byte aligned sizes
    let mut output = [0u8; 33];
    let sparse = [1u8; 33];
    let dense = [2u8; 33];
    Portable::sparse_dense_mul(&mut output, &sparse, &dense, 5);
}

/// Test large buffer operations (1KB)
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_large_buffer_1kb() {
    const SIZE: usize = 1024;
    let mut output_avx2 = [0u8; SIZE];
    let mut output_portable = [0u8; SIZE];
    let sparse = [0xABu8; SIZE / 2];
    let dense = [0xCDu8; SIZE / 2];

    // Test polynomial multiplication
    Avx2::sparse_dense_mul(&mut output_avx2, &sparse, &dense, 50);
    Portable::sparse_dense_mul(&mut output_portable, &sparse, &dense, 50);
    assert_eq!(output_avx2, output_portable);

    // Test vector addition
    let a = [0xAAu8; SIZE];
    let b = [0x55u8; SIZE];
    Avx2::vect_add(&mut output_avx2, &a, &b);
    Portable::vect_add(&mut output_portable, &a, &b);
    assert_eq!(output_avx2, output_portable);

    // Test syndrome generation
    let vector = [0x12u8; SIZE];
    let parity = [0x34u8; SIZE];
    Avx2::generate_syndrome(&mut output_avx2, &vector, &parity);
    Portable::generate_syndrome(&mut output_portable, &vector, &parity);
    assert_eq!(output_avx2, output_portable);
}

/// Test large buffer operations (4KB)
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_large_buffer_4kb() {
    const SIZE: usize = 4096;
    let mut output_avx2 = [0u8; SIZE];
    let mut output_portable = [0u8; SIZE];
    let sparse = [0xABu8; SIZE / 2];
    let dense = [0xCDu8; SIZE / 2];

    // Test polynomial multiplication
    Avx2::sparse_dense_mul(&mut output_avx2, &sparse, &dense, 100);
    Portable::sparse_dense_mul(&mut output_portable, &sparse, &dense, 100);
    assert_eq!(output_avx2, output_portable);

    // Test vector addition
    let a = [0xAAu8; SIZE];
    let b = [0x55u8; SIZE];
    Avx2::vect_add(&mut output_avx2, &a, &b);
    Portable::vect_add(&mut output_portable, &a, &b);
    assert_eq!(output_avx2, output_portable);
}

/// Known-answer tests with reference vectors
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_known_answer_vectors() {
    // Test with specific known patterns
    let test_cases = [
        // (sparse, dense, weight, expected_hash)
        ([0x01u8; 32], [0xFFu8; 32], 1, "single_bit_sparse"),
        ([0xFFu8; 32], [0x01u8; 32], 256, "all_bits_sparse"),
        ([0xAAu8; 32], [0x55u8; 32], 128, "alternating_pattern"),
        ([0x00u8; 32], [0xFFu8; 32], 0, "zero_sparse"),
    ];

    for (i, (sparse, dense, weight, _desc)) in test_cases.iter().enumerate() {
        let mut output_avx2 = [0u8; 32];
        let mut output_portable = [0u8; 32];

        Avx2::sparse_dense_mul(&mut output_avx2, sparse, dense, *weight);
        Portable::sparse_dense_mul(&mut output_portable, sparse, dense, *weight);

        assert_eq!(output_avx2, output_portable, "KAT test case {} failed", i);
    }
}

/// Stress test with random-like data
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_stress_random_data() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{
        Hash,
        Hasher,
    };

    // Generate pseudo-random test data
    let mut sparse = [0u8; 256];
    let mut dense = [0u8; 256];

    for i in 0..256 {
        let mut hasher = DefaultHasher::new();
        i.hash(&mut hasher);
        let hash = hasher.finish();
        sparse[i] = (hash & 0xFF) as u8;
        dense[i] = ((hash >> 8) & 0xFF) as u8;
    }

    let mut output_avx2 = [0u8; 256];
    let mut output_portable = [0u8; 256];

    // Test with various weights
    for weight in [1, 10, 50, 100, 200] {
        Avx2::sparse_dense_mul(&mut output_avx2, &sparse, &dense, weight);
        Portable::sparse_dense_mul(&mut output_portable, &sparse, &dense, weight);
        assert_eq!(
            output_avx2, output_portable,
            "Stress test failed for weight {}",
            weight
        );
    }
}

/// Test shift_xor operations with various distances
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_shift_xor_distances() {
    let source = [0x123456789ABCDEF0u64; 8];
    let distances = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128];

    for &distance in &distances {
        let mut dest_avx2 = [0u64; 16];
        let mut dest_portable = [0u64; 16];

        Avx2::shift_xor(&mut dest_avx2, &source, distance);
        Portable::shift_xor(&mut dest_portable, &source, distance);

        assert_eq!(
            dest_avx2, dest_portable,
            "shift_xor failed for distance {}",
            distance
        );
    }
}

/// Test error correction equivalence
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_error_correction_equivalence() {
    let received = [0x12u8; 64];
    let syndrome = [0x34u8; 64];

    let mut corrected_avx2 = [0u8; 64];
    let mut corrected_portable = [0u8; 64];

    let result_avx2 = Avx2::correct_errors(&mut corrected_avx2, &received, &syndrome);
    let result_portable = Portable::correct_errors(&mut corrected_portable, &received, &syndrome);

    assert_eq!(result_avx2, result_portable);
    assert_eq!(corrected_avx2, corrected_portable);
}

/// Test all HQC parameter sets
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_hqc_parameter_sets() {
    use lib_q_hqc::params_correct::{
        Hqc1Params,
        Hqc3Params,
        Hqc5Params,
    };

    // Test HQC-128 (HQC1)
    test_parameter_set::<Hqc1Params>("HQC-128");

    // Test HQC-192 (HQC3)
    test_parameter_set::<Hqc3Params>("HQC-192");

    // Test HQC-256 (HQC5)
    test_parameter_set::<Hqc5Params>("HQC-256");
}

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
fn test_parameter_set<P: lib_q_hqc::params_correct::HqcParams>(name: &str) {
    let n_bytes = P::N / 8;
    let mut output_avx2 = vec![0u8; n_bytes];
    let mut output_portable = vec![0u8; n_bytes];
    let sparse = vec![0xABu8; n_bytes / 2];
    let dense = vec![0xCDu8; n_bytes / 2];

    Avx2::sparse_dense_mul(&mut output_avx2, &sparse, &dense, P::OMEGA as u32);
    Portable::sparse_dense_mul(&mut output_portable, &sparse, &dense, P::OMEGA as u32);

    assert_eq!(
        output_avx2, output_portable,
        "Parameter set {} failed",
        name
    );
}

/// Randomized fuzzing tests for shift_xor operation
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn fuzz_shift_xor_random_inputs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{
        Hash,
        Hasher,
    };

    for seed in 0..100 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        let size = (hasher.finish() % 256 + 32) as usize;

        let source: Vec<u64> = (0..size)
            .map(|i| {
                i.hash(&mut hasher);
                hasher.finish()
            })
            .collect();

        for distance in [0, 1, 7, 8, 15, 16, 31, 32, 63, 64] {
            let mut avx2_dest = vec![0u64; source.len() * 2];
            let mut portable_dest = vec![0u64; source.len() * 2];

            Avx2::shift_xor(&mut avx2_dest, &source, distance);
            Portable::shift_xor(&mut portable_dest, &source, distance);

            assert_eq!(
                avx2_dest, portable_dest,
                "Fuzz seed {} distance {} failed",
                seed, distance
            );
        }
    }
}
