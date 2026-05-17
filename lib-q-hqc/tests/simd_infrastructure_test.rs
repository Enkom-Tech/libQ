//! Test SIMD infrastructure and basic functionality

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_hqc::simd::Avx2;
use lib_q_hqc::simd::{
    PolynomialOps,
    Portable,
    SyndromeOps,
    runtime,
};

/// Test that SIMD infrastructure compiles and basic functions work
#[test]
fn test_simd_infrastructure() {
    // Test runtime detection
    runtime::detect_cpu_features();
    let implementation = runtime::get_best_implementation();
    println!("Best available implementation: {}", implementation);

    // Test that we can call the functions without panicking
    let mut output = [0u8; 16];
    let sparse = [0u8; 16];
    let dense = [0u8; 16];

    // This should not panic
    Portable::sparse_dense_mul(&mut output, &sparse, &dense, 10, 16 * 8);

    // Test syndrome operations
    let mut syndrome = [0u8; 16];
    let vector = [0u8; 16];
    let parity = [0u8; 16];

    Portable::generate_syndrome(&mut syndrome, &vector, &parity);

    println!("✓ SIMD infrastructure test passed");
}

/// Test AVX2 feature availability
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[test]
fn test_avx2_availability() {
    let has_avx2 = runtime::has_avx2();
    println!("AVX2 available: {}", has_avx2);

    // Test that AVX2 functions can be called
    let mut output = [0u8; 16];
    let sparse = [0u8; 16];
    let dense = [0u8; 16];

    Avx2::sparse_dense_mul(&mut output, &sparse, &dense, 10, 16 * 8);

    println!("✓ AVX2 availability test passed");
}

/// Test that portable implementation always works
#[test]
fn test_portable_implementation() {
    let mut output = [0u8; 16];
    let sparse = [0u8; 16];
    let dense = [0u8; 16];

    // Test polynomial operations
    Portable::sparse_dense_mul(&mut output, &sparse, &dense, 10, 16 * 8);

    // Test vector operations
    let mut dest = [0u64; 4];
    let source = [1u64, 2u64, 3u64, 4u64];
    Portable::shift_xor(&mut dest, &source, 1);

    // Test syndrome operations
    let mut syndrome = [0u8; 16];
    let vector = [0u8; 16];
    let parity = [0u8; 16];

    Portable::generate_syndrome(&mut syndrome, &vector, &parity);

    println!("✓ Portable implementation test passed");
}
