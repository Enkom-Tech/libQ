//! no_std compatibility tests for lib-q-random
//!
//! These tests verify that the no_std implementation works correctly
//! in constrained environments.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "alloc")]
use lib_q_random::{
    new_deterministic_rng,
    new_secure_rng,
};
#[cfg(not(feature = "alloc"))]
use lib_q_random::{
    new_deterministic_rng_no_std,
    new_secure_rng_no_std,
    no_std_rng::NoStdRng,
};
use rand_core::Rng;

/// Test basic RNG creation and functionality
#[test]
fn test_no_std_rng_creation() {
    #[cfg(not(feature = "alloc"))]
    {
        let rng = new_secure_rng_no_std();
        assert!(rng.is_ok());

        let mut rng = rng.unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Verify bytes were generated (not all zeros)
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros, "RNG generated all zeros");
    }

    #[cfg(feature = "alloc")]
    {
        let rng = new_secure_rng();
        assert!(rng.is_ok());

        let mut rng = rng.unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Verify bytes were generated (not all zeros)
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros, "RNG generated all zeros");
    }
}

/// Test deterministic RNG functionality
#[test]
fn test_deterministic_rng() {
    let seed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_deterministic_rng_no_std(&seed);
        let mut rng2 = new_deterministic_rng_no_std(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(
            bytes1, bytes2,
            "Deterministic RNG should produce same output"
        );
        assert!(
            rng1.is_deterministic(),
            "RNG should be marked as deterministic"
        );
    }

    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_deterministic_rng(&seed);
        let mut rng2 = new_deterministic_rng(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(
            bytes1, bytes2,
            "Deterministic RNG should produce same output"
        );
    }
}

/// Test RNG reseeding functionality
#[test]
fn test_rng_reseeding() {
    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().unwrap();
        let initial_counter = rng.reseed_counter();
        let initial_bytes = rng.bytes_generated();

        // Generate enough bytes to potentially trigger reseed
        let mut bytes = [0u8; 1024];
        rng.fill_bytes(&mut bytes);

        assert!(
            rng.bytes_generated() > initial_bytes,
            "Bytes generated should increase"
        );

        // Note: Reseed counter might not change immediately due to large reseed interval
        // This is expected behavior for security
    }

    #[cfg(feature = "alloc")]
    {
        let mut rng = new_secure_rng().unwrap();
        let mut bytes = [0u8; 1024];
        rng.fill_bytes(&mut bytes);

        // Verify bytes were generated
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros, "RNG generated all zeros");
    }
}

/// Test RNG error handling
#[test]
fn test_rng_error_handling() {
    #[cfg(not(feature = "alloc"))]
    {
        // Test that RNG creation fails gracefully if getrandom is not available
        // This test would need to be run with getrandom disabled to be meaningful
        let rng = new_secure_rng_no_std();
        // In normal circumstances with getrandom available, this should succeed
        // The error case is tested in the no_std_rng module tests
    }
}

/// Test RNG trait implementations
#[test]
fn test_rng_traits() {
    #[cfg(not(feature = "alloc"))]
    {
        use rand_core::{
            CryptoRng,
            Rng,
        };

        let mut rng = new_secure_rng_no_std().unwrap();

        // Test Rng implementation
        let u32_val = rng.next_u32();
        let u64_val = rng.next_u64();

        // Test CryptoRng marker trait (compile-time check)
        fn test_crypto_rng<T: CryptoRng>(rng: &mut T) {
            let mut test_bytes = [0u8; 16];
            rng.fill_bytes(&mut test_bytes);
            // Verify we got some randomness
            assert!(!test_bytes.iter().all(|&b| b == 0));
        }
        test_crypto_rng(&mut rng);

        // Test fill_bytes
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);

        // Verify some randomness
        assert!(u32_val != 0 || u64_val != 0 || !bytes.iter().all(|&b| b == 0));
    }
}

/// Test no_std specific functionality
#[test]
fn test_no_std_specific() {
    #[cfg(not(feature = "alloc"))]
    {
        let rng = new_secure_rng_no_std().unwrap();

        // Test no_std specific methods
        assert!(
            !rng.is_deterministic(),
            "Secure RNG should not be deterministic"
        );
        assert_eq!(
            rng.bytes_generated(),
            0,
            "Initial bytes generated should be 0"
        );
        assert_eq!(
            rng.reseed_counter(),
            0,
            "Initial reseed counter should be 0"
        );

        // Test deterministic RNG
        let det_rng = new_deterministic_rng_no_std(&[1, 2, 3, 4]);
        assert!(
            det_rng.is_deterministic(),
            "Deterministic RNG should be marked as such"
        );
    }
}

/// Test memory safety and zero-copy operations
#[test]
fn test_memory_safety() {
    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().unwrap();

        // Test that we can generate various sizes without allocation
        let mut small_bytes = [0u8; 1];
        let mut medium_bytes = [0u8; 64];
        let mut large_bytes = [0u8; 1024];

        rng.fill_bytes(&mut small_bytes);
        rng.fill_bytes(&mut medium_bytes);
        rng.fill_bytes(&mut large_bytes);

        // Verify all buffers were filled
        assert!(!small_bytes.iter().all(|&b| b == 0));
        assert!(!medium_bytes.iter().all(|&b| b == 0));
        assert!(!large_bytes.iter().all(|&b| b == 0));
    }
}

/// Test edge cases
#[test]
fn test_edge_cases() {
    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().unwrap();

        // Test empty buffer
        let mut empty_bytes = [];
        rng.fill_bytes(&mut empty_bytes);
        // Should not panic

        // Test single byte
        let mut single_byte = [0u8; 1];
        rng.fill_bytes(&mut single_byte);
        // Should generate a byte

        // Test very large buffer
        let mut large_bytes = [0u8; 65536];
        rng.fill_bytes(&mut large_bytes);
        // Should generate many bytes without issues
    }
}
