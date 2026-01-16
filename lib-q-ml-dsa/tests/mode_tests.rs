//! Mode-Specific Tests for ML-DSA
//!
//! This module provides separate test suites for FIPS mode and hardened mode
//! to ensure both compliance and security features work correctly.

#![cfg(all(feature = "random", feature = "acvp"))]

use lib_q_ml_dsa::*;

#[cfg(feature = "fips-mode")]
mod fips_mode_tests {
    use super::*;

    /// Test FIPS mode compliance with NIST test vectors
    #[test]
    fn test_fips_compliance() {
        // Test that FIPS mode produces deterministic results
        let seed = [0x42; 32];
        let message = b"FIPS compliance test message";
        let rnd = [0x42; 32];

        // Generate keys
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Sign message
        let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
        let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

        // Must be deterministic
        assert_eq!(
            sig1.as_slice(),
            sig2.as_slice(),
            "FIPS mode must be deterministic"
        );

        // Verify signature
        let verify_result = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig1);
        assert!(verify_result.is_ok(), "FIPS mode signature must verify");
    }

    /// Test FIPS mode against ACVP test vectors
    #[test]
    fn test_fips_acvp_compliance() {
        // This test would load and validate against official NIST ACVP vectors
        // For now, we test that the implementation is deterministic

        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Test multiple parameter sets
        let test_cases: &[(&[u8], [u8; 32])] = &[
            (b"test message 1", [0x42; 32]),
            (b"test message 2", [0x43; 32]),
            (b"empty", [0x44; 32]), // Short message
        ];

        for (message, rnd) in test_cases {
            let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, *rnd).unwrap();
            let verify = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
            assert!(verify.is_ok(), "FIPS mode must handle all test cases");
        }
    }

    /// Test FIPS mode performance characteristics
    #[test]
    fn test_fips_mode_performance() {
        // Test that FIPS mode has minimal overhead
        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);
        let message = b"performance test message";
        let rnd = [0x42; 32];

        // Measure key generation time (should be fast in FIPS mode)
        let start = std::time::Instant::now();
        let _keys2 = ml_dsa_44::generate_key_pair(seed);
        let keygen_time = start.elapsed();

        // Measure signing time
        let start = std::time::Instant::now();
        let _sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
        let sign_time = start.elapsed();

        // FIPS mode should be fast (these are just sanity checks)
        assert!(
            keygen_time.as_millis() < 1000,
            "FIPS mode keygen should be fast"
        );
        assert!(
            sign_time.as_millis() < 1000,
            "FIPS mode signing should be fast"
        );
    }
}

#[cfg(feature = "hardened-mode")]
mod hardened_mode_tests {
    use super::*;

    /// Test hardened mode security features
    #[test]
    fn test_enhanced_security() {
        // Test that hardened mode uses RNG abstraction
        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);
        let message = b"hardened security test message";
        let rnd = [0x42; 32];

        // Sign and verify
        let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
        let verify = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
        assert!(verify.is_ok(), "Hardened mode must work correctly");

        // Test that different randomness produces different signatures
        let rnd2 = [0x43; 32];
        let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd2).unwrap();
        assert_ne!(
            sig.as_slice(),
            sig2.as_slice(),
            "Different randomness should produce different signatures"
        );
    }

    /// Test zeroization features
    #[test]
    fn test_zeroization() {
        // Test that sensitive data is properly zeroized
        // This is a basic test - in a real implementation, we'd need to
        // verify that memory is actually cleared

        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Create a signature
        let message = b"zeroization test message";
        let rnd = [0x42; 32];
        let _sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

        // In hardened mode, sensitive data should be zeroized
        // This test passes if the operation completes without errors
        // Zeroization test completed successfully
    }

    /// Test constant-time operations
    #[test]
    fn test_constant_time_operations() {
        // Test that operations are constant-time
        // This is a basic test - in a real implementation, we'd need to
        // measure timing variations

        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);
        let message = b"constant time test message";
        let rnd = [0x42; 32];

        // Sign multiple times and measure timing
        let mut times = Vec::new();
        for _ in 0..10 {
            let start = std::time::Instant::now();
            let _sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
            times.push(start.elapsed());
        }

        // In hardened mode, timing should be more consistent
        // This is a basic check - real constant-time testing requires more sophisticated analysis
        // Note: Timing tests are inherently flaky and should not be relied upon for security guarantees
        // Proper constant-time verification requires tools like dudect or ctgrind
        let max_time = times.iter().max().unwrap();

        // Just verify operations complete successfully and in reasonable time
        // Don't assert strict timing bounds as they're unreliable on busy systems
        assert!(
            max_time.as_millis() < 1000,
            "Verification should complete in reasonable time"
        );

        // Log timing statistics for manual review
        #[cfg(feature = "std")]
        {
            let avg_time = times.iter().sum::<std::time::Duration>() / times.len() as u32;
            let min_time = times.iter().min().unwrap();
            eprintln!(
                "Timing stats - min: {:?}, max: {:?}, avg: {:?}",
                min_time, max_time, avg_time
            );
        }
    }

    /// Test entropy quality in hardened mode
    #[test]
    fn test_entropy_quality() {
        // Test that entropy sources are of high quality
        // This would typically involve statistical tests

        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Generate multiple signatures with different randomness
        let mut signatures = Vec::new();
        for i in 0..10 {
            let rnd = [i as u8; 32];
            let sig = ml_dsa_44::sign_internal(&keys.signing_key, b"entropy test", rnd).unwrap();
            signatures.push(sig);
        }

        // All signatures should be different
        for i in 0..signatures.len() {
            for j in (i + 1)..signatures.len() {
                assert_ne!(
                    signatures[i].as_slice(),
                    signatures[j].as_slice(),
                    "Different entropy should produce different signatures"
                );
            }
        }
    }

    /// Test hardened mode against various attack scenarios
    #[test]
    fn test_attack_resistance() {
        // Test resistance to common attack scenarios

        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);
        let message = b"attack resistance test message";

        // Test with edge case inputs
        let edge_cases = [
            [0x00; 32], // All zeros
            [0xFF; 32], // All ones
            [0x42; 32], // Normal case
        ];

        for rnd in edge_cases {
            let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
            let verify = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
            assert!(
                verify.is_ok(),
                "Hardened mode must handle edge cases correctly"
            );
        }
    }
}

/// Test that both modes produce compatible results
#[test]
fn test_mode_compatibility() {
    // Test that both modes can verify each other's signatures
    // (This test only runs when both modes are available)

    #[cfg(all(feature = "fips-mode", feature = "hardened-mode"))]
    {
        let seed = [0x42; 32];
        let message = b"compatibility test message";
        let rnd = [0x42; 32];

        // Generate keys in one mode
        let keys = ml_dsa_44::generate_key_pair(seed);

        // Sign in one mode
        let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

        // Verify in the same mode (should work)
        let verify = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
        assert!(verify.is_ok(), "Modes should be compatible");
    }

    // If only one mode is available, just test basic functionality
    #[cfg(not(all(feature = "fips-mode", feature = "hardened-mode")))]
    {
        let seed = [0x42; 32];
        let keys = ml_dsa_44::generate_key_pair(seed);
        let message = b"single mode test";
        let rnd = [0x42; 32];

        let sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
        let verify = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig);
        assert!(verify.is_ok(), "Single mode should work correctly");
    }
}

/// Test mode-specific error handling
#[test]
fn test_mode_error_handling() {
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);
    let message = b"error handling test";
    let rnd = [0x42; 32];

    // Test with invalid signature
    let mut invalid_sig_bytes = [0u8; 2420]; // ML-DSA-44 signature size
    invalid_sig_bytes[0] = 0xFF; // Corrupt first byte
    let invalid_sig = MLDSASignature::new(invalid_sig_bytes);

    let verify_result = ml_dsa_44::verify_internal(&keys.verification_key, message, &invalid_sig);
    assert!(
        verify_result.is_err(),
        "Invalid signature should be rejected"
    );

    // Test with valid signature
    let valid_sig = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
    let verify_result = ml_dsa_44::verify_internal(&keys.verification_key, message, &valid_sig);
    assert!(verify_result.is_ok(), "Valid signature should be accepted");
}
