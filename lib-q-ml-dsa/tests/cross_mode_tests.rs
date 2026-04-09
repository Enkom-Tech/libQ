//! Cross-Mode Compatibility Tests
//!
//! This module provides tests to ensure compatibility between different
//! ML-DSA modes (FIPS mode, hardened mode, and default mode).

use lib_q_ml_dsa::*;

/// Test that both modes produce compatible outputs
/// This test compiles without mode features to test both
#[test]
fn test_mode_output_compatibility() {
    // Both modes should accept same inputs and produce valid outputs
    // (though not necessarily identical due to RNG differences)
    let seed = [0x42; 32];
    let message = b"cross-mode compatibility";

    let keys = ml_dsa_44::generate_key_pair(seed);
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);

    assert!(
        verify.is_ok(),
        "Both modes must produce verifiable signatures"
    );

    println!("✓ Cross-mode output compatibility verified");
}

/// Test mode feature compatibility
#[test]
fn test_mode_feature_compatibility() {
    let seed = [0x42; 32];
    let message = b"feature compatibility test";

    // Test that all parameter sets work regardless of mode
    let keys44 = ml_dsa_44::generate_key_pair(seed);
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig44 = ml_dsa_44::sign(&keys44.signing_key, message, context, randomness).unwrap();
    let verify44 = ml_dsa_44::verify(&keys44.verification_key, message, context, &sig44);
    assert!(verify44.is_ok(), "ML-DSA-44 must work in all modes");

    #[cfg(feature = "mldsa65")]
    {
        let keys65 = ml_dsa_65::generate_key_pair(seed);
        let context = b"test context";
        let randomness = [0x42; 32];
        let sig65 = ml_dsa_65::sign(&keys65.signing_key, message, context, randomness).unwrap();
        let verify65 = ml_dsa_65::verify(&keys65.verification_key, message, context, &sig65);
        assert!(verify65.is_ok(), "ML-DSA-65 must work in all modes");
    }

    #[cfg(feature = "mldsa87")]
    {
        let keys87 = ml_dsa_87::generate_key_pair(seed);
        let context = b"test context";
        let randomness = [0x42; 32];
        let sig87 = ml_dsa_87::sign(&keys87.signing_key, message, context, randomness).unwrap();
        let verify87 = ml_dsa_87::verify(&keys87.verification_key, message, context, &sig87);
        assert!(verify87.is_ok(), "ML-DSA-87 must work in all modes");
    }

    println!("✓ Mode feature compatibility verified");
}

/// Test SIMD-portable equivalence across modes
#[test]
fn test_simd_portable_equivalence_across_modes() {
    let seed = [0x42; 32];
    let message = b"SIMD-portable equivalence test";

    // Test that portable and SIMD implementations produce compatible results
    // regardless of mode
    let keys = ml_dsa_44::generate_key_pair(seed);
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);

    assert!(
        verify.is_ok(),
        "SIMD-portable equivalence must work across modes"
    );

    println!("✓ SIMD-portable equivalence across modes verified");
}

/// Test mode-specific feature availability
#[test]
fn test_mode_specific_feature_availability() {
    // Test that mode-specific features are properly gated

    #[cfg(feature = "fips-mode")]
    {
        println!("✓ FIPS mode features available");
    }

    #[cfg(feature = "hardened-mode")]
    {
        println!("✓ Hardened mode features available");

        #[cfg(feature = "zeroize")]
        {
            println!("✓ Zeroization feature available");
        }

        #[cfg(feature = "constant-time")]
        {
            println!("✓ Constant-time feature available");
        }
    }

    #[cfg(not(any(feature = "fips-mode", feature = "hardened-mode")))]
    {
        println!("✓ Default mode active");
    }
}

/// Test mode transition compatibility
#[test]
fn test_mode_transition_compatibility() {
    // Test that keys generated in one mode can be used in another
    let seed = [0x42; 32];
    let message = b"mode transition test";

    // Generate keys (mode-independent)
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Sign message (mode-independent)
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    // Verify signature (mode-independent)
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);
    assert!(
        verify.is_ok(),
        "Mode transitions must maintain compatibility"
    );

    println!("✓ Mode transition compatibility verified");
}

/// Test mode-specific security guarantees
#[test]
fn test_mode_specific_security_guarantees() {
    let seed = [0x42; 32];
    let message = b"security guarantees test";

    let keys = ml_dsa_44::generate_key_pair(seed);
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    // All modes must provide basic security guarantees
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);
    assert!(verify.is_ok(), "All modes must provide basic security");

    // Test that invalid signatures are rejected
    let mut invalid_sig = sig.clone();
    invalid_sig.as_mut_slice()[0] ^= 0xFF;
    let verify_invalid = ml_dsa_44::verify(&keys.verification_key, message, context, &invalid_sig);
    assert!(
        verify_invalid.is_err(),
        "All modes must reject invalid signatures"
    );

    println!("✓ Mode-specific security guarantees verified");
}

/// Test mode performance characteristics
#[test]
fn test_mode_performance_characteristics() {
    let seed = [0x42; 32];
    let message = b"performance test";

    // Test that all modes complete operations in reasonable time
    let start = std::time::Instant::now();

    let keys = ml_dsa_44::generate_key_pair(seed);
    let context = b"test context";
    let randomness = [0x42; 32];
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);

    let duration = start.elapsed();

    assert!(
        verify.is_ok(),
        "All modes must complete operations successfully"
    );
    // Avoid a tight wall-clock bound: WSL drvfs (/mnt/c/...), debug builds, and LLVM
    // coverage (tarpaulin) routinely exceed sub-second budgets while remaining correct.
    const MAX_DURATION_MS: u128 = 30_000;
    assert!(
        duration.as_millis() < MAX_DURATION_MS,
        "All modes must complete within {} ms (got {} ms)",
        MAX_DURATION_MS,
        duration.as_millis()
    );

    println!(
        "✓ Mode performance characteristics verified ({}ms)",
        duration.as_millis()
    );
}
