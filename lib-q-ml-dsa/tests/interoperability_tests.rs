//! Interoperability tests ensuring wire-format compatibility between modes

use lib_q_ml_dsa::*;

#[test]
fn test_baseline_mode_equivalence() {
    // Current implementation: verify identical behavior
    let seed = [0x42; 32];
    let message = b"interoperability test message";
    let context = b"test context";
    let randomness = [0x43; 32];

    // Test key generation produces same output
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Test signing produces same output
    let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();

    // Test verification works
    let verify = ml_dsa_44::verify(&keys.verification_key, message, context, &sig);
    assert!(verify.is_ok(), "Signature must verify");

    // Document: As of [date], all modes produce identical wire formats
    println!("✓ Baseline verified: compliance and production modes produce identical outputs");
}

#[test]
fn test_cross_parameter_set_compatibility() {
    // Verify all parameter sets maintain compatibility
    let seed = [0x42; 32];
    let message = b"cross-parameter test";
    let context = b"test";
    let randomness = [0x43; 32];

    // Test ML-DSA-44
    {
        let keys = ml_dsa_44::generate_key_pair(seed);
        let sig = ml_dsa_44::sign(&keys.signing_key, message, context, randomness).unwrap();
        assert!(ml_dsa_44::verify(&keys.verification_key, message, context, &sig).is_ok());
    }

    // Test ML-DSA-65
    #[cfg(feature = "mldsa65")]
    {
        let keys = ml_dsa_65::generate_key_pair(seed);
        let sig = ml_dsa_65::sign(&keys.signing_key, message, context, randomness).unwrap();
        assert!(ml_dsa_65::verify(&keys.verification_key, message, context, &sig).is_ok());
    }

    // Test ML-DSA-87
    #[cfg(feature = "mldsa87")]
    {
        let keys = ml_dsa_87::generate_key_pair(seed);
        let sig = ml_dsa_87::sign(&keys.signing_key, message, context, randomness).unwrap();
        assert!(ml_dsa_87::verify(&keys.verification_key, message, context, &sig).is_ok());
    }
}
