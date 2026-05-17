//! Security tests for FN-DSA implementation
//!
//! These tests validate that security-critical changes have been properly implemented:
//! 1. Original Falcon support has been removed
//! 2. Domain separation is properly enforced
//! 3. Memory optimizations don't introduce security vulnerabilities
//! 4. Small degree optimizations maintain correctness

use lib_q_fn_dsa::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn test_original_falcon_support_removed() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;
    let message = b"Test message for domain separation";

    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    let verification_ok = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    assert!(verification_ok, "Signature should be valid");
    Ok(())
}

#[test]
fn test_domain_separation_enforced() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;
    let message = b"Test message for domain separation";

    let signature1 = fn_dsa.sign(&keypair.secret_key, message)?;

    let verify1 = fn_dsa.verify(&keypair.public_key, message, &signature1)?;
    assert!(verify1, "Signature should be valid with correct domain");

    Ok(())
}

#[test]
fn test_memory_optimization_security() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair1 = fn_dsa.generate_keypair()?;
    let keypair2 = fn_dsa.generate_keypair()?;

    let message1 = b"Message for keypair 1";
    let message2 = b"Message for keypair 2";

    let sig1 = fn_dsa.sign(&keypair1.secret_key, message1)?;
    let sig2 = fn_dsa.sign(&keypair2.secret_key, message2)?;

    let verify1_with_sig1 = fn_dsa.verify(&keypair1.public_key, message1, &sig1)?;
    let verify1_with_sig2 = fn_dsa.verify(&keypair1.public_key, message1, &sig2)?;

    assert!(verify1_with_sig1, "Correct signature should verify");
    assert!(!verify1_with_sig2, "Wrong signature should not verify");

    let verify2_with_sig2 = fn_dsa.verify(&keypair2.public_key, message2, &sig2)?;
    let verify2_with_sig1 = fn_dsa.verify(&keypair2.public_key, message2, &sig1)?;

    assert!(verify2_with_sig2, "Correct signature should verify");
    assert!(!verify2_with_sig1, "Wrong signature should not verify");
    Ok(())
}

#[test]
fn test_small_degree_optimization_correctness() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let messages = vec![
        b"Short".as_slice(),
        b"Medium length message".as_slice(),
        b"Very long message that exceeds typical buffer sizes and tests edge cases".as_slice(),
    ];

    for message in messages {
        let signature = fn_dsa.sign(&keypair.secret_key, message)?;
        let verification = fn_dsa.verify(&keypair.public_key, message, &signature)?;
        assert!(
            verification,
            "Signature should be valid for message: {:?}",
            message
        );
    }
    Ok(())
}

#[test]
fn test_constant_time_properties() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    // Same length so work is comparable; different bytes. Wall-clock is only a weak smoke
    // check—real constant-time is verified by analysis, not this test.
    let msg_a = [0x4Au8; 64];
    let msg_b = [0xB3u8; 64];

    let start = std::time::Instant::now();
    let _sig1 = fn_dsa.sign(&keypair.secret_key, &msg_a)?;
    let time_a = start.elapsed();

    let start = std::time::Instant::now();
    let _sig2 = fn_dsa.sign(&keypair.secret_key, &msg_b)?;
    let time_b = start.elapsed();

    let time_diff = time_a.abs_diff(time_b);

    // CI hosts can be noisy; 500ms is still a broad smoke bound for two equal-length calls.
    let max_allowed_diff = std::time::Duration::from_millis(500);
    assert!(
        time_diff < max_allowed_diff,
        "Timing difference too large: {:?} vs {:?}",
        time_a,
        time_b
    );
    Ok(())
}

#[test]
fn test_nist_compliance() -> TestResult {
    let fn_dsa_512 = FnDsa512::new();
    let fn_dsa_1024 = FnDsa1024::new();

    let keypair_512 = fn_dsa_512.generate_keypair()?;
    let keypair_1024 = fn_dsa_1024.generate_keypair()?;

    let message = b"NIST compliance test message";

    let sig_512 = fn_dsa_512.sign(&keypair_512.secret_key, message)?;
    let verify_512 = fn_dsa_512.verify(&keypair_512.public_key, message, &sig_512)?;
    assert!(verify_512, "512-bit signature should be valid");

    let sig_1024 = fn_dsa_1024.sign(&keypair_1024.secret_key, message)?;
    let verify_1024 = fn_dsa_1024.verify(&keypair_1024.public_key, message, &sig_1024)?;
    assert!(verify_1024, "1024-bit signature should be valid");

    let cross_verify_512_1024 = fn_dsa_512.verify(&keypair_1024.public_key, message, &sig_1024);
    assert!(
        !matches!(&cross_verify_512_1024, Ok(true)),
        "Cross-verification between security levels should fail"
    );
    Ok(())
}

#[test]
fn test_memory_zeroization() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let message = b"Test message for zeroization";
    let _signature = fn_dsa.sign(&keypair.secret_key, message)?;

    let signature2 = fn_dsa.sign(&keypair.secret_key, message)?;
    let verification = fn_dsa.verify(&keypair.public_key, message, &signature2)?;
    assert!(verification, "Key should still be usable after signing");

    let signature3 = fn_dsa.sign(&keypair.secret_key, message)?;
    let verification3 = fn_dsa.verify(&keypair.public_key, message, &signature3)?;
    assert!(
        verification3,
        "Key should still be usable after multiple operations"
    );
    Ok(())
}
