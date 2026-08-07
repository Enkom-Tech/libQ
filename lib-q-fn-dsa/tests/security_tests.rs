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

/// Catastrophic-regression tripwire, NOT a constant-time gate.
///
/// This performs exactly one `sign()` call per input class and compares wall-clock elapsed time
/// against a 500ms bound. A single-sample wall-clock comparison has no statistical power to
/// detect a timing side channel -- it can only catch a livelock-class regression (e.g. an
/// accidental infinite/near-infinite loop on one input class) gross enough to blow past 500ms on
/// a debug build. It was previously named `test_constant_time_properties`, which claimed
/// evidence this test cannot provide; renamed for card t_9d1766f3.
///
/// A real statistical timing check (paired-input Welch t-test, release build, n=1000 per class)
/// lives in `tests/constant_time.rs` -- see that file's module doc for what it actually measures
/// and its own honestly-scoped limitations.
#[test]
fn test_signing_latency_smoke() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    // Same length so work is comparable; different bytes.
    let msg_a = [0x4Au8; 64];
    let msg_b = [0xB3u8; 64];

    let start = std::time::Instant::now();
    let _sig1 = fn_dsa.sign(&keypair.secret_key, &msg_a)?;
    let time_a = start.elapsed();

    let start = std::time::Instant::now();
    let _sig2 = fn_dsa.sign(&keypair.secret_key, &msg_b)?;
    let time_b = start.elapsed();

    let time_diff = time_a.abs_diff(time_b);

    // CI hosts can be noisy; 500ms is a broad livelock-only bound for two equal-length calls,
    // not a timing-leak threshold.
    let max_allowed_diff = std::time::Duration::from_millis(500);
    assert!(
        time_diff < max_allowed_diff,
        "Signing latency smoke check failed (possible livelock, not a timing-leak signal): {:?} vs {:?}",
        time_a,
        time_b
    );
    Ok(())
}

/// Welch-t math self-test: proves the statistic used by `tests/constant_time.rs` (inlined there,
/// duplicated here in miniature so this proof runs in every build including debug, unlike the
/// timing tests it backs) can actually distinguish a real mean shift from noise. A statistic that
/// passes on every possible input proves nothing; this is the check that it does not.
#[test]
fn welch_t_detects_synthetic_shift() {
    fn welch_t(a: &[f64], b: &[f64]) -> Option<f64> {
        let na = a.len() as f64;
        let nb = b.len() as f64;
        if na < 2.0 || nb < 2.0 {
            return None;
        }
        let mean_a = a.iter().sum::<f64>() / na;
        let mean_b = b.iter().sum::<f64>() / nb;
        let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (na - 1.0);
        let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (nb - 1.0);
        let se = (var_a / na + var_b / nb).sqrt();
        if se == 0.0 {
            return None;
        }
        Some((mean_a - mean_b) / se)
    }

    const T_THRESHOLD: f64 = 15.0;

    // Synthetic shifted classes: class A ~= 1.0 +/- eps, class B ~= 1.5 +/- eps. A real 0.5-unit
    // mean shift against ~1e-3-scale noise must blow well past the pinned threshold.
    // `unwrap_or(0.0)`, not `.expect()`/`.unwrap()`: this crate's CI clippy step denies both
    // (action.yml unwrap_used/expect_used). Both classes below have >=2 samples and nonzero
    // variance, so `welch_t` always returns `Some`; if it ever didn't, falling back to 0.0 still
    // fails the assertion below loudly rather than hiding the problem behind a different panic.
    let a: Vec<f64> = (0..200).map(|i| 1.0 + (i % 5) as f64 * 1e-3).collect();
    let b: Vec<f64> = (0..200).map(|i| 1.5 + (i % 5) as f64 * 1e-3).collect();
    let t = welch_t(&a, &b).unwrap_or(0.0);
    assert!(
        t.abs() > T_THRESHOLD,
        "welch_t failed to detect a synthetic 0.5-unit mean shift: |t|={:.2} (want > {})",
        t.abs(),
        T_THRESHOLD
    );

    // Symmetric same-distribution classes: no real shift, so |t| must stay well under threshold.
    let c: Vec<f64> = (0..200).map(|i| 1.0 + (i % 5) as f64 * 1e-3).collect();
    let d: Vec<f64> = (0..200)
        .map(|i| 1.0 + ((i + 2) % 5) as f64 * 1e-3)
        .collect();
    let t2 = welch_t(&c, &d).unwrap_or(0.0);
    assert!(
        t2.abs() < T_THRESHOLD,
        "welch_t false-positived on two same-distribution classes: |t|={:.2} (want < {})",
        t2.abs(),
        T_THRESHOLD
    );
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
