//! Integration tests for lib-q-random
//!
//! This module provides comprehensive integration tests for the lib-q-random crate,
//! testing the interaction between different components and ensuring proper
//! functionality across various use cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Conditional imports based on feature flags
#[cfg(feature = "alloc")]
use lib_q_random::entropy::{
    DeterministicEntropySource,
    EntropySourceFactory,
    OsEntropySource,
    UserEntropySource,
};
#[cfg(feature = "alloc")]
use lib_q_random::traits::{
    EntropySource,
    EntropySourceType,
    SecureRng,
    SecurityLevel,
};
#[cfg(feature = "alloc")]
use lib_q_random::validation::quick_entropy_check;
#[cfg(feature = "alloc")]
use lib_q_random::{
    EntropyQuality,
    EntropyValidator,
    LibQRng,
    new_deterministic_rng,
    new_secure_rng,
};
// no_std imports
#[cfg(not(feature = "alloc"))]
use lib_q_random::{
    new_deterministic_rng_no_std,
    new_secure_rng_no_std,
};
use rand_core::Rng;

#[test]
fn test_secure_rng_creation() {
    #[cfg(feature = "alloc")]
    {
        // Test secure RNG creation (may fail in some environments)
        let result = new_secure_rng();
        // We don't assert success here as it depends on platform capabilities
        if let Ok(rng) = result {
            assert!(rng.is_secure());
            assert_eq!(rng.security_level(), SecurityLevel::CryptographicallySecure);
            assert!(!rng.is_deterministic());
        }
    }

    #[cfg(not(feature = "alloc"))]
    {
        // Test no_std secure RNG creation
        let result = new_secure_rng_no_std();
        if let Ok(mut rng) = result {
            // Test basic functionality
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            assert!(!bytes.iter().all(|&b| b == 0));
        }
    }
}

#[test]
fn test_deterministic_rng_creation() {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    #[cfg(feature = "alloc")]
    {
        let rng = new_deterministic_rng(seed);
        assert!(!rng.is_secure());
        assert_eq!(rng.security_level(), SecurityLevel::Deterministic);
        assert!(rng.is_deterministic());
    }

    #[cfg(not(feature = "alloc"))]
    {
        let rng = new_deterministic_rng_no_std(seed);
        assert!(rng.is_deterministic());
    }
}

#[test]
fn test_deterministic_rng_consistency() {
    let seed = [42u8; 32];

    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_deterministic_rng(seed);
        let mut rng2 = new_deterministic_rng(seed);

        let mut bytes1 = [0u8; 64];
        let mut bytes2 = [0u8; 64];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_deterministic_rng_no_std(seed);
        let mut rng2 = new_deterministic_rng_no_std(seed);

        let mut bytes1 = [0u8; 64];
        let mut bytes2 = [0u8; 64];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }
}

#[test]
fn test_deterministic_rng_different_seeds() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];

    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_deterministic_rng(seed1);
        let mut rng2 = new_deterministic_rng(seed2);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_ne!(bytes1, bytes2);
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_deterministic_rng_no_std(seed1);
        let mut rng2 = new_deterministic_rng_no_std(seed2);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_ne!(bytes1, bytes2);
    }
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_factory_deterministic() {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&[1, 2, 3, 4]);
    let source = EntropySourceFactory::create_deterministic_entropy(seed);

    assert_eq!(source.source_type(), EntropySourceType::Deterministic);
    assert_eq!(source.quality(), 0.0);
    assert!(source.is_available());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_factory_user() {
    let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let source = EntropySourceFactory::create_user_entropy(entropy_data);

    assert_eq!(source.source_type(), EntropySourceType::User);
    assert!(source.is_available());
}

#[test]
#[cfg(feature = "alloc")]
fn test_os_entropy_source() {
    let source = OsEntropySource::new();
    assert_eq!(source.source_type(), EntropySourceType::OperatingSystem);
    assert!(!source.name().is_empty());
}

#[test]
#[cfg(feature = "alloc")]
fn test_deterministic_entropy_source() {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&[1, 2, 3, 4]);
    let mut source = DeterministicEntropySource::new(seed);

    assert_eq!(source.source_type(), EntropySourceType::Deterministic);
    assert_eq!(source.quality(), 0.0);
    assert!(source.is_available());

    let mut bytes = [0u8; 16];
    let result = source.get_entropy(&mut bytes);
    assert!(result.is_ok());
}

#[test]
#[cfg(feature = "alloc")]
fn test_user_entropy_source() {
    let entropy_data = vec![1, 2, 3, 4, 5];
    let mut source = UserEntropySource::new(entropy_data);

    assert_eq!(source.source_type(), EntropySourceType::User);
    assert!(source.is_available());

    let mut bytes = [0u8; 8];
    let result = source.get_entropy(&mut bytes);
    assert!(result.is_ok());

    // Should cycle through the entropy data
    assert_eq!(bytes, [1, 2, 3, 4, 5, 1, 2, 3]);
}

#[test]
#[cfg(feature = "alloc")]
fn test_user_entropy_source_with_quality() {
    let entropy_data = vec![1, 2, 3, 4, 5];
    let source = UserEntropySource::with_quality(entropy_data, 0.9);

    assert_eq!(source.quality(), 0.9);
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_validator_creation() {
    let validator = EntropyValidator::new();
    assert_eq!(validator.min_entropy_bits(), 128);
    assert_eq!(validator.quality_threshold(), 0.8);
    assert!(!validator.is_strict_mode());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_validator_custom_settings() {
    let validator = EntropyValidator::with_settings(256, 2048, 0.9, true);
    assert_eq!(validator.min_entropy_bits(), 256);
    assert_eq!(validator.max_entropy_bits(), 2048);
    assert_eq!(validator.quality_threshold(), 0.9);
    assert!(validator.is_strict_mode());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_validation_empty_data() {
    let validator = EntropyValidator::new();
    let result = validator.validate_entropy(&[]);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_validation_insufficient_data() {
    let validator = EntropyValidator::new();
    let data = [1, 2, 3, 4, 5]; // Less than 16 bytes
    let result = validator.validate_entropy(&data);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_quality_creation() {
    let quality = EntropyQuality::new(0.8, 0.9, 0.7, 0.1);
    assert_eq!(quality.overall, 0.8);
    assert_eq!(quality.uniformity, 0.9);
    assert_eq!(quality.independence, 0.7);
    assert_eq!(quality.predictability, 0.1);
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_quality_assessment() {
    let quality = EntropyQuality::new(0.95, 0.9, 0.8, 0.05);
    assert!(quality.is_excellent());
    assert!(quality.is_good());
    assert!(!quality.is_poor());
    assert!(quality.is_acceptable(0.8));
}

#[test]
#[cfg(feature = "alloc")]
fn test_quick_entropy_check() {
    // Good entropy (random-looking data)
    let good_data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(quick_entropy_check(&good_data));

    // Bad entropy (all zeros)
    let bad_data = [0u8; 16];
    assert!(!quick_entropy_check(&bad_data));

    // Bad entropy (repeating pattern)
    let pattern_data = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
    assert!(!quick_entropy_check(&pattern_data));
}

#[test]
fn test_rng_interface_compliance() {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    #[cfg(feature = "alloc")]
    {
        let mut rng = new_deterministic_rng(seed);

        // Test Rng interface
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();
        assert_ne!(val1, val2);

        let val3 = rng.next_u64();
        let val4 = rng.next_u64();
        assert_ne!(val3, val4);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        assert_ne!(bytes, [0u8; 32]);
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_deterministic_rng_no_std(seed);

        // Test Rng interface
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();
        assert_ne!(val1, val2);

        let val3 = rng.next_u64();
        let val4 = rng.next_u64();
        assert_ne!(val3, val4);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        assert_ne!(bytes, [0u8; 32]);
    }
}

#[test]
#[cfg(feature = "alloc")]
fn test_rng_reseed_functionality() {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut rng = new_deterministic_rng(seed);

    // Test reseed functionality
    let result = rng.reseed();
    assert!(result.is_ok());

    // Test reseed interval
    let interval = rng.reseed_interval();
    assert!(interval.is_none()); // Deterministic RNGs don't need reseeding
}

#[test]
#[cfg(feature = "alloc")]
fn test_rng_state_information() {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let rng = new_deterministic_rng(seed);

    assert_eq!(rng.reseed_counter(), 0);
    assert_eq!(rng.bytes_generated(), 0);
    assert!(!rng.entropy_source_name().is_empty());
    assert_eq!(rng.entropy_source_type(), EntropySourceType::Deterministic);
}

#[test]
#[cfg(feature = "alloc")]
fn test_rng_display_formatting() {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let rng = new_deterministic_rng(seed);

    let display = format!("{}", rng);
    assert!(display.contains("LibQRng"));
    assert!(display.contains("Deterministic"));
}

#[test]
#[cfg(feature = "alloc")]
fn test_custom_rng_creation() {
    let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let entropy_source = UserEntropySource::new(entropy_data);
    let rng = LibQRng::new_custom(entropy_source);

    assert!(!rng.is_deterministic());
    assert_eq!(rng.security_level(), SecurityLevel::CryptographicallySecure);
    assert_eq!(rng.entropy_source_type(), EntropySourceType::User);
}

#[test]
#[cfg(feature = "alloc")]
fn test_rng_configuration() {
    use lib_q_random::traits::RngConfig;

    let config = RngConfig::default();
    let rng = LibQRng::with_config(&config);
    assert!(rng.is_ok());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_cycling() {
    let entropy_data = vec![1, 2, 3];
    let mut source = UserEntropySource::new(entropy_data);

    let mut bytes = [0u8; 9];
    source.get_entropy(&mut bytes).unwrap();

    // Should cycle through the entropy data
    assert_eq!(bytes, [1, 2, 3, 1, 2, 3, 1, 2, 3]);
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_availability() {
    let source = OsEntropySource::new();
    // Availability depends on platform and features
    let _ = source.is_available();

    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&[1, 2, 3, 4]);
    let source = DeterministicEntropySource::new(seed);
    assert!(source.is_available());

    let entropy_data = vec![1, 2, 3, 4, 5];
    let source = UserEntropySource::new(entropy_data);
    assert!(source.is_available());
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_quality() {
    let source = OsEntropySource::new();
    assert!(source.quality() > 0.0);

    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&[1, 2, 3, 4]);
    let source = DeterministicEntropySource::new(seed);
    assert_eq!(source.quality(), 0.0);

    let entropy_data = vec![1, 2, 3, 4, 5];
    let source = UserEntropySource::with_quality(entropy_data, 0.8);
    assert_eq!(source.quality(), 0.8);
}

#[test]
#[cfg(feature = "alloc")]
fn test_entropy_source_max_entropy() {
    let source = OsEntropySource::new();
    let max_entropy = source.max_entropy_per_call();
    assert!(max_entropy.is_some());

    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&[1, 2, 3, 4]);
    let source = DeterministicEntropySource::new(seed);
    let max_entropy = source.max_entropy_per_call();
    assert!(max_entropy.is_none());

    let entropy_data = vec![1, 2, 3, 4, 5];
    let source = UserEntropySource::new(entropy_data);
    let max_entropy = source.max_entropy_per_call();
    assert_eq!(max_entropy, Some(5));
}
