//! Comprehensive security tests for lib-q-aead
//!
//! This module provides extensive security testing including:
//! - Constant-time operation verification
//! - Side-channel attack resistance testing
//! - Memory safety testing
//! - Input validation testing
//! - Timing attack resistance testing

use std::time::Instant;

use lib_q_aead::timing::{
    TimingProtection,
    protect_timing_with_timing,
    set_timing_protection,
};
use lib_q_aead::validation::{
    InputValidator,
    ValidationConfig,
    set_input_validator,
};
use lib_q_aead::*;
use lib_q_core::{
    AeadKey,
    Algorithm,
    Nonce,
};

fn test_key_for_security(algorithm: Algorithm) -> AeadKey {
    match algorithm {
        Algorithm::RomulusN | Algorithm::RomulusM => {
            AeadKey::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        }
        _ => AeadKey::new(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]),
    }
}

/// Key length that is invalid for `algorithm` (for negative tests).
fn invalid_key_wrong_size(algorithm: Algorithm) -> AeadKey {
    match algorithm {
        Algorithm::RomulusN | Algorithm::RomulusM => AeadKey::new(vec![0u8; 32]),
        _ => AeadKey::new(vec![0u8; 16]),
    }
}

/// Test constant-time operations
#[test]
fn test_constant_time_operations() {
    use lib_q_aead::security::constant_time::*;

    // Test constant-time equality
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    let c = [1, 2, 3, 4, 6];

    assert!(constant_time_eq(&a, &b));
    assert!(!constant_time_eq(&a, &c));

    // Test constant-time selection
    let result1 = constant_time_select(true, 42u8, 24u8);
    let result2 = constant_time_select(false, 42u8, 24u8);
    assert_eq!(result1, 42);
    assert_eq!(result2, 24);

    // Test constant-time copy
    let src = [1, 2, 3, 4, 5];
    let mut dst = [0; 5];
    constant_time_copy(true, &src, &mut dst);
    assert_eq!(dst, src);

    let mut dst2 = [0; 5];
    constant_time_copy(false, &src, &mut dst2);
    assert_eq!(dst2, [0; 5]);

    // Test constant-time zero
    let mut data = [1, 2, 3, 4, 5];
    constant_time_zero(true, &mut data);
    assert_eq!(data, [0; 5]);

    let mut data2 = [1, 2, 3, 4, 5];
    constant_time_zero(false, &mut data2);
    assert_eq!(data2, [1, 2, 3, 4, 5]);

    // Test constant-time swap
    let mut a = 42u8;
    let mut b = 24u8;
    constant_time_swap(true, &mut a, &mut b);
    assert_eq!(a, 24);
    assert_eq!(b, 42);

    let mut c = 10u8;
    let mut d = 20u8;
    constant_time_swap(false, &mut c, &mut d);
    assert_eq!(c, 10);
    assert_eq!(d, 20);
}

/// Test memory safety operations
#[test]
fn test_memory_safety_operations() {
    use lib_q_aead::security::memory::*;

    // Test secure zero
    let mut data = [1, 2, 3, 4, 5];
    secure_zero(&mut data);
    assert_eq!(data, [0; 5]);

    // Test secure zero slice
    let mut data = [1, 2, 3, 4, 5];
    secure_zero_slice(&mut data);
    assert_eq!(data, [0; 5]);

    // Test secure copy
    let src = [1, 2, 3, 4, 5];
    let mut dst = [0; 5];
    secure_copy(&mut dst, &src);
    assert_eq!(dst, src);

    // Test secure copy slice
    let src = [1, 2, 3, 4, 5];
    let mut dst = [0; 5];
    secure_copy_slice(&mut dst, &src);
    assert_eq!(dst, src);

    // Test secure move
    let mut src = [1, 2, 3, 4, 5];
    let mut dst = [0; 5];
    secure_move(&mut dst, &mut src);
    assert_eq!(dst, [1, 2, 3, 4, 5]);
    assert_eq!(src, [0; 5]);

    // Test secure move slice
    let mut src = [1, 2, 3, 4, 5];
    let mut dst = [0; 5];
    secure_move_slice(&mut dst, &mut src);
    assert_eq!(dst, [1, 2, 3, 4, 5]);
    assert_eq!(src, [0; 5]);

    // Test secure compare
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    let c = [1, 2, 3, 4, 6];
    assert!(secure_compare(&a, &b));
    assert!(!secure_compare(&a, &c));

    // Test secure compare slice
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    let c = [1, 2, 3, 4, 6];
    assert!(secure_compare_slice(&a, &b));
    assert!(!secure_compare_slice(&a, &c));

    // Test secure fill
    let mut data = [0u8; 5];
    secure_fill(&mut data, 42);
    assert_eq!(data, [42; 5]);

    // Test secure fill slice
    let mut data = [0; 5];
    secure_fill_slice(&mut data, 42);
    assert_eq!(data, [42; 5]);

    // Test secure XOR
    let mut a = [0b1010, 0b1100, 0b1111];
    let b = [0b1100, 0b1010, 0b0000];
    secure_xor(&mut a, &b);
    assert_eq!(a, [0b0110, 0b0110, 0b1111]);

    // Test secure XOR slice
    let mut a = [0b1010, 0b1100, 0b1111];
    let b = [0b1100, 0b1010, 0b0000];
    secure_xor_slice(&mut a, &b);
    assert_eq!(a, [0b0110, 0b0110, 0b1111]);
}

/// Test input validation
#[test]
fn test_input_validation() {
    use lib_q_aead::security::validation::*;

    let validator = InputValidator::new();

    // Test key validation
    let valid_key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(validator.validate_key(&valid_key).is_ok());

    let empty_key = [];
    assert!(validator.validate_key(&empty_key).is_err());

    let zero_key = [0; 16];
    assert!(validator.validate_key(&zero_key).is_err());

    let all_ones_key = [0xFF; 16];
    assert!(validator.validate_key(&all_ones_key).is_err());

    let repeated_pattern_key = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2];
    assert!(validator.validate_key(&repeated_pattern_key).is_err());

    // Test nonce validation
    let valid_nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(validator.validate_nonce(&valid_nonce).is_ok());

    let empty_nonce = [];
    assert!(validator.validate_nonce(&empty_nonce).is_err());

    let zero_nonce = [0; 16];
    assert!(validator.validate_nonce(&zero_nonce).is_err());

    let all_ones_nonce = [0xFF; 16];
    assert!(validator.validate_nonce(&all_ones_nonce).is_err());

    // Test plaintext validation
    let valid_plaintext = b"Hello, World!";
    assert!(validator.validate_plaintext(valid_plaintext).is_ok());

    // Test ciphertext validation
    let valid_ciphertext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(validator.validate_ciphertext(&valid_ciphertext).is_ok());

    let empty_ciphertext = [];
    assert!(validator.validate_ciphertext(&empty_ciphertext).is_err());

    // Test associated data validation
    let valid_associated_data = b"metadata";
    assert!(
        validator
            .validate_associated_data(valid_associated_data)
            .is_ok()
    );

    // Test size validation
    assert!(validator.validate_key_size(32, 32).is_ok());
    assert!(validator.validate_key_size(16, 32).is_err());

    assert!(validator.validate_nonce_size(16, 16).is_ok());
    assert!(validator.validate_nonce_size(12, 16).is_err());
}

/// Test side-channel protection
#[test]
fn test_side_channel_protection() {
    use lib_q_aead::security::side_channel::*;

    let protection = SideChannelProtection::new();

    // Test secure key compare
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 4];
    let c = [1, 2, 3, 5];
    assert!(protection.secure_key_compare(&a, &b));
    assert!(!protection.secure_key_compare(&a, &c));

    // Test secure key select
    let a = [1, 2, 3, 4];
    let b = [5, 6, 7, 8];

    #[cfg(feature = "alloc")]
    {
        let result1 = protection.secure_key_select(1, &a, &b);
        assert_eq!(result1, a);

        let result0 = protection.secure_key_select(0, &a, &b);
        assert_eq!(result0, b);
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut result = [0; 4];
        protection.secure_key_select(1, &a, &b, &mut result);
        assert_eq!(result, a);

        protection.secure_key_select(0, &a, &b, &mut result);
        assert_eq!(result, b);
    }

    // Test secure memory access
    let data = [1, 2, 3, 4, 5];
    assert_eq!(protection.secure_memory_access(&data, 2), Some(&3));
    assert_eq!(protection.secure_memory_access(&data, 10), None);

    // Test secure conditional execute
    let mut executed = false;
    let result = protection.secure_conditional_execute(true, || {
        executed = true;
        true
    });
    assert!(result);
    assert!(executed);

    // Test secure conditional execute no return
    let mut executed = false;
    protection.secure_conditional_execute_no_return(true, || {
        executed = true;
    });
    assert!(executed);

    // Test secure loop
    let mut count = 0;
    protection.secure_loop(5, |_| {
        count += 1;
        true
    });
    assert_eq!(count, 5);

    // Test secure array access
    let array = [1, 2, 3, 4, 5];
    assert_eq!(protection.secure_array_access(&array, 2), Some(&3));
    assert_eq!(protection.secure_array_access(&array, 10), None);

    // Test secure string compare
    assert!(protection.secure_string_compare("hello", "hello"));
    assert!(!protection.secure_string_compare("hello", "world"));

    // Test secure integer compare
    assert!(protection.secure_integer_compare(42, 42));
    assert!(!protection.secure_integer_compare(42, 24));

    // Test secure integer operations
    assert_eq!(protection.secure_integer_add(10, 5), 15);
    assert_eq!(protection.secure_integer_sub(10, 5), 5);
    assert_eq!(protection.secure_integer_mul(10, 5), 50);
    assert_eq!(protection.secure_integer_div(10, 5), 2);
    assert_eq!(protection.secure_integer_mod(10, 5), 0);

    // Test secure bitwise operations
    assert_eq!(protection.secure_bitwise_and(0b1010, 0b1100), 0b1000);
    assert_eq!(protection.secure_bitwise_or(0b1010, 0b1100), 0b1110);
    assert_eq!(protection.secure_bitwise_xor(0b1010, 0b1100), 0b0110);
    assert_eq!(protection.secure_bitwise_not(0b1010), !0b1010);

    // Test secure shift operations
    assert_eq!(protection.secure_left_shift(0b1010, 2), 0b101000);
    assert_eq!(protection.secure_right_shift(0b1010, 2), 0b10);
    assert_eq!(protection.secure_rotate_left(0b1010, 2), 0b101000);
    assert_eq!(
        protection.secure_rotate_right(0b1010, 2),
        0b1010u64.rotate_right(2)
    );

    // Test secure conditional operations
    let mut value = 42u64;
    protection.secure_conditional_assign(true, &mut value, 24);
    assert_eq!(value, 24);

    protection.secure_conditional_assign(false, &mut value, 100);
    assert_eq!(value, 24);

    // Test secure conditional increment
    let mut value = 42u64;
    protection.secure_conditional_increment(true, &mut value);
    assert_eq!(value, 43);

    protection.secure_conditional_increment(false, &mut value);
    assert_eq!(value, 43);

    // Test secure conditional decrement
    let mut value = 42u64;
    protection.secure_conditional_decrement(true, &mut value);
    assert_eq!(value, 41);

    protection.secure_conditional_decrement(false, &mut value);
    assert_eq!(value, 41);

    // Test secure conditional add
    let mut value = 42u64;
    protection.secure_conditional_add(true, &mut value, 10);
    assert_eq!(value, 52);

    protection.secure_conditional_add(false, &mut value, 5);
    assert_eq!(value, 52);

    // Test secure conditional subtract
    let mut value = 42u64;
    protection.secure_conditional_subtract(true, &mut value, 10);
    assert_eq!(value, 32);

    protection.secure_conditional_subtract(false, &mut value, 5);
    assert_eq!(value, 32);

    // Test secure conditional multiply
    let mut value = 42u64;
    protection.secure_conditional_multiply(true, &mut value, 2);
    assert_eq!(value, 84);

    protection.secure_conditional_multiply(false, &mut value, 3);
    assert_eq!(value, 84);

    // Test secure conditional divide
    let mut value = 42u64;
    protection.secure_conditional_divide(true, &mut value, 2);
    assert_eq!(value, 21);

    protection.secure_conditional_divide(false, &mut value, 3);
    assert_eq!(value, 21);

    // Test secure conditional modulo
    let mut value = 42u64;
    protection.secure_conditional_modulo(true, &mut value, 10);
    assert_eq!(value, 2);

    protection.secure_conditional_modulo(false, &mut value, 5);
    assert_eq!(value, 2);

    // Test secure conditional bitwise operations
    let mut value = 0b1010u64;
    protection.secure_conditional_bitwise_and(true, &mut value, 0b1100);
    assert_eq!(value, 0b1000);

    protection.secure_conditional_bitwise_or(true, &mut value, 0b0010);
    assert_eq!(value, 0b1010);

    protection.secure_conditional_bitwise_xor(true, &mut value, 0b1111);
    assert_eq!(value, 0b0101);

    protection.secure_conditional_bitwise_not(true, &mut value);
    assert_eq!(value, !0b0101);

    // Test secure conditional shift operations
    let mut value = 0b1010u64;
    protection.secure_conditional_left_shift(true, &mut value, 2);
    assert_eq!(value, 0b101000);

    protection.secure_conditional_right_shift(true, &mut value, 2);
    assert_eq!(value, 0b1010);

    protection.secure_conditional_rotate_left(true, &mut value, 2);
    assert_eq!(value, 0b101000);

    protection.secure_conditional_rotate_right(true, &mut value, 2);
    assert_eq!(value, 0b1010);
}

/// Test timing attack protection
#[test]
fn test_timing_attack_protection() {
    use lib_q_aead::security::timing::*;

    let protection = TimingProtection::new();

    // Test protect
    let result = protection.protect(|| 42);
    assert_eq!(result, 42);

    // Test protect with timing
    let (result, elapsed) = protection.protect_with_timing(|| 42);
    assert_eq!(result, 42);
    assert!(elapsed > 0);

    // Test global timing protection
    let result = protect_timing(|| 42);
    assert_eq!(result, 42);

    // Test global timing protection with timing
    let (result, elapsed) = protect_timing_with_timing(|| 42);
    assert_eq!(result, 42);
    assert!(elapsed > 0);
}

/// Test AEAD operations with security enhancements
#[test]
fn test_aead_operations_with_security() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test with valid inputs
        let key = test_key_for_security(algorithm);
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let plaintext = b"Hello, World!";
        let associated_data = Some(b"metadata".as_slice());

        // Test encryption
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, associated_data);
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Test decryption
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, associated_data);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);

        // Test with invalid inputs
        let invalid_key = invalid_key_wrong_size(algorithm);
        let invalid_nonce = Nonce::new(vec![0; 12]); // Wrong size

        // Test with invalid key
        let result = aead.encrypt(&invalid_key, &nonce, plaintext, associated_data);
        assert!(result.is_err());

        // Test with invalid nonce
        let result = aead.encrypt(&key, &invalid_nonce, plaintext, associated_data);
        assert!(result.is_err());

        // Test with tampered ciphertext
        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 0xFF;

        let result = aead.decrypt(&key, &nonce, &tampered_ciphertext, associated_data);
        assert!(result.is_err());

        // Test with wrong associated data
        let wrong_associated_data = Some(b"wrong metadata".as_slice());
        let result = aead.decrypt(&key, &nonce, &ciphertext, wrong_associated_data);
        assert!(result.is_err());
    }
}

/// Test security configuration
#[test]
fn test_security_configuration() {
    use lib_q_aead::security::*;

    // Test default configuration
    let config = SecurityConfig::default();
    assert!(config.constant_time);
    assert!(config.side_channel_protection);
    assert!(config.secure_memory);
    assert!(config.strict_validation);
    assert!(config.timing_protection);
    assert!(config.fault_injection_protection);

    // Test strict configuration
    let config = SecurityConfig::strict();
    assert!(config.constant_time);
    assert!(config.side_channel_protection);
    assert!(config.secure_memory);
    assert!(config.strict_validation);
    assert!(config.timing_protection);
    assert!(config.fault_injection_protection);

    // Test permissive configuration
    let config = SecurityConfig::permissive();
    assert!(!config.constant_time);
    assert!(!config.side_channel_protection);
    assert!(!config.secure_memory);
    assert!(!config.strict_validation);
    assert!(!config.timing_protection);
    assert!(!config.fault_injection_protection);

    // Test balanced configuration
    let config = SecurityConfig::balanced();
    assert!(config.constant_time);
    assert!(config.side_channel_protection);
    assert!(config.secure_memory);
    assert!(config.strict_validation);
    assert!(!config.timing_protection);
    assert!(!config.fault_injection_protection);

    // Test security context (explicit default config: parallel tests may mutate globals)
    let ctx = SecurityContext::with_config(SecurityConfig::default());
    assert!(ctx.operation_id() > 0);
    // Note: elapsed_time() returns u64, so it's always >= 0
    // We just verify it's a valid timestamp
    let _elapsed = ctx.elapsed_time();
    assert!(ctx.constant_time_enabled());
    assert!(ctx.side_channel_protection_enabled());
    assert!(ctx.secure_memory_enabled());
    assert!(ctx.strict_validation_enabled());
    assert!(ctx.timing_protection_enabled());
    assert!(ctx.fault_injection_protection_enabled());

    // Test security context with custom configuration
    let config = SecurityConfig::permissive();
    let ctx = SecurityContext::with_config(config);
    assert!(!ctx.constant_time_enabled());
    assert!(!ctx.side_channel_protection_enabled());
    assert!(!ctx.secure_memory_enabled());
    assert!(!ctx.strict_validation_enabled());
    assert!(!ctx.timing_protection_enabled());
    assert!(!ctx.fault_injection_protection_enabled());

    // Test global security configuration
    let original_config = get_security_config();

    let new_config = SecurityConfig::permissive();
    set_security_config(new_config);

    let retrieved_config = get_security_config();
    assert_eq!(retrieved_config, new_config);

    // Restore original config
    set_security_config(original_config);
}

/// Test comprehensive security integration
#[test]
fn test_comprehensive_security_integration() {
    use lib_q_aead::security::*;

    // Set strict security configuration
    let strict_config = SecurityConfig::strict();
    set_security_config(strict_config);

    // Test with strict validation
    let validator = InputValidator::with_config(ValidationConfig::strict());
    set_input_validator(validator);

    // Test with strict timing protection
    let timing_protection = TimingProtection::strict();
    set_timing_protection(timing_protection);

    // Test AEAD operations with strict security
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test with valid inputs
        let key = test_key_for_security(algorithm);
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let plaintext = b"Hello, World!";
        let associated_data = Some(b"metadata".as_slice());

        // Test encryption with timing protection
        let (ciphertext, timing) =
            protect_timing_with_timing(|| aead.encrypt(&key, &nonce, plaintext, associated_data));
        assert!(ciphertext.is_ok());
        assert!(timing > 0); // Should be positive after protection

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Test decryption with timing protection
        let (decrypted, timing) =
            protect_timing_with_timing(|| aead.decrypt(&key, &nonce, &ciphertext, associated_data));
        assert!(decrypted.is_ok());
        assert!(timing > 0); // Should be positive after protection
        assert_eq!(decrypted.unwrap(), plaintext);

        // Test with invalid inputs (should fail with strict validation)
        let invalid_key = invalid_key_wrong_size(algorithm);
        let invalid_nonce = Nonce::new(vec![0; 12]); // Wrong size

        // Test with invalid key
        let result = aead.encrypt(&invalid_key, &nonce, plaintext, associated_data);
        assert!(result.is_err());

        // Test with invalid nonce
        let result = aead.encrypt(&key, &invalid_nonce, plaintext, associated_data);
        assert!(result.is_err());

        // Test with tampered ciphertext
        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 0xFF;

        let result = aead.decrypt(&key, &nonce, &tampered_ciphertext, associated_data);
        assert!(result.is_err());

        // Test with wrong associated data
        let wrong_associated_data = Some(b"wrong metadata".as_slice());
        let result = aead.decrypt(&key, &nonce, &ciphertext, wrong_associated_data);
        assert!(result.is_err());
    }

    // Restore default configurations
    set_security_config(SecurityConfig::default());
    set_input_validator(InputValidator::new());
    set_timing_protection(TimingProtection::default());
}

/// Test security performance impact
#[test]
fn test_security_performance_impact() {
    // Note: Removed unused security imports

    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = test_key_for_security(algorithm);
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let plaintext = b"Hello, World!";
        let associated_data = Some(b"metadata".as_slice());

        let ciphertext = aead.encrypt(&key, &nonce, plaintext, associated_data);
        assert!(ciphertext.is_ok());
        let ciphertext = ciphertext.unwrap();

        // Compare decrypt with timing wrapper vs plain decrypt (same work; wall-clock can
        // fluctuate heavily under parallel CI). Previously this compared encrypt vs decrypt,
        // which is not a stable "overhead" ratio.
        let start = Instant::now();
        let decrypted_baseline = aead.decrypt(&key, &nonce, &ciphertext, associated_data);
        let without_wrapper = start.elapsed();
        assert!(decrypted_baseline.is_ok());

        let start = Instant::now();
        let (decrypted, timing) =
            protect_timing_with_timing(|| aead.decrypt(&key, &nonce, &ciphertext, associated_data));
        let with_wrapper = start.elapsed();
        assert!(decrypted.is_ok());
        assert!(timing > 0);

        // Coarse `Instant` resolution (e.g. Windows) can make baselines 0ns; a 1ns floor
        // makes ratios explode. Floor the baseline for this smoke check only.
        const MIN_BASELINE_NS: u128 = 10_000; // 10 µs
        let baseline_ns = without_wrapper.as_nanos().max(MIN_BASELINE_NS);
        let with_ns = with_wrapper.as_nanos();
        let ratio = with_ns as f64 / baseline_ns as f64;
        assert!(
            (0.01..=100.0).contains(&ratio),
            "Security overhead ratio (wrapped decrypt / floored plain decrypt): {}",
            ratio
        );
    }
}

/// Test security error handling
#[test]
fn test_security_error_handling() {
    // Note: Removed unused security imports

    // Test with strict validation
    let validator = InputValidator::with_config(ValidationConfig::strict());

    // Test various invalid inputs
    let empty_key = [];
    assert!(validator.validate_key(&empty_key).is_err());

    let zero_key = [0; 16];
    assert!(validator.validate_key(&zero_key).is_err());

    let all_ones_key = [0xFF; 16];
    assert!(validator.validate_key(&all_ones_key).is_err());

    let repeated_pattern_key = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2];
    assert!(validator.validate_key(&repeated_pattern_key).is_err());

    let empty_nonce = [];
    assert!(validator.validate_nonce(&empty_nonce).is_err());

    let zero_nonce = [0; 16];
    assert!(validator.validate_nonce(&zero_nonce).is_err());

    let all_ones_nonce = [0xFF; 16];
    assert!(validator.validate_nonce(&all_ones_nonce).is_err());

    let empty_ciphertext = [];
    assert!(validator.validate_ciphertext(&empty_ciphertext).is_err());

    // Test with suspicious patterns
    let suspicious_plaintext = b"<script>alert('xss')</script>";
    assert!(validator.validate_plaintext(suspicious_plaintext).is_err());
}

/// Test security configuration persistence
#[test]
fn test_security_configuration_persistence() {
    use lib_q_aead::security::*;

    // Test that security configurations persist across operations
    let strict_config = SecurityConfig::strict();
    set_security_config(strict_config);

    // Perform some operations
    let validator = InputValidator::new();
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(validator.validate_key(&key).is_ok());

    // Check that configuration is still strict
    let retrieved_config = get_security_config();
    assert_eq!(retrieved_config, strict_config);

    // Test that configuration can be changed
    let permissive_config = SecurityConfig::permissive();
    set_security_config(permissive_config);

    let retrieved_config = get_security_config();
    assert_eq!(retrieved_config, permissive_config);

    // Restore default configuration
    set_security_config(SecurityConfig::default());
}

/// Test security context isolation
#[test]
fn test_security_context_isolation() {
    use lib_q_aead::security::*;

    // Test that different security contexts are isolated
    let ctx1 = SecurityContext::new();
    let ctx2 = SecurityContext::new();

    assert_ne!(ctx1.operation_id(), ctx2.operation_id());

    // Test that contexts maintain their configuration
    let strict_config = SecurityConfig::strict();
    let ctx_strict = SecurityContext::with_config(strict_config);

    let permissive_config = SecurityConfig::permissive();
    let ctx_permissive = SecurityContext::with_config(permissive_config);

    assert!(ctx_strict.constant_time_enabled());
    assert!(!ctx_permissive.constant_time_enabled());

    assert!(ctx_strict.side_channel_protection_enabled());
    assert!(!ctx_permissive.side_channel_protection_enabled());

    assert!(ctx_strict.secure_memory_enabled());
    assert!(!ctx_permissive.secure_memory_enabled());

    assert!(ctx_strict.strict_validation_enabled());
    assert!(!ctx_permissive.strict_validation_enabled());

    assert!(ctx_strict.timing_protection_enabled());
    assert!(!ctx_permissive.timing_protection_enabled());

    assert!(ctx_strict.fault_injection_protection_enabled());
    assert!(!ctx_permissive.fault_injection_protection_enabled());
}

/// Test security feature flags
#[test]
fn test_security_feature_flags() {
    use lib_q_aead::security::*;

    // Test that security features can be enabled/disabled
    let config = SecurityConfig {
        constant_time: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.constant_time);

    // Test side-channel protection
    let config = SecurityConfig {
        side_channel_protection: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.side_channel_protection);

    // Test secure memory
    let config = SecurityConfig {
        secure_memory: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.secure_memory);

    // Test strict validation
    let config = SecurityConfig {
        strict_validation: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.strict_validation);

    // Test timing protection
    let config = SecurityConfig {
        timing_protection: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.timing_protection);

    // Test fault injection protection
    let config = SecurityConfig {
        fault_injection_protection: false,
        ..Default::default()
    };
    set_security_config(config);
    let retrieved_config = get_security_config();
    assert!(!retrieved_config.fault_injection_protection);

    // Restore default configuration
    set_security_config(SecurityConfig::default());
}

/// Test security integration with AEAD operations
#[test]
fn test_security_integration_with_aead_operations() {
    use lib_q_aead::security::*;

    // Test that security enhancements work with AEAD operations
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test with different security configurations
        let configs = [
            SecurityConfig::strict(),
            SecurityConfig::balanced(),
            SecurityConfig::permissive(),
        ];

        for config in configs {
            set_security_config(config);

            let key = test_key_for_security(algorithm);
            let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
            let plaintext = b"Hello, World!";
            let associated_data = Some(b"metadata".as_slice());

            // Test encryption
            let ciphertext = aead.encrypt(&key, &nonce, plaintext, associated_data);
            assert!(ciphertext.is_ok());

            let ciphertext = ciphertext.unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

            // Test decryption
            let decrypted = aead.decrypt(&key, &nonce, &ciphertext, associated_data);
            assert!(decrypted.is_ok());
            assert_eq!(decrypted.unwrap(), plaintext);
        }
    }

    // Restore default configuration
    set_security_config(SecurityConfig::default());
}
