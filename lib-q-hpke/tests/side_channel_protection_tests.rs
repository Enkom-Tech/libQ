#![cfg(feature = "std")]

use std::time::{
    Duration,
    Instant,
};

use lib_q_hpke::security::side_channel::*;
use lib_q_hpke::security::*;

/// Test timing attack resistance for key comparison
#[test]
fn test_timing_attack_resistance() {
    let protection = SideChannelProtection::strict();

    // Test with different length strings to ensure timing doesn't leak length
    let short_a = b"a";
    let short_b = b"b";
    let long_a = b"this_is_a_very_long_string_that_should_take_longer_to_compare";
    let long_b = b"this_is_a_very_long_string_that_should_take_longer_to_compare";

    // Measure timing for short strings
    let start = Instant::now();
    let _ = protection.secure_key_compare(short_a, short_b);
    let short_time = start.elapsed();

    // Measure timing for long strings
    let start = Instant::now();
    let _ = protection.secure_key_compare(long_a, long_b);
    let long_time = start.elapsed();

    // The timing should be similar (within reasonable bounds)
    // This is a basic test - in practice, you'd want more sophisticated timing analysis
    let time_diff = if short_time > long_time {
        short_time - long_time
    } else {
        long_time - short_time
    };

    // Allow for some timing variation but ensure it's not too large
    assert!(
        time_diff < Duration::from_micros(100),
        "Timing difference too large: {:?}",
        time_diff
    );
}

/// Test constant-time memory operations
#[test]
fn test_constant_time_memory_operations() {
    let protection = SideChannelProtection::strict();

    // Test secure memory copy
    let mut dst = [0u8; 16];
    let src = [
        1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8,
    ];

    protection.secure_memory_copy(1, &mut dst, &src);
    assert_eq!(dst, src);

    protection.secure_memory_copy(0, &mut dst, &[0u8; 16]);
    assert_eq!(dst, src); // Should be unchanged

    // Test secure memory zero
    let mut data = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8];
    protection.secure_memory_zero(1, &mut data);
    assert_eq!(data, [0u8; 8]);

    data = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8];
    protection.secure_memory_zero(0, &mut data);
    assert_eq!(data, [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8]); // Should be unchanged

    // Test secure memory swap
    let mut a = [1u8, 2u8, 3u8, 4u8];
    let mut b = [5u8, 6u8, 7u8, 8u8];
    let a_orig = a;
    let b_orig = b;

    protection.secure_memory_swap(1, &mut a, &mut b);
    assert_eq!(a, b_orig);
    assert_eq!(b, a_orig);

    protection.secure_memory_swap(0, &mut a, &mut b);
    assert_eq!(a, b_orig); // Should be unchanged
    assert_eq!(b, a_orig); // Should be unchanged
}

/// Test secure key selection with various inputs
#[test]
fn test_secure_key_selection() {
    let protection = SideChannelProtection::strict();

    let key_a = b"key_a_data";
    let key_b = b"key_b_data";

    // Test selection with choice = 1
    let result1 = protection.secure_key_select(1, key_a, key_b);
    assert_eq!(result1, key_a);

    // Test selection with choice = 0
    let result0 = protection.secure_key_select(0, key_a, key_b);
    assert_eq!(result0, key_b);

    // Test with different length keys
    let short_key = b"short";
    let long_key = b"this_is_a_much_longer_key";

    let result_short = protection.secure_key_select(1, short_key, long_key);
    assert_eq!(result_short, short_key);

    let result_long = protection.secure_key_select(0, short_key, long_key);
    assert_eq!(result_long, long_key);
}

/// Test secure integer operations
#[test]
fn test_secure_integer_operations() {
    let protection = SideChannelProtection::strict();

    // Test integer comparison
    assert!(protection.secure_integer_compare(42u64, 42u64));
    assert!(!protection.secure_integer_compare(42u64, 43u64));
    assert!(!protection.secure_integer_compare(43u64, 42u64));

    // Test integer selection
    let a = 0x123456789ABCDEF0u64;
    let b = 0xFEDCBA9876543210u64;

    let result1 = protection.secure_integer_select(1, a, b);
    assert_eq!(result1, a);

    let result0 = protection.secure_integer_select(0, a, b);
    assert_eq!(result0, b);

    // Test edge cases
    assert!(protection.secure_integer_compare(0u64, 0u64));
    assert!(protection.secure_integer_compare(u64::MAX, u64::MAX));
    assert!(!protection.secure_integer_compare(0u64, u64::MAX));
}

/// Test secure boolean operations
#[test]
fn test_secure_boolean_operations() {
    let protection = SideChannelProtection::strict();

    // Test AND operation
    assert!(protection.secure_boolean_and(true, true));
    assert!(!protection.secure_boolean_and(true, false));
    assert!(!protection.secure_boolean_and(false, true));
    assert!(!protection.secure_boolean_and(false, false));

    // Test OR operation
    assert!(protection.secure_boolean_or(true, true));
    assert!(protection.secure_boolean_or(true, false));
    assert!(protection.secure_boolean_or(false, true));
    assert!(!protection.secure_boolean_or(false, false));

    // Test XOR operation
    assert!(!protection.secure_boolean_xor(true, true));
    assert!(protection.secure_boolean_xor(true, false));
    assert!(protection.secure_boolean_xor(false, true));
    assert!(!protection.secure_boolean_xor(false, false));
}

/// Test secure string comparison
#[test]
fn test_secure_string_comparison() {
    let protection = SideChannelProtection::strict();

    let str_a = "hello";
    let str_b = "hello";
    let str_c = "world";
    let str_d = "hell";

    assert!(protection.secure_string_compare(str_a, str_b));
    assert!(!protection.secure_string_compare(str_a, str_c));
    assert!(!protection.secure_string_compare(str_a, str_d));

    // Test with empty strings
    assert!(protection.secure_string_compare("", ""));
    assert!(!protection.secure_string_compare("", "a"));
    assert!(!protection.secure_string_compare("a", ""));

    // Test with unicode strings
    let unicode_a = "café";
    let unicode_b = "café";
    let unicode_c = "cafe";

    assert!(protection.secure_string_compare(unicode_a, unicode_b));
    assert!(!protection.secure_string_compare(unicode_a, unicode_c));
}

/// Test secure array access
#[test]
fn test_secure_array_access() {
    let protection = SideChannelProtection::strict();
    let array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Test valid indices
    assert_eq!(protection.secure_array_access(&array, 0), Some(&1));
    assert_eq!(protection.secure_array_access(&array, 5), Some(&6));
    assert_eq!(protection.secure_array_access(&array, 9), Some(&10));

    // Test invalid indices
    assert_eq!(protection.secure_array_access(&array, 10), None);
    assert_eq!(protection.secure_array_access(&array, 100), None);

    // Test with empty array
    let empty_array: [i32; 0] = [];
    assert_eq!(protection.secure_array_access(&empty_array, 0), None);
}

/// Test secure conditional execution
#[test]
fn test_secure_conditional_execution() {
    let protection = SideChannelProtection::strict();

    let mut executed = false;

    // Test with condition = true
    let result = protection.secure_conditional_execute(true, || {
        executed = true;
        Ok(())
    });
    assert!(result.is_ok());
    assert!(executed);

    // Test with condition = false
    executed = false;
    let result = protection.secure_conditional_execute(false, || {
        executed = true;
        Ok(())
    });
    assert!(result.is_ok());
    assert!(!executed); // Should not have executed

    // Test with error condition
    let result = protection.secure_conditional_execute(true, || {
        Err(lib_q_hpke::HpkeError::CryptoError("test error".to_string()))
    });
    assert!(result.is_err());

    let result = protection.secure_conditional_execute(false, || {
        Err(lib_q_hpke::HpkeError::CryptoError("test error".to_string()))
    });
    assert!(result.is_ok()); // Should not propagate error when condition is false
}

/// Test secure conditional return
#[test]
fn test_secure_conditional_return() {
    let protection = SideChannelProtection::strict();

    let value = 42;

    // Test with condition = true
    let result = protection.secure_conditional_return(true, value);
    assert_eq!(result, Some(value));

    // Test with condition = false
    let result = protection.secure_conditional_return(false, value);
    assert_eq!(result, None);
}

/// Test secure error handling
#[test]
fn test_secure_error_handling() {
    let protection = SideChannelProtection::strict();

    let error = lib_q_hpke::HpkeError::CryptoError("test error".to_string());

    // Test with condition = true
    let result: Result<i32, _> = protection.secure_error_handling(true, error.clone());
    assert!(result.is_err());

    // Test with condition = false
    let result: Result<i32, _> = protection.secure_error_handling(false, error);
    assert!(result.is_ok());
}

/// Test global side-channel protection functions
#[test]
fn test_global_side_channel_protection() {
    // Set up global protection
    let protection = SideChannelProtection::strict();
    set_side_channel_protection(protection);

    // Test global functions
    let a = b"hello";
    let b = b"hello";
    let c = b"world";

    assert!(secure_key_compare(a, b));
    assert!(!secure_key_compare(a, c));

    let result = secure_key_select(1, a, c);
    assert_eq!(result, a);

    let result = secure_key_select(0, a, c);
    assert_eq!(result, c);

    // Test string comparison
    assert!(secure_string_compare("hello", "hello"));
    assert!(!secure_string_compare("hello", "world"));

    // Test integer operations
    assert!(secure_integer_compare(42u64, 42u64));
    assert!(!secure_integer_compare(42u64, 43u64));

    let result = secure_integer_select(1, 42u64, 43u64);
    assert_eq!(result, 42u64);

    // Test boolean operations
    assert!(secure_boolean_and(true, true));
    assert!(!secure_boolean_and(true, false));

    assert!(secure_boolean_or(true, false));
    assert!(!secure_boolean_or(false, false));

    assert!(secure_boolean_xor(true, false));
    assert!(!secure_boolean_xor(true, true));
}

/// Test side-channel protection with different configurations
#[test]
fn test_side_channel_protection_configurations() {
    // Test strict configuration
    let strict = SideChannelProtection::strict();
    assert!(strict.timing_protection);
    assert!(strict.power_analysis_protection);
    assert!(strict.cache_attack_protection);
    assert!(strict.fault_injection_protection);

    // Test permissive configuration
    let permissive = SideChannelProtection::permissive();
    assert!(!permissive.timing_protection);
    assert!(!permissive.power_analysis_protection);
    assert!(!permissive.cache_attack_protection);
    assert!(!permissive.fault_injection_protection);

    // Test default configuration
    let default = SideChannelProtection::new();
    assert!(default.timing_protection);
    assert!(default.power_analysis_protection);
    assert!(default.cache_attack_protection);
    assert!(default.fault_injection_protection);
}

/// Test timing noise addition
#[test]
fn test_timing_noise() {
    let protection = SideChannelProtection::strict();

    let base_delay = 1000u64; // 1 microsecond

    // Test that timing noise is added
    let noisy_delay = protection.add_timing_noise(base_delay);
    assert!(noisy_delay >= base_delay);

    // Test with permissive configuration (no noise)
    let permissive = SideChannelProtection::permissive();
    let no_noise_delay = permissive.add_timing_noise(base_delay);
    assert_eq!(no_noise_delay, base_delay);
}

/// Test memory operations with different data patterns
#[test]
fn test_memory_operations_data_patterns() {
    let protection = SideChannelProtection::strict();

    // Test with all zeros
    let mut zeros = [0u8; 16];
    let src_zeros = [0u8; 16];
    protection.secure_memory_copy(1, &mut zeros, &src_zeros);
    assert_eq!(zeros, src_zeros);

    // Test with all ones
    let mut ones = [0u8; 16];
    let src_ones = [0xFFu8; 16];
    protection.secure_memory_copy(1, &mut ones, &src_ones);
    assert_eq!(ones, src_ones);

    // Test with alternating pattern
    let mut alt = [0u8; 16];
    let src_alt = [0xAAu8; 16];
    protection.secure_memory_copy(1, &mut alt, &src_alt);
    assert_eq!(alt, src_alt);

    // Test with random-like pattern
    let mut random = [0u8; 16];
    let src_random = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    protection.secure_memory_copy(1, &mut random, &src_random);
    assert_eq!(random, src_random);
}

/// Test edge cases and boundary conditions
#[test]
fn test_edge_cases() {
    let protection = SideChannelProtection::strict();

    // Test with empty slices
    let empty_a: &[u8] = &[];
    let empty_b: &[u8] = &[];
    assert!(protection.secure_key_compare(empty_a, empty_b));

    // Test with single byte
    let single_a = [1u8];
    let single_b = [1u8];
    let single_c = [2u8];
    assert!(protection.secure_key_compare(&single_a, &single_b));
    assert!(!protection.secure_key_compare(&single_a, &single_c));

    // Test with maximum size
    let large_a = vec![1u8; 1024];
    let large_b = vec![1u8; 1024];
    let large_c = vec![2u8; 1024];
    assert!(protection.secure_key_compare(&large_a, &large_b));
    assert!(!protection.secure_key_compare(&large_a, &large_c));

    // Test integer edge cases
    assert!(protection.secure_integer_compare(0u64, 0u64));
    assert!(protection.secure_integer_compare(u64::MAX, u64::MAX));
    assert!(!protection.secure_integer_compare(0u64, u64::MAX));
    assert!(!protection.secure_integer_compare(u64::MAX, 0u64));
}
