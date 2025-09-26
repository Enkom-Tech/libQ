#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "custom-entropy")]
use lib_q_random::custom_entropy::{
    CustomEntropyConfig,
    CustomEntropySource,
    EntropyContext,
    EntropyQuality,
    generate_custom_entropy,
    get_entropy_source_info,
    has_custom_entropy_source,
    register_custom_entropy_source,
    unregister_custom_entropy_source,
};
#[cfg(not(feature = "alloc"))]
use lib_q_random::{
    new_deterministic_rng_no_std,
    new_secure_rng_no_std,
    no_std_rng::NoStdRng,
};
// RngCore is not used in this test file

// Test entropy callback that generates predictable data
#[allow(dead_code)]
unsafe extern "C" fn test_entropy_callback(dest: *mut u8, len: usize, _context: *mut u8) -> i32 {
    if dest.is_null() {
        return -1;
    }

    // Generate predictable test data (handle empty buffer case)
    for i in 0..len {
        unsafe {
            *dest.add(i) = (i as u8).wrapping_add(42);
        }
    }

    0
}

// Test entropy callback that fails
#[allow(dead_code)]
unsafe extern "C" fn failing_entropy_callback(
    _dest: *mut u8,
    _len: usize,
    _context: *mut u8,
) -> i32 {
    -1 // Always fail
}

// Test entropy callback that generates high-quality random data
#[allow(dead_code)]
unsafe extern "C" fn high_quality_entropy_callback(
    dest: *mut u8,
    len: usize,
    _context: *mut u8,
) -> i32 {
    if dest.is_null() || len == 0 {
        return -1;
    }

    // Generate high-quality test data (simulating hardware RNG)
    for i in 0..len {
        unsafe {
            *dest.add(i) = ((i * 7 + 13) % 256) as u8;
        }
    }

    0
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_registration() {
    // Initially no source registered
    assert!(!has_custom_entropy_source());
    assert!(get_entropy_source_info().is_none());

    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "test_registration",
    };

    // Register the source
    unsafe {
        register_custom_entropy_source(&source);
    }

    assert!(has_custom_entropy_source());
    let info = get_entropy_source_info().unwrap();
    assert_eq!(info.0, "test_registration");
    assert_eq!(info.1, EntropyQuality::User);

    // Unregister the source
    unregister_custom_entropy_source();
    assert!(!has_custom_entropy_source());
    assert!(get_entropy_source_info().is_none());
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_generation() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "test_generation",
    };

    // Register the source
    unsafe {
        register_custom_entropy_source(&source);
    }

    // Test entropy generation
    let mut buffer = [0u8; 16];
    generate_custom_entropy(&mut buffer).unwrap();

    // Check that the callback was called (predictable test data)
    for (i, &byte) in buffer.iter().enumerate() {
        assert_eq!(byte, (i as u8).wrapping_add(42));
    }

    // Test different buffer sizes
    let mut small_buffer = [0u8; 4];
    generate_custom_entropy(&mut small_buffer).unwrap();
    for (i, &byte) in small_buffer.iter().enumerate() {
        assert_eq!(byte, (i as u8).wrapping_add(42));
    }

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_failure() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: failing_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "failing_source",
    };

    // Register the failing source
    unsafe {
        register_custom_entropy_source(&source);
    }

    // Test entropy generation failure
    let mut buffer = [0u8; 8];
    let result = generate_custom_entropy(&mut buffer);
    assert!(result.is_err());

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_no_source() {
    // Ensure no source is registered
    unregister_custom_entropy_source();

    let mut buffer = [0u8; 8];
    let result = generate_custom_entropy(&mut buffer);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_quality_levels() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();

    // Test hardware quality
    let hardware_source = CustomEntropySource {
        callback: high_quality_entropy_callback,
        context,
        quality: EntropyQuality::Hardware,
        config: config.clone(),
        source_id: "hardware_source",
    };

    unsafe {
        register_custom_entropy_source(&hardware_source);
    }

    let info = get_entropy_source_info().unwrap();
    assert_eq!(info.1, EntropyQuality::Hardware);
    assert!(info.1.is_secure());

    // Test OS quality
    let os_source = CustomEntropySource {
        callback: high_quality_entropy_callback,
        context,
        quality: EntropyQuality::Os,
        config: config.clone(),
        source_id: "os_source",
    };

    unsafe {
        register_custom_entropy_source(&os_source);
    }

    let info = get_entropy_source_info().unwrap();
    assert_eq!(info.1, EntropyQuality::Os);
    assert!(info.1.is_secure());

    // Test user quality
    let user_source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config: config.clone(),
        source_id: "user_source",
    };

    unsafe {
        register_custom_entropy_source(&user_source);
    }

    let info = get_entropy_source_info().unwrap();
    assert_eq!(info.1, EntropyQuality::User);
    assert!(info.1.is_secure());

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_config_validation() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig {
        max_bytes_per_call: 8, // Limit to 8 bytes
        ..Default::default()
    };

    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "limited_source",
    };

    unsafe {
        register_custom_entropy_source(&source);
    }

    // Test within limit
    let mut small_buffer = [0u8; 4];
    generate_custom_entropy(&mut small_buffer).unwrap();

    // Test exceeding limit
    let mut large_buffer = [0u8; 16];
    let result = generate_custom_entropy(&mut large_buffer);
    assert!(result.is_err());

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_deterministic_validation() {
    let context = EntropyContext::empty();
    let mut config = CustomEntropyConfig::default();
    config.validate_quality = true;

    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::Deterministic, // Low quality
        config,
        source_id: "deterministic_source",
    };

    unsafe {
        register_custom_entropy_source(&source);
    }

    let mut buffer = [0u8; 8];
    let result = generate_custom_entropy(&mut buffer);
    assert!(result.is_err());

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_context_data() {
    let test_data = [1u8, 2, 3, 4, 5];
    let context = unsafe { EntropyContext::new(test_data.as_ptr() as *mut u8, test_data.len()) };
    let config = CustomEntropyConfig::default();

    // Test callback that uses context data
    unsafe extern "C" fn context_entropy_callback(
        dest: *mut u8,
        len: usize,
        context: *mut u8,
    ) -> i32 {
        if dest.is_null() || len == 0 || context.is_null() {
            return -1;
        }

        let context_data = unsafe { core::slice::from_raw_parts(context, 5) };
        for i in 0..len {
            unsafe {
                *dest.add(i) = context_data[i % context_data.len()];
            }
        }

        0
    }

    let source = CustomEntropySource {
        callback: context_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "context_source",
    };

    unsafe {
        register_custom_entropy_source(&source);
    }

    let mut buffer = [0u8; 10];
    generate_custom_entropy(&mut buffer).unwrap();

    // Check that context data was used
    for (i, &byte) in buffer.iter().enumerate() {
        assert_eq!(byte, test_data[i % test_data.len()]);
    }

    unregister_custom_entropy_source();
}

#[test]
#[cfg(all(not(feature = "alloc"), feature = "custom-entropy"))]
fn test_custom_entropy_with_no_std_rng() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "rng_test_source",
    };

    // Register the source
    unsafe {
        register_custom_entropy_source(&source);
    }

    // Test that NoStdRng can use the custom entropy source
    let mut rng = NoStdRng::new().unwrap();
    let mut buffer = [0u8; 32];
    rng.fill_bytes(&mut buffer);

    // The buffer should be filled (though we can't predict the exact values
    // since NoStdRng might use getrandom as fallback)
    let has_non_zero = buffer.iter().any(|&b| b != 0);
    assert!(has_non_zero);

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_multiple_registrations() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();

    // Register first source
    let source1 = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config: config.clone(),
        source_id: "source1",
    };

    unsafe {
        register_custom_entropy_source(&source1);
    }

    assert_eq!(get_entropy_source_info().unwrap().0, "source1");

    // Register second source (should replace first)
    let source2 = CustomEntropySource {
        callback: high_quality_entropy_callback,
        context,
        quality: EntropyQuality::Hardware,
        config,
        source_id: "source2",
    };

    unsafe {
        register_custom_entropy_source(&source2);
    }

    assert_eq!(get_entropy_source_info().unwrap().0, "source2");
    assert_eq!(
        get_entropy_source_info().unwrap().1,
        EntropyQuality::Hardware
    );

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_edge_cases() {
    let context = EntropyContext::empty();
    let config = CustomEntropyConfig::default();
    let source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::User,
        config,
        source_id: "edge_case_source",
    };

    unsafe {
        register_custom_entropy_source(&source);
    }

    // Test empty buffer
    let mut empty_buffer = [];
    let result = generate_custom_entropy(&mut empty_buffer);
    assert!(result.is_ok());

    // Test single byte
    let mut single_byte = [0u8; 1];
    generate_custom_entropy(&mut single_byte).unwrap();
    assert_eq!(single_byte[0], 42);

    unregister_custom_entropy_source();
}

#[test]
#[cfg(feature = "custom-entropy")]
fn test_custom_entropy_security_validation() {
    let context = EntropyContext::empty();
    let mut config = CustomEntropyConfig::default();
    config.validate_quality = true;

    // Test secure source
    let secure_source = CustomEntropySource {
        callback: high_quality_entropy_callback,
        context,
        quality: EntropyQuality::Hardware,
        config: config.clone(),
        source_id: "secure_source",
    };

    unsafe {
        register_custom_entropy_source(&secure_source);
    }

    let mut buffer = [0u8; 8];
    let result = generate_custom_entropy(&mut buffer);
    assert!(result.is_ok());

    // Test insecure source
    let insecure_source = CustomEntropySource {
        callback: test_entropy_callback,
        context,
        quality: EntropyQuality::Deterministic,
        config,
        source_id: "insecure_source",
    };

    unsafe {
        register_custom_entropy_source(&insecure_source);
    }

    let result = generate_custom_entropy(&mut buffer);
    assert!(result.is_err());

    unregister_custom_entropy_source();
}
