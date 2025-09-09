//! Comprehensive tests for the lib-q-sponge API
//!
//! These tests ensure complete coverage of the public API exported by lib-q-sponge.

// Import all public items from lib-q-sponge to ensure we test them
use lib_q_sponge::*;

#[test]
fn test_sponge_exports_keccak_functions() {
    // Test that all required Keccak functions are properly exported

    // Test f1600 (this function should be accessible and not cause compilation errors)
    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    f1600(&mut state);

    // Verify that the state changed
    assert_ne!(state[0], 0x1234567890ABCDEF);

    // Test other exported keccak functions
    let mut state_800 = [0u32; 25];
    state_800[0] = 0x12345678;
    f800(&mut state_800);
    assert_ne!(state_800[0], 0x12345678);

    let mut state_400 = [0u16; 25];
    state_400[0] = 0x1234;
    f400(&mut state_400);
    assert_ne!(state_400[0], 0x1234);

    let mut state_200 = [0u8; 25];
    state_200[0] = 0x12;
    f200(&mut state_200);
    assert_ne!(state_200[0], 0x12);
}

#[test]
fn test_sponge_exports_ascon_functions() {
    // Test that the Ascon State implementation is properly exported

    // Create a state with test data
    let mut state = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);

    // Apply permutation
    state.permute_12();

    // Verify state changed
    assert_ne!(state[0], 0x1234567890ABCDEF);

    // Test other permutation functions
    let mut state = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    state.permute_8();
    assert_ne!(state[0], 0x1234567890ABCDEF);

    let mut state = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    state.permute_6();
    assert_ne!(state[0], 0x1234567890ABCDEF);

    // Test permute_n
    let mut state = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    assert!(state.permute_n(6).is_ok());
    assert_ne!(state[0], 0x1234567890ABCDEF);
}

#[test]
fn test_sponge_exports_keccak_optimization_functions() {
    // Test that the optimization-related functions are properly exported

    // Test optimization level
    let best = OptimizationLevel::best_available();
    assert!(best.is_available());

    // Test optimized permutation
    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    p1600_optimized(&mut state, OptimizationLevel::Reference);
    assert_ne!(state[0], 0x1234567890ABCDEF);

    // Test fast loop absorption
    let mut state = [0u64; 25];
    let data = b"Test data for fast loop absorption";
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);
    assert!(offset > 0);
    assert_ne!(state[0], 0);
}

#[test]
fn test_sponge_exports_keccak_feature_config() {
    // Test that feature configuration functions are properly exported

    // Test feature detection
    let report = detection::detect_available_features();
    assert!(!report.summary().is_empty());

    // Test feature configuration
    let config = FeatureConfig::new();
    assert!(config.optimization_level.is_available());

    // Test specialized configurations
    let security_config = FeatureConfig::security_optimized();
    assert_eq!(
        security_config.optimization_level,
        OptimizationLevel::Reference
    );

    let perf_config = FeatureConfig::performance_optimized();
    assert_eq!(perf_config.optimization_level, OptimizationLevel::Maximum);
}

#[test]
fn test_sponge_ascon_state_conversions() {
    // Test State conversion methods

    // Create a state
    let state = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    // Test as_bytes
    let bytes = state.as_bytes();
    assert_eq!(bytes.len(), 40);

    // Test TryFrom for u64 slice
    let slice = &[
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    ];
    let state2 = State::from(slice);
    assert_eq!(state2[0], state[0]);

    // Test From for u64 array
    let array = [
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    ];
    let state3 = State::from(&array);
    assert_eq!(state3[0], state[0]);
}

#[cfg(feature = "simd")]
mod simd_tests {
    use lib_q_sponge::OptimizationLevel;
    use lib_q_sponge::parallel::p1600_parallel;

    #[test]
    fn test_sponge_exports_simd_functions() {
        // Test that SIMD functionality is properly exported

        // Create multiple states
        let mut states = [[0u64; 25]; 4];

        // Initialize with test data
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }

        // Process states in parallel
        p1600_parallel(&mut states, OptimizationLevel::Reference);

        // Verify that states have changed
        for (i, state) in states.iter().enumerate() {
            assert_ne!(state[0], 0x1234567890ABCDEF + i as u64);
        }
    }
}

#[cfg(all(feature = "simd", feature = "multithreading"))]
mod multithreading_tests {
    use lib_q_sponge::OptimizationLevel;
    use lib_q_sponge::parallel::p1600_multithreaded;

    #[test]
    fn test_sponge_exports_multithreaded_functions() {
        // Test that multithreaded functionality is properly exported

        // Create multiple states
        let states = [[0u64; 25]; 4];

        // Initialize with test data
        let mut states = states;
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }

        // Process states using multithreaded implementation
        let result = p1600_multithreaded(&states, OptimizationLevel::Reference);

        // Check that the operation succeeded
        assert!(result.is_ok());

        // Verify that states have changed
        for (i, state) in result.unwrap().iter().enumerate() {
            assert_ne!(state[0], 0x1234567890ABCDEF + i as u64);
        }
    }
}
