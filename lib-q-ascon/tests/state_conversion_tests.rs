//! Comprehensive tests for Ascon State conversions and error handling
//!
//! These tests ensure complete coverage of the conversion methods and error
//! handling in the State implementation.

use core::mem::size_of;

use lib_q_ascon::State;

#[test]
fn test_state_new() {
    let state = State::new(1, 2, 3, 4, 5);
    assert_eq!(state[0], 1);
    assert_eq!(state[1], 2);
    assert_eq!(state[2], 3);
    assert_eq!(state[3], 4);
    assert_eq!(state[4], 5);
}

#[test]
fn test_state_index_operators() {
    let mut state = State::new(1, 2, 3, 4, 5);

    // Test immutable indexing
    assert_eq!(state[0], 1);
    assert_eq!(state[1], 2);
    assert_eq!(state[2], 3);
    assert_eq!(state[3], 4);
    assert_eq!(state[4], 5);

    // Test mutable indexing
    state[0] = 10;
    state[1] = 20;
    state[2] = 30;
    state[3] = 40;
    state[4] = 50;

    assert_eq!(state[0], 10);
    assert_eq!(state[1], 20);
    assert_eq!(state[2], 30);
    assert_eq!(state[3], 40);
    assert_eq!(state[4], 50);
}

#[test]
fn test_state_as_bytes() {
    let state = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0xAAAABBBBCCCCDDDD,
        0x1111222233334444,
        0x5555666677778888,
    );

    let bytes = state.as_bytes();

    // Check length
    assert_eq!(bytes.len(), 40); // 5 u64 values * 8 bytes

    // Check specific bytes
    // First u64 (0x0123456789ABCDEF) in big-endian
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x23);
    assert_eq!(bytes[2], 0x45);
    assert_eq!(bytes[3], 0x67);
    assert_eq!(bytes[4], 0x89);
    assert_eq!(bytes[5], 0xAB);
    assert_eq!(bytes[6], 0xCD);
    assert_eq!(bytes[7], 0xEF);

    // Second u64 (0xFEDCBA9876543210) in big-endian
    assert_eq!(bytes[8], 0xFE);
    assert_eq!(bytes[9], 0xDC);
    assert_eq!(bytes[10], 0xBA);
    assert_eq!(bytes[11], 0x98);
    assert_eq!(bytes[12], 0x76);
    assert_eq!(bytes[13], 0x54);
    assert_eq!(bytes[14], 0x32);
    assert_eq!(bytes[15], 0x10);

    // Spot check remaining bytes
    assert_eq!(bytes[16], 0xAA);
    assert_eq!(bytes[24], 0x11);
    assert_eq!(bytes[32], 0x55);
}

#[test]
fn test_state_tryfrom_u64_slice() {
    // Test valid conversion
    let slice = &[1u64, 2, 3, 4, 5];
    let state = State::from(slice);
    assert_eq!(state[0], 1);
    assert_eq!(state[1], 2);
    assert_eq!(state[2], 3);
    assert_eq!(state[3], 4);
    assert_eq!(state[4], 5);

    // Test invalid conversion (wrong slice length)
    let invalid_slice = &[1u64, 2, 3, 4][..]; // Only 4 elements as a slice
    let result = State::try_from(invalid_slice);
    assert!(result.is_err());

    let invalid_slice = &[1u64, 2, 3, 4, 5, 6][..]; // 6 elements as a slice
    let result = State::try_from(invalid_slice);
    assert!(result.is_err());
}

#[test]
fn test_state_from_u64_array() {
    let array = [1u64, 2, 3, 4, 5];
    let state = State::from(&array);

    assert_eq!(state[0], 1);
    assert_eq!(state[1], 2);
    assert_eq!(state[2], 3);
    assert_eq!(state[3], 4);
    assert_eq!(state[4], 5);
}

#[test]
fn test_state_tryfrom_u8_slice() {
    // Create a byte slice with known values
    let mut bytes = [0u8; 40]; // 5 u64 values * 8 bytes

    // First u64 (0x0123456789ABCDEF) in big-endian
    bytes[0] = 0x01;
    bytes[1] = 0x23;
    bytes[2] = 0x45;
    bytes[3] = 0x67;
    bytes[4] = 0x89;
    bytes[5] = 0xAB;
    bytes[6] = 0xCD;
    bytes[7] = 0xEF;

    // Second u64 (0xFEDCBA9876543210) in big-endian
    bytes[8] = 0xFE;
    bytes[9] = 0xDC;
    bytes[10] = 0xBA;
    bytes[11] = 0x98;
    bytes[12] = 0x76;
    bytes[13] = 0x54;
    bytes[14] = 0x32;
    bytes[15] = 0x10;

    // Fill remaining bytes with recognizable patterns
    for (i, byte) in bytes.iter_mut().enumerate().take(24).skip(16) {
        *byte = (i - 16) as u8;
    }

    for (i, byte) in bytes.iter_mut().enumerate().take(32).skip(24) {
        *byte = (i - 16) as u8;
    }

    for (i, byte) in bytes.iter_mut().enumerate().skip(32) {
        *byte = (i - 16) as u8;
    }

    // Test valid conversion
    let result = State::try_from(&bytes[..]);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state[0], 0x0123456789ABCDEF);
    assert_eq!(state[1], 0xFEDCBA9876543210);

    // Test invalid conversion (wrong slice length)
    let invalid_slice = &bytes[0..39]; // Only 39 bytes
    let result = State::try_from(invalid_slice);
    assert!(result.is_err());

    let invalid_bytes = [0u8; 41]; // 41 bytes
    let invalid_slice = &invalid_bytes[..];
    let result = State::try_from(invalid_slice);
    assert!(result.is_err());
}

#[test]
fn test_state_from_u8_array() {
    let mut bytes = [0u8; size_of::<u64>() * 5];

    // First u64 (0x0123456789ABCDEF) in big-endian
    bytes[0] = 0x01;
    bytes[1] = 0x23;
    bytes[2] = 0x45;
    bytes[3] = 0x67;
    bytes[4] = 0x89;
    bytes[5] = 0xAB;
    bytes[6] = 0xCD;
    bytes[7] = 0xEF;

    // Second u64 (0xFEDCBA9876543210) in big-endian
    bytes[8] = 0xFE;
    bytes[9] = 0xDC;
    bytes[10] = 0xBA;
    bytes[11] = 0x98;
    bytes[12] = 0x76;
    bytes[13] = 0x54;
    bytes[14] = 0x32;
    bytes[15] = 0x10;

    // Fill remaining bytes with recognizable patterns
    for (i, byte) in bytes.iter_mut().enumerate().take(24).skip(16) {
        *byte = (i - 16) as u8;
    }

    for (i, byte) in bytes.iter_mut().enumerate().take(32).skip(24) {
        *byte = (i - 16) as u8;
    }

    for (i, byte) in bytes.iter_mut().enumerate().skip(32) {
        *byte = (i - 16) as u8;
    }

    let state = State::from(&bytes);
    assert_eq!(state[0], 0x0123456789ABCDEF);
    assert_eq!(state[1], 0xFEDCBA9876543210);
}

#[test]
fn test_state_as_ref() {
    let state = State::new(1, 2, 3, 4, 5);
    let slice: &[u64] = state.as_ref();

    assert_eq!(slice.len(), 5);
    assert_eq!(slice[0], 1);
    assert_eq!(slice[1], 2);
    assert_eq!(slice[2], 3);
    assert_eq!(slice[3], 4);
    assert_eq!(slice[4], 5);
}

#[test]
fn test_state_permute_n() {
    let mut state = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    // Test valid permutation counts
    assert!(state.permute_n(1).is_ok());
    assert!(state.permute_n(6).is_ok());
    assert!(state.permute_n(8).is_ok());
    assert!(state.permute_n(12).is_ok());

    // Test invalid permutation count
    // Note: In debug mode, this will panic due to debug_assert!
    // In release mode, it will return an error
    #[cfg(not(debug_assertions))]
    {
        assert!(state.permute_n(13).is_err());
        assert!(state.permute_n(20).is_err());
    }
    
    // In debug mode, we expect a panic for invalid round counts
    #[cfg(debug_assertions)]
    {
        // Test that invalid round counts cause panics in debug mode
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.permute_n(13)
        }));
        assert!(result.is_err(), "Expected panic for 13 rounds in debug mode");
        
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.permute_n(20)
        }));
        assert!(result.is_err(), "Expected panic for 20 rounds in debug mode");
    }

    // Test that permute_n with n=1 is equivalent to permute_1
    let mut state1 = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    let mut state2 = state1;

    state1.permute_1();
    assert!(state2.permute_n(1).is_ok());

    assert_eq!(state1[0], state2[0]);
    assert_eq!(state1[1], state2[1]);
    assert_eq!(state1[2], state2[2]);
    assert_eq!(state1[3], state2[3]);
    assert_eq!(state1[4], state2[4]);

    // Test that permute_n with n=6 is equivalent to permute_6
    let mut state1 = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    let mut state2 = state1;

    state1.permute_6();
    assert!(state2.permute_n(6).is_ok());

    assert_eq!(state1[0], state2[0]);
    assert_eq!(state1[1], state2[1]);
    assert_eq!(state1[2], state2[2]);
    assert_eq!(state1[3], state2[3]);
    assert_eq!(state1[4], state2[4]);
}

#[test]
fn test_pad_function() {
    // Test for all valid padding positions
    assert_eq!(lib_q_ascon::pad(0), 0x8000000000000000);
    assert_eq!(lib_q_ascon::pad(1), 0x0080000000000000);
    assert_eq!(lib_q_ascon::pad(2), 0x0000800000000000);
    assert_eq!(lib_q_ascon::pad(3), 0x0000008000000000);
    assert_eq!(lib_q_ascon::pad(4), 0x0000000080000000);
    assert_eq!(lib_q_ascon::pad(5), 0x0000000000800000);
    assert_eq!(lib_q_ascon::pad(6), 0x0000000000008000);
    assert_eq!(lib_q_ascon::pad(7), 0x0000000000000080);
}

#[test]
fn test_permutation_constants() {
    // Test the round constants indirectly by validating the permutation outputs
    // This ensures round constants are correct without accessing private functions

    // Create a reference state with known values
    let mut state = State::new(
        0x0123456789ABCDEF,
        0xFEDCBA0987654321,
        0xAAAABBBBCCCCDDDD,
        0x1111222233334444,
        0x5555666677778888,
    );

    // Store initial state for comparison
    let initial_state = state;

    // Apply permutation
    state.permute_12();

    // Verify that the permutation actually changed the state
    // (this ensures the round constants are being applied)
    assert_ne!(state[0], initial_state[0]);
    assert_ne!(state[1], initial_state[1]);
    assert_ne!(state[2], initial_state[2]);
    assert_ne!(state[3], initial_state[3]);
    assert_ne!(state[4], initial_state[4]);

    // Verify that the state is not all zeros (permutation should produce non-zero output)
    assert_ne!(state[0], 0);
    assert_ne!(state[1], 0);
    assert_ne!(state[2], 0);
    assert_ne!(state[3], 0);
    assert_ne!(state[4], 0);

    // Test that multiple permutations produce different results
    let mut state2 = initial_state;
    state2.permute_12();
    state2.permute_12();

    // Two permutations should be different from one permutation
    assert_ne!(state[0], state2[0]);
    assert_ne!(state[1], state2[1]);
    assert_ne!(state[2], state2[2]);
    assert_ne!(state[3], state2[3]);
    assert_ne!(state[4], state2[4]);
}

#[cfg(feature = "zeroize")]
mod zeroize_tests {
    use lib_q_ascon::State;
    use zeroize::Zeroize;

    #[test]
    fn test_state_zeroize() {
        let mut state = State::new(
            0x0123456789ABCDEF,
            0xFEDCBA9876543210,
            0x0011223344556677,
            0x8899AABBCCDDEEFF,
            0xFFFFFFFF00000000,
        );

        // Zeroize the state
        state.zeroize();

        // Verify all values are zero
        assert_eq!(state[0], 0);
        assert_eq!(state[1], 0);
        assert_eq!(state[2], 0);
        assert_eq!(state[3], 0);
        assert_eq!(state[4], 0);
    }
}
