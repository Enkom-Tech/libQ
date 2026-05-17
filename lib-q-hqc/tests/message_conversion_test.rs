//! Test message conversion functions for HQC
//!
//! This module tests that bytes_to_u64_array and u64_array_to_message_bytes
//! are proper inverse functions.

use lib_q_hqc::*;

/// Test that message conversion functions are inverses
#[test]
fn test_message_conversion_inverses() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test with various message values
    let test_messages = [
        [0u8; 16],    // All zeros
        [0xFFu8; 16], // All ones
        [0x5Au8; 16], // Pattern 01011010
        [0xA5u8; 16], // Pattern 10100101
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ], // Sequential
        [
            0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D,
            0x1E, 0x0F,
        ], // Reverse sequential
    ];

    for (i, original_message) in test_messages.iter().enumerate() {
        println!("Testing message {}: {:02x?}", i, original_message);

        // Convert bytes to u64 array using PKE method
        let u64_array = pke.bytes_to_u64_array(original_message, 16);
        println!("  -> u64 array: {:02x?}", u64_array);

        // Convert back to bytes using PKE method
        let recovered_bytes = pke.u64_array_to_bytes(&u64_array, 16);
        println!("  -> recovered: {:02x?}", recovered_bytes);

        // Check if they match
        assert_eq!(
            original_message,
            recovered_bytes.as_slice(),
            "Message conversion failed for test case {}",
            i
        );

        println!("  ✅ Conversion successful");
    }
}

/// Test with random messages
#[test]
fn test_message_conversion_random() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test with 100 random messages
    for i in 0..100 {
        let mut message = [0u8; 16];
        for (j, item) in message.iter_mut().enumerate() {
            *item = (i * 7 + j * 13) as u8; // Simple pseudo-random
        }

        let u64_array = pke.bytes_to_u64_array(&message, 16);
        let recovered = pke.u64_array_to_bytes(&u64_array, 16);

        assert_eq!(
            message,
            recovered.as_slice(),
            "Random message conversion failed for iteration {}",
            i
        );
    }
}

/// Test edge cases
#[test]
fn test_message_conversion_edge_cases() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test with messages that might cause issues
    let edge_cases = [
        [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ], // High bit set
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ], // Low bit set
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ], // All bits set
    ];

    for (i, message) in edge_cases.iter().enumerate() {
        println!("Testing edge case {}: {:02x?}", i, message);

        let u64_array = pke.bytes_to_u64_array(message, 16);
        let recovered = pke.u64_array_to_bytes(&u64_array, 16);

        assert_eq!(
            message,
            recovered.as_slice(),
            "Edge case conversion failed for case {}",
            i
        );

        println!("  ✅ Edge case successful");
    }
}

/// Test byte order and endianness
#[test]
fn test_message_conversion_endianness() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Test with a message that will show endianness issues
    let message = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    println!("Testing endianness with message: {:02x?}", message);

    let u64_array = pke.bytes_to_u64_array(&message, 16);
    println!("u64 array: {:02x?}", u64_array);

    // Check if the u64 values make sense
    // If little-endian: first u64 should be 0x0807060504030201
    // If big-endian: first u64 should be 0x0102030405060708
    println!("First u64: 0x{:016x}", u64_array[0]);

    let recovered = pke.u64_array_to_bytes(&u64_array, 16);
    println!("Recovered: {:02x?}", recovered);

    assert_eq!(message, recovered.as_slice(), "Endianness test failed");

    println!("✅ Endianness test successful");
}
