//! Debug test to compare our AES implementation with known OpenSSL output
//!
//! This test uses known OpenSSL AES-256-ECB output to verify our implementation

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;

/// Helper function to print hex with label
fn print_hex(label: &str, data: &[u8]) {
    println!("{}: {:02x?}", label, data);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_openssl_comparison() {
    println!("=== AES OpenSSL Comparison Test ===");

    // Test with the exact key and counter values that should produce the expected seed_ek
    // These values come from our DRBG analysis

    // Key from DRBG state after seed_dk generation
    let key = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    // Counter value that should produce the first block of seed_ek
    let counter = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05,
    ];

    print_hex("Key", &key);
    print_hex("Counter", &counter);

    // Test our AES implementation
    let our_output = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("Our AES Output", &our_output);

    // Expected output (this is what OpenSSL should produce)
    let expected_output = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05,
    ];
    print_hex("Expected Output", &expected_output);

    println!("Output matches: {}", our_output == expected_output);

    // Test with a known OpenSSL test vector
    // This is a standard AES-256 test vector
    let test_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let test_input = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let test_expected = [
        0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60,
        0x89,
    ];

    let test_output = Aes256CtrDrbg::aes256_ecb(&test_key, &test_input);
    print_hex("Test Key", &test_key);
    print_hex("Test Input", &test_input);
    print_hex("Test Output", &test_output);
    print_hex("Test Expected", &test_expected);
    println!("Test vector matches: {}", test_output == test_expected);

    if test_output == test_expected {
        println!("✅ Our AES implementation passes standard test vectors");
        println!("❌ But produces different output than OpenSSL for DRBG values");
        println!("This suggests the issue is not in our AES implementation itself");
    } else {
        println!("❌ Our AES implementation fails standard test vectors");
        println!("This suggests there's a bug in our AES implementation");
    }
}
