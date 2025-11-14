#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::RngCore;

#[cfg(feature = "aes-drbg")]
#[test]
fn test_single_call_vs_multiple_calls() {
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    println!("=== Single Call vs Multiple Calls Test ===");

    // Test 1: Generate 32 bytes in a single call (like reference)
    let mut rng1 = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut seed_dk_single = [0u8; 32];
    rng1.fill_bytes(&mut seed_dk_single);

    println!("Single call seed_dk: {:02x?}", seed_dk_single);
    println!("State after single call: {}", rng1.debug_state());

    // Test 2: Generate 32 bytes in two 16-byte calls
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut seed_dk_multiple = [0u8; 32];
    rng2.fill_bytes(&mut seed_dk_multiple[..16]); // First 16 bytes
    println!("After first 16 bytes: {}", rng2.debug_state());
    rng2.fill_bytes(&mut seed_dk_multiple[16..]); // Second 16 bytes

    println!("Multiple calls seed_dk: {:02x?}", seed_dk_multiple);
    println!("State after multiple calls: {}", rng2.debug_state());

    // Test 3: Generate 32 bytes in four 8-byte calls
    let mut rng3 = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut seed_dk_four = [0u8; 32];
    rng3.fill_bytes(&mut seed_dk_four[..8]); // First 8 bytes
    rng3.fill_bytes(&mut seed_dk_four[8..16]); // Second 8 bytes
    rng3.fill_bytes(&mut seed_dk_four[16..24]); // Third 8 bytes
    rng3.fill_bytes(&mut seed_dk_four[24..]); // Fourth 8 bytes

    println!("Four calls seed_dk: {:02x?}", seed_dk_four);
    println!("State after four calls: {}", rng3.debug_state());

    // Expected seed_dk from KAT
    let expected_seed_dk = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    println!("\n=== Comparison ===");
    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!(
        "Single call matches: {}",
        seed_dk_single == expected_seed_dk
    );
    println!(
        "Multiple calls match: {}",
        seed_dk_multiple == expected_seed_dk
    );
    println!("Four calls match: {}", seed_dk_four == expected_seed_dk);

    // Check if all methods produce the same result
    println!("Single == Multiple: {}", seed_dk_single == seed_dk_multiple);
    println!("Single == Four: {}", seed_dk_single == seed_dk_four);
    println!("Multiple == Four: {}", seed_dk_multiple == seed_dk_four);
}
