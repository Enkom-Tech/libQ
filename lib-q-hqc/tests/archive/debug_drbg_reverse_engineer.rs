//! Reverse engineer what Key and V should be to produce expected output

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_reverse_engineer_key_v() {
    println!("=== Reverse Engineering Key and V ===");

    // Expected first 16 bytes of seed_dk
    let expected_first_block: [u8; 16] = [
        0x12, 0xDA, 0xF0, 0x31, 0xBD, 0xC7, 0xFC, 0x59, 0x2E, 0x00, 0x03, 0xA2, 0x1E, 0xEF, 0xA9,
        0xA1,
    ];

    // Expected second 16 bytes of seed_dk
    let expected_second_block: [u8; 16] = [
        0x01, 0x95, 0x39, 0xAB, 0xCC, 0xC8, 0xF6, 0x70, 0x75, 0x94, 0x7C, 0xBF, 0xEA, 0xAC, 0x98,
        0xC5,
    ];

    println!("Expected first block:  {:02x?}", expected_first_block);
    println!("Expected second block: {:02x?}", expected_second_block);

    // We know that:
    // first_block = AES(Key, V+1)
    // second_block = AES(Key, V+2)

    // If we had the Key, we could decrypt to get V+1 and V+2
    // But we don't have the Key, so we can't directly reverse engineer

    // However, we can try to see if there's a pattern
    // Let's check what V+1 and V+2 would be if V after instantiate is what we computed
    let v_after_instantiate: [u8; 16] = [
        0x06, 0xD2, 0xD0, 0x98, 0xF8, 0xD2, 0xE3, 0x40, 0xD7, 0x3E, 0x68, 0x69, 0x32, 0x51, 0xC0,
        0x8B,
    ];

    let key_after_instantiate: [u8; 32] = [
        0xCD, 0xF7, 0xFD, 0x06, 0x1C, 0xAD, 0xBF, 0xA5, 0xC7, 0x2D, 0xCD, 0x1B, 0x34, 0xE9, 0x96,
        0xE8, 0x10, 0x5D, 0x8A, 0x56, 0x58, 0x41, 0x0A, 0xD7, 0xA3, 0x6D, 0x2D, 0x2D, 0x2C, 0x57,
        0x9E, 0xFF,
    ];

    println!("\nOur computed Key after instantiate:");
    println!("{:02x?}", key_after_instantiate);
    println!("\nOur computed V after instantiate:");
    println!("{:02x?}", v_after_instantiate);

    // Increment V
    let mut v1 = v_after_instantiate;
    v1[15] += 1; // Simple increment for now
    println!("\nV+1 (simple increment): {:02x?}", v1);

    let aes_ctx = Aes256CtxPure::new(&key_after_instantiate);
    let computed_first = aes_ctx.encrypt_block(&v1);
    println!("Computed first block:   {:02x?}", computed_first);
    println!("Match: {}", computed_first == expected_first_block);

    // The fact that they don't match means either Key or V is wrong
    // Let's check if maybe V should be different
}
