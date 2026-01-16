//! Test AES with the exact Key from instantiate to see if it matches OpenSSL

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_aes_with_instantiate_key() {
    println!("=== Testing AES with Key from instantiate ===");

    // Key after instantiate (what we computed)
    let key: [u8; 32] = [
        0xCD, 0xF7, 0xFD, 0x06, 0x1C, 0xAD, 0xBF, 0xA5, 0xC7, 0x2D, 0xCD, 0x1B, 0x34, 0xE9, 0x96,
        0xE8, 0x10, 0x5D, 0x8A, 0x56, 0x58, 0x41, 0x0A, 0xD7, 0xA3, 0x6D, 0x2D, 0x2D, 0x2C, 0x57,
        0x9E, 0xFF,
    ];

    // V after instantiate
    let v: [u8; 16] = [
        0x06, 0xD2, 0xD0, 0x98, 0xF8, 0xD2, 0xE3, 0x40, 0xD7, 0x3E, 0x68, 0x69, 0x32, 0x51, 0xC0,
        0x8B,
    ];

    // V+1 (after first increment)
    let mut v1 = v;
    v1[15] += 1;

    println!("Key: {:02x?}", key);
    println!("V:   {:02x?}", v);
    println!("V+1: {:02x?}", v1);

    let aes_ctx = Aes256CtxPure::new(&key);
    let output = aes_ctx.encrypt_block(&v1);

    println!("AES(Key, V+1): {:02x?}", output);
    println!(
        "Expected first block: [12, da, f0, 31, bd, c7, fc, 59, 2e, 00, 03, a2, 1e, ef, a9, a1]"
    );

    // If this doesn't match, then either Key or V is wrong
    // If it does match, then the issue is elsewhere
}
