//! Debug test for hash_i function to verify seed derivation

use lib_q_hqc::Hqc1Params;
use lib_q_hqc::hqc_pke::HqcPke;

#[test]
fn test_hash_i_produces_correct_seeds() {
    println!("=== Testing hash_i seed derivation ===");

    // seed_pke from intermediate values (32 bytes)
    // NOTE: hash_i is called with seed_pke, NOT seed_kem!
    // seed_pke is derived from seed_kem using XOF (SHAKE-256 with domain=1)
    let seed_pke: [u8; 32] = [
        0x81, 0x31, 0x3D, 0xE3, 0x2A, 0xD3, 0x6C, 0x47, 0x79, 0x86, 0x5F, 0xE6, 0x6D, 0xDA, 0x28,
        0xAA, 0x92, 0x28, 0x81, 0x8C, 0x0F, 0x3E, 0x2F, 0xA0, 0x34, 0x8E, 0xF1, 0x6E, 0x37, 0x7D,
        0x10, 0x49,
    ];

    // Expected seed_dk from intermediate values
    let expected_seed_dk: [u8; 32] = [
        0x12, 0xDA, 0xF0, 0x31, 0xBD, 0xC7, 0xFC, 0x59, 0x2E, 0x00, 0x03, 0xA2, 0x1E, 0xEF, 0xA9,
        0xA1, 0x01, 0x95, 0x39, 0xAB, 0xCC, 0xC8, 0xF6, 0x70, 0x75, 0x94, 0x7C, 0xBF, 0xEA, 0xAC,
        0x98, 0xC5,
    ];

    // Expected seed_ek from intermediate values
    let expected_seed_ek: [u8; 32] = [
        0xEF, 0x2B, 0x80, 0xF4, 0x6F, 0x3A, 0x64, 0x37, 0xB4, 0xD8, 0x69, 0xBB, 0x38, 0xBD, 0xD6,
        0x00, 0x4B, 0xFF, 0x72, 0xBC, 0xD0, 0xCE, 0xB1, 0x39, 0xB4, 0xB8, 0xD4, 0x73, 0x01, 0xF4,
        0xFC, 0xB1,
    ];

    println!("seed_pke: {:02x?}", seed_pke);

    // Create HQC PKE instance
    let pke = HqcPke::<Hqc1Params>::new().expect("PKE creation failed");

    // Call hash_i with seed_pke (NOT seed_kem!)
    let mut output = [0u8; 64];
    pke.hash_i(&mut output, &seed_pke);

    let seed_dk = &output[..32];
    let seed_ek = &output[32..64];

    println!("Computed seed_dk: {:02x?}", seed_dk);
    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("seed_dk match: {}", seed_dk == expected_seed_dk);

    println!("Computed seed_ek: {:02x?}", seed_ek);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);
    println!("seed_ek match: {}", seed_ek == expected_seed_ek);

    assert_eq!(seed_dk, expected_seed_dk.as_slice(), "seed_dk mismatch");
    assert_eq!(seed_ek, expected_seed_ek.as_slice(), "seed_ek mismatch");
}
