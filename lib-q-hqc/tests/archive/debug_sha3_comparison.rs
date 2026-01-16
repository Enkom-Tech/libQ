//! Debug test to compare SHA3-512 implementations

#[test]
fn test_sha3_512_comparison() {
    use lib_q_sha3::{
        Digest as Digest1,
        Sha3_512 as Sha3_512_LibQ,
    };
    use sha3::{
        Digest as Digest2,
        Sha3_512 as Sha3_512_External,
    };

    // seed_kem from intermediate values (32 bytes)
    let seed_kem: [u8; 32] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7,
    ];

    let domain: u8 = 2;

    println!("=== Testing SHA3-512 implementations ===");
    println!("Input: {:02x?}", seed_kem);
    println!("Domain: {:02x}", domain);

    // Test lib_q_sha3
    {
        let mut hasher = Sha3_512_LibQ::new();
        hasher.update(&seed_kem);
        hasher.update([domain]);
        let result = hasher.finalize();
        println!("\nlib_q_sha3 result:");
        println!("  First 32 (seed_dk): {:02x?}", &result[..32]);
        println!("  Next 32 (seed_ek):  {:02x?}", &result[32..64]);
    }

    // Test external sha3 crate
    {
        let mut hasher = Sha3_512_External::new();
        Digest2::update(&mut hasher, &seed_kem);
        Digest2::update(&mut hasher, &[domain]);
        let result = hasher.finalize();
        println!("\nsha3 crate result:");
        println!("  First 32 (seed_dk): {:02x?}", &result[..32]);
        println!("  Next 32 (seed_ek):  {:02x?}", &result[32..64]);
    }

    // Test just the seed without domain (to see base SHA3-512 output)
    {
        let mut hasher1 = Sha3_512_LibQ::new();
        hasher1.update(&seed_kem);
        let result1 = hasher1.finalize();

        let mut hasher2 = Sha3_512_External::new();
        Digest2::update(&mut hasher2, &seed_kem);
        let result2 = hasher2.finalize();

        println!("\nWithout domain:");
        println!("  lib_q_sha3:  {:02x?}", &result1[..32]);
        println!("  sha3 crate:  {:02x?}", &result2[..32]);
        println!("  Match: {}", result1[..] == result2[..]);
    }

    // Expected from intermediate values
    let expected_seed_dk: [u8; 32] = [
        0x12, 0xDA, 0xF0, 0x31, 0xBD, 0xC7, 0xFC, 0x59, 0x2E, 0x00, 0x03, 0xA2, 0x1E, 0xEF, 0xA9,
        0xA1, 0x01, 0x95, 0x39, 0xAB, 0xCC, 0xC8, 0xF6, 0x70, 0x75, 0x94, 0x7C, 0xBF, 0xEA, 0xAC,
        0x98, 0xC5,
    ];

    let expected_seed_ek: [u8; 32] = [
        0xEF, 0x2B, 0x80, 0xF4, 0x6F, 0x3A, 0x64, 0x37, 0xB4, 0xD8, 0x69, 0xBB, 0x38, 0xBD, 0xD6,
        0x00, 0x4B, 0xFF, 0x72, 0xBC, 0xD0, 0xCE, 0xB1, 0x39, 0xB4, 0xB8, 0xD4, 0x73, 0x01, 0xF4,
        0xFC, 0xB1,
    ];

    println!("\nExpected from reference:");
    println!("  seed_dk: {:02x?}", expected_seed_dk);
    println!("  seed_ek: {:02x?}", expected_seed_ek);
}
