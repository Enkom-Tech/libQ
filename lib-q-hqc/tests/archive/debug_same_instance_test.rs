#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::Rng;

#[cfg(feature = "aes-drbg")]
#[test]
fn test_same_drbg_instance() {
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    println!("=== Same DRBG Instance Test (Reference Behavior) ===");

    // Initialize DRBG with KAT seed (like reference implementation)
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed);
    println!("Initial state: {}", rng.debug_state());

    // First call: randombytes(seed_dk, 32)
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);

    println!("After first call - seed_dk: {:02x?}", seed_dk);
    println!("State after first call: {}", rng.debug_state());

    // Second call: randombytes(seed_ek, 32) - with SAME DRBG instance
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);

    println!("After second call - seed_ek: {:02x?}", seed_ek);
    println!("State after second call: {}", rng.debug_state());

    // Expected values from KAT
    let expected_seed_dk = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("\n=== Comparison ===");
    println!("seed_dk matches: {}", seed_dk == expected_seed_dk);
    println!("seed_ek matches: {}", seed_ek == expected_seed_ek);

    if seed_dk == expected_seed_dk && seed_ek == expected_seed_ek {
        println!("🎉 SUCCESS: Both seeds match KAT exactly!");
    } else {
        println!("❌ FAILURE: Seeds do not match KAT");
        if seed_dk != expected_seed_dk {
            println!("  seed_dk differences:");
            for i in 0..32 {
                if seed_dk[i] != expected_seed_dk[i] {
                    println!(
                        "    Byte {}: got {:02x}, expected {:02x}",
                        i, seed_dk[i], expected_seed_dk[i]
                    );
                }
            }
        }
        if seed_ek != expected_seed_ek {
            println!("  seed_ek differences:");
            for i in 0..32 {
                if seed_ek[i] != expected_seed_ek[i] {
                    println!(
                        "    Byte {}: got {:02x}, expected {:02x}",
                        i, seed_ek[i], expected_seed_ek[i]
                    );
                }
            }
        }
    }
}
