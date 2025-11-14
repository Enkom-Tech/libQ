use lib_q_hqc::Hqc1Params;
use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use rand_core::RngCore;

#[test]
fn test_pke_roundtrip_basic() {
    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    // Test with a simple message (u64 array)
    let message = vec![0x0102030405060708u64, 0x090A0B0C0D0E0F10u64];

    // Generate keypair with SHAKE256 PRNG
    let mut entropy_input = [0u8; 48];
    entropy_input[0] = 0x42; // Simple entropy for testing
    let mut rng = create_shake256_prng_rng(entropy_input);
    let (pk, sk) = pke.keygen(&mut rng).unwrap();

    // Generate random theta
    let mut theta = [0u8; 32];
    rng.fill_bytes(&mut theta);

    // Encrypt
    let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();

    // Decrypt
    let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();

    println!("Original message: {:02x?}", message);
    println!("Decrypted message: {:02x?}", decrypted);

    assert_eq!(message, decrypted, "PKE roundtrip failed");
    println!("✓ PKE roundtrip successful!");
}

#[test]
fn test_multiple_pke_roundtrips() {
    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    let mut success_count = 0;
    let total_tests = 10;

    for i in 0..total_tests {
        let message = vec![i as u64; 2];

        // Generate different entropy for each test
        let mut entropy_input = [0u8; 48];
        entropy_input[0] = i as u8;
        let mut rng = create_shake256_prng_rng(entropy_input);

        let (pk, sk) = pke.keygen(&mut rng).unwrap();

        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();

        if message == decrypted {
            success_count += 1;
        } else {
            println!(
                "Failed at iteration {}: expected {:02x?}, got {:02x?}",
                i, message, decrypted
            );
        }
    }

    println!(
        "PKE success rate: {}/{} ({:.1}%)",
        success_count,
        total_tests,
        (success_count as f64 / total_tests as f64) * 100.0
    );

    if success_count == total_tests {
        println!("✓ All PKE roundtrips successful!");
    } else {
        println!("✗ Some PKE roundtrips failed");
    }

    // We expect 100% success rate after the fix
    assert_eq!(
        success_count, total_tests,
        "PKE should have 100% success rate"
    );
}
