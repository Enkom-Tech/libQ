#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::hqc_pke::HqcPke;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::params_correct::Hqc1Params;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use rand_core::Rng;

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_drbg_vs_keygen_contradiction() {
    println!("=== DRBG vs Keygen Contradiction Test ===\n");

    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Test 1: Direct DRBG output comparison
    println!("Test 1: Direct DRBG output comparison");
    let mut rust_rng = Aes256CtrDrbg::instantiate(&seed);
    let mut bearssl_rng = BearSslAes256CtrDrbg::instantiate(&seed);

    let mut rust_output = [0u8; 32];
    let mut bearssl_output = [0u8; 32];

    rust_rng.fill_bytes(&mut rust_output);
    bearssl_rng.fill_bytes(&mut bearssl_output);

    println!("Rust DRBG output:    {:02x?}", rust_output);
    println!("BearSSL DRBG output: {:02x?}", bearssl_output);
    println!("DRBG outputs match:  {}", rust_output == bearssl_output);

    // Test 2: Keygen with same seed
    println!("\nTest 2: Keygen with same seed");
    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    let (pk1, sk1) = pke.keygen_with_seed(&seed).unwrap();
    let (pk2, sk2) = pke.keygen_with_seed(&seed).unwrap();

    println!("Public keys match:   {}", pk1.as_bytes() == pk2.as_bytes());
    println!("Secret keys match:   {}", sk1.data == sk2.data);

    // Test 3: Check which DRBG is actually being used
    println!("\nTest 3: Check which DRBG is being used");

    // Force use of Rust DRBG
    #[cfg(feature = "aes-drbg")]
    {
        let (pk_rust, sk_rust) = pke.keygen_with_seed(&seed).unwrap();
        println!("Rust DRBG public key:  {:02x?}", &pk_rust.as_bytes()[..16]);
        println!("Rust DRBG secret key:  {:02x?}", &sk_rust.data[..16]);
    }

    // Force use of BearSSL DRBG
    #[cfg(feature = "bearssl-aes")]
    {
        let (pk_bearssl, sk_bearssl) = pke.keygen_with_seed(&seed).unwrap();
        println!(
            "BearSSL DRBG public key: {:02x?}",
            &pk_bearssl.as_bytes()[..16]
        );
        println!("BearSSL DRBG secret key: {:02x?}", &sk_bearssl.data[..16]);
    }

    println!("\n=== Analysis ===");
    println!("If DRBG outputs differ but keygen outputs match, then:");
    println!("1. The keygen is using the same DRBG implementation both times");
    println!("2. The feature flags are not working as expected");
    println!("3. There's a fallback mechanism in place");
}
