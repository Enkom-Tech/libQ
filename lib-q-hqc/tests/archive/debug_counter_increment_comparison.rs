#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;

#[cfg(feature = "aes-drbg")]
#[test]
fn test_rust_counter_increment() {
    let mut v = [0u8; 16];
    println!("Initial: {:02x?}", v);

    // Test increment from 0
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);

    // Test increment from 0xFF
    v[15] = 0xFF;
    println!("Set to 0xFF: {:02x?}", v);
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);

    // Test increment from 0xFFFF (two bytes)
    v[14] = 0xFF;
    v[15] = 0xFF;
    println!("Set to 0xFFFF: {:02x?}", v);
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_bearssl_counter_increment() {
    let mut v = [0u8; 16];
    println!("Initial: {:02x?}", v);

    // Test increment from 0
    BearSslAes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);

    // Test increment from 0xFF
    v[15] = 0xFF;
    println!("Set to 0xFF: {:02x?}", v);
    BearSslAes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);

    // Test increment from 0xFFFF (two bytes)
    v[14] = 0xFF;
    v[15] = 0xFF;
    println!("Set to 0xFFFF: {:02x?}", v);
    BearSslAes256CtrDrbg::increment_counter(&mut v);
    println!("After increment: {:02x?}", v);
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_counter_increment_comparison() {
    println!("=== Counter Increment Comparison ===");

    // Test 1: Increment from 0
    let mut v1 = [0u8; 16];
    let mut v2 = [0u8; 16];

    Aes256CtrDrbg::increment_counter(&mut v1);
    BearSslAes256CtrDrbg::increment_counter(&mut v2);

    println!("Rust increment from 0: {:02x?}", v1);
    println!("BearSSL increment from 0: {:02x?}", v2);
    println!("Match: {}", v1 == v2);

    // Test 2: Increment from 0xFF
    v1[15] = 0xFF;
    v2[15] = 0xFF;

    Aes256CtrDrbg::increment_counter(&mut v1);
    BearSslAes256CtrDrbg::increment_counter(&mut v2);

    println!("Rust increment from 0xFF: {:02x?}", v1);
    println!("BearSSL increment from 0xFF: {:02x?}", v2);
    println!("Match: {}", v1 == v2);

    // Test 3: Increment from 0xFFFF
    v1[14] = 0xFF;
    v1[15] = 0xFF;
    v2[14] = 0xFF;
    v2[15] = 0xFF;

    Aes256CtrDrbg::increment_counter(&mut v1);
    BearSslAes256CtrDrbg::increment_counter(&mut v2);

    println!("Rust increment from 0xFFFF: {:02x?}", v1);
    println!("BearSSL increment from 0xFFFF: {:02x?}", v2);
    println!("Match: {}", v1 == v2);
}
