//! Debug AES with zero key to verify our AES implementation

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_aes_zero_key() {
    println!("=== Testing AES with zero key ===");

    // Test with all-zero key and various V values
    let key = [0u8; 32];

    // V = 0x00...01 (after first increment from all zeros)
    let mut v1 = [0u8; 16];
    v1[15] = 1;

    let aes_ctx = Aes256CtxPure::new(&key);
    let output1 = aes_ctx.encrypt_block(&v1);
    println!("AES(Key=0, V=0x00...01): {:02x?}", output1);

    // Expected from NIST: AES-256 with all-zero key and input 0x00...01
    // This should match what OpenSSL produces
    let expected_openssl = [
        0x53, 0x0F, 0x8A, 0xFB, 0xC7, 0x45, 0x36, 0xB9, 0xA9, 0x63, 0xB4, 0xF1, 0xC4, 0xCB, 0x73,
        0x8B,
    ];
    println!("Expected (OpenSSL):     {:02x?}", expected_openssl);
    println!("Match: {}", output1 == expected_openssl);

    // V = 0x00...02
    let mut v2 = [0u8; 16];
    v2[15] = 2;
    let output2 = aes_ctx.encrypt_block(&v2);
    println!("AES(Key=0, V=0x00...02): {:02x?}", output2);

    // V = 0x00...03
    let mut v3 = [0u8; 16];
    v3[15] = 3;
    let output3 = aes_ctx.encrypt_block(&v3);
    println!("AES(Key=0, V=0x00...03): {:02x?}", output3);
}
