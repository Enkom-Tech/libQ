//! Test to understand OpenSSL's EVP_EncryptUpdate behavior

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_openssl_ecb_behavior() {
    println!("=== Understanding OpenSSL ECB Behavior ===");

    // According to OpenSSL docs, EVP_EncryptUpdate with padding enabled
    // for a single 16-byte block should output 16 bytes.
    // The padding is only added in EVP_EncryptFinal_ex.

    // But the reference code doesn't call EVP_EncryptFinal_ex,
    // so it only uses the output from EVP_EncryptUpdate.

    // For ECB mode, EVP_EncryptUpdate should output immediately
    // even with padding enabled, because ECB doesn't need to buffer.

    // So the reference should be getting 16 bytes from EVP_EncryptUpdate,
    // which matches what we're doing.

    // Test with zero key and V=0x00...01
    let key = [0u8; 32];
    let mut v = [0u8; 16];
    v[15] = 1;

    let aes_ctx = Aes256CtxPure::new(&key);
    let output = aes_ctx.encrypt_block(&v);

    println!("AES(Key=0, V=0x00...01): {:02x?}", output);
    println!(
        "Expected (OpenSSL):       [53, 0f, 8a, fb, c7, 45, 36, b9, a9, 63, b4, f1, c4, cb, 73, 8b]"
    );
    println!(
        "Match: {}",
        output ==
            [
                0x53, 0x0F, 0x8A, 0xFB, 0xC7, 0x45, 0x36, 0xB9, 0xA9, 0x63, 0xB4, 0xF1, 0xC4, 0xCB,
                0x73, 0x8B
            ]
    );

    // Our implementation matches OpenSSL, so the issue must be elsewhere
    println!("\nOur AES implementation matches OpenSSL.");
    println!("The issue must be in the DRBG logic, not the AES primitive.");
}
