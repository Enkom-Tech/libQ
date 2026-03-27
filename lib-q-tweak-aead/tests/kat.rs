//! Regression: fixed ciphertext+tag for all-zero key/nonce, empty AD.
use lib_q_tweak_aead::crypto::encrypt;

#[test]
fn kat_encrypt_libq_empty_ad() {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let ad = b"";
    let pt = b"libQ";
    let mut out = [0u8; 4 + 32];
    encrypt(&key, &nonce, ad, pt, &mut out).unwrap();
    assert_eq!(
        out.as_slice(),
        hex::decode("4b77faf686b79b9f0cb22a26a3d2f10882b40b801c15c8801bd8eb7c01d2f13b5e13661a")
            .unwrap()
            .as_slice()
    );
}
