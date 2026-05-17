//! Regression: fixed ciphertext+tag for an all-zero key/nonce and empty AD.
use lib_q_duplex_aead::crypto::encrypt;

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
        hex::decode("f29a81ccfe8256130e71ca5f315903d2f7bb918a88fd14525a9224c2ce16a6f5f19fb8d1")
            .unwrap()
            .as_slice()
    );
}
