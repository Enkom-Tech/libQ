use lib_q_core::{
    Aead,
    AeadKey,
    Nonce,
};
use lib_q_duplex_aead::DuplexSpongeAead;

#[test]
fn roundtrip_empty_ad() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0xA5u8; 32]);
    let nonce = Nonce::new(vec![0x3Cu8; 16]);
    let pt = b"hello duplex sponge aead";
    let ct = aead.encrypt(&key, &nonce, pt, None).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn roundtrip_with_ad() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![1u8; 32]);
    let nonce = Nonce::new(vec![2u8; 16]);
    let ad = b"associated data";
    let pt = vec![0u8; 200];
    let ct = aead.encrypt(&key, &nonce, &pt, Some(ad)).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, Some(ad)).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn roundtrip_full_rate_boundary() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![9u8; 32]);
    let nonce = Nonce::new(vec![8u8; 16]);
    let pt = vec![0xEEu8; 136];
    let ct = aead.encrypt(&key, &nonce, &pt, None).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn tamper_fails() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![5u8; 32]);
    let nonce = Nonce::new(vec![6u8; 16]);
    let mut ct = aead.encrypt(&key, &nonce, b"x", None).unwrap();
    ct[0] ^= 1;
    assert!(aead.decrypt(&key, &nonce, &ct, None).is_err());
}
