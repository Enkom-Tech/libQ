//! Duplex-sponge AEAD integration with HPKE (`duplex-sponge-aead` feature).

#![cfg(all(feature = "std", feature = "duplex-sponge-aead"))]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::traits::AeadProvider;
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
};
use lib_q_kem::LibQKemProvider;

fn key32() -> [u8; 32] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
}

fn nonce16() -> [u8; 16] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(7))
}

#[test]
fn duplex_sponge_provider_seal_open_roundtrip() {
    let provider = PostQuantumProvider::new();
    let key = key32();
    let nonce = nonce16();
    let aad = b"hpke_duplex_aad";
    let pt = b"hello duplex hpke";

    let ct = provider
        .seal(HpkeAead::DuplexSpongeAead, &key, &nonce, aad, pt)
        .expect("duplex seal");
    assert!(ct.len() >= pt.len() + HpkeAead::DuplexSpongeAead.tag_len());

    let out = provider
        .open(HpkeAead::DuplexSpongeAead, &key, &nonce, aad, &ct)
        .expect("duplex open");
    assert_eq!(out.as_slice(), pt);
}

#[test]
fn duplex_sponge_hpke_single_shot_roundtrip() {
    let kem_provider = Box::new(LibQKemProvider::new().expect("KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(kem_provider);
    hpke_ctx.set_cipher_suite(HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::DuplexSpongeAead,
    ));

    let mut kem_ctx =
        KemContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("keygen");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let info = b"duplex-hpke-test";
    let aad = b"aad";
    let plaintext = b"single-shot duplex";

    let (encap, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, plaintext)
        .expect("hpke seal");

    let opened = hpke_ctx
        .open(&encap, &recipient_sk, info, aad, &ciphertext)
        .expect("hpke open");

    assert_eq!(opened.as_slice(), plaintext);
}

#[test]
fn duplex_sponge_hpke_streaming_roundtrip() {
    let kem_provider = Box::new(LibQKemProvider::new().expect("KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(kem_provider);
    hpke_ctx.set_cipher_suite(HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::DuplexSpongeAead,
    ));

    let mut kem_ctx =
        KemContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("keygen");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let info = b"duplex-stream";
    let mut sender = hpke_ctx
        .setup_sender(&recipient_pk, info)
        .expect("setup sender");
    let ct0 = sender.seal(b"a", b"m0").expect("seal 0");
    let ct1 = sender.seal(b"b", b"m1").expect("seal 1");

    let mut receiver = hpke_ctx
        .setup_receiver(sender.encapsulated_key(), &recipient_sk, info)
        .expect("setup receiver");
    assert_eq!(receiver.open(b"a", &ct0).expect("open 0"), b"m0");
    assert_eq!(receiver.open(b"b", &ct1).expect("open 1"), b"m1");
}
