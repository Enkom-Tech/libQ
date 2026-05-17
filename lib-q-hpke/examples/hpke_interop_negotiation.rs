//! Minimal integrator flow: interoperability profile, deterministic suite negotiation,
//! then HPKE single-shot seal/open with raw bytes (post-quantum HPKE only).

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use lib_q_hpke::interop::{
    HpkeCapabilities,
    HpkeInteropProfile,
    negotiate_hpke_capabilities,
};
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    HpkePskWireFormat,
};
use lib_q_kem::LibQKemProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let local = HpkeCapabilities {
        profile: HpkeInteropProfile::RfcStrictPq,
        suite_preferences: vec![suite],
        supported_modes: vec![HpkeMode::Base],
        psk_wire_preferences: vec![HpkePskWireFormat::Rfc9180],
    };
    let remote = local.clone();

    let negotiated = negotiate_hpke_capabilities(&local, &remote)?;
    eprintln!(
        "negotiated: mode={:?} suite=({:?},{:?},{:?}) psk_wire={:?}",
        negotiated.mode,
        negotiated.suite.kem,
        negotiated.suite.kdf,
        negotiated.suite.aead,
        negotiated.psk_wire_format
    );

    let provider = Box::new(LibQKemProvider::new()?);
    let mut hpke = HpkeContext::with_provider(provider);
    hpke.set_cipher_suite(negotiated.suite);

    let mut kem_ctx = KemContext::with_provider(Box::new(LibQKemProvider::new()?));
    let recipient = kem_ctx.generate_keypair(Algorithm::MlKem512, None)?;
    let recipient_pk = KemPublicKey::new(recipient.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient.secret_key().as_bytes().to_vec());

    let info = b"app-binding: transcript-hash-placeholder";
    let aad = b"example-aad";
    let plaintext = b"hello from hpke_interop_negotiation example";

    let (enc_bytes, ciphertext) = hpke.seal(&recipient_pk, info, aad, plaintext)?;
    let opened = hpke.open(&enc_bytes, &recipient_sk, info, aad, &ciphertext)?;
    assert_eq!(opened.as_slice(), plaintext);
    eprintln!("seal/open ok, encapsulated_key_len={}", enc_bytes.len());
    Ok(())
}
