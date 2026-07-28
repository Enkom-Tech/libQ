//! Randomized round-trip property tests for HPKE.
//!
//! These replace `tests/fuzzing/security_fuzzing_tests.rs`, which was never a cargo test target
//! (a `tests/<dir>/` with no `main.rs` is not auto-discovered) and had rotted against an
//! `create_auth_proof`/`verify_auth_proof` provider API that no longer exists.
//!
//! Only the tests that add coverage over the deterministic suites survive here. The dropped
//! ones were superseded by `security_validation_comprehensive_tests.rs`:
//! `test_comprehensive_input_validation` already covers key/nonce/AEAD/zero-key rejection at the
//! exact `len ± 1` boundaries, and `test_sequence_number_overflow_protection` already covers the
//! `NeedsRekey` transition.
//!
//! What is genuinely additive is *randomized length coverage of the round trip*: the old versions
//! treated any `Err` as an acceptable outcome, which made them close to vacuous, so the tests
//! below assert that a successful seal must decrypt back to the original plaintext.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::providers::AeadProvider;
use lib_q_hpke::security::prng::{
    CryptoRng,
    Kt128Rng,
};
use lib_q_hpke::{
    HpkeAead,
    HpkeContext,
};
use lib_q_kem::LibQKemProvider;

fn random_bytes(rng: &mut Kt128Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v).unwrap();
    v
}

/// `random_bytes` with a randomly drawn length in `min..min + span`.
fn random_sized_bytes(rng: &mut Kt128Rng, min: usize, span: u32) -> Vec<u8> {
    let len = min + (rng.next_u32().unwrap() % span) as usize;
    random_bytes(rng, len)
}

fn keypair() -> (KemPublicKey, KemSecretKey) {
    let mut kem_ctx =
        KemContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));
    let kp = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("keypair");
    (
        KemPublicKey::new(kp.public_key().as_bytes().to_vec()),
        KemSecretKey::new(kp.secret_key().as_bytes().to_vec()),
    )
}

/// A sender context must stay usable across many sequential `seal` calls with randomly sized
/// AAD and plaintext, and a receiver set up from the same encapsulation must decrypt each one
/// in order.
#[test]
fn randomized_context_seal_open_sequence() {
    let mut rng = Kt128Rng::from_seed(&[7u8; 32]);

    for round in 0..8 {
        let (recipient_pk, recipient_sk) = keypair();
        let mut hpke_ctx =
            HpkeContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));

        let info = random_sized_bytes(&mut rng, 0, 1024);

        let mut sender_ctx = hpke_ctx
            .setup_sender(&recipient_pk, &info)
            .unwrap_or_else(|e| panic!("round {round}: setup_sender failed: {e}"));
        let mut receiver_ctx = hpke_ctx
            .setup_receiver(sender_ctx.encapsulated_key(), &recipient_sk, &info)
            .unwrap_or_else(|e| panic!("round {round}: setup_receiver failed: {e}"));

        // AEAD sequence numbers advance in lockstep, so the messages must be opened in the
        // same order they were sealed.
        for i in 0..10 {
            let message = random_sized_bytes(&mut rng, 0, 1024);
            let aad = random_sized_bytes(&mut rng, 0, 512);

            let ciphertext = sender_ctx
                .seal(&aad, &message)
                .unwrap_or_else(|e| panic!("round {round} msg {i}: seal failed: {e}"));
            let decrypted = receiver_ctx
                .open(&aad, &ciphertext)
                .unwrap_or_else(|e| panic!("round {round} msg {i}: open failed: {e}"));

            assert_eq!(
                decrypted, message,
                "round {round} msg {i}: round trip must preserve the plaintext"
            );
        }
    }
}

/// Single-shot `seal`/`open` must round-trip for large randomly sized messages, AAD, and info.
#[test]
fn randomized_single_shot_large_inputs() {
    let mut rng = Kt128Rng::from_seed(&[8u8; 32]);

    for round in 0..8 {
        let (recipient_pk, recipient_sk) = keypair();
        let mut hpke_ctx =
            HpkeContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));

        let message = random_sized_bytes(&mut rng, 1024, 65536 - 1024);
        let msg_len = message.len();
        let aad = random_bytes(&mut rng, 1024);
        let info = random_bytes(&mut rng, 1024);

        let (encapsulated_key, ciphertext) = hpke_ctx
            .seal(&recipient_pk, &info, &aad, &message)
            .unwrap_or_else(|e| panic!("round {round}: seal failed for {msg_len} bytes: {e}"));

        let decrypted = hpke_ctx
            .open(&encapsulated_key, &recipient_sk, &info, &aad, &ciphertext)
            .unwrap_or_else(|e| panic!("round {round}: open failed for {msg_len} bytes: {e}"));

        assert_eq!(
            decrypted, message,
            "round {round}: {msg_len}-byte round trip must preserve the plaintext"
        );
    }
}

/// A ciphertext opened under different AAD than it was sealed with must be rejected.
#[test]
fn randomized_aad_mismatch_is_rejected() {
    let mut rng = Kt128Rng::from_seed(&[9u8; 32]);

    for round in 0..8 {
        let (recipient_pk, recipient_sk) = keypair();
        let mut hpke_ctx =
            HpkeContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));

        let info = random_bytes(&mut rng, 64);
        let message = random_sized_bytes(&mut rng, 1, 512);
        let aad = random_sized_bytes(&mut rng, 1, 128);

        let (encapsulated_key, ciphertext) = hpke_ctx
            .seal(&recipient_pk, &info, &aad, &message)
            .unwrap_or_else(|e| panic!("round {round}: seal failed: {e}"));

        let mut wrong_aad = aad.clone();
        wrong_aad[0] ^= 1;

        let result = hpke_ctx.open(
            &encapsulated_key,
            &recipient_sk,
            &info,
            &wrong_aad,
            &ciphertext,
        );
        assert!(
            result.is_err(),
            "round {round}: opening under mismatched AAD must fail"
        );
    }
}

/// A ciphertext shorter than the AEAD tag carries no authenticated data and must be rejected
/// rather than under-read.
///
/// This is the one property from the deleted `fuzz_ciphertext_length_validation` that had no
/// surviving equivalent anywhere in the crate's tests.
#[test]
fn undersized_ciphertext_is_rejected() {
    let aead = HpkeAead::Saturnin256;
    let provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();
    let key = vec![1u8; aead.key_len()];
    let nonce = vec![0u8; aead.nonce_len()];

    // Anything shorter than the tag cannot be a well-formed ciphertext.
    for len in [0usize, 1, 7, 15, 16, 31] {
        if len >= aead.tag_len() {
            continue;
        }
        let short_ciphertext = vec![0xAAu8; len];
        assert!(
            provider
                .open(aead, &key, &nonce, b"", &short_ciphertext)
                .is_err(),
            "a {len}-byte ciphertext is shorter than the {}-byte tag and must be rejected",
            aead.tag_len()
        );
    }
}

/// A truncated ciphertext must fail to open at the context level too.
#[test]
fn truncated_ciphertext_is_rejected() {
    let (recipient_pk, recipient_sk) = keypair();
    let mut hpke_ctx =
        HpkeContext::with_provider(Box::new(LibQKemProvider::new().expect("KEM provider")));

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(
            &recipient_pk,
            b"info",
            b"aad",
            b"a message worth truncating",
        )
        .expect("seal");

    for cut in [1usize, 4, 16] {
        if cut >= ciphertext.len() {
            continue;
        }
        let truncated = &ciphertext[..ciphertext.len() - cut];
        assert!(
            hpke_ctx
                .open(&encapsulated_key, &recipient_sk, b"info", b"aad", truncated)
                .is_err(),
            "a ciphertext truncated by {cut} bytes must not open"
        );
    }
}
