//! Comprehensive AuthPSK mode tests for HPKE implementation
//!
//! B14 interim fix: AuthPSK mode routes through the same `PostQuantumProvider::auth_encapsulate`
//! / `auth_decapsulate` as plain Auth mode (see `hpke_core::setup_sender_with_mode`), which does
//! not soundly bind the sender's static secret key (RFC 9180 Section 5.1.3 AuthEncap/AuthDecap
//! gap) and so is disabled and fails closed. These tests used to validate full AuthPSK round
//! trips (setup, encrypt/decrypt, wrong-PSK / wrong-sender rejection, key export, multiple
//! messages, error handling); they now assert the fail-closed behavior instead. See
//! `lib-q-hpke/tests/auth_encap_validation_tests.rs` for the forgery this replaced.

#![cfg(feature = "std")]
#![allow(unused_variables, unused_mut, clippy::useless_vec)]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::{
    HpkeContext,
    HpkePskWireFormat,
};
use lib_q_kem::LibQKemProvider;

/// Test that AuthPSK mode fails closed (B14) for basic setup — sender and receiver alike.
#[test]
fn test_authpsk_mode_fails_closed_basic() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"shared-secret-key-32-bytes-long";
    let psk_id = b"psk-identifier";

    let sender_ctx_result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        psk,
        psk_id,
        &sender_sk,
        &sender_pk,
    );
    assert!(
        sender_ctx_result.is_err(),
        "AuthPSK mode sender setup must fail closed (B14)"
    );

    // With no valid sender context to build a real encapsulated key from, exercise receiver setup
    // against a well-formed-sized placeholder — it must fail closed too.
    let placeholder_enc = vec![0u8; lib_q_hpke::HpkeKem::MlKem512.enc_len() * 2 + 32];
    let receiver_ctx_result = hpke_ctx.setup_receiver_auth_psk(
        &placeholder_enc,
        &recipient_sk,
        b"test info",
        psk,
        psk_id,
        &sender_pk,
    );
    assert!(
        receiver_ctx_result.is_err(),
        "AuthPSK mode receiver setup must fail closed (B14)"
    );
}

/// AuthPSK mode fails closed (B14) the same way regardless of the PSK / PSK ID used — it never
/// got far enough to validate them.
#[test]
fn test_authpsk_mode_fails_closed_for_different_psk_values() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());

    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let test_cases = vec![
        (b"psk-1".as_slice(), b"id-1".as_slice()),
        (b"different-psk".as_slice(), b"different-id".as_slice()),
        (
            b"very-long-psk-key-that-is-more-than-32-bytes".as_slice(),
            b"long-id".as_slice(),
        ),
    ];

    for (psk, psk_id) in test_cases {
        let result = hpke_ctx.setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        );
        assert!(
            result.is_err(),
            "AuthPSK setup must fail closed (B14) regardless of the PSK/PSK ID used"
        );
    }
}

/// AuthPSK mode fails closed (B14) with `LibQCommitmentSuffix` wire format too — the wire format
/// choice doesn't matter since sender setup never gets past AuthEncap.
#[test]
fn test_authpsk_mode_fails_closed_with_commitment_suffix_wire_format() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    hpke_ctx.set_psk_wire_format(HpkePskWireFormat::LibQCommitmentSuffix);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());

    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"correct-psk";
    let psk_id = b"correct-id";

    let result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        psk,
        psk_id,
        &sender_sk,
        &sender_pk,
    );
    assert!(
        result.is_err(),
        "AuthPSK setup must fail closed (B14) regardless of PSK wire format"
    );
}

/// AuthPSK mode fails closed (B14) for edge-case PSK inputs (empty PSK, empty PSK ID, very long
/// PSK) exactly as it does for a "normal" PSK — there is no successful configuration anymore.
#[test]
fn test_authpsk_mode_fails_closed_for_edge_case_psks() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());

    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let long_psk = vec![0u8; 1000];
    let cases: Vec<(&[u8], &[u8])> = vec![
        (b"", b"psk-id"),
        (b"psk", b""),
        (&long_psk, b"psk-id"),
        (b"valid-psk", b"valid-id"),
    ];

    for (psk, psk_id) in cases {
        let result = hpke_ctx.setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        );
        assert!(
            result.is_err(),
            "AuthPSK setup must fail closed (B14) for every PSK/PSK ID shape, including edge cases"
        );
    }
}
