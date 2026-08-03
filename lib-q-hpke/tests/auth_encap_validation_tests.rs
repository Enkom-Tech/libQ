//! Comprehensive tests for AuthEncap/AuthDecap implementation validation
//!
//! These tests validate that the authentication implementation provides proper
//! cryptographic authentication guarantees as required by RFC 9180.

#![cfg(feature = "std")]
#![allow(unused_imports, unused_variables)]

use lib_q_core::{
    Algorithm,
    Kem,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hash::Sha3_256;
use lib_q_hash::digest::Digest;
use lib_q_hpke::HpkeKem;
use lib_q_hpke::providers::KemProvider;
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::security::test_rng::TestRng;
use lib_q_kem::LibQKemProvider;

/// RED-FIRST (B14): HPKE Auth mode authenticates nothing.
///
/// `PostQuantumProvider::create_auth_tag` (the internal function backing `auth_decapsulate`'s
/// verification) hashes only public values: `shared_secret || sender_pk || encapsulated_key`. It
/// never touches any sender secret key. So anyone who can encapsulate to the recipient's public
/// key (which is, by definition, public) can compute that same shared secret themselves, forge a
/// tag for an arbitrary claimed sender identity, and have `auth_decapsulate` accept it.
///
/// This test plays exactly that attacker: it performs ordinary (non-authenticated) KEM
/// encapsulation to the recipient — no sender secret key is used or even generated for the real
/// sender side — then reproduces the tag scheme externally (SHA3-256 is public knowledge; no
/// library internals are needed) for a claimed sender identity of the attacker's choosing, and
/// checks whether `auth_decapsulate` accepts the forgery.
///
/// Before the interim fail-closed fix, it did. After the fix, `auth_decapsulate` (and
/// `auth_encapsulate`) return an explicit error unconditionally, so the forged tag — like every
/// other input — is rejected.
#[test]
fn auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // The "forged" identity: some keypair whose PUBLIC key the attacker claims as the sender.
    // Crucially, the corresponding secret key is never generated for the attacker's use here —
    // only its public key bytes are needed to mount the forgery.
    let forged_sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Forged identity key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Attacker: ordinary (non-auth) KEM encapsulation to the recipient's public key. This uses no
    // sender secret key at all — it's exactly what anyone who knows the recipient's public key can
    // do.
    let (encapsulated_key, shared_secret) = hpke_provider
        .encapsulate(
            HpkeKem::MlKem512,
            recipient_keypair.public_key().as_bytes(),
            &mut TestRng::default(),
        )
        .expect("Plain (non-auth) encapsulation should succeed");

    // Forge the auth tag exactly the way the (broken) scheme computes it:
    // SHA3-256(shared_secret || claimed_sender_pk || encapsulated_key). Every input here is
    // public / attacker-known; no sender secret key appears anywhere in this computation.
    let mut forged_input = Vec::new();
    forged_input.extend_from_slice(shared_secret.as_slice());
    forged_input.extend_from_slice(forged_sender_keypair.public_key().as_bytes());
    forged_input.extend_from_slice(&encapsulated_key);
    let forged_tag = Sha3_256::digest(&forged_input);

    let mut forged_authenticated_encapsulated_key = encapsulated_key;
    forged_authenticated_encapsulated_key.extend_from_slice(&forged_tag);

    let result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &forged_authenticated_encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        forged_sender_keypair.public_key().as_bytes(),
    );

    assert!(
        result.is_err(),
        "auth_decapsulate accepted a forged sender identity backed by NO sender secret key \
         anywhere (B14) — Auth mode must fail closed until AuthEncap/AuthDecap are redesigned to \
         bind the sender's static secret key per RFC 9180 Section 5.1.3"
    );
}

/// B14 interim fix: `auth_encapsulate`/`auth_decapsulate` fail closed unconditionally, for valid
/// keys as much as for invalid ones — there is currently no sound way to authenticate a sender in
/// this scheme (see `auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key`
/// above), so it must not pretend to succeed just because the caller supplied well-formed keys.
/// This replaces the pre-fix `test_auth_encap_auth_decap_authentication`, which asserted the
/// round trip succeeded.
#[test]
fn test_auth_encap_auth_decap_fails_closed_for_valid_keys() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    let auth_encap_result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        sender_keypair.secret_key().as_bytes(),
        recipient_keypair.public_key().as_bytes(),
        &mut TestRng::default(),
    );

    assert!(
        auth_encap_result.is_err(),
        "Auth mode must fail closed (B14) even for entirely valid, well-formed keys"
    );

    // AuthDecap likewise fails closed unconditionally; there is no valid authenticated
    // encapsulated key to construct via AuthEncap to test a "correct" round trip against.
    let placeholder_encapsulated_key = vec![0u8; HpkeKem::MlKem512.enc_len() + 32];
    let auth_decap_result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &placeholder_encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        sender_keypair.public_key().as_bytes(),
    );
    assert!(
        auth_decap_result.is_err(),
        "Auth mode must fail closed (B14) even for well-formed input sizes"
    );
}

/// B14 interim fix: with `auth_encapsulate` itself now failing closed, there is no longer a
/// "wrong sender public key at AuthDecap" scenario to distinguish from a correct one — every
/// AuthDecap call fails the same way. This replaces the pre-fix
/// `test_auth_decap_fails_with_wrong_sender`, whose premise (a successful AuthEncap to build a
/// real authenticated encapsulated key from) no longer holds.
#[test]
fn test_auth_encap_fails_closed_so_wrong_sender_scenario_is_moot() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    let auth_encap_result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        sender_keypair.secret_key().as_bytes(),
        recipient_keypair.public_key().as_bytes(),
        &mut TestRng::default(),
    );

    assert!(
        auth_encap_result.is_err(),
        "AuthEncap should fail closed (B14), leaving no valid encapsulated key to attack a \
         wrong-sender AuthDecap scenario against"
    );
}

/// Test that AuthEncap/AuthDecap fail closed (B14) for every supported ML-KEM variant, not just
/// ML-KEM-512 — the interim fix must not be size- or algorithm-specific.
#[test]
fn test_auth_encap_auth_decap_fail_closed_for_all_ml_kem_variants() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let hpke_provider = PostQuantumProvider::new();

    for (kem, algorithm) in [
        (HpkeKem::MlKem768, Algorithm::MlKem768),
        (HpkeKem::MlKem1024, Algorithm::MlKem1024),
    ] {
        let sender_keypair = kem_ctx
            .generate_keypair(algorithm, None)
            .expect("Sender key generation should work");

        let recipient_keypair = kem_ctx
            .generate_keypair(algorithm, None)
            .expect("Recipient key generation should work");

        let auth_encap_result = hpke_provider.auth_encapsulate(
            kem,
            sender_keypair.secret_key().as_bytes(),
            recipient_keypair.public_key().as_bytes(),
            &mut TestRng::default(),
        );
        assert!(
            auth_encap_result.is_err(),
            "AuthEncap should fail closed (B14) for {kem:?}"
        );

        let placeholder_encapsulated_key = vec![0u8; kem.enc_len() + 32];
        let auth_decap_result = hpke_provider.auth_decapsulate(
            kem,
            &placeholder_encapsulated_key,
            recipient_keypair.secret_key().as_bytes(),
            sender_keypair.public_key().as_bytes(),
        );
        assert!(
            auth_decap_result.is_err(),
            "AuthDecap should fail closed (B14) for {kem:?}"
        );
    }
}

/// Test that derive_public_key works correctly
#[test]
fn test_derive_public_key() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate a key pair
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Test that we can derive the public key from the secret key
    // This is used internally by auth_encapsulate
    let kem_impl = lib_q_kem::ml_kem::MlKem512Impl::default();

    let derived_public_key = kem_impl
        .derive_public_key(&lib_q_core::KemSecretKey::new(
            keypair.secret_key().as_bytes().to_vec(),
        ))
        .expect("Should be able to derive public key");

    // The derived public key should match the original public key
    assert_eq!(
        derived_public_key.data,
        keypair.public_key().as_bytes(),
        "Derived public key should match original public key"
    );
}

/// Pre-fix, this test's premise was that AuthEncap provides "cryptographic proof of sender
/// identity" by comparing it against plain (non-authenticated) encapsulation. That premise was
/// false (B14: the "proof" never touched a sender secret key — see
/// `auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key`). Now that Auth
/// mode fails closed, the meaningful thing to assert is that it fails closed identically whether
/// or not a real KEM operation to the same recipient would have succeeded.
#[test]
fn test_auth_mode_provides_no_proof_and_fails_closed_instead() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Plain (non-authenticated) encapsulation to the same recipient succeeds — the KEM itself is
    // fine; only the "Auth" layer is disabled.
    let kem_impl = lib_q_kem::ml_kem::MlKem512Impl::default();
    let standard_result = kem_impl.encapsulate(&lib_q_core::KemPublicKey::new(
        recipient_keypair.public_key().as_bytes().to_vec(),
    ));
    assert!(
        standard_result.is_ok(),
        "Plain (non-auth) encapsulation to the same recipient should still work"
    );

    // AuthEncap to the identical recipient, with a perfectly valid sender keypair, fails closed.
    let auth_encap_result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        sender_keypair.secret_key().as_bytes(),
        recipient_keypair.public_key().as_bytes(),
        &mut TestRng::default(),
    );
    assert!(
        auth_encap_result.is_err(),
        "AuthEncap must fail closed (B14) even though the underlying KEM operation is healthy"
    );
}
