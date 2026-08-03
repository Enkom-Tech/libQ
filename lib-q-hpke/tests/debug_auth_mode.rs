//! Debug test for Auth mode
//!
//! B14 interim fix: this test used to walk through Auth-mode sender/receiver setup step by step,
//! printing intermediate sizes, and asserting the derived keys matched. Auth mode is now disabled
//! (see `PostQuantumProvider::auth_mode_unavailable` and
//! `lib-q-hpke/tests/auth_encap_validation_tests.rs` for why), so there is no successful setup
//! left to walk through. This keeps the debug/diagnostic spirit of the original test — print what
//! happens — while asserting the fail-closed outcome.

#![cfg(feature = "std")]

use std::sync::Arc;

use lib_q_core::{
    Algorithm,
    KemContext,
};
use lib_q_hpke::hpke_core::setup_sender_with_mode;
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::traits::HpkeCryptoProvider;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    HpkePskWireFormat,
};
use lib_q_kem::LibQKemProvider;

/// Debug Auth mode step by step
#[test]
fn debug_auth_mode() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Generate sender key pair for Auth mode
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    println!(
        "Recipient PK size: {}",
        recipient_keypair.public_key().as_bytes().len()
    );
    println!(
        "Recipient SK size: {}",
        recipient_keypair.secret_key().as_bytes().len()
    );
    println!(
        "Sender PK size: {}",
        sender_keypair.public_key().as_bytes().len()
    );
    println!(
        "Sender SK size: {}",
        sender_keypair.secret_key().as_bytes().len()
    );

    // Setup sender context with Auth mode — B14: this now fails closed unconditionally.
    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();
    let sender_result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"test-info",
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    );

    println!("Auth mode sender setup result: {:?}", sender_result.is_ok());
    assert!(
        sender_result.is_err(),
        "Auth mode sender setup must fail closed (B14): sender authentication is not soundly \
         bound to the sender's static secret key"
    );
}
