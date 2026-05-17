//! Debug test for Auth mode

#![cfg(feature = "std")]

use std::sync::Arc;

use lib_q_core::{
    Algorithm,
    KemContext,
};
use lib_q_hpke::hpke_core::{
    setup_receiver_with_mode,
    setup_sender_with_mode,
};
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

    // Setup sender context with Auth mode
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let sender_ctx = setup_sender_with_mode(
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
    )
    .expect("Auth mode sender setup should work");

    println!(
        "Sender encapsulated key size: {}",
        sender_ctx.encapsulated_key.len()
    );
    println!(
        "Sender shared secret size: {}",
        sender_ctx.shared_secret.len()
    );
    println!("Sender key size: {}", sender_ctx.key.len());
    println!("Sender nonce size: {}", sender_ctx.nonce.len());

    // Setup receiver context with Auth mode
    let receiver_ctx = setup_receiver_with_mode(
        &mut kem_ctx,
        &sender_ctx.encapsulated_key,
        recipient_keypair.secret_key(),
        b"test-info",
        &cipher_suite,
        hpke_crypto.as_ref(),
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    )
    .expect("Auth mode receiver setup should work");

    println!(
        "Receiver shared secret size: {}",
        receiver_ctx.shared_secret.len()
    );
    println!("Receiver key size: {}", receiver_ctx.key.len());
    println!("Receiver nonce size: {}", receiver_ctx.nonce.len());

    // Check if keys match
    println!("Keys match: {}", sender_ctx.key == receiver_ctx.key);
    println!("Nonces match: {}", sender_ctx.nonce == receiver_ctx.nonce);
    println!(
        "Shared secrets match: {}",
        sender_ctx.shared_secret == receiver_ctx.shared_secret
    );

    if sender_ctx.key != receiver_ctx.key {
        println!("Sender key: {:?}", &sender_ctx.key[..8]);
        println!("Receiver key: {:?}", &receiver_ctx.key[..8]);
    }

    if sender_ctx.shared_secret != receiver_ctx.shared_secret {
        println!("Sender shared secret: {:?}", &sender_ctx.shared_secret[..8]);
        println!(
            "Receiver shared secret: {:?}",
            &receiver_ctx.shared_secret[..8]
        );
    }

    // This should pass if Auth mode is working correctly
    assert_eq!(sender_ctx.key, receiver_ctx.key);
    assert_eq!(sender_ctx.nonce, receiver_ctx.nonce);
    assert_eq!(sender_ctx.shared_secret, receiver_ctx.shared_secret);
}
