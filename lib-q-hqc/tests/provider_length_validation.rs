//! An over-long secret key or ciphertext must be REJECTED, not silently truncated.
//!
//! `LibQHqcProvider` checked `len() < EXPECTED` at nine sites and then sliced `[..EXPECTED]`,
//! so any input LONGER than the expected size was accepted and the surplus discarded. That is a
//! malleable encoding: two distinct byte strings decode to the same key or ciphertext, and a
//! caller round-tripping bytes gets back something it did not send. Exact-length rejection is
//! the only correct behaviour for a fixed-size wire format.
#![cfg(all(feature = "hqc128", feature = "std"))]

use lib_q_core::api::{
    Algorithm,
    KemOperations,
};
use lib_q_hqc::provider::LibQHqcProvider;

#[test]
fn decapsulate_rejects_an_over_long_secret_key() {
    let provider = LibQHqcProvider::new().expect("provider construction should succeed");
    let keypair = provider
        .generate_keypair(Algorithm::Hqc128, None)
        .expect("keygen should succeed");

    // One trailing byte beyond the exact size. Previously accepted and truncated away.
    let mut too_long = keypair.secret_key().data.clone();
    let exact = too_long.len();
    too_long.push(0x00);

    let sk = lib_q_core::KemSecretKey::new(too_long);
    // Any well-formed ciphertext will do; the length gate must fire before it is used.
    let (ct, _ss) = provider
        .encapsulate(Algorithm::Hqc128, keypair.public_key(), None)
        .expect("encapsulate should succeed");

    let result = provider.decapsulate(Algorithm::Hqc128, &sk, &ct);
    assert!(
        result.is_err(),
        "a secret key one byte longer than {exact} must be rejected, not truncated"
    );
}

#[test]
fn decapsulate_rejects_an_over_long_ciphertext() {
    let provider = LibQHqcProvider::new().expect("provider construction should succeed");
    let keypair = provider
        .generate_keypair(Algorithm::Hqc128, None)
        .expect("keygen should succeed");
    let (ct, _ss) = provider
        .encapsulate(Algorithm::Hqc128, keypair.public_key(), None)
        .expect("encapsulate should succeed");

    let mut too_long = ct.clone();
    let exact = too_long.len();
    too_long.push(0x00);

    let result = provider.decapsulate(Algorithm::Hqc128, keypair.secret_key(), &too_long);
    assert!(
        result.is_err(),
        "a ciphertext one byte longer than {exact} must be rejected, not truncated"
    );
}
