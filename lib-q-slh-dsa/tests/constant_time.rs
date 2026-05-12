// Copyright 2025 Enkom Tech
// Copyright 2025 Nexlab-One
// SPDX-License-Identifier: Apache-2.0

//! Constant-time and comparison-hardening smoke tests for SLH-DSA.
//!
//! These checks mirror other lib-Q crates: exercise `lib_q_core::Utils::constant_time_compare`
//! and ensure verification rejects altered signatures. They do not replace dedicated
//! timing analysis or `dudect`-style measurement.
#![cfg(not(target_arch = "wasm32"))]

use lib_q_core::Utils;
use lib_q_slh_dsa::{
    Shake128f,
    Signature,
    SigningKey,
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use signature::{
    Keypair,
    RandomizedSigner,
    Verifier,
};

#[inline]
fn test_rng_from_material(seed: &[u8]) -> ChaCha8Rng {
    let mut expanded = [0u8; 32];
    let take = seed.len().min(32);
    expanded[..take].copy_from_slice(&seed[..take]);
    ChaCha8Rng::from_seed(expanded)
}

#[test]
fn test_utils_constant_time_compare() {
    let a = [1u8; 32];
    let b = [1u8; 32];
    assert!(Utils::constant_time_compare(&a, &b));

    let mut c = [1u8; 32];
    c[0] = 0;
    assert!(!Utils::constant_time_compare(&a, &c));

    let short = [1u8; 31];
    assert!(!Utils::constant_time_compare(&a, &short));
    assert!(!Utils::constant_time_compare(&short, &a));
}

#[test]
fn test_verify_rejects_bit_flipped_signature() {
    let mut key_randomness = [0u8; 32];
    for (i, b) in key_randomness.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = test_rng_from_material(&key_randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let message = b"constant-time validation message";
    let mut signing_randomness = [0u8; 16];
    for (i, b) in signing_randomness.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_rng = test_rng_from_material(&signing_randomness);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("sign");

    assert!(verifying_key.verify(message, &signature).is_ok());

    let mut raw = signature.to_bytes().to_vec();
    let flip_at = raw.len() / 2;
    raw[flip_at] ^= 0xFF;
    let tampered = Signature::<Shake128f>::try_from(raw.as_slice()).expect("same-length sig");
    assert!(
        verifying_key.verify(message, &tampered).is_err(),
        "verification must reject a modified signature"
    );
}
