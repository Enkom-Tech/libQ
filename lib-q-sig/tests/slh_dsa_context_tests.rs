//! FIPS-205 signing-context KATs for the SLH-DSA wrapper.
//!
//! The negative cases are the point. A `*_with_context` entry point that accepts a `context`
//! argument and then drops it on the floor would pass every positive assertion in this file —
//! only `wrong_context_is_rejected` and the cross-verification tests can catch that.

#![cfg(all(feature = "slh-dsa", feature = "alloc"))]

use lib_q_core::Algorithm;
use lib_q_sig::slh_dsa::{
    SLH_DSA_CONTEXT_MAX_LEN,
    SlhDsa,
};

/// Cheapest parameter set; the context is threaded identically for all six.
const ALG: Algorithm = Algorithm::SlhDsaShake256128fRobust;
const KEY_RANDOMNESS: [u8; 48] = [0x11u8; 48];
const SIGN_RANDOMNESS: [u8; 32] = [0x22u8; 32];
const MESSAGE: &[u8] = b"slh-dsa context KAT message";
const CONTEXT: &[u8] = b"wapp.sh/entitlement-v0";

fn keypair(slh_dsa: &SlhDsa) -> lib_q_core::SigKeypair {
    slh_dsa
        .generate_keypair_with_randomness(ALG, &KEY_RANDOMNESS)
        .expect("keypair generation")
}

/// An empty context must reproduce the context-free path *byte for byte*.
///
/// This is the wire-compatibility guarantee: the pre-existing entry points already signed under
/// an empty FIPS-205 context, so signatures produced before this change stay valid.
#[test]
fn empty_context_matches_the_context_free_path() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);

    let legacy = slh_dsa
        .sign_for_algorithm(ALG, kp.secret_key(), MESSAGE, Some(&SIGN_RANDOMNESS))
        .expect("legacy sign");
    let empty_ctx = slh_dsa
        .sign_for_algorithm_with_context(ALG, kp.secret_key(), MESSAGE, &[], Some(&SIGN_RANDOMNESS))
        .expect("empty-context sign");

    assert_eq!(
        legacy, empty_ctx,
        "an empty context must not change the signature bytes"
    );
}

#[test]
fn round_trip_under_a_context() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);

    let signature = slh_dsa
        .sign_for_algorithm_with_context(
            ALG,
            kp.secret_key(),
            MESSAGE,
            CONTEXT,
            Some(&SIGN_RANDOMNESS),
        )
        .expect("sign under context");

    assert!(
        slh_dsa
            .verify_for_algorithm_with_context(ALG, kp.public_key(), MESSAGE, CONTEXT, &signature)
            .expect("verify must reach a verdict"),
        "a signature must verify under the context it was produced with"
    );
}

/// The discriminating test: a binding that ignores `context` would fail here and nowhere else.
#[test]
fn wrong_context_is_rejected() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);

    let signature = slh_dsa
        .sign_for_algorithm_with_context(
            ALG,
            kp.secret_key(),
            MESSAGE,
            CONTEXT,
            Some(&SIGN_RANDOMNESS),
        )
        .expect("sign under context");

    assert!(
        !slh_dsa
            .verify_for_algorithm_with_context(
                ALG,
                kp.public_key(),
                MESSAGE,
                b"wapp.sh/index-entry-v0",
                &signature
            )
            .expect("verify must reach a verdict"),
        "a signature must not verify under a different context"
    );
}

/// A context-bound signature must not verify through the context-free entry point, and a
/// context-free signature must not verify under a non-empty context.
#[test]
fn context_and_context_free_signatures_do_not_cross_verify() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);

    let ctx_sig = slh_dsa
        .sign_for_algorithm_with_context(
            ALG,
            kp.secret_key(),
            MESSAGE,
            CONTEXT,
            Some(&SIGN_RANDOMNESS),
        )
        .expect("sign under context");
    assert!(
        !slh_dsa
            .verify_for_algorithm(ALG, kp.public_key(), MESSAGE, &ctx_sig)
            .expect("verify must reach a verdict"),
        "a context-bound signature must not verify context-free"
    );

    let plain_sig = slh_dsa
        .sign_for_algorithm(ALG, kp.secret_key(), MESSAGE, Some(&SIGN_RANDOMNESS))
        .expect("legacy sign");
    assert!(
        !slh_dsa
            .verify_for_algorithm_with_context(ALG, kp.public_key(), MESSAGE, CONTEXT, &plain_sig)
            .expect("verify must reach a verdict"),
        "a context-free signature must not verify under a context"
    );
}

/// FIPS 205 length-prefixes the context with a single byte, so 255 is representable.
#[test]
fn max_length_context_round_trips() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);
    let context = vec![0xABu8; SLH_DSA_CONTEXT_MAX_LEN];

    let signature = slh_dsa
        .sign_for_algorithm_with_context(
            ALG,
            kp.secret_key(),
            MESSAGE,
            &context,
            Some(&SIGN_RANDOMNESS),
        )
        .expect("sign under a 255-byte context");

    assert!(
        slh_dsa
            .verify_for_algorithm_with_context(ALG, kp.public_key(), MESSAGE, &context, &signature)
            .expect("verify must reach a verdict"),
        "a 255-byte context must round trip"
    );
}

/// An over-long context is a hard error on both sides — a caller bug, not a bad-signature
/// verdict, and never a silent truncation to 255 bytes.
#[test]
fn over_long_context_is_rejected_not_truncated() {
    let slh_dsa = SlhDsa::new();
    let kp = keypair(&slh_dsa);
    let too_long = vec![0xCDu8; SLH_DSA_CONTEXT_MAX_LEN + 1];

    assert!(
        slh_dsa
            .sign_for_algorithm_with_context(
                ALG,
                kp.secret_key(),
                MESSAGE,
                &too_long,
                Some(&SIGN_RANDOMNESS)
            )
            .is_err(),
        "signing under a 256-byte context must fail"
    );

    let signature = slh_dsa
        .sign_for_algorithm_with_context(
            ALG,
            kp.secret_key(),
            MESSAGE,
            CONTEXT,
            Some(&SIGN_RANDOMNESS),
        )
        .expect("sign under context");
    assert!(
        slh_dsa
            .verify_for_algorithm_with_context(ALG, kp.public_key(), MESSAGE, &too_long, &signature)
            .is_err(),
        "verifying under a 256-byte context must fail rather than truncate"
    );
}

/// The context must be bound for every parameter set, not just the one the other tests use.
#[test]
fn every_parameter_set_binds_the_context() {
    let slh_dsa = SlhDsa::new();

    for (alg, key_randomness_len) in [
        (Algorithm::SlhDsaSha256128fRobust, 48),
        (Algorithm::SlhDsaSha256192fRobust, 72),
        (Algorithm::SlhDsaSha256256fRobust, 96),
        (Algorithm::SlhDsaShake256128fRobust, 48),
        (Algorithm::SlhDsaShake256192fRobust, 72),
        (Algorithm::SlhDsaShake256256fRobust, 96),
    ] {
        let key_randomness = vec![0x33u8; key_randomness_len];
        let kp = slh_dsa
            .generate_keypair_with_randomness(alg, &key_randomness)
            .unwrap_or_else(|e| panic!("{alg:?}: keypair generation failed: {e}"));

        let signature = slh_dsa
            .sign_for_algorithm_with_context(
                alg,
                kp.secret_key(),
                MESSAGE,
                CONTEXT,
                Some(&SIGN_RANDOMNESS),
            )
            .unwrap_or_else(|e| panic!("{alg:?}: sign failed: {e}"));

        assert!(
            slh_dsa
                .verify_for_algorithm_with_context(
                    alg,
                    kp.public_key(),
                    MESSAGE,
                    CONTEXT,
                    &signature
                )
                .unwrap_or_else(|e| panic!("{alg:?}: verify failed: {e}")),
            "{alg:?}: must verify under the correct context"
        );
        assert!(
            !slh_dsa
                .verify_for_algorithm_with_context(
                    alg,
                    kp.public_key(),
                    MESSAGE,
                    b"other-context",
                    &signature
                )
                .unwrap_or_else(|e| panic!("{alg:?}: verify failed: {e}")),
            "{alg:?}: must reject a different context"
        );
    }
}
