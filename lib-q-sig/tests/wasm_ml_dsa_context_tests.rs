//! WASM-side KATs for the ML-DSA signing-context bindings.
//!
//! Run with `wasm-pack test --node -p lib-q-sig --features wasm,ml-dsa` (this file deliberately
//! does NOT `wasm_bindgen_test_configure!(run_in_browser)` so it can run headless in node).
//!
//! The negative cases are the point: a binding that takes a `context` argument and then drops it
//! would pass every positive assertion here.

#![cfg(all(feature = "wasm", feature = "ml-dsa", target_arch = "wasm32"))]

use js_sys::Uint8Array;
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_sig::ml_dsa::MlDsa;
use wasm_bindgen_test::*;

/// Real GIP-style domain separation strings — the ones a browser client must be able to verify.
const ENTITLEMENT_CTX: &[u8] = b"wapp.sh/entitlement-v0";
const INDEX_ENTRY_CTX: &[u8] = b"wapp.sh/index-entry-v0";

fn u8a(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

fn fixed_keypair(ml_dsa: &MlDsa) -> (Uint8Array, Uint8Array) {
    let seed = [0x11u8; KEY_GENERATION_RANDOMNESS_SIZE];
    let kp = ml_dsa
        .generate_keypair_wasm(Some(u8a(&seed)))
        .expect("keygen");
    (kp.public_key(), kp.secret_key())
}

#[wasm_bindgen_test]
fn context_bound_signature_round_trips_through_wasm() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let (pk, sk) = fixed_keypair(&ml_dsa);
    let message = b"entitlement:abc123";
    let randomness = [0x22u8; SIGNING_RANDOMNESS_SIZE];

    let sig = ml_dsa
        .sign_with_context_wasm(
            sk,
            u8a(message),
            u8a(ENTITLEMENT_CTX),
            Some(u8a(&randomness)),
        )
        .expect("sign_with_context_wasm");

    assert!(
        ml_dsa
            .verify_with_context_wasm(pk.clone(), u8a(message), u8a(ENTITLEMENT_CTX), sig.clone())
            .expect("verify_with_context_wasm"),
        "must verify under the same context"
    );

    assert!(
        !ml_dsa
            .verify_with_context_wasm(pk.clone(), u8a(message), u8a(INDEX_ENTRY_CTX), sig.clone())
            .expect("verify_with_context_wasm"),
        "must NOT verify under a different context"
    );

    assert!(
        !ml_dsa
            .verify_with_context_wasm(pk.clone(), u8a(message), u8a(&[]), sig.clone())
            .expect("verify_with_context_wasm"),
        "must NOT verify under an empty context"
    );

    assert!(
        !ml_dsa
            .verify_wasm(pk, u8a(message), sig)
            .expect("verify_wasm"),
        "the pre-existing empty-context binding must NOT accept a context-bound signature"
    );
}

/// The cosign-style artifact path (empty context) must be untouched by the new bindings.
#[wasm_bindgen_test]
fn empty_context_wasm_path_is_unchanged() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let (pk, sk) = fixed_keypair(&ml_dsa);
    let message = b"artifact-digest";
    let randomness = [0x44u8; SIGNING_RANDOMNESS_SIZE];

    let legacy = ml_dsa
        .sign_wasm(sk.clone(), u8a(message), Some(u8a(&randomness)))
        .expect("sign_wasm");
    let explicit_empty = ml_dsa
        .sign_with_context_wasm(sk, u8a(message), u8a(&[]), Some(u8a(&randomness)))
        .expect("sign_with_context_wasm");

    assert_eq!(
        legacy.to_vec(),
        explicit_empty.to_vec(),
        "an explicitly empty context must be byte-identical to sign_wasm"
    );

    assert!(
        ml_dsa
            .verify_wasm(pk.clone(), u8a(message), legacy.clone())
            .expect("verify_wasm")
    );
    assert!(
        ml_dsa
            .verify_with_context_wasm(pk, u8a(message), u8a(&[]), legacy)
            .expect("verify_with_context_wasm")
    );
}

#[wasm_bindgen_test]
fn over_long_context_is_rejected_not_silently_truncated() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let (_pk, sk) = fixed_keypair(&ml_dsa);
    let too_long = vec![0x41u8; 256];
    let randomness = [0x55u8; SIGNING_RANDOMNESS_SIZE];

    let err = ml_dsa
        .sign_with_context_wasm(sk, u8a(b"m"), u8a(&too_long), Some(u8a(&randomness)))
        .expect_err(
            "a 256-byte context is unrepresentable in FIPS-204 and must be an error, not a \
             truncation",
        );

    // The JS error must name the context-size violation. A bare `is_err()` here would also be
    // satisfied by an unrelated rejection (bad randomness size, bad key material) that never
    // reached the length check at all.
    let message = err.as_string().unwrap_or_default();
    assert!(
        message.contains("associated data size") && message.contains("255"),
        "the JS error must report the context-length violation, got {message:?}"
    );
}
