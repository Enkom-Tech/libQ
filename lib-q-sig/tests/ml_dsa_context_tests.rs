//! FIPS-204 signing-context KATs for the ML-DSA surface exposed to WASM.
//!
//! The bindings used to hardcode an empty context, so a context-bound signature (GIP domain
//! separation, e.g. `wapp.sh/entitlement-v0`) could not be verified from a browser. The tests
//! that matter here are the NEGATIVE ones: a binding that accepts a context argument and then
//! ignores it would still pass every positive test below.

#![cfg(feature = "ml-dsa")]

use lib_q_core::api::{
    Algorithm,
    SignatureOperations,
};
use lib_q_core::{
    SigPublicKey,
    SigSecretKey,
    Signature,
};
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_sig::ml_dsa::{
    ML_DSA_CONTEXT_MAX_LEN,
    MlDsa,
};
use lib_q_sig::provider::LibQSignatureProvider;

/// Real GIP-style domain separation strings, i.e. the ones this work exists to unblock.
const ENTITLEMENT_CTX: &[u8] = b"wapp.sh/entitlement-v0";
const INDEX_ENTRY_CTX: &[u8] = b"wapp.sh/index-entry-v0";

fn keypair(ml_dsa: &MlDsa, seed: u8) -> (SigPublicKey, SigSecretKey) {
    let kp = ml_dsa
        .generate_keypair_with_randomness([seed; KEY_GENERATION_RANDOMNESS_SIZE])
        .expect("keygen");
    (
        SigPublicKey::new(kp.public_key().as_bytes().to_vec()),
        SigSecretKey::new(kp.secret_key().as_bytes().to_vec()),
    )
}

fn variants() -> [MlDsa; 3] {
    [MlDsa::ml_dsa_44(), MlDsa::ml_dsa_65(), MlDsa::ml_dsa_87()]
}

#[test]
fn context_bound_signature_verifies_under_the_same_context() {
    for ml_dsa in variants() {
        let (pk, sk) = keypair(&ml_dsa, 0x11);
        let message = b"entitlement:abc123";

        let sig = ml_dsa
            .sign_with_randomness_and_context(
                &sk,
                message,
                ENTITLEMENT_CTX,
                [0x22; SIGNING_RANDOMNESS_SIZE],
            )
            .expect("sign with context");

        assert!(
            ml_dsa
                .verify_with_context(&pk, message, ENTITLEMENT_CTX, &sig)
                .expect("verify"),
            "signature must verify under the context it was produced with"
        );
    }
}

#[test]
fn context_bound_signature_fails_under_a_different_context() {
    for ml_dsa in variants() {
        let (pk, sk) = keypair(&ml_dsa, 0x11);
        let message = b"entitlement:abc123";

        let sig = ml_dsa
            .sign_with_randomness_and_context(
                &sk,
                message,
                ENTITLEMENT_CTX,
                [0x22; SIGNING_RANDOMNESS_SIZE],
            )
            .expect("sign with context");

        assert!(
            !ml_dsa
                .verify_with_context(&pk, message, INDEX_ENTRY_CTX, &sig)
                .expect("verify"),
            "a signature must NOT verify under a different context"
        );
    }
}

#[test]
fn context_bound_signature_fails_under_the_empty_context() {
    for ml_dsa in variants() {
        let (pk, sk) = keypair(&ml_dsa, 0x11);
        let message = b"entitlement:abc123";

        let sig = ml_dsa
            .sign_with_randomness_and_context(
                &sk,
                message,
                ENTITLEMENT_CTX,
                [0x22; SIGNING_RANDOMNESS_SIZE],
            )
            .expect("sign with context");

        assert!(
            !ml_dsa
                .verify_with_context(&pk, message, &[], &sig)
                .expect("verify"),
            "a context-bound signature must NOT verify under the empty context"
        );
        assert!(
            !ml_dsa.verify(&pk, message, &sig).expect("verify"),
            "the legacy empty-context entry point must NOT accept a context-bound signature"
        );
    }
}

#[test]
fn empty_context_signature_fails_under_a_non_empty_context() {
    for ml_dsa in variants() {
        let (pk, sk) = keypair(&ml_dsa, 0x33);
        let message = b"artifact-digest";

        // The cosign-style artifact path: signed with no context.
        let sig = ml_dsa
            .sign_with_randomness(&sk, message, [0x44; SIGNING_RANDOMNESS_SIZE])
            .expect("sign");

        assert!(
            !ml_dsa
                .verify_with_context(&pk, message, ENTITLEMENT_CTX, &sig)
                .expect("verify"),
            "an empty-context signature must NOT verify under a non-empty context"
        );
    }
}

/// The empty-context path is what `sign_wasm`/`verify_wasm` and the cosign-style artifact
/// signatures use; the refactor must not have moved those bytes.
#[test]
fn empty_context_path_is_unchanged() {
    for ml_dsa in variants() {
        let (pk, sk) = keypair(&ml_dsa, 0x55);
        let message = b"artifact-digest";
        let randomness = [0x66; SIGNING_RANDOMNESS_SIZE];

        let legacy = ml_dsa
            .sign_with_randomness(&sk, message, randomness)
            .expect("sign");
        let explicit_empty = ml_dsa
            .sign_with_randomness_and_context(&sk, message, &[], randomness)
            .expect("sign");

        assert_eq!(
            legacy, explicit_empty,
            "sign_with_randomness must be byte-identical to an explicitly empty context"
        );
        assert!(ml_dsa.verify(&pk, message, &legacy).expect("verify"));
        assert!(
            ml_dsa
                .verify_with_context(&pk, message, &[], &legacy)
                .expect("verify")
        );
    }
}

#[test]
fn context_longer_than_255_bytes_is_rejected() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let (pk, sk) = keypair(&ml_dsa, 0x77);
    let too_long = vec![0x41u8; ML_DSA_CONTEXT_MAX_LEN + 1];
    let max_len = vec![0x41u8; ML_DSA_CONTEXT_MAX_LEN];

    // Asserted on the error KIND, not merely `is_err()`: a size check that fired for some other
    // reason (bad key material, a disabled feature) would satisfy a bare `is_err()` without the
    // context length ever being looked at.
    let signed = ml_dsa.sign_with_randomness_and_context(
        &sk,
        b"m",
        &too_long,
        [0x88; SIGNING_RANDOMNESS_SIZE],
    );
    assert!(
        matches!(
            signed,
            Err(lib_q_core::Error::InvalidAssociatedDataSize {
                max: ML_DSA_CONTEXT_MAX_LEN,
                actual,
            }) if actual == ML_DSA_CONTEXT_MAX_LEN + 1
        ),
        "a context longer than 255 bytes is unrepresentable in FIPS-204 and must be rejected as \
         such; got {signed:?}"
    );

    // A 255-byte context is representable and must round-trip.
    let sig = ml_dsa
        .sign_with_randomness_and_context(&sk, b"m", &max_len, [0x88; SIGNING_RANDOMNESS_SIZE])
        .expect("sign at max context length");
    assert!(
        ml_dsa
            .verify_with_context(&pk, b"m", &max_len, &sig)
            .expect("verify")
    );

    // Verification with an over-long context is a caller error, not a `false` verdict — and it
    // must be THAT error, not an incidental key/signature rejection.
    let verified = ml_dsa.verify_with_context(&pk, b"m", &too_long, &sig);
    assert!(
        matches!(
            verified,
            Err(lib_q_core::Error::InvalidAssociatedDataSize {
                max: ML_DSA_CONTEXT_MAX_LEN,
                ..
            })
        ),
        "an unrepresentable context is a caller error, not a `false` verdict; got {verified:?}"
    );
}

/// The provider layer is what `WasmSignatureContext::{sign,verify}_with_context` dispatches
/// through, so the context has to survive that hop too.
#[test]
fn provider_layer_threads_the_context() {
    let provider = LibQSignatureProvider::new().expect("provider");
    let ml_dsa = MlDsa::ml_dsa_65();
    let (pk, sk) = keypair(&ml_dsa, 0x99);
    let message = b"entitlement:abc123";

    let sig = provider
        .sign_with_context(Algorithm::MlDsa65, &sk, message, ENTITLEMENT_CTX, None)
        .expect("provider sign with context");

    assert!(
        provider
            .verify_with_context(Algorithm::MlDsa65, &pk, message, ENTITLEMENT_CTX, &sig)
            .expect("provider verify")
    );
    assert!(
        !provider
            .verify_with_context(Algorithm::MlDsa65, &pk, message, INDEX_ENTRY_CTX, &sig)
            .expect("provider verify")
    );
    assert!(
        !provider
            .verify(Algorithm::MlDsa65, &pk, message, &sig)
            .expect("provider verify")
    );
}

/// The `SignatureOperations` trait default is the safety net for every provider that has not
/// opted into contexts: it must refuse a non-empty context rather than drop it and answer as if
/// the caller had never asked for one.
///
/// This is asserted against a minimal implementor rather than a real algorithm on purpose — a
/// concrete algorithm makes the test depend on feature flags and on input validators that fire
/// long before the context check, so it can end up passing without ever reaching the branch it
/// is named for.
#[test]
fn trait_default_refuses_a_context_it_cannot_honour() {
    /// Implements only the three required methods; inherits the context defaults.
    struct ContextObliviousProvider;

    const SENTINEL: &[u8] = b"signed-without-a-context";

    impl SignatureOperations for ContextObliviousProvider {
        fn generate_keypair(
            &self,
            _algorithm: Algorithm,
            _randomness: Option<&[u8]>,
        ) -> lib_q_core::Result<lib_q_core::SigKeypair> {
            unimplemented!("not exercised")
        }

        fn sign(
            &self,
            _algorithm: Algorithm,
            _secret_key: &SigSecretKey,
            _message: &[u8],
            _randomness: Option<&[u8]>,
        ) -> lib_q_core::Result<Vec<u8>> {
            Ok(SENTINEL.to_vec())
        }

        fn verify(
            &self,
            _algorithm: Algorithm,
            _public_key: &SigPublicKey,
            _message: &[u8],
            _signature: &[u8],
        ) -> lib_q_core::Result<bool> {
            Ok(true)
        }
    }

    let provider = ContextObliviousProvider;
    let sk = SigSecretKey::new(vec![1u8; 32]);
    let pk = SigPublicKey::new(vec![1u8; 32]);

    // Non-empty context: must be refused, NOT answered.
    let signed = provider.sign_with_context(Algorithm::MlDsa65, &sk, b"m", ENTITLEMENT_CTX, None);
    assert!(
        matches!(signed, Err(lib_q_core::Error::NotImplemented { .. })),
        "a non-empty context must be refused as unsupported, never silently dropped; got {signed:?}"
    );

    let verified =
        provider.verify_with_context(Algorithm::MlDsa65, &pk, b"m", ENTITLEMENT_CTX, SENTINEL);
    assert!(
        matches!(verified, Err(lib_q_core::Error::NotImplemented { .. })),
        "a non-empty context must never be verified away as `true`; got {verified:?}"
    );

    // Empty context: must transparently delegate to the context-free implementation.
    assert_eq!(
        provider
            .sign_with_context(Algorithm::MlDsa65, &sk, b"m", &[], None)
            .expect("empty context delegates"),
        SENTINEL
    );
    assert!(
        provider
            .verify_with_context(Algorithm::MlDsa65, &pk, b"m", &[], SENTINEL)
            .expect("empty context delegates")
    );
}
