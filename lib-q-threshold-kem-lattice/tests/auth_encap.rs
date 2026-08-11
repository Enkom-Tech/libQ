//! Tests for the authenticated encapsulator (`src/auth_encap.rs`) — the deployable "closure B"
//! mitigation for the malformed-ciphertext insider probe (`THRESHOLD_SECURITY.md` §4–§6).
//!
//! Covers:
//! - the existing `v1` wire is untouched (byte-identical KAT round-trip through the new type).
//! - the authenticator verifies for an honestly produced `AuthenticatedCiphertext`.
//! - four independent negative controls: forged tag, truncated tag, tag valid for a different
//!   ciphertext, tag valid under a different key.
//! - `partial_decap_authenticated_budgeted` rejects an unauthenticated ciphertext before it would
//!   touch share material (and still charges no budget on rejection).

use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::threshold::{
    DecapBudget,
    ZeroShareSeeds,
    partial_decap_authenticated_budgeted,
};
use lib_q_threshold_kem_lattice::{
    AUTH_TAG_BYTES,
    AuthKey,
    AuthenticatedCiphertext,
    Ciphertext,
    SecretShare,
    ThresholdKemError,
    ThresholdKemLatticePublicKey,
    authenticated_encapsulate,
    kem,
    verify_authenticator,
};
use zeroize::Zeroizing;

const THRESHOLD: u8 = 3;

const PK_T0: &[u8] = include_bytes!("data/kat_pk_v1.bin");
const SHARE_1: &[u8] = include_bytes!("data/kat_share_1_v1.bin");

fn fixture_pk() -> ThresholdKemLatticePublicKey {
    ThresholdKemLatticePublicKey {
        threshold: THRESHOLD,
        t0_bytes: PK_T0.to_vec(),
    }
}

fn fixture_share() -> SecretShare {
    SecretShare {
        index: 1,
        threshold: THRESHOLD,
        share_bytes: Zeroizing::new(SHARE_1.to_vec()),
    }
}

fn kat_mu() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

/// Pin from `tests/kat.rs`: `sha3_256(ct.to_bytes())` for `μ = (0..32)` under the fixture key.
const PIN_CT_DIGEST: &str = "44c97ce84313de0074ca9c0ddbae682c278957e13e969c45033d0d0aebf7fb7c";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The v1 `Ciphertext` wire is frozen. `AuthenticatedCiphertext` is purely additive: its inner `ct`
/// must serialize to *exactly* the same bytes as the un-authenticated KAT ciphertext, and
/// `AuthenticatedCiphertext::to_bytes` must be `ct.to_bytes() ‖ tag` with nothing else interleaved.
#[test]
fn authenticated_ciphertext_wraps_the_unchanged_v1_wire() {
    let pk = fixture_pk();
    let t0 = pk.t0().expect("t0");
    let ct = kem::encapsulate_derand(&t0, &kat_mu());

    // The plain ciphertext bytes are still exactly the pinned v1 KAT vector.
    assert_eq!(hex(&lib_q_sha3::sha3_256(&ct.to_bytes())), PIN_CT_DIGEST);

    let auth_key = AuthKey::from_bytes([0x42u8; 32]);
    let tag = {
        // Build an AuthenticatedCiphertext by hand from the pinned ct (not via
        // authenticated_encapsulate, which samples a fresh random μ) to check the layering exactly.
        let act_ss = lib_q_threshold_kem_lattice::authenticated_encapsulate(
            &pk,
            &auth_key,
            &mut new_deterministic_rng([0x11u8; 32]),
        )
        .expect("authenticated_encapsulate");
        act_ss.1.tag
    };
    let act = AuthenticatedCiphertext {
        ct: ct.clone(),
        tag,
    };

    let bytes = act.to_bytes();
    assert_eq!(bytes.len(), AuthenticatedCiphertext::BYTES);
    assert_eq!(bytes.len(), Ciphertext::BYTES + AUTH_TAG_BYTES);
    // Prefix is byte-identical to the unauthenticated wire.
    assert_eq!(&bytes[..Ciphertext::BYTES], &ct.to_bytes()[..]);
    // Suffix is exactly the tag, nothing else.
    assert_eq!(&bytes[Ciphertext::BYTES..], &tag[..]);

    // Round-trips.
    let parsed = AuthenticatedCiphertext::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed.ct, ct);
    assert_eq!(parsed.tag, tag);
}

#[test]
fn authenticated_encapsulate_preserves_ss_and_ct_shape() {
    let pk = fixture_pk();
    let mut rng = new_deterministic_rng([0x77u8; 32]);
    let (ss, act) = authenticated_encapsulate(&pk, &AuthKey::from_bytes([0xAAu8; 32]), &mut rng)
        .expect("authenticated_encapsulate");
    assert_eq!(ss.len(), 32);
    assert!(act.ct.is_well_formed());
    assert_eq!(act.tag.len(), AUTH_TAG_BYTES);
}

#[test]
fn authenticator_verifies_for_honest_ciphertext() {
    let pk = fixture_pk();
    let auth_key = AuthKey::from_bytes([0x01u8; 32]);
    let mut rng = new_deterministic_rng([0x02u8; 32]);
    let (_ss, act) =
        authenticated_encapsulate(&pk, &auth_key, &mut rng).expect("authenticated_encapsulate");

    let ok = verify_authenticator(&pk, &auth_key, &act);
    assert_eq!(ok.unwrap_u8(), 1, "honest authenticator must verify");
}

// ---------------------------------------------------------------------------
// Negative controls — every one of these MUST be rejected.
// ---------------------------------------------------------------------------

#[test]
fn negative_control_forged_tag_is_rejected() {
    let pk = fixture_pk();
    let auth_key = AuthKey::from_bytes([0x03u8; 32]);
    let mut rng = new_deterministic_rng([0x04u8; 32]);
    let (_ss, mut act) =
        authenticated_encapsulate(&pk, &auth_key, &mut rng).expect("authenticated_encapsulate");

    // Flip one bit of a plausible-looking, all-zero forged tag.
    act.tag = [0u8; AUTH_TAG_BYTES];
    let result = verify_authenticator(&pk, &auth_key, &act);
    let observed = result.unwrap_u8();
    assert_eq!(observed, 0, "forged (zeroed) tag must NOT verify");

    // Also exercise the gated entry point end-to-end.
    let share = fixture_share();
    let subset = [1u8, 2, 3];
    let mut seeds_rng = new_deterministic_rng([0x05u8; 32]);
    let seeds = ZeroShareSeeds::setup(THRESHOLD, &mut seeds_rng);
    let mut budget = DecapBudget::authenticated();
    let err = partial_decap_authenticated_budgeted(
        &share,
        &subset,
        &pk,
        &auth_key,
        &act,
        &seeds,
        &mut seeds_rng,
        &mut budget,
    )
    .expect_err("forged tag must be rejected before any partial is produced");
    assert_eq!(err, ThresholdKemError::AuthenticationFailed);
    // Rejection must not consume a budget slot.
    assert_eq!(
        budget.used(),
        0,
        "a rejected authenticator must not charge the budget"
    );
}

#[test]
fn negative_control_truncated_tag_fails_to_parse() {
    let pk = fixture_pk();
    let auth_key = AuthKey::from_bytes([0x06u8; 32]);
    let mut rng = new_deterministic_rng([0x07u8; 32]);
    let (_ss, act) =
        authenticated_encapsulate(&pk, &auth_key, &mut rng).expect("authenticated_encapsulate");

    let mut bytes = act.to_bytes();
    assert_eq!(bytes.len(), AuthenticatedCiphertext::BYTES);
    bytes.truncate(bytes.len() - 5); // chop 5 bytes off the tag
    let result = AuthenticatedCiphertext::from_bytes(&bytes);
    assert_eq!(
        result,
        Err(ThresholdKemError::EncodingCiphertext),
        "a truncated authenticated ciphertext must fail to parse, not silently short-tag-verify"
    );
}

#[test]
fn negative_control_tag_for_different_ciphertext_is_rejected() {
    let pk = fixture_pk();
    let auth_key = AuthKey::from_bytes([0x08u8; 32]);
    let mut rng_a = new_deterministic_rng([0x09u8; 32]);
    let mut rng_b = new_deterministic_rng([0x0Au8; 32]);
    let (_ss_a, act_a) =
        authenticated_encapsulate(&pk, &auth_key, &mut rng_a).expect("encapsulate a");
    let (_ss_b, act_b) =
        authenticated_encapsulate(&pk, &auth_key, &mut rng_b).expect("encapsulate b");
    assert_ne!(
        act_a.ct, act_b.ct,
        "fixture must produce two distinct ciphertexts"
    );

    // Splice b's valid tag onto a's ciphertext.
    let spliced = AuthenticatedCiphertext {
        ct: act_a.ct.clone(),
        tag: act_b.tag,
    };
    let result = verify_authenticator(&pk, &auth_key, &spliced);
    assert_eq!(
        result.unwrap_u8(),
        0,
        "a tag valid for a DIFFERENT ciphertext must not verify against this one"
    );
}

#[test]
fn negative_control_tag_under_different_key_is_rejected() {
    let pk = fixture_pk();
    let key_a = AuthKey::from_bytes([0x0Bu8; 32]);
    let key_b = AuthKey::from_bytes([0x0Cu8; 32]);
    let mut rng = new_deterministic_rng([0x0Du8; 32]);
    let (_ss, act) = authenticated_encapsulate(&pk, &key_a, &mut rng).expect("encapsulate");

    // act.tag is valid under key_a; verifying under key_b must fail.
    let result = verify_authenticator(&pk, &key_b, &act);
    assert_eq!(
        result.unwrap_u8(),
        0,
        "a tag valid under a DIFFERENT auth key must not verify"
    );

    // Sanity: the same act still verifies under the correct key.
    let ok = verify_authenticator(&pk, &key_a, &act);
    assert_eq!(ok.unwrap_u8(), 1);
}

#[test]
fn authenticated_gated_partial_decap_succeeds_for_honest_ciphertext() {
    let pk = fixture_pk();
    let auth_key = AuthKey::from_bytes([0x0Eu8; 32]);
    let mut rng = new_deterministic_rng([0x0Fu8; 32]);
    let (_ss, act) = authenticated_encapsulate(&pk, &auth_key, &mut rng).expect("encapsulate");

    let share = fixture_share();
    let subset = [1u8, 2, 3];
    let seeds = ZeroShareSeeds::setup(THRESHOLD, &mut rng);
    let mut budget = DecapBudget::authenticated();
    let partial = partial_decap_authenticated_budgeted(
        &share,
        &subset,
        &pk,
        &auth_key,
        &act,
        &seeds,
        &mut rng,
        &mut budget,
    )
    .expect("honest authenticated ciphertext must be accepted");
    assert_eq!(partial.index, 1);
    assert_eq!(
        budget.used(),
        1,
        "a successful partial must charge exactly one budget slot"
    );
}
