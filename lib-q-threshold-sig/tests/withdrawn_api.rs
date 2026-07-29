//! Abuse suite: prove the withdrawn API cannot be coaxed into producing a key or accepting a
//! signature.
//!
//! Each test walks a step of the attack the original construction permitted — obtain key
//! material, produce a signature, get `verify` to say yes — and asserts that the step is now
//! impossible through the public API. These tests deliberately contain no forgery procedure:
//! the arithmetic that made forgery trivial has been deleted from the crate, so there is
//! nothing to reproduce here. What is asserted is the *absence* of any successful outcome.

mod common;

#[allow(deprecated)]
use lib_q_threshold_sig::{
    ThresholdSigError,
    aggregate,
    decode_signature,
    encode_signature,
    identify_abort,
    keygen_shares,
    proactive_refresh,
    setup,
    sign_round1,
    sign_round2,
    verify,
};

/// Step 1 of the abuse chain: get a key. Every parameter choice is refused, so an attacker
/// never obtains the published-key-that-is-the-private-key in the first place.
#[test]
#[allow(deprecated)]
fn step1_cannot_obtain_any_key_material() {
    let profile = setup();
    let mut rng = common::deterministic_rng(0x01);
    let mut refused = 0usize;
    let params: [(u8, u8); 8] = [
        (1, 1),
        (2, 3),
        (3, 5),
        (3, 8),
        (5, 5),
        (64, 64),
        (0, 0),
        (255, 255),
    ];
    for (threshold, count) in params {
        match keygen_shares(&profile, threshold, count, &mut rng) {
            Err(ThresholdSigError::SchemeWithdrawn) => refused += 1,
            other => panic!("keygen_shares({threshold},{count}) did not refuse: {other:?}"),
        }
    }
    println!(
        "STEP1: {refused}/{} keygen parameter sets refused; 0 keys issued",
        params.len()
    );
    assert_eq!(refused, params.len());
}

/// Step 2 of the abuse chain: produce a signature. Both signing rounds and aggregation refuse,
/// so no signature can be minted through the honest path either.
#[test]
#[allow(deprecated)]
fn step2_cannot_produce_a_signature() {
    let profile = setup();
    let mut rng = common::deterministic_rng(0x02);
    let pk = common::inert_public_key();
    let share = common::inert_share(1);
    let state = common::inert_round1_state(1);
    let commitments: Vec<_> = (1..=common::THRESHOLD)
        .map(common::inert_commitment)
        .collect();
    let partials: Vec<_> = (1..=common::THRESHOLD).map(common::inert_partial).collect();
    let msg = b"abuse-attempt";

    assert_eq!(
        sign_round1(&profile, &share, msg, &mut rng).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "sign_round1 must refuse",
    );
    assert_eq!(
        sign_round2(&profile, &pk, msg, &share, &state, &commitments).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "sign_round2 must refuse",
    );
    assert_eq!(
        aggregate(&profile, &pk, msg, &commitments, &partials).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "aggregate must refuse",
    );
    assert_eq!(
        identify_abort(&profile, &pk, msg, &commitments, &partials).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "identify_abort must refuse",
    );
    assert_eq!(
        proactive_refresh(&profile, &[share], &mut rng).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "proactive_refresh must refuse",
    );
    println!("STEP2: all 5 signing-path entry points refused; 0 signatures produced");
}

/// Step 3 of the abuse chain, and the one that matters most: get `verify` to accept.
///
/// The original verifier accepted attacker-constructed signatures on attacker-chosen messages.
/// Here we sweep a wide space of hand-built signatures, messages and public keys and assert
/// that `verify` never returns `Ok` at all — so it can never return `Ok(true)`.
#[test]
#[allow(deprecated)]
fn step3_verify_never_accepts_anything() {
    let profile = setup();
    let mut attempts = 0usize;
    let mut accepted = 0usize;
    let mut ok_results = 0usize;

    for t in 0..256u32 {
        let msg = format!("attacker-chosen-message-{t}");
        let filler = u8::try_from(t % 256).unwrap_or(0);
        let mut pk = common::inert_public_key();
        pk.group_key = [filler; 32];
        for v in &mut pk.share_verifiers {
            v.verifying_key = [filler ^ 0x5A; 32];
        }
        let mut sig = common::inert_signature();
        sig.r_agg = [filler; 32];
        sig.z = [filler ^ 0xA5; 32];

        attempts += 1;
        match verify(&profile, &pk, msg.as_bytes(), &sig) {
            Ok(true) => {
                accepted += 1;
                ok_results += 1;
            }
            Ok(false) => ok_results += 1,
            Err(ThresholdSigError::SchemeWithdrawn) => {}
            other => panic!("verify returned an unexpected result: {other:?}"),
        }
    }

    println!(
        "STEP3: {attempts} forgery attempts on attacker-chosen messages -> \
         {accepted} accepted, {ok_results} reached any Ok(_) verdict"
    );
    assert_eq!(accepted, 0, "verify must never accept a signature");
    assert_eq!(ok_results, 0, "verify must never return Ok at all");
}

/// The wire codecs stay live, but they are a dead end: a blob can be framed and parsed, and the
/// result still cannot be verified. Serialization must not become a back door to acceptance.
#[test]
#[allow(deprecated)]
fn codecs_do_not_reopen_the_verification_path() {
    let profile = setup();
    let sig = common::inert_signature();
    let bytes = encode_signature(&sig).expect("encode_signature is pure serialization");
    let decoded = decode_signature(&bytes).expect("decode_signature is pure serialization");
    assert_eq!(decoded, sig, "codec must round-trip");

    let pk = common::inert_public_key();
    assert_eq!(
        verify(&profile, &pk, b"anything", &decoded).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "a round-tripped signature must still be unverifiable",
    );
    println!("CODECS: round-trip succeeded, verification still refused");
}

/// The refusal must be self-explanatory to whoever hits it in production logs.
#[test]
fn refusal_message_explains_the_withdrawal_and_the_exposure() {
    let msg = ThresholdSigError::SchemeWithdrawn.to_string();
    for needle in ["WITHDRAWN", "authenticated nothing", "compromised"] {
        assert!(
            msg.contains(needle),
            "message must mention {needle:?}: {msg}"
        );
    }
    println!("MESSAGE: {msg}");
}
