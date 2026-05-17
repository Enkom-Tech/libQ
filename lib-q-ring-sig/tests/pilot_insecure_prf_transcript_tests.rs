//! Integration tests for the pilot insecure PRF transcript (not a ring signature).

use lib_q_prf::{
    GoldKey256,
    GoldPrfParams256,
    LegendreKey256,
    LegendrePrfParams256,
    u256_to_le_bytes,
};
use lib_q_ring_sig::dualring_prf::verify_dualring_prf_batch_u256;
use lib_q_ring_sig::pilot_insecure_prf_transcript::{
    PilotPrfTranscriptError,
    PilotPrfTranscriptMemberSecrets256,
    pilot_prf_transcript_sign_u256,
    pilot_prf_transcript_verify_batch_u256,
    pilot_prf_transcript_verify_u256,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn member_from_seed(
    seed: u8,
) -> (
    PilotPrfTranscriptMemberSecrets256,
    LegendreKey256,
    GoldKey256,
) {
    let leg_p = LegendrePrfParams256::pilot();
    let gold_p = GoldPrfParams256::pilot();
    let leg = LegendreKey256::derive_from_seed(&[seed, 1, 2, 3], &leg_p).expect("leg");
    let gold = GoldKey256::derive_from_seed(&[seed, 4, 5, 6], &gold_p).expect("gold");
    let m = PilotPrfTranscriptMemberSecrets256 {
        legendre_key_le: u256_to_le_bytes(leg.as_uint()),
        gold_key_le: u256_to_le_bytes(gold.as_uint()),
    };
    (m, leg, gold)
}

#[test]
fn pilot_prf_transcript_sign_verify_roundtrip() {
    let (m0, _l0, _g0) = member_from_seed(0xA1);
    let (m1, l1, g1) = member_from_seed(0xB2);
    let ring = [m0, m1];
    let msg = b"hello-pilot-prf-transcript";
    let mut rng = ChaCha20Rng::from_seed([0xC0u8; 32]);
    let sig = pilot_prf_transcript_sign_u256(&mut rng, &ring, 1, &l1, &g1, msg).expect("sign");
    pilot_prf_transcript_verify_u256(&ring, 1, msg, &sig).expect("verify");
}

#[test]
fn pilot_prf_transcript_rejects_tampered_challenge() {
    let (m0, l0, g0) = member_from_seed(0x01);
    let (m1, _l1, _g1) = member_from_seed(0x02);
    let ring = [m0, m1];
    let msg = b"tamper";
    let mut rng = ChaCha20Rng::from_seed([0x01u8; 32]);
    let mut sig = pilot_prf_transcript_sign_u256(&mut rng, &ring, 0, &l0, &g0, msg).expect("sign");
    sig.challenge[0] ^= 0xFF;
    let e = pilot_prf_transcript_verify_u256(&ring, 0, msg, &sig).unwrap_err();
    assert_eq!(e, PilotPrfTranscriptError::Rejected);
}

#[test]
fn pilot_prf_transcript_batch_two() {
    let (m0, l0, g0) = member_from_seed(0x11);
    let (m1, l1, g1) = member_from_seed(0x22);
    let ring = [m0, m1];
    let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
    let s0 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 0, &l0, &g0, b"m0").expect("s0");
    let s1 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 1, &l1, &g1, b"m1").expect("s1");
    let items = vec![(b"m0".to_vec(), 0, s0), (b"m1".to_vec(), 1, s1)];
    pilot_prf_transcript_verify_batch_u256(&ring, &items).expect("batch");
}

#[test]
fn pilot_prf_transcript_batch_rejects_when_only_late_item_tampered() {
    let (m0, l0, g0) = member_from_seed(0x33);
    let (m1, l1, g1) = member_from_seed(0x44);
    let ring = [m0, m1];
    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let s0 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 0, &l0, &g0, b"m0").expect("s0");
    let mut s1 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 1, &l1, &g1, b"m1").expect("s1");
    s1.challenge[0] ^= 0xFF;
    let items = vec![(b"m0".to_vec(), 0, s0), (b"m1".to_vec(), 1, s1)];
    let e = pilot_prf_transcript_verify_batch_u256(&ring, &items).unwrap_err();
    assert_eq!(e, PilotPrfTranscriptError::Rejected);
}

#[test]
fn pilot_prf_transcript_batch_rejects_when_only_early_item_tampered() {
    let (m0, l0, g0) = member_from_seed(0x55);
    let (m1, l1, g1) = member_from_seed(0x66);
    let ring = [m0, m1];
    let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
    let mut s0 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 0, &l0, &g0, b"m0").expect("s0");
    let s1 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 1, &l1, &g1, b"m1").expect("s1");
    s0.challenge[0] ^= 0xFF;
    let items = vec![(b"m0".to_vec(), 0, s0), (b"m1".to_vec(), 1, s1)];
    let e = pilot_prf_transcript_verify_batch_u256(&ring, &items).unwrap_err();
    assert_eq!(e, PilotPrfTranscriptError::Rejected);
}

#[test]
fn dualring_prf_batch_matches_pilot_wrapper() {
    let (m0, l0, g0) = member_from_seed(0x88);
    let (m1, l1, g1) = member_from_seed(0x99);
    let ring = [m0, m1];
    let mut rng = ChaCha20Rng::from_seed([0x88u8; 32]);
    let s0 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 0, &l0, &g0, b"a").expect("s0");
    let s1 = pilot_prf_transcript_sign_u256(&mut rng, &ring, 1, &l1, &g1, b"b").expect("s1");
    let items_ok = vec![
        (b"a".to_vec(), 0, s0.clone()),
        (b"b".to_vec(), 1, s1.clone()),
    ];
    assert!(pilot_prf_transcript_verify_batch_u256(&ring, &items_ok).is_ok());
    assert!(verify_dualring_prf_batch_u256(&ring, &items_ok).is_ok());

    let mut s1_bad = s1;
    s1_bad.challenge[0] ^= 0xFF;
    let items_bad = vec![(b"a".to_vec(), 0, s0), (b"b".to_vec(), 1, s1_bad)];
    assert_eq!(
        pilot_prf_transcript_verify_batch_u256(&ring, &items_bad).unwrap_err(),
        verify_dualring_prf_batch_u256(&ring, &items_bad).unwrap_err(),
    );
}

#[test]
fn pilot_prf_transcript_batch_empty_ok() {
    let (m0, _, _) = member_from_seed(0x77);
    verify_dualring_prf_batch_u256(core::slice::from_ref(&m0), &[]).expect("empty batch");
}
