//! DualRing-PRF pilot transcript integration tests.

use lib_q_prf::{
    GoldKey256,
    GoldPrfParams256,
    LegendreKey256,
    LegendrePrfParams256,
    u256_to_le_bytes,
};
use lib_q_ring_sig::{
    DualRingPrfError,
    DualRingPrfMemberPublic256,
    sign_dualring_prf_u256,
    verify_dualring_prf_batch_u256,
    verify_dualring_prf_u256,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn member_from_seed(seed: u8) -> (DualRingPrfMemberPublic256, LegendreKey256, GoldKey256) {
    let leg_p = LegendrePrfParams256::pilot();
    let gold_p = GoldPrfParams256::pilot();
    let leg = LegendreKey256::derive_from_seed(&[seed, 1, 2, 3], &leg_p).expect("leg");
    let gold = GoldKey256::derive_from_seed(&[seed, 4, 5, 6], &gold_p).expect("gold");
    let m = DualRingPrfMemberPublic256 {
        legendre_key_le: u256_to_le_bytes(&leg.k),
        gold_key_le: u256_to_le_bytes(&gold.k),
    };
    (m, leg, gold)
}

#[test]
fn dualring_prf_sign_verify_roundtrip() {
    let (m0, _l0, _g0) = member_from_seed(0xA1);
    let (m1, l1, g1) = member_from_seed(0xB2);
    let ring = [m0, m1];
    let msg = b"hello-dualring-prf";
    let mut rng = ChaCha20Rng::from_seed([0xC0u8; 32]);
    let sig = sign_dualring_prf_u256(&mut rng, &ring, 1, &l1, &g1, msg).expect("sign");
    verify_dualring_prf_u256(&ring, 1, msg, &sig).expect("verify");
}

#[test]
fn dualring_prf_rejects_tampered_challenge() {
    let (m0, l0, g0) = member_from_seed(0x01);
    let (m1, _l1, _g1) = member_from_seed(0x02);
    let ring = [m0, m1];
    let msg = b"tamper";
    let mut rng = ChaCha20Rng::from_seed([0x01u8; 32]);
    let mut sig = sign_dualring_prf_u256(&mut rng, &ring, 0, &l0, &g0, msg).expect("sign");
    sig.challenge[0] ^= 0xFF;
    let e = verify_dualring_prf_u256(&ring, 0, msg, &sig).unwrap_err();
    assert_eq!(e, DualRingPrfError::Rejected);
}

#[test]
fn dualring_prf_batch_two() {
    let (m0, l0, g0) = member_from_seed(0x11);
    let (m1, l1, g1) = member_from_seed(0x22);
    let ring = [m0, m1];
    let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
    let s0 = sign_dualring_prf_u256(&mut rng, &ring, 0, &l0, &g0, b"m0").expect("s0");
    let s1 = sign_dualring_prf_u256(&mut rng, &ring, 1, &l1, &g1, b"m1").expect("s1");
    let items = vec![(b"m0".to_vec(), 0, s0), (b"m1".to_vec(), 1, s1)];
    verify_dualring_prf_batch_u256(&ring, &items).expect("batch");
}
