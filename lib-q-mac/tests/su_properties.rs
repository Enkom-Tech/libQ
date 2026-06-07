//! Bounded-query simulations documenting SU stability and exclusiveness properties.

use lib_q_mac::{
    QcwMac,
    QcwMacKey,
};
use lib_q_random::new_deterministic_rng;

const QUERY_BUDGET: usize = 64;

fn seed_from_u64(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&seed.to_le_bytes());
    out
}

#[test]
fn su_stability_queried_tags_verify() {
    let mut rng = new_deterministic_rng(seed_from_u64(0x5155_0001));
    let key = QcwMacKey::generate(&mut rng);
    for i in 0..QUERY_BUDGET {
        let msg = format!("msg-{i}");
        let ad = format!("ad-{i}");
        let tag = QcwMac::sign(&key, msg.as_bytes(), ad.as_bytes());
        assert!(QcwMac::verify(&key, msg.as_bytes(), ad.as_bytes(), &tag));
    }
}

#[test]
fn su_exclusiveness_tamper_rejects() {
    let mut rng = new_deterministic_rng(seed_from_u64(0x5155_0002));
    let key = QcwMacKey::generate(&mut rng);
    let msg = b"novel-message";
    let ad = b"novel-ad";
    let tag = QcwMac::sign(&key, msg, ad);
    let mut bad = tag;
    bad[3] ^= 0x40;
    assert!(!QcwMac::verify(&key, msg, ad, &bad));
}
