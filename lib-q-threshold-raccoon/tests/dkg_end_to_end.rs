//! Field-mismatch closure: a **dealerless** `lib-q-dkg` key drives this signer end-to-end.
//!
//! The DKG output (`SigningShare` / `VerificationKeySet`) is byte-identical to this crate's
//! `SecretShare` / public key, so the dealerless DKG is a drop-in keygen for the signer — no GF(256)
//! `lib-q-threshold-sig` involved. Run with `--release`.

use lib_q_dkg::{
    dkg_run_honest,
    setup as dkg_setup,
};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_raccoon::{
    SecretShare,
    ShareVerifier,
    ThresholdRaccoonPublicKey,
    combine_opening,
    sign,
    verify,
};

#[test]
fn dealerless_dkg_key_signs_and_verifies() {
    let mut rng = new_deterministic_rng([0x71u8; 32]);

    // Dealerless DKG (lib-q-dkg) → shares + group key.
    let kg = dkg_run_honest(&dkg_setup(), 5, 3, &mut rng).expect("dkg");

    // Reinterpret the DKG output as this signer's key material (byte-identical formats).
    let pk = ThresholdRaccoonPublicKey {
        threshold: kg.public_key.threshold,
        group_key: kg.public_key.group_key.clone(),
        share_verifiers: kg
            .public_key
            .share_verifiers
            .iter()
            .map(|v| ShareVerifier {
                index: v.index,
                verifying_key: v.verifying_key.clone(),
            })
            .collect(),
    };
    let shares: Vec<SecretShare> = kg
        .secret_shares
        .iter()
        .map(|s| SecretShare {
            index: s.index,
            threshold: s.threshold,
            share_bytes: s.share_bytes.clone(),
        })
        .collect();

    // Combine a threshold subset → sign → verify against the DKG group key.
    let subset: Vec<_> = shares.iter().take(3).cloned().collect();
    let opening = combine_opening(&subset).expect("combine");
    let msg = b"dealerless-dkg-then-sign";
    let sig = sign(&mut rng, &pk, &opening, msg).expect("sign");
    assert!(
        verify(&pk, msg, &sig),
        "dealerless DKG key must produce a verifying signature"
    );
    assert!(!verify(&pk, b"tampered", &sig), "wrong message must fail");
}
