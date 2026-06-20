//! Shared fixtures for the blind-token integration tests.

use lib_q_blind_token::{
    Credential,
    IssuerPublic,
    IssuerSecret,
    blind,
    blind_sign,
    keygen_issuer,
    unblind,
};

/// Issuer key identifier used across the tests / KAT.
pub const ISSUER_KEY_ID: u32 = 1;

/// Epoch label used across the tests / KAT.
pub const EPOCH: u32 = 7;

/// Deterministic RNG seeded from a single byte (KAT reproducibility).
#[must_use]
pub fn det_rng(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}

/// Run a full issuance and return the issuer key + a finalized credential.
pub fn issue(seed: u8) -> (IssuerPublic, IssuerSecret, Credential) {
    let mut rng = det_rng(seed);
    let (issuer_pub, issuer_priv) = keygen_issuer(&mut rng, ISSUER_KEY_ID, EPOCH);
    let (req, state) = blind(&mut rng, &issuer_pub);
    let resp = blind_sign(&mut rng, &issuer_priv, &req);
    let cred = unblind(&issuer_pub, &state, &resp).expect("valid credential");
    (issuer_pub, issuer_priv, cred)
}
