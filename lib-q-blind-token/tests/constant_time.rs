//! Structural constant-time pin for `unblind()`'s credential-acceptance check
//! (`lib-q-blind-token/src/lattice/scheme.rs`, `centered_coeffs(&ax).ct_eq(&centered_coeffs(&u))`).
//!
//! These tests prove the CODE SHAPE — that a mismatch anywhere in the compared ring element is
//! rejected, including at the very last coefficient — NOT the timing itself. Timing cannot be
//! observed from a unit test, and this repo explicitly rejects wall-clock timing tests (see card
//! t_043571b4). The property that actually breaks under a short-circuiting comparator is
//! "rejects at every position"; that's what's pinned here, and it's demonstrated red against a
//! representative prefix-only comparator in the accompanying scratchpad log
//! (`scratchpad/audit-triage/fix-ct-tests-2.md`), matching the methodology used for lib-q-mac et
//! al. in commit f756fbc.

#[allow(dead_code)]
mod common;

use common::{
    EPOCH,
    ISSUER_KEY_ID,
    det_rng,
};
use lib_q_blind_token::{
    blind,
    blind_sign,
    keygen_issuer,
    unblind,
};

/// Baseline: an honestly-issued credential unblinds successfully.
#[test]
fn valid_credential_unblinds() {
    let mut rng = det_rng(1);
    let (issuer_pub, issuer_priv) = keygen_issuer(&mut rng, ISSUER_KEY_ID, EPOCH);
    let (req, state) = blind(&mut rng, &issuer_pub);
    let resp = blind_sign(&mut rng, &issuer_priv, &req);
    assert!(unblind(&issuer_pub, &state, &resp).is_some());
}

/// The verification equation is `A·x == d·a_tok + d0`, checked in constant time over the whole
/// centered-coefficient vector of the resulting ring element (`ax` vs `u`). Corrupting a single
/// coefficient of the issuer's GPV preimage response `x` — at ANY of the `N` positions of its
/// first component, exhaustively, including the last one — must be rejected. A short-circuiting
/// comparator that only checks a prefix of the compared ring element would miss corruption whose
/// effect (after the linear map `A·x`) lands only in later coefficients; this test would catch
/// that class of regression.
#[test]
fn corrupted_response_rejected_at_every_coefficient() {
    let mut rng = det_rng(2);
    let (issuer_pub, issuer_priv) = keygen_issuer(&mut rng, ISSUER_KEY_ID, EPOCH);
    let (req, state) = blind(&mut rng, &issuer_pub);
    let resp = blind_sign(&mut rng, &issuer_priv, &req);

    // Sanity: the unperturbed response does verify (otherwise the loop below would be vacuous).
    assert!(unblind(&issuer_pub, &state, &resp).is_some());

    let n = resp.x[0].coeffs.len();
    for j in 0..n {
        let mut bad_resp = resp.clone();
        // Flip one coefficient of the first preimage element; any nonzero perturbation of the
        // secret response must be caught, wherever in the vector it lands.
        bad_resp.x[0].coeffs[j] ^= 1;
        assert!(
            unblind(&issuer_pub, &state, &bad_resp).is_none(),
            "corruption of response coefficient {j} of {n} was not rejected"
        );
    }
}
