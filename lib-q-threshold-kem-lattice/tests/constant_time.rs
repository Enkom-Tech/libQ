//! Structural (non-timing) pin on the FO⊥ re-encryption comparison in `kem.rs::ct_eq`, used by
//! `finish_decap` (reached via [`decapsulate_reference`]) to reject a ciphertext whose
//! re-encryption under the recovered message does not match the one presented.
//!
//! Does NOT measure wall-clock timing -- that is unmeasurable in a unit test and out of scope per
//! card t_043571b4 (a prior "constant-time" test compared two algorithms' speeds and was
//! rejected). What this pins is the code SHAPE: `ct_eq` folds `diff |= x ^ y` over every
//! coefficient of every `p` element and of `v`, with no early return -- a forged/mauled
//! ciphertext must be rejected regardless of WHICH coefficient, in WHICH ring element, diverges.
//! This is the crate's own documented "malformed-ct insider probe" surface (see
//! `lib-q-threshold-kem-lattice/README.md` and memory note threshold-kem-lattice-dealerless): a
//! comparison that only inspected a subset of coefficients would let a mauled ciphertext outside
//! that subset slip through as if it were valid, silently handing out a shared secret derived
//! from the WRONG ciphertext.
//!
//! Run in release: the shared `lib-q-dkg` lattice keygen is slow in debug (see roundtrip.rs).

use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::{
    decapsulate_reference,
    encapsulate,
    keygen_shares,
    setup,
};

const THRESHOLD: u8 = 3;
const PARTIES: u8 = 5;

/// Tamper a single coefficient of `ct.v` and of every `ct.p[k]`, at first/middle/last position
/// within each ring element, and confirm `decapsulate_reference` rejects every one of them. A
/// comparison that only examined a prefix of the coefficients (or only the `p` elements, or only
/// `v`) would still pass some of these while failing others -- exactly the asymmetry this test is
/// built to catch (see the `ct_eq` mutation below, `first_p_element_only`, which reproduces that
/// exact class of regression and is confirmed to make this test fail).
#[test]
fn tampered_ciphertext_rejected_at_every_coefficient_group() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x77u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    let subset = &keygen.secret_shares[..usize::from(THRESHOLD)];

    // Sanity: the untampered ciphertext must decapsulate.
    decapsulate_reference(&keygen.public_key, subset, &ct).expect("baseline decap must succeed");

    let n = ct.v.coeffs.len();
    let positions = [0usize, n / 2, n - 1];

    // Tamper v.
    for &pos in &positions {
        let mut bad = ct.clone();
        bad.v.coeffs[pos] ^= 1;
        assert!(
            decapsulate_reference(&keygen.public_key, subset, &bad).is_err(),
            "corruption at v.coeffs[{pos}] was not rejected"
        );
    }

    // Tamper every p[k], including the LAST one -- the group most likely to be skipped by a
    // truncated/early-exit comparison.
    for k in 0..ct.p.len() {
        for &pos in &positions {
            let mut bad = ct.clone();
            bad.p[k].coeffs[pos] ^= 1;
            assert!(
                decapsulate_reference(&keygen.public_key, subset, &bad).is_err(),
                "corruption at p[{k}].coeffs[{pos}] was not rejected"
            );
        }
    }
}
