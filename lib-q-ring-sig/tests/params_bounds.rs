//! Falsification tests for the ring-sig `z_inf_bound` no-op defect (lane `b-params`).
//!
//! `Poly::infinity_norm` centres coefficients to `(-q/2, q/2]` before taking the absolute value
//! (`lib-q-ring/src/poly.rs`), so no canonical (`[0, q)`-represented) `z` can ever exceed
//! `q/2 = 4_190_208`. Any `z_inf_bound` at or above that value makes the verifier's norm check
//! (`lib_q_lattice_zkp::util::module_norm_within_bound`) an unconditional pass — a gate that
//! cannot fail. `verify_dualring_lb`/`verify_federation_opening` cannot be used to observe this
//! directly: a tampered `z` also fails the linear opening equation, so `.is_err()` is true at
//! every bound and would not isolate the norm gate. These tests check the bound value itself and
//! call the norm gate directly instead.

use lib_q_lattice_zkp::util::module_norm_within_bound;
use lib_q_ring::Poly;
use lib_q_ring_sig::RingSigParams;

/// ML-DSA field modulus (`lib-q-ring::constants::FIELD_MODULUS`), restated here so the test does
/// not depend on a `pub` re-export of the constant.
const Q: i32 = 8_380_417;

#[test]
fn every_profile_bound_is_short_enough_to_bind() {
    for (name, p) in [
        ("mldsa65_pilot", RingSigParams::mldsa65_pilot()),
        (
            "nist_security_category_1",
            RingSigParams::nist_security_category_1(),
        ),
        (
            "nist_security_category_3",
            RingSigParams::nist_security_category_3(),
        ),
        (
            "nist_security_category_5",
            RingSigParams::nist_security_category_5(),
        ),
    ] {
        assert!(
            p.z_inf_bound < Q / 2,
            "{name}: z_inf_bound {} >= q/2 {} — the verifier's norm check can never reject",
            p.z_inf_bound,
            Q / 2,
        );
    }
}

#[test]
fn norm_gate_rejects_a_maximal_z() {
    // Maximal centred infinity-norm value any canonical (`[0, q)`-represented) coefficient can
    // reach: q/2 itself (see `lib-q-ring/src/poly.rs::infinity_norm`, and the exhaustive residue
    // scan in the architect's design.md §1.4 confirming the max is exactly q/2 = 4_190_208).
    let mut worst = Poly::zero();
    for c in worst.coeffs.iter_mut() {
        *c = Q / 2;
    }
    let p = RingSigParams::nist_security_category_1();
    assert!(
        !bool::from(module_norm_within_bound(
            core::slice::from_ref(&worst),
            p.z_inf_bound
        )),
        "a maximal-norm z (||z||_inf = q/2 = {}) must be rejected by the norm gate at bound {}",
        Q / 2,
        p.z_inf_bound,
    );

    // Positive control: an honestly-sized z (measured honest ||z||_inf <= 1_045_492 across every
    // path and ring size tried, design.md §3.2 PROBE 3/4) must still pass. Proves the gate is not
    // simply rejecting everything post-fix.
    let mut ok = Poly::zero();
    ok.coeffs[0] = 1_039_936;
    assert!(
        bool::from(module_norm_within_bound(
            core::slice::from_ref(&ok),
            p.z_inf_bound
        )),
        "an honestly-sized z (1_039_936) must still pass the norm gate at bound {}",
        p.z_inf_bound,
    );
}
