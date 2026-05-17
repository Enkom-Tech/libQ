//! Ensures `libq::zkp::plonky` resolves when `zkp-plonky` is enabled on the umbrella crate.

use libq::zkp::plonky::uni_stark::ProverError;

#[test]
fn umbrella_zkp_plonky_uni_stark_type_visible() {
    assert!(core::mem::size_of::<ProverError>() > 0);
}
