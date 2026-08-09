//! Card t_1558e72f: HQC public keys must be `seed_ek (32 bytes) || s (CEIL(N/8) bytes)` per the
//! HQC v5.0.0 (2025-08-22) specification (`PROVENANCE.md`'s cited reference). This test derives
//! the expected length from `VEC_N_SIZE_BYTES` directly rather than comparing a constant to its
//! own definition (see `params.rs`'s prior tautological asserts for that failure mode),
//! and adds a runtime leg so a serialization-only regression (constant right, encoder wrong) would
//! also be caught.

use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};

const SEED_EK_BYTES: usize = 32;

#[test]
fn public_key_constant_is_seed32_plus_ceil_n_over_8() {
    assert_eq!(
        Hqc1Params::PUBLIC_KEY_BYTES,
        SEED_EK_BYTES + Hqc1Params::VEC_N_SIZE_BYTES,
        "HQC-128 public key constant"
    );
    assert_eq!(
        Hqc3Params::PUBLIC_KEY_BYTES,
        SEED_EK_BYTES + Hqc3Params::VEC_N_SIZE_BYTES,
        "HQC-192 public key constant"
    );
    assert_eq!(
        Hqc5Params::PUBLIC_KEY_BYTES,
        SEED_EK_BYTES + Hqc5Params::VEC_N_SIZE_BYTES,
        "HQC-256 public key constant"
    );
}

fn keygen_pk_len<P: HqcParams>() -> usize {
    let pke = HqcPke::<P>::new().unwrap();
    let seed = [0u8; 32];
    let (pk, _sk) = pke.keygen_with_seed(&seed).unwrap();
    pk.as_bytes().len()
}

#[test]
fn keygen_output_matches_seed32_plus_ceil_n_over_8() {
    assert_eq!(
        keygen_pk_len::<Hqc1Params>(),
        SEED_EK_BYTES + Hqc1Params::VEC_N_SIZE_BYTES,
        "HQC-128 keygen output length"
    );
    assert_eq!(
        keygen_pk_len::<Hqc3Params>(),
        SEED_EK_BYTES + Hqc3Params::VEC_N_SIZE_BYTES,
        "HQC-192 keygen output length"
    );
    assert_eq!(
        keygen_pk_len::<Hqc5Params>(),
        SEED_EK_BYTES + Hqc5Params::VEC_N_SIZE_BYTES,
        "HQC-256 keygen output length"
    );
}
