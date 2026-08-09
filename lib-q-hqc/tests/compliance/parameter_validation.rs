//! Wire-format KEM sizes must match `lib_q_types::hqc` (workspace single source of truth).

use lib_q_hqc::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};
use lib_q_types::hqc;

#[test]
fn hqc_params_match_lib_q_types_wire_sizes() {
    // NOTE (card t_1558e72f sweep): `Hqc*Params::PUBLIC_KEY_BYTES` is *defined* as
    // `hqc::HQC*_PUBLIC_KEY_BYTES` (see `params.rs`), so comparing them here is a
    // constant checked only against its own source -- it cannot fail regardless of the value.
    // Replaced with an independently-derived check (32-byte seed + `VEC_N_SIZE_BYTES`), matching
    // the fix applied to the equivalent asserts in `params.rs`'s own test module.
    assert_eq!(
        Hqc1Params::PUBLIC_KEY_BYTES,
        32 + Hqc1Params::VEC_N_SIZE_BYTES
    );
    assert_eq!(Hqc1Params::SECRET_KEY_BYTES, hqc::HQC128_SECRET_KEY_BYTES);
    assert_eq!(Hqc1Params::CIPHERTEXT_BYTES, hqc::HQC128_CIPHERTEXT_BYTES);

    assert_eq!(
        Hqc3Params::PUBLIC_KEY_BYTES,
        32 + Hqc3Params::VEC_N_SIZE_BYTES
    );
    assert_eq!(Hqc3Params::SECRET_KEY_BYTES, hqc::HQC192_SECRET_KEY_BYTES);
    assert_eq!(Hqc3Params::CIPHERTEXT_BYTES, hqc::HQC192_CIPHERTEXT_BYTES);

    assert_eq!(
        Hqc5Params::PUBLIC_KEY_BYTES,
        32 + Hqc5Params::VEC_N_SIZE_BYTES
    );
    assert_eq!(Hqc5Params::SECRET_KEY_BYTES, hqc::HQC256_SECRET_KEY_BYTES);
    assert_eq!(Hqc5Params::CIPHERTEXT_BYTES, hqc::HQC256_CIPHERTEXT_BYTES);
}
