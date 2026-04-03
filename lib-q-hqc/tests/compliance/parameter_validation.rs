//! Wire-format KEM sizes must match `lib_q_types::hqc` (workspace single source of truth).

use lib_q_hqc::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
};
use lib_q_types::hqc;

#[test]
fn hqc_params_match_lib_q_types_wire_sizes() {
    assert_eq!(Hqc1Params::PUBLIC_KEY_BYTES, hqc::HQC128_PUBLIC_KEY_BYTES);
    assert_eq!(Hqc1Params::SECRET_KEY_BYTES, hqc::HQC128_SECRET_KEY_BYTES);
    assert_eq!(Hqc1Params::CIPHERTEXT_BYTES, hqc::HQC128_CIPHERTEXT_BYTES);

    assert_eq!(Hqc3Params::PUBLIC_KEY_BYTES, hqc::HQC192_PUBLIC_KEY_BYTES);
    assert_eq!(Hqc3Params::SECRET_KEY_BYTES, hqc::HQC192_SECRET_KEY_BYTES);
    assert_eq!(Hqc3Params::CIPHERTEXT_BYTES, hqc::HQC192_CIPHERTEXT_BYTES);

    assert_eq!(Hqc5Params::PUBLIC_KEY_BYTES, hqc::HQC256_PUBLIC_KEY_BYTES);
    assert_eq!(Hqc5Params::SECRET_KEY_BYTES, hqc::HQC256_SECRET_KEY_BYTES);
    assert_eq!(Hqc5Params::CIPHERTEXT_BYTES, hqc::HQC256_CIPHERTEXT_BYTES);
}
