use lib_q_ml_dsa::ml_dsa_65::{
    self,
    MLDSA65KeyPair,
    MLDSA65Signature,
};
use lib_q_ml_dsa::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};

mod bench_utils;

fn main() {
    bench_group_libcrux!(
        "65",
        "portable",
        ml_dsa_65::portable,
        MLDSA65KeyPair,
        MLDSA65Signature
    );
    #[cfg(feature = "simd128")]
    bench_group_libcrux!(
        "65",
        "neon",
        ml_dsa_65::neon,
        MLDSA65KeyPair,
        MLDSA65Signature
    );
    #[cfg(feature = "simd256")]
    bench_group_libcrux!(
        "65",
        "avx2",
        ml_dsa_65::avx2,
        MLDSA65KeyPair,
        MLDSA65Signature
    );

    bench_group_fips204!("65", fips204::ml_dsa_65, 3309);
}
