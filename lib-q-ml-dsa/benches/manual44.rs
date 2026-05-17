use lib_q_ml_dsa::ml_dsa_44::{
    self,
    MLDSA44KeyPair,
    MLDSA44Signature,
};
use lib_q_ml_dsa::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};

mod bench_utils;

fn main() {
    bench_group_libcrux!(
        "44",
        "portable",
        ml_dsa_44::portable,
        MLDSA44KeyPair,
        MLDSA44Signature
    );
    #[cfg(feature = "simd128")]
    bench_group_libcrux!(
        "44",
        "neon",
        ml_dsa_44::neon,
        MLDSA44KeyPair,
        MLDSA44Signature
    );
    #[cfg(feature = "simd256")]
    bench_group_libcrux!(
        "44",
        "avx2",
        ml_dsa_44::avx2,
        MLDSA44KeyPair,
        MLDSA44Signature
    );

    bench_group_fips204!("44", fips204::ml_dsa_44, 2420);
}
