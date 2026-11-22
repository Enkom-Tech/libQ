use lib_q_ml_dsa::ml_dsa_65::{self, MLDSA65KeyPair, MLDSA65Signature};
use lib_q_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};

mod bench_utils;

fn main() {
    bench_group_libcrux!(
        "65",
        "portable",
        ml_dsa_65::portable,
        MLDSA65KeyPair,
        MLDSA65Signature
    );
    #[cfg(all(feature = "simd128", target_arch = "aarch64"))]
    bench_group_libcrux!(
        "65",
        "neon",
        ml_dsa_65::neon,
        MLDSA65KeyPair,
        MLDSA65Signature
    );
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    bench_group_libcrux!(
        "65",
        "avx2",
        ml_dsa_65::avx2,
        MLDSA65KeyPair,
        MLDSA65Signature
    );
}
