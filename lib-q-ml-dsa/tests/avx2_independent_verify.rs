//! Diagnostic for the ML-DSA AVX2 reduce defect: is the AVX2 ("simd256") ML-DSA-44 sigGen output from the ACVP
//! vector a VALID-BUT-DIFFERENT signature, or a WRONG one?
//!
//! The cross-implementation check that used to live here verified the AVX2 signature with the
//! third-party `fips204` crate. That dev-dependency is gone: lib-Q keeps no third-party FIPS 204
//! implementation in its test graph. Conformance of the AVX2 path is covered byte for byte by the NIST ACVP sigGen
//! vectors in `tests/acvp.rs`, which compare against NIST's expected signatures rather than
//! against any implementation's own verify(). What remains here is the determinism check.
#![cfg(all(feature = "simd256", feature = "acvp", feature = "mldsa44"))]
#![allow(deprecated)]
use lib_q_ml_dsa::{MLDSASigningKey, ml_dsa_44};

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn avx2_sign_internal_is_deterministic_across_repeated_calls_same_process() {
    let sk_hex = include_str!("acvp_repro_sk.hex");
    let msg_hex = include_str!("acvp_repro_msg.hex");
    let sk_bytes = from_hex(sk_hex.trim());
    let msg_bytes = from_hex(msg_hex.trim());
    let rnd = [0u8; 32];
    let sk_arr: [u8; 2560] = sk_bytes.clone().try_into().unwrap();

    let first = ml_dsa_44::sign_internal(&MLDSASigningKey::new(sk_arr), &msg_bytes, rnd)
        .unwrap()
        .as_slice()
        .to_vec();
    for i in 0..50 {
        let sig = ml_dsa_44::sign_internal(&MLDSASigningKey::new(sk_arr), &msg_bytes, rnd)
            .unwrap()
            .as_slice()
            .to_vec();
        assert_eq!(
            sig, first,
            "sign_internal produced a DIFFERENT signature on call {i} for the SAME (sk, message, rnd) \
             within the same process -- nondeterminism, not just a different valid rejection outcome"
        );
    }
    eprintln!(
        "first 32 bytes of the (repeated, same-process) signature: {:02x?}",
        &first[..32]
    );
}
