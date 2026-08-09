//! Diagnostic for t_f88bc433: is the AVX2 ("simd256") ML-DSA-44 sigGen output from the ACVP
//! vector a VALID-BUT-DIFFERENT signature, or a WRONG one?
//!
//! Independent check: derive the public key from the ACVP `sk` using the fips204 crate (a
//! separate, independently-implemented pure-Rust FIPS 204 implementation already a dev-dependency
//! of this crate for benchmarking), then verify the libQ AVX2-produced signature with fips204's
//! verifier -- NOT libQ's own verify(), which is what accepted these signatures unnoticed.
#![cfg(all(feature = "simd256", feature = "acvp", feature = "mldsa44"))]
#![allow(deprecated)]
use fips204::ml_dsa_44 as ref_impl;
use fips204::traits::{
    SerDes,
    Signer,
};
use lib_q_ml_dsa::{
    MLDSASigningKey,
    ml_dsa_44,
};

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn avx2_siggen_output_is_independently_valid() {
    // tcId 1, ML-DSA-44, from tests/kats/acvp-1_1_0_36/siggen/prompt.json
    let sk_hex = include_str!("acvp_repro_sk.hex");
    let msg_hex = include_str!("acvp_repro_msg.hex");
    let sk_bytes = from_hex(sk_hex.trim());
    let msg_bytes = from_hex(msg_hex.trim());
    let rnd = [0u8; 32];

    // 1) Produce the AVX2 (simd256) signature via libQ's multiplexed sign_internal, exactly as
    // tests/acvp.rs does. On this CPU (AVX2 present) this dispatches to the AVX2 path -- the one
    // under investigation.
    let sk_arr: [u8; 2560] = sk_bytes.clone().try_into().unwrap();
    let signature =
        ml_dsa_44::sign_internal(&MLDSASigningKey::new(sk_arr), &msg_bytes, rnd).unwrap();
    eprintln!(
        "AVX2 signature (first 64 bytes): {:02x?}",
        &signature.as_slice()[..64]
    );

    // 2) Derive the public key from the SAME sk bytes using fips204 (independent implementation)
    // and verify the AVX2-produced signature with FIPS204's own (portable, non-libQ) verifier.
    let fips_sk = ref_impl::PrivateKey::try_from_bytes(sk_arr).expect("fips204 sk decode failed");
    let fips_pk = fips_sk.get_public_key();

    // ACVP internal sign/verify uses the empty context (ML-DSA.Sign_internal / Verify_internal
    // wrap M as 0x00 || 0x00 || M, i.e. context = "").
    let sig_arr: [u8; 2420] = signature.as_slice().try_into().unwrap();
    let verified = ref_impl::_internal_verify(&fips_pk, &msg_bytes, &sig_arr, &[]);
    eprintln!("fips204 (independent) verify_internal of AVX2 signature: {verified}");

    assert!(
        verified,
        "AVX2-produced ML-DSA-44 signature FAILED independent verification by fips204 \
         (a separate, non-libQ implementation) -- the AVX2 output is not a valid ML-DSA \
         signature, not merely a different valid one"
    );

    // 3) For comparison, also confirm the fips204 pk agrees with the portable path's own encoding
    // expectations isn't needed here -- the load-bearing check is step 2's assert above. Print
    // whether portable's signature (already known, from the failing assertion in tests/acvp.rs,
    // to equal NIST's expected result) also verifies under this same derived pk, as a sanity
    // check that our pk derivation is right.
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
