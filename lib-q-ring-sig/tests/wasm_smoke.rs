//! wasm-bindgen-test smoke: DualRing-LB pilot singleton on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    commit,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_random::new_deterministic_rng_no_std;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_random::new_secure_rng;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ring::{
    ModuleVec,
    Poly,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ring_sig::dualring_lb::{
    sign_dualring_lb,
    verify_dualring_lb,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use rand_core::TryRng;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

/// 32-byte seed for deterministic wasm tests: first 8 bytes are `tag` (little-endian); remainder
/// zero. Not secret. Used with [`new_deterministic_rng_no_std`] for reproducible `sign_dualring_lb` smoke.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[inline]
fn test_deterministic_seed32(tag: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&tag.to_le_bytes());
    s
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ring_sig_wasm_rng_smoke() {
    let mut rng = new_secure_rng().expect("secure rng");
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    rng.try_fill_bytes(&mut out_a).expect("fill a");
    rng.try_fill_bytes(&mut out_b).expect("fill b");

    assert!(
        out_a.iter().any(|b| *b != 0),
        "entropy buffer should not be all zero"
    );
    assert_ne!(out_a, out_b, "sequential outputs should differ");
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ring_sig_dualring_lb_pilot_wasm() {
    let key = AjtaiCommitmentKey {
        seed: [0x5Du8; 32],
        params: AjtaiParameters::new(2, 1),
    };
    // Witness must be non-trivial: if `com = A·wit` is zero, `c·com` vanishes and the opening
    // equation no longer binds the Fiat–Shamir transcript (wrong messages would still verify).
    let mut o = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    o.randomness.0[0].coeffs[0] = 1;
    let com = commit(&key, &o);
    let ring = [com.clone()];
    let msg = b"wasm-smoke";
    let mut rng = new_deterministic_rng_no_std(test_deterministic_seed32(0xC0FFEE_u64));
    let sig =
        sign_dualring_lb(&mut rng, &key, &o, &com, &ring, msg, 39, 20_000_000, 512).expect("sign");
    verify_dualring_lb(&key, &ring, msg, &sig, 39, 20_000_000).expect("verify");
    assert!(
        verify_dualring_lb(&key, &ring, b"other-message", &sig, 39, 20_000_000).is_err(),
        "verify must reject wrong message"
    );
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
