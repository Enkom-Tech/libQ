//! Isolated fixed-weight sampler harness.
//!
//! `tests/hardened_dudect_smoke.rs` times the whole hardened HQC *decapsulation* -- useful for
//! catching gross regressions, but useless for aiming a future power/EM probe at the one
//! function this crate's `hardened` feature specifically hardens:
//! `HqcPke::vect_generate_random_support1` / `vect_generate_random_support2`. See
//! `SECURITY.md`'s "Power/EM side channel on fixed-weight sampling" section (ePrint
//! 2026/1462) for why those two functions, and only those two, are the attacked surface.
//!
//! This file isolates that call boundary: every test here calls only the sampler, with no
//! surrounding keygen/encrypt/decrypt work interleaved, so a trigger placed immediately
//! before/after one of these calls captures exactly the sampler and nothing else -- narrower
//! than the whole-KEM smoke, which is the acceptance criterion this file exists to satisfy.
//! Building and running a power/EM trace against it is explicitly OUT of scope here (no
//! oscilloscope/EM probe available for this work); this only proves the isolated call boundary is
//! correct and reachable independent of the rest of the KEM.
//!
//! Runs under both the default and `hardened` builds (no `required-features`): default
//! features (`std`, `alloc`, `random`) already make `HqcPke`/`Hqc{1,3,5}Params` compile, and the
//! point of this file is to give a stable probe target regardless of which build a future
//! evaluation targets. Byte-identity between the two builds for full KEM output is proven
//! separately by running `tests/nist_kem_kat.rs` with and without `--features hardened` (see
//! `SECURITY.md`, "Recommendations"); this file checks the sampler's own output contract
//! (correct weight, no duplicates, in-range, deterministic for a fixed XOF seed) in isolation.

use lib_q_hqc::hqc_pke::HqcPke;
use lib_q_hqc::internal::shake256::Shake256Xof;
use lib_q_hqc::{Hqc1Params, Hqc3Params, Hqc5Params, HqcParams};

fn xof_for(seed: &[u8; 32], domain: u8) -> Shake256Xof {
    let mut xof = Shake256Xof::new();
    xof.init_with_domain(seed, domain).expect("shake256 init");
    xof
}

/// PROBE TARGET 1: `vect_generate_random_support1` in complete isolation -- weight `OMEGA`,
/// the long-term secret (`x`, `y`) sampler ePrint 2026/1462's first attack targets directly
/// (100% key recovery, 900,000 distinguisher calls, unmasked implementation).
fn isolated_support1<P: HqcParams>(seed: &[u8; 32]) -> Vec<u32> {
    let pke = HqcPke::<P>::new().expect("HqcPke::new");
    let mut xof = xof_for(seed, 1);
    let mut support = vec![0u32; P::OMEGA];
    pke.vect_generate_random_support1(&mut xof, &mut support, P::OMEGA)
        .expect("vect_generate_random_support1");
    support
}

/// PROBE TARGET 2: `vect_generate_random_support2` in isolation -- weight `OMEGA_E`, the
/// ephemeral encryption-noise sampler. Same attack class, lower severity (not the long-term
/// secret) per `SECURITY.md`.
fn isolated_support2<P: HqcParams>(seed: &[u8; 32]) -> Vec<u32> {
    let pke = HqcPke::<P>::new().expect("HqcPke::new");
    let mut xof = xof_for(seed, 2);
    let mut support = vec![0u32; P::OMEGA_E];
    pke.vect_generate_random_support2(&mut xof, &mut support, P::OMEGA_E)
        .expect("vect_generate_random_support2");
    support
}

fn assert_valid_support<P: HqcParams>(support: &[u32], weight: usize) {
    assert_eq!(
        support.len(),
        weight,
        "support vector must have `weight` entries"
    );
    for &v in support {
        assert!(
            (v as usize) < P::N,
            "support value {v} out of range [0, {})",
            P::N
        );
    }
    let mut sorted = support.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        weight,
        "support set must have exactly `weight` DISTINCT values -- a duplicate here means the \
         (possibly branchless, under `hardened`) duplicate-check regressed"
    );
}

macro_rules! isolated_tests_for {
    ($mod_name:ident, $params:ty) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn support1_isolated_is_valid_and_deterministic() {
                let seed = [0x11u8; 32];
                let a = isolated_support1::<$params>(&seed);
                let b = isolated_support1::<$params>(&seed);
                assert_valid_support::<$params>(&a, <$params>::OMEGA);
                assert_eq!(a, b, "same XOF seed must reproduce the same support set");
            }

            #[test]
            fn support2_isolated_is_valid_and_deterministic() {
                let seed = [0x22u8; 32];
                let a = isolated_support2::<$params>(&seed);
                let b = isolated_support2::<$params>(&seed);
                assert_valid_support::<$params>(&a, <$params>::OMEGA_E);
                assert_eq!(a, b, "same XOF seed must reproduce the same support set");
            }

            #[test]
            fn support1_isolated_varies_with_seed() {
                let a = isolated_support1::<$params>(&[0x33u8; 32]);
                let b = isolated_support1::<$params>(&[0x44u8; 32]);
                assert_ne!(
                    a, b,
                    "different XOF seeds must not collide on such a short run"
                );
            }

            #[test]
            fn support2_isolated_varies_with_seed() {
                let a = isolated_support2::<$params>(&[0x55u8; 32]);
                let b = isolated_support2::<$params>(&[0x66u8; 32]);
                assert_ne!(
                    a, b,
                    "different XOF seeds must not collide on such a short run"
                );
            }
        }
    };
}

isolated_tests_for!(hqc128, Hqc1Params);
isolated_tests_for!(hqc192, Hqc3Params);
isolated_tests_for!(hqc256, Hqc5Params);

/// Tight repeated-invocation loop over ONLY the sampler -- the shape a power/EM harness would
/// actually drive (many back-to-back calls with independent seeds, no other crypto operation
/// interleaved), isolated from full keygen. Not a timing/power assertion itself -- see the
/// module doc comment for why that is out of scope here; this is the call boundary a future
/// instrumented evaluation attaches a trigger to.
#[test]
fn support1_isolated_tight_loop_probe_target() {
    for i in 0..64u8 {
        let seed = [i; 32];
        let support = isolated_support1::<Hqc1Params>(&seed);
        assert_valid_support::<Hqc1Params>(&support, Hqc1Params::OMEGA);
    }
}

#[test]
fn support2_isolated_tight_loop_probe_target() {
    for i in 0..64u8 {
        let seed = [i; 32];
        let support = isolated_support2::<Hqc1Params>(&seed);
        assert_valid_support::<Hqc1Params>(&support, Hqc1Params::OMEGA_E);
    }
}
