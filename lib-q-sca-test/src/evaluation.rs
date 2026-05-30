//! Trace acquisition hooks for TVLA-style screening (first-order Welch *t*-test).
//!
//! Real evaluations require a DUT, a scope or EM probe, trace alignment, and preprocessing. This
//! module documents the acceptance criterion and exposes **numeric** helpers only; it does not
//! implement hardware drivers.

/// Recommended first-order leakage screening threshold on \\(|t|\\) (NIST-style TVLA literature).
pub const DEFAULT_TVLA_ABS_T: f64 = 4.5;

/// Suggested minimum trace count per class for exploratory screening (public labs often use 10⁶+).
pub const SUGGESTED_TRACES_PER_CLASS: u64 = 1_000_000;

/// Returns `true` if \\(|t| < \\) [`DEFAULT_TVLA_ABS_T`].
#[must_use]
pub fn first_order_screen_passes(t_statistic: f64) -> bool {
    t_statistic.abs() < DEFAULT_TVLA_ABS_T
}

/// Map a fixed-vs-random experiment to pass/fail using [`crate::welch_t_statistic`].
#[must_use]
pub fn screen_fixed_vs_random(fixed: &[f64], random: &[f64]) -> Option<bool> {
    crate::welch_t_statistic(fixed, random).map(first_order_screen_passes)
}

#[cfg(feature = "mldsa")]
use lib_q_ml_dsa::ml_dsa_44::portable;
#[cfg(feature = "mlkem")]
use lib_q_ml_kem::{
    Decapsulate,
    Encapsulate,
    KemCore,
    MlKem768,
};

/// Collect fixed-vs-random wall-clock timings for ML-KEM decapsulation (TVLA-style smoke harness).
///
/// The `fixed` class reuses one `(dk, ct)` pair. The `random` class rotates across independently
/// generated `(dk, ct)` pairs so the secret key material varies per sample.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_tvla_timings(samples: usize) -> (Vec<f64>, Vec<f64>) {
    let mut rng = lib_q_random::LibQRng::new_secure().expect("secure rng");
    let (fixed_dk, fixed_ek) = MlKem768::generate(&mut rng);
    let (fixed_ct, _fixed_ss) = fixed_ek.encapsulate(&mut rng).expect("encap");

    let mut random_pairs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
        random_pairs.push((dk, ct));
    }

    let fixed = crate::sample_wall_times(
        || {
            let ss = fixed_dk.decapsulate(&fixed_ct).expect("decap");
            std::hint::black_box(ss);
        },
        samples,
    );
    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let (dk, ct) = &random_pairs[random_idx];
            let ss = dk.decapsulate(ct).expect("decap");
            std::hint::black_box(ss);
            random_idx = (random_idx + 1) % random_pairs.len();
        },
        samples,
    );

    (fixed, random)
}

/// Collect fixed-vs-random wall-clock timings for ML-DSA signing (TVLA-style smoke harness).
///
/// The `fixed` class signs with one fixed signing key. The `random` class rotates signing keys.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_tvla_timings(samples: usize) -> (Vec<f64>, Vec<f64>) {
    let msg = b"lib-q-sca-tvla";
    let ctx = b"";
    let rnd = [0x42u8; 32];

    let fixed_kp = portable::generate_key_pair([0x11u8; 32]);
    let random_kps: Vec<_> = (0..samples)
        .map(|i| portable::generate_key_pair([i as u8; 32]))
        .collect();

    let fixed = crate::sample_wall_times(
        || {
            let sig = portable::sign(&fixed_kp.signing_key, msg, ctx, rnd).expect("sign");
            std::hint::black_box(sig);
        },
        samples,
    );
    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let sig =
                portable::sign(&random_kps[random_idx].signing_key, msg, ctx, rnd).expect("sign");
            std::hint::black_box(sig);
            random_idx = (random_idx + 1) % random_kps.len();
        },
        samples,
    );
    (fixed, random)
}

/// CI-friendly first-order TVLA screen for ML-KEM decapsulation.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_tvla_screen(samples: usize) -> Option<bool> {
    let (fixed, random) = mlkem_decaps_tvla_timings(samples);
    screen_fixed_vs_random(&fixed, &random)
}

/// CI-friendly first-order TVLA screen for ML-DSA signing.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_tvla_screen(samples: usize) -> Option<bool> {
    let (fixed, random) = mldsa_sign_tvla_timings(samples);
    screen_fixed_vs_random(&fixed, &random)
}

/// CI-friendly dudect-style timing screen for ML-KEM decapsulation.
#[cfg(feature = "mlkem")]
pub fn mlkem_decaps_dudect_screen(samples: usize, threshold: f64) -> bool {
    let (fixed, random) = mlkem_decaps_tvla_timings(samples);
    let mut joined = fixed;
    joined.extend(random);
    crate::dudect::timing_passes_loose(threshold, &joined)
}

/// CI-friendly dudect-style timing screen for ML-DSA signing.
#[cfg(feature = "mldsa")]
pub fn mldsa_sign_dudect_screen(samples: usize, threshold: f64) -> bool {
    let (fixed, random) = mldsa_sign_tvla_timings(samples);
    let mut joined = fixed;
    joined.extend(random);
    crate::dudect::timing_passes_loose(threshold, &joined)
}

/// Collect fixed-vs-random wall-clock timings for the hardened lattice-ZKP opening prover.
///
/// The `fixed` class re-proves one fixed token opening; the `random` class rotates token
/// header fields so the witness varies per sample. The hardened prover runs a fixed
/// `max_attempts` rejection loop, so its wall time should be independent of which class is
/// proved — that input-independence is the property under test.
#[cfg(feature = "lattice-zkp-hardened")]
pub fn lattice_zkp_prove_opening_tvla_timings(samples: usize) -> (Vec<f64>, Vec<f64>) {
    use lib_q_lattice_zkp::{
        AjtaiCommitmentKey,
        LatticeZkpProfileV0,
        TOKEN_EPOCH_LEN,
        TOKEN_ORIGIN_LEN,
        TOKEN_SERIAL_LEN,
        commit,
        opening_from_token_fields,
    };

    use crate::privacy_workloads::touch_opening_prove;

    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: [0x42u8; 32],
        params: profile.ajtai.clone(),
    };
    let ctx = b"sca-test-lattice-zkp-prove";
    let mut rng = lib_q_random::LibQRng::new_secure().expect("secure rng");

    let fixed_serial = [0x11u8; TOKEN_SERIAL_LEN];
    let fixed_origin = [0x22u8; TOKEN_ORIGIN_LEN];
    let fixed_epoch = [0x33u8; TOKEN_EPOCH_LEN];
    let fixed_opening = opening_from_token_fields(2, 1, &fixed_serial, &fixed_origin, &fixed_epoch)
        .expect("opening");
    let fixed_com = commit(&key, &fixed_opening);

    let fixed = crate::sample_wall_times(
        || {
            let _ = touch_opening_prove(
                &mut rng,
                &key,
                &fixed_opening,
                &fixed_com,
                ctx,
                profile.tau,
                profile.z_inf_bound,
                profile.max_prove_attempts,
            );
        },
        samples,
    );

    let mut random_idx = 0usize;
    let random_openings: Vec<_> = (0..samples)
        .map(|i| {
            let serial = [i as u8; TOKEN_SERIAL_LEN];
            let origin = [i.wrapping_add(1) as u8; TOKEN_ORIGIN_LEN];
            let epoch = [i.wrapping_add(2) as u8; TOKEN_EPOCH_LEN];
            let opening =
                opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("opening");
            let com = commit(&key, &opening);
            (opening, com)
        })
        .collect();

    let random = crate::sample_wall_times(
        || {
            let (opening, com) = &random_openings[random_idx];
            let _ = touch_opening_prove(
                &mut rng,
                &key,
                opening,
                com,
                ctx,
                profile.tau,
                profile.z_inf_bound,
                profile.max_prove_attempts,
            );
            random_idx = (random_idx + 1) % random_openings.len();
        },
        samples,
    );

    (fixed, random)
}

/// Collect fixed-vs-random wall-clock timings for HQC KEM key generation.
///
/// The `fixed` class reuses one 48-byte KEM seed. The `random` class rotates seeds so
/// derived PKE material varies per sample.
#[cfg(feature = "hqc-hardened")]
pub fn hqc_keygen_tvla_timings<P: lib_q_hqc::HqcParams>(samples: usize) -> (Vec<f64>, Vec<f64>) {
    use lib_q_hqc::hqc_kem::HqcKem;

    let kem = HqcKem::<P>::new().expect("HQC KEM");
    let fixed_seed = [0x42u8; 48];
    let random_seeds: Vec<[u8; 48]> = (0..samples)
        .map(|i| {
            let mut seed = [0u8; 48];
            seed[0] = i as u8;
            seed[1] = i.wrapping_add(1) as u8;
            seed[2] = i.wrapping_add(2) as u8;
            seed
        })
        .collect();

    let fixed = crate::sample_wall_times(
        || {
            let (_pk, _sk) = kem.keygen_with_seed(&fixed_seed).expect("keygen");
            std::hint::black_box((_pk, _sk));
        },
        samples,
    );

    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let (_pk, _sk) = kem
                .keygen_with_seed(&random_seeds[random_idx])
                .expect("keygen");
            std::hint::black_box((_pk, _sk));
            random_idx = (random_idx + 1) % random_seeds.len();
        },
        samples,
    );

    (fixed, random)
}

/// Collect fixed-vs-random wall-clock timings for HQC KEM encapsulation.
///
/// The `fixed` class reuses one public key and one SHAKE256-PRNG stream (32-byte KEM
/// prefix consumed). The `random` class rotates keypairs and encapsulation PRNG seeds.
#[cfg(feature = "hqc-hardened")]
pub fn hqc_encapsulate_tvla_timings<P: lib_q_hqc::HqcParams>(
    samples: usize,
) -> (Vec<f64>, Vec<f64>) {
    use lib_q_hqc::hqc_kem::{
        HqcKem,
        HqcKemPublicKey,
    };
    use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
    use rand_core::Rng;

    let kem = HqcKem::<P>::new().expect("HQC KEM");
    let fixed_seed = [0x11u8; 48];
    let (fixed_pk, _) = kem.keygen_with_seed(&fixed_seed).expect("keygen");

    let random_pairs: Vec<([u8; 48], HqcKemPublicKey<P>)> = (0..samples)
        .map(|i| {
            let mut seed = [0u8; 48];
            seed[0] = i as u8;
            seed[3] = i.wrapping_add(3) as u8;
            let (pk, _sk) = kem.keygen_with_seed(&seed).expect("keygen");
            (seed, pk)
        })
        .collect();

    let fixed = crate::sample_wall_times(
        || {
            let mut rng = create_shake256_prng_rng(fixed_seed);
            let mut kem_prefix = [0u8; 32];
            rng.fill_bytes(&mut kem_prefix);
            let (ct, ss) = kem.encapsulate(&fixed_pk, &mut rng).expect("encapsulate");
            std::hint::black_box((ct, ss));
        },
        samples,
    );

    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let (seed, pk) = &random_pairs[random_idx];
            let mut rng = create_shake256_prng_rng(*seed);
            let mut kem_prefix = [0u8; 32];
            rng.fill_bytes(&mut kem_prefix);
            let (ct, ss) = kem.encapsulate(pk, &mut rng).expect("encapsulate");
            std::hint::black_box((ct, ss));
            random_idx = (random_idx + 1) % random_pairs.len();
        },
        samples,
    );

    (fixed, random)
}

/// Collect fixed-vs-random wall-clock timings for HQC KEM decapsulation.
///
/// The `fixed` class reuses one `(sk, ct)` pair. The `random` class rotates pairs.
#[cfg(feature = "hqc-hardened")]
pub fn hqc_decapsulate_tvla_timings<P: lib_q_hqc::HqcParams>(
    samples: usize,
) -> (Vec<f64>, Vec<f64>) {
    use lib_q_hqc::hqc_kem::HqcKem;
    use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
    use rand_core::Rng;

    let kem = HqcKem::<P>::new().expect("HQC KEM");
    let fixed_seed = [0x22u8; 48];
    let (fixed_pk, fixed_sk) = kem.keygen_with_seed(&fixed_seed).expect("keygen");
    let mut fixed_rng = create_shake256_prng_rng(fixed_seed);
    let mut kem_prefix = [0u8; 32];
    fixed_rng.fill_bytes(&mut kem_prefix);
    let (fixed_ct, _) = kem
        .encapsulate(&fixed_pk, &mut fixed_rng)
        .expect("encapsulate");

    let mut random_pairs = Vec::with_capacity(samples);
    for i in 0..samples {
        let mut seed = [0u8; 48];
        seed[0] = i as u8;
        seed[4] = i.wrapping_add(4) as u8;
        let (pk, sk) = kem.keygen_with_seed(&seed).expect("keygen");
        let mut rng = create_shake256_prng_rng(seed);
        let mut prefix = [0u8; 32];
        rng.fill_bytes(&mut prefix);
        let (ct, _) = kem.encapsulate(&pk, &mut rng).expect("encapsulate");
        random_pairs.push((sk, ct));
    }

    let fixed = crate::sample_wall_times(
        || {
            let ss = kem.decapsulate(&fixed_sk, &fixed_ct).expect("decapsulate");
            std::hint::black_box(ss);
        },
        samples,
    );

    let mut random_idx = 0usize;
    let random = crate::sample_wall_times(
        || {
            let (sk, ct) = &random_pairs[random_idx];
            let ss = kem.decapsulate(sk, ct).expect("decapsulate");
            std::hint::black_box(ss);
            random_idx = (random_idx + 1) % random_pairs.len();
        },
        samples,
    );

    (fixed, random)
}

#[cfg(feature = "hqc-hardened")]
macro_rules! hqc_tvla_screen_impl {
    ($params:ty, $timings:ident, $samples:expr) => {{
        let (fixed, random) = $timings::<$params>($samples);
        screen_fixed_vs_random(&fixed, &random)
    }};
}

#[cfg(feature = "hqc-hardened")]
macro_rules! hqc_dudect_screen_impl {
    ($params:ty, $timings:ident, $samples:expr, $threshold:expr) => {{
        let (fixed, random) = $timings::<$params>($samples);
        let mut joined = fixed;
        joined.extend(random);
        crate::dudect::timing_passes_loose($threshold, &joined)
    }};
}

/// CI-friendly first-order TVLA screen for HQC-128 key generation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_keygen_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc1Params, hqc_keygen_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-192 key generation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc192_keygen_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc3Params, hqc_keygen_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-256 key generation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc256_keygen_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc5Params, hqc_keygen_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-128 encapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_encapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc1Params, hqc_encapsulate_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-192 encapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc192_encapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc3Params, hqc_encapsulate_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-256 encapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc256_encapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc5Params, hqc_encapsulate_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-128 decapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_decapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc1Params, hqc_decapsulate_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-192 decapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc192_decapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc3Params, hqc_decapsulate_tvla_timings, samples)
}

/// CI-friendly first-order TVLA screen for HQC-256 decapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc256_decapsulate_tvla_screen(samples: usize) -> Option<bool> {
    hqc_tvla_screen_impl!(lib_q_hqc::Hqc5Params, hqc_decapsulate_tvla_timings, samples)
}

/// CI-friendly dudect-style timing screen for HQC-128 key generation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_keygen_dudect_screen(samples: usize, threshold: f64) -> bool {
    hqc_dudect_screen_impl!(
        lib_q_hqc::Hqc1Params,
        hqc_keygen_tvla_timings,
        samples,
        threshold
    )
}

/// CI-friendly dudect-style timing screen for HQC-128 encapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_encapsulate_dudect_screen(samples: usize, threshold: f64) -> bool {
    hqc_dudect_screen_impl!(
        lib_q_hqc::Hqc1Params,
        hqc_encapsulate_tvla_timings,
        samples,
        threshold
    )
}

/// CI-friendly dudect-style timing screen for HQC-128 decapsulation.
#[cfg(feature = "hqc-hardened")]
pub fn hqc128_decapsulate_dudect_screen(samples: usize, threshold: f64) -> bool {
    hqc_dudect_screen_impl!(
        lib_q_hqc::Hqc1Params,
        hqc_decapsulate_tvla_timings,
        samples,
        threshold
    )
}

/// CI-friendly dudect-style timing screen for hardened lattice-ZKP opening prove.
#[cfg(feature = "lattice-zkp-hardened")]
pub fn lattice_zkp_prove_opening_dudect_screen(samples: usize, threshold: f64) -> bool {
    let (fixed, random) = lattice_zkp_prove_opening_tvla_timings(samples);
    let mut joined = fixed;
    joined.extend(random);
    crate::dudect::timing_passes_loose(threshold, &joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_sanity() {
        assert!(first_order_screen_passes(0.1));
        assert!(!first_order_screen_passes(10.0));
    }

    #[cfg(feature = "mlkem")]
    #[test]
    fn mlkem_tvla_and_dudect_smoke() {
        let _ = mlkem_decaps_tvla_screen(32).expect("t-stat");
        let _ = mlkem_decaps_dudect_screen(32, DEFAULT_TVLA_ABS_T);
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn mldsa_tvla_and_dudect_smoke() {
        let _ = mldsa_sign_tvla_screen(32).expect("t-stat");
        let _ = mldsa_sign_dudect_screen(32, DEFAULT_TVLA_ABS_T);
    }

    #[cfg(feature = "lattice-zkp-hardened")]
    #[test]
    fn lattice_zkp_hardened_prove_dudect_smoke() {
        let _ = lattice_zkp_prove_opening_dudect_screen(16, DEFAULT_TVLA_ABS_T);
    }

    #[cfg(feature = "hqc-hardened")]
    #[test]
    fn hqc_hardened_tvla_and_dudect_smoke() {
        // HQC-128 only in CI smoke; 192/256 are exercised by `self_cert` full battery.
        const SAMPLES: usize = 4;
        let _ = hqc128_keygen_tvla_screen(SAMPLES).expect("hqc128 keygen t-stat");
        let _ = hqc128_encapsulate_tvla_screen(SAMPLES).expect("hqc128 encaps t-stat");
        let _ = hqc128_decapsulate_tvla_screen(SAMPLES).expect("hqc128 decaps t-stat");
        let _ = hqc128_keygen_dudect_screen(SAMPLES, DEFAULT_TVLA_ABS_T);
        let _ = hqc128_encapsulate_dudect_screen(SAMPLES, DEFAULT_TVLA_ABS_T);
        let _ = hqc128_decapsulate_dudect_screen(SAMPLES, DEFAULT_TVLA_ABS_T);
    }

    /// Wall-clock TVLA at scale (slow). Run: `cargo test -p lib-q-sca-test -- --ignored --nocapture`.
    ///
    /// Prints Welch *t* for manual review. The |*t*| < 4.5 gate targets **instrumented** traces; OS
    /// scheduling noise routinely violates it for `std::time::Instant` wall times, so we do not assert
    /// that threshold here.
    #[cfg(feature = "mldsa")]
    #[test]
    #[ignore = "slow: ~10k sign timings per class; for harness scale only"]
    fn mldsa_sign_tvla_screen_10k_welch_report() {
        const SAMPLES: usize = 10_000;
        let (fixed, random) = mldsa_sign_tvla_timings(SAMPLES);
        let t = crate::welch_t_statistic(&fixed, &random).expect("welch t-statistic");
        eprintln!(
            "ML-DSA Sign wall-clock Welch t (n={SAMPLES} per class): {t:.6} (first-order EM/TVLA gate is |t| < {DEFAULT_TVLA_ABS_T})"
        );
        assert!(t.is_finite(), "t-statistic must be finite");
    }
}
