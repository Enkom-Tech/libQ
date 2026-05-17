//! Statistical helpers for TVLA-style and timing-based leakage smoke tests.
#![forbid(unsafe_code)]

pub mod dudect;
pub mod evaluation;
pub mod tvla_synthetic;

#[cfg(feature = "privacy")]
pub mod privacy_workloads;

/// Configuration for TVLA-style *t*-tests.
#[derive(Clone, Debug)]
pub struct TvlaConfig {
    /// Absolute *t* threshold (e.g. 4.5 for first-order screening).
    pub abs_t_threshold: f64,
}

impl Default for TvlaConfig {
    fn default() -> Self {
        Self {
            abs_t_threshold: 4.5,
        }
    }
}

/// Welch’s *t*-statistic for two samples (unequal variances).
pub fn welch_t_statistic(a: &[f64], b: &[f64]) -> Option<f64> {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    if na < 2.0 || nb < 2.0 {
        return None;
    }
    let mean_a = a.iter().sum::<f64>() / na;
    let mean_b = b.iter().sum::<f64>() / nb;
    let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (na - 1.0);
    let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (nb - 1.0);
    let se = (var_a / na + var_b / nb).sqrt();
    if se == 0.0 {
        return None;
    }
    Some((mean_a - mean_b) / se)
}

/// Returns `true` if \\(|t| < \\) `cfg.abs_t_threshold`.
pub fn tvla_passes(cfg: &TvlaConfig, fixed: &[f64], random: &[f64]) -> bool {
    match welch_t_statistic(fixed, random) {
        Some(t) => t.abs() < cfg.abs_t_threshold,
        None => false,
    }
}

/// Collect `n` timing samples using `std::time::Instant` (wall clock).
pub fn sample_wall_times<F: FnMut()>(mut f: F, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = std::time::Instant::now();
        f();
        out.push(t0.elapsed().as_secs_f64());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welch_near_identical_means_small_t() {
        let a: Vec<f64> = (0..100).map(|i| i as f64 * 1e-9).collect();
        let b: Vec<f64> = (0..100).map(|i| i as f64 * 1e-9 + 1e-12).collect();
        let t = welch_t_statistic(&a, &b).expect("t");
        assert!(t.abs() < 4.5, "t={t}");
    }

    #[test]
    fn tvla_config_default_threshold() {
        let cfg = TvlaConfig::default();
        let fixed = vec![1.0, 1.01, 0.99, 1.02];
        let random = vec![1.0, 1.0, 1.0, 1.0];
        assert!(tvla_passes(&cfg, &fixed, &random));
    }
}

#[cfg(all(test, feature = "mlkem"))]
mod mlkem_smoke {
    use lib_q_ml_kem::{
        Decapsulate,
        Encapsulate,
        KemCore,
        MlKem768,
    };

    #[test]
    fn kem_round_trip_hardened() {
        let mut rng = lib_q_random::LibQRng::new_secure().expect("secure rng");
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss1) = ek.encapsulate(&mut rng).unwrap();
        let ss2 = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }
}

#[cfg(all(test, feature = "privacy"))]
mod privacy_smoke {
    use lib_q_lattice_zkp::sigma::opening::sample_random_opening;
    use lib_q_lattice_zkp::{
        AjtaiCommitmentKey,
        AjtaiOpening,
        AjtaiParameters,
        BlindIssuance,
        BlindRequest,
        commit,
    };
    use lib_q_ring::{
        ModuleVec,
        Poly,
    };
    use lib_q_ring_sig::{
        MemberIssuerKey,
        RingSigParams,
        sign_federation_message,
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    use crate::privacy_workloads::{
        touch_blind_verify,
        touch_federation_digest,
        touch_federation_verify,
        touch_nullifier,
        touch_witness_nullifier,
    };

    #[inline]
    fn test_seed32(tag: u64) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&tag.to_le_bytes());
        seed
    }

    #[test]
    fn privacy_workloads_run() {
        let key = AjtaiCommitmentKey {
            seed: [0x55u8; 32],
            params: AjtaiParameters::new(2, 1),
        };
        let o = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let c = commit(&key, &o);
        let c2 = commit(&key, &o);
        let _ = touch_nullifier(&c, b"tvla-realm");
        let _ = touch_witness_nullifier(&o, b"tvla-realm");
        let _ = touch_federation_digest(core::slice::from_ref(&c));
        let _ = touch_federation_digest(&[c, c2]);
    }

    #[test]
    fn touch_blind_verify_accepts_round_trip_bundle() {
        let key = AjtaiCommitmentKey {
            seed: [0x6Au8; 32],
            params: AjtaiParameters::new(2, 1),
        };
        let p = RingSigParams::mldsa65_pilot();

        let user_opening = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let mut rng = ChaCha8Rng::from_seed(test_seed32(0x10A5_BEEF_u64));
        let (_req, st) =
            BlindIssuance::request(&mut rng, &key, user_opening).expect("blind request");
        let issuer_opening = sample_random_opening(&mut rng, &key);
        let blind_req = BlindRequest {
            com_blinded: st.com_blinded.clone(),
        };
        let resp = BlindIssuance::issuer_sign(
            &mut rng,
            &key,
            &blind_req,
            &issuer_opening,
            b"sca-blind-realm",
            p.tau,
            p.z_inf_bound,
            p.max_prove_attempts,
        )
        .expect("issuer sign");
        let bundle = BlindIssuance::finalize(st, resp).expect("finalize");

        touch_blind_verify(&key, &bundle, b"sca-blind-realm", p.tau, p.z_inf_bound)
            .expect("blind verify workload");
    }

    #[test]
    fn touch_federation_verify_accepts_signed_message() {
        let key = AjtaiCommitmentKey {
            seed: [0x77u8; 32],
            params: AjtaiParameters::new(2, 1),
        };
        let p = RingSigParams::mldsa65_pilot();
        let mut rng = ChaCha8Rng::from_seed(test_seed32(0xFEED_FACE_u64));

        let a = MemberIssuerKey::from_opening(
            &key,
            AjtaiOpening {
                message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
                randomness: ModuleVec(vec![Poly::zero()]),
            },
        )
        .expect("member a");
        let mut m_b = vec![Poly::zero(), Poly::zero()];
        m_b[0].coeffs[0] = 4;
        let b = MemberIssuerKey::from_opening(
            &key,
            AjtaiOpening {
                message: ModuleVec(m_b),
                randomness: ModuleVec(vec![Poly::zero()]),
            },
        )
        .expect("member b");
        let ring = [a.commitment.clone(), b.commitment.clone()];
        let proof = sign_federation_message(
            &mut rng,
            &key,
            &b.opening,
            &b.commitment,
            &ring,
            b"sca-fed-msg",
            p.tau,
            p.z_inf_bound,
            p.max_prove_attempts,
        )
        .expect("sign federation");

        touch_federation_verify(&key, &ring, 1, b"sca-fed-msg", &proof, p.tau, p.z_inf_bound)
            .expect("federation verify workload");
    }
}

#[cfg(all(test, feature = "mldsa"))]
mod mldsa_smoke {
    use lib_q_ml_dsa::ml_dsa_44::portable;

    #[test]
    fn sign_verify_smoke() {
        let kp = portable::generate_key_pair([0xA5u8; 32]);
        let msg = b"sca-test smoke";
        let sig = portable::sign(&kp.signing_key, msg, b"", [0x3Cu8; 32]).expect("sign");
        portable::verify(&kp.verification_key, msg, b"", &sig).expect("verify");
    }
}
