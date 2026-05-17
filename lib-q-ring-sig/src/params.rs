//! Parameter documentation for federation ring openings.
//!
//! Wire sizes and soundness margins follow the [`lib_q_lattice_zkp::AjtaiParameters`]
//! chosen by the integrator. Typical pilot settings reuse ML-DSA-65–compatible
//! `tau` and infinity-norm bounds from lattice ZKP examples.

/// Recommended Fiat–Shamir parameters for pilot integrations (ML-DSA-65 style).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingSigParams {
    /// Sparse ternary challenge weight (e.g. 39 or 49).
    pub tau: usize,
    /// Infinity-norm bound on aggregated responses (prover-side abort).
    pub z_inf_bound: i32,
    /// Maximum prover retries for rejection sampling.
    pub max_prove_attempts: usize,
}

impl RingSigParams {
    /// Pilot profile aligned with `lib-q-lattice-zkp` unit tests.
    #[must_use]
    pub fn mldsa65_pilot() -> Self {
        Self {
            tau: 39,
            z_inf_bound: 20_000_000,
            max_prove_attempts: 512,
        }
    }

    /// NIST security category 1–oriented pilot (sparse challenge weight aligned with ML-DSA-44 examples).
    #[must_use]
    pub fn nist_security_category_1() -> Self {
        Self {
            tau: 39,
            z_inf_bound: 20_000_000,
            max_prove_attempts: 512,
        }
    }

    /// NIST security category 3–oriented pilot (ML-DSA-65–style `tau` / response bound).
    #[must_use]
    pub fn nist_security_category_3() -> Self {
        Self {
            tau: 49,
            z_inf_bound: 30_000_000,
            max_prove_attempts: 768,
        }
    }

    /// NIST security category 5–oriented pilot (ML-DSA-87–style `tau` / response bound).
    #[must_use]
    pub fn nist_security_category_5() -> Self {
        Self {
            tau: 60,
            z_inf_bound: 40_000_000,
            max_prove_attempts: 1024,
        }
    }
}
