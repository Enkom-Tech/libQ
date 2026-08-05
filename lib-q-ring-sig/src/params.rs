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
    /// Infinity-norm bound on aggregated responses.
    ///
    /// This is a **verifier-side soundness gate**, not merely a prover-side abort threshold: the
    /// verifier rejects any opening whose response exceeds it
    /// (`lib_q_lattice_zkp::sigma::opening::verify_opening` /
    /// `verify_dual_ring_opening` -> `module_norm_within_bound`). `lib_q_ring::Poly::infinity_norm`
    /// centres coefficients to `(-q/2, q/2]` before taking the absolute value, so **any value at
    /// or above `q/2` (`4_190_208` for the ML-DSA modulus) makes this check unconditionally pass**
    /// — a gate that can never reject, and Module-SIS binding of the Ajtai commitment is not
    /// enforced. Use [`lib_q_lattice_zkp::profile::V0_Z_INF_BOUND`], the already-audited frozen
    /// bound ("soundness fix #5" in that crate), not a hand-picked literal.
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
            z_inf_bound: lib_q_lattice_zkp::profile::V0_Z_INF_BOUND,
            max_prove_attempts: 512,
        }
    }

    /// NIST security category 1–oriented pilot (sparse challenge weight aligned with ML-DSA-44 examples).
    #[must_use]
    pub fn nist_security_category_1() -> Self {
        Self {
            tau: 39,
            z_inf_bound: lib_q_lattice_zkp::profile::V0_Z_INF_BOUND,
            max_prove_attempts: 512,
        }
    }

    /// NIST security category 3–oriented pilot (ML-DSA-65–style `tau` / response bound).
    #[must_use]
    pub fn nist_security_category_3() -> Self {
        Self {
            tau: 49,
            z_inf_bound: lib_q_lattice_zkp::profile::V0_Z_INF_BOUND,
            max_prove_attempts: 768,
        }
    }

    /// NIST security category 5–oriented pilot (ML-DSA-87–style `tau` / response bound).
    #[must_use]
    pub fn nist_security_category_5() -> Self {
        Self {
            tau: 60,
            z_inf_bound: lib_q_lattice_zkp::profile::V0_Z_INF_BOUND,
            max_prove_attempts: 1024,
        }
    }
}
