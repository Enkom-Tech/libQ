//! Shared fixtures for the DKG integration tests.

/// Committee size used across the tests / KAT.
pub const PARTIES: u8 = 5;

/// Reconstruction threshold used across the tests / KAT.
pub const THRESHOLD: u8 = 3;

/// Deterministic RNG seeded from a single byte (KAT reproducibility).
#[must_use]
pub fn det_rng(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}
