//! HQC compliance suite.
//!
//! These modules previously sat under `tests/compliance/` behind a `mod.rs`, which cargo does
//! not treat as a test target — so they were never compiled and had rotted against the current
//! API. This `main.rs` makes them a real target again.
//!
//! Byte-exact KAT verification is *not* here: it lives in `tests/nist_kem_kat.rs`, which checks
//! against the official NIST `.rsp` vectors.

mod cross_implementation;
mod parameter_validation;
mod prng_determinism;
