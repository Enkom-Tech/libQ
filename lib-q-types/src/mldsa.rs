//! ML-DSA (FIPS 204) object sizes (bytes) shared across the workspace.
//!
//! Single source of truth consumed by `lib-q-core` (`SecurityConstants`). The real
//! implementation crate, `lib-q-ml-dsa`, computes its own sizes from private `const fn`
//! formulas (`signing_key_size` / `verification_key_size` / `signature_size` in
//! `src/constants.rs`) and carries a conformance test asserting equality against the
//! constants here.
//!
//! `lib-q-types` must not depend on `lib-q-ml-dsa` (that would cycle back through
//! `lib-q-core`, which `lib-q-ml-dsa` depends on), so the FIPS 204 sizes are listed here as
//! plain literals rather than re-derived from the formula.

/// ML-DSA-44 public (verification) key length.
pub const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
/// ML-DSA-44 secret (signing) key length.
pub const MLDSA44_SECRET_KEY_BYTES: usize = 2560;
/// ML-DSA-44 signature length.
pub const MLDSA44_SIGNATURE_BYTES: usize = 2420;

/// ML-DSA-65 public (verification) key length.
pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 secret (signing) key length.
pub const MLDSA65_SECRET_KEY_BYTES: usize = 4032;
/// ML-DSA-65 signature length.
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;

/// ML-DSA-87 public (verification) key length.
pub const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
/// ML-DSA-87 secret (signing) key length.
pub const MLDSA87_SECRET_KEY_BYTES: usize = 4896;
/// ML-DSA-87 signature length.
pub const MLDSA87_SIGNATURE_BYTES: usize = 4627;
