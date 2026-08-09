//! SLH-DSA (FIPS 205) object sizes (bytes) shared across the workspace.
//!
//! Single source of truth consumed by `lib-q-core` (`SecurityConstants`). The real
//! implementation crate, `lib-q-slh-dsa`, derives its own sizes from the type-level
//! `SkLen` / `VkLen` / `SigLen` associated `typenum` constants on each parameter set (see
//! `ParameterSet` in `src/lib.rs`) and carries a conformance test asserting equality against
//! the constants here.
//!
//! `lib-q-types` must not depend on `lib-q-slh-dsa` (that would cycle back through
//! `lib-q-core`, which `lib-q-slh-dsa` depends on), so the FIPS 205 "f" (fast) parameter-set
//! sizes are listed here as plain literals rather than re-derived.

/// SLH-DSA-SHA2-128f / SHAKE-128f public key length (`2 * N`, N = 16).
pub const SLHDSA_128F_PUBLIC_KEY_BYTES: usize = 32;
/// SLH-DSA-SHA2-128f / SHAKE-128f secret key length (`4 * N`, N = 16).
pub const SLHDSA_128F_SECRET_KEY_BYTES: usize = 64;
/// SLH-DSA-SHA2-128f / SHAKE-128f signature length.
pub const SLHDSA_128F_SIGNATURE_BYTES: usize = 17_088;

/// SLH-DSA-SHA2-192f / SHAKE-192f public key length (`2 * N`, N = 24).
pub const SLHDSA_192F_PUBLIC_KEY_BYTES: usize = 48;
/// SLH-DSA-SHA2-192f / SHAKE-192f secret key length (`4 * N`, N = 24).
pub const SLHDSA_192F_SECRET_KEY_BYTES: usize = 96;
/// SLH-DSA-SHA2-192f / SHAKE-192f signature length.
pub const SLHDSA_192F_SIGNATURE_BYTES: usize = 35_664;

/// SLH-DSA-SHA2-256f / SHAKE-256f public key length (`2 * N`, N = 32).
pub const SLHDSA_256F_PUBLIC_KEY_BYTES: usize = 64;
/// SLH-DSA-SHA2-256f / SHAKE-256f secret key length (`4 * N`, N = 32).
pub const SLHDSA_256F_SECRET_KEY_BYTES: usize = 128;
/// SLH-DSA-SHA2-256f / SHAKE-256f signature length.
pub const SLHDSA_256F_SIGNATURE_BYTES: usize = 49_856;
