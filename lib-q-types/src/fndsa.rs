//! FN-DSA object sizes (bytes) shared across the workspace.
//!
//! Unlike the other families in this crate, these ARE genuinely derived at compile time from
//! `lib-q-fn-dsa-comm`'s own `const fn` formulas (`sign_key_size` / `vrfy_key_size` /
//! `signature_size`), not hand-maintained literals. `lib-q-fn-dsa-comm` has no dependency on
//! `lib-q-types` or `lib-q-core` (only `rand_core` / `cpufeatures`), so this edge is acyclic.
//!
//! This closes the exact bug class that motivated this module: `lib-q-core`'s
//! `SecurityConstants` once hand-copied `sign_key_size(10)` as the literal `2561`, which is
//! `sign_key_size` evaluated with logn=9's `nbits_fg` branch instead of logn=10's -- the real
//! value is `2305`. A hand-copied literal can silently drift from the formula; a `const`
//! initialized directly by calling the formula cannot.

use fn_dsa_comm::{
    sign_key_size,
    signature_size,
    vrfy_key_size,
};

/// FN-DSA-512 (logn = 9) secret (signing) key length.
pub const FNDSA512_SECRET_KEY_BYTES: usize = sign_key_size(9);
/// FN-DSA-512 (logn = 9) public (verifying) key length.
pub const FNDSA512_PUBLIC_KEY_BYTES: usize = vrfy_key_size(9);
/// FN-DSA-512 (logn = 9) signature length.
pub const FNDSA512_SIGNATURE_BYTES: usize = signature_size(9);

/// FN-DSA-1024 (logn = 10) secret (signing) key length.
pub const FNDSA1024_SECRET_KEY_BYTES: usize = sign_key_size(10);
/// FN-DSA-1024 (logn = 10) public (verifying) key length.
pub const FNDSA1024_PUBLIC_KEY_BYTES: usize = vrfy_key_size(10);
/// FN-DSA-1024 (logn = 10) signature length.
pub const FNDSA1024_SIGNATURE_BYTES: usize = signature_size(10);

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-evident by construction (these are `const fn` calls, not literals) -- kept as a
    /// readable regression pin for the historical 2561-vs-2305 bug.
    #[test]
    fn fn_dsa_1024_secret_key_matches_the_historical_correction() {
        assert_eq!(FNDSA1024_SECRET_KEY_BYTES, 2305);
        assert_eq!(FNDSA1024_PUBLIC_KEY_BYTES, 1793);
        assert_eq!(FNDSA1024_SIGNATURE_BYTES, 1280);
        assert_eq!(FNDSA512_SECRET_KEY_BYTES, 1281);
        assert_eq!(FNDSA512_PUBLIC_KEY_BYTES, 897);
        assert_eq!(FNDSA512_SIGNATURE_BYTES, 666);
    }
}
