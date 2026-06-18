//! Backend dispatch for the Rocca-S core.
//!
//! [`encrypt`] / [`decrypt`] select a hardware AES backend at runtime when the
//! corresponding `simd-*` feature is enabled and the CPU advertises AES support,
//! otherwise they fall back to the portable scalar implementation in
//! [`crate::state`]. All three backends are bit-for-bit equivalent; this is
//! enforced by `tests/simd_equivalence.rs`.

#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) mod aesni;
#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
pub(crate) mod neon;
pub(crate) mod runtime;

/// Encrypt `plaintext` into `out` (same length) and return the 256-bit tag.
#[inline]
pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    #[cfg(all(
        feature = "simd-aesni",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    {
        if runtime::has_aes() {
            // SAFETY: `has_aes()` confirmed the CPU supports the AES/SSE2 features
            // required by `aesni::encrypt`'s `target_feature` gate.
            return unsafe { aesni::encrypt(key, nonce, ad, plaintext, out) };
        }
    }
    #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
    {
        if runtime::has_aes() {
            // SAFETY: `has_aes()` confirmed ARMv8 AES support.
            return unsafe { neon::encrypt(key, nonce, ad, plaintext, out) };
        }
    }
    crate::state::encrypt(key, nonce, ad, plaintext, out)
}

/// Decrypt `ciphertext` into `out` (same length) and return the recomputed tag.
#[inline]
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    #[cfg(all(
        feature = "simd-aesni",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    {
        if runtime::has_aes() {
            // SAFETY: see `encrypt`.
            return unsafe { aesni::decrypt(key, nonce, ad, ciphertext, out) };
        }
    }
    #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
    {
        if runtime::has_aes() {
            // SAFETY: see `encrypt`.
            return unsafe { neon::decrypt(key, nonce, ad, ciphertext, out) };
        }
    }
    crate::state::decrypt(key, nonce, ad, ciphertext, out)
}

/// Whether a hardware AES backend is active for the current build/CPU.
///
/// Used by tests to decide whether the scalar-vs-hardware equivalence check is
/// meaningful on this machine.
pub fn hardware_backend_active() -> bool {
    #[cfg(all(
        feature = "simd-aesni",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    {
        return runtime::has_aes();
    }
    #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
    {
        return runtime::has_aes();
    }
    #[allow(unreachable_code)]
    false
}
