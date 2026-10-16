//! Runtime selection of the AES-round backend.
//!
//! The backends live in `lib-q-intrinsics` (`aes_round`); this crate's `simd-aesni`
//! / `simd-neon` features compile them in (`lib-q-intrinsics/aes-round-hw`).

/// Runs the hardware entry point that matches this CPU, else the portable one.
///
/// `aesni` and `neon` must name `#[target_feature]` entry points; they are reached
/// only after `hardware_aes_available()` returned `true`.
macro_rules! dispatch {
    (aesni => $aesni:expr, neon => $neon:expr, soft => $soft:expr $(,)?) => {{
        #[cfg(all(
            feature = "simd-aesni",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        {
            if lib_q_intrinsics::aes_round::hardware_aes_available() {
                // SAFETY: AES-NI and SSE2 support was confirmed at runtime just above.
                return unsafe { $aesni };
            }
        }
        #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
        {
            if lib_q_intrinsics::aes_round::hardware_aes_available() {
                // SAFETY: ARMv8 AES support was confirmed at runtime just above.
                return unsafe { $neon };
            }
        }
        $soft
    }};
}
pub(crate) use dispatch;
