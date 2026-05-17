//! Runtime CPU feature detection and dispatch for SIMD operations
//!
//! This module provides runtime detection of available CPU features
//! and dispatches to the appropriate SIMD implementation.

#![allow(unsafe_code)]

use core::sync::atomic::{
    AtomicBool,
    Ordering,
};

// Global state for CPU feature detection
static AVX2_AVAILABLE: AtomicBool = AtomicBool::new(false);
static DETECTION_DONE: AtomicBool = AtomicBool::new(false);

/// Detect available CPU features at runtime
///
/// This function is thread-safe and can be called multiple times.
/// It will only perform detection once and cache the results.
///
/// # Safety
///
/// This function uses unsafe CPUID and XGETBV intrinsics:
/// - CPUID is a standard x86 instruction and is safe to call
/// - XGETBV requires OS support for extended state management
/// - The function handles all error cases gracefully
/// - Results are cached in atomic variables for thread safety
///
/// The function is safe to call on any x86_64 system and will
/// gracefully handle systems without AVX2 support.
pub fn detect_cpu_features() {
    if DETECTION_DONE.load(Ordering::Relaxed) {
        return;
    }

    #[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
    {
        unsafe {
            // CPUID function 1: Processor Info and Feature Bits
            let result = core::arch::x86_64::__cpuid(1);

            // Check OSXSAVE (bit 27 of ECX)
            let osxsave = (result.ecx & (1 << 27)) != 0;

            if osxsave {
                // CPUID function 7: Extended Features
                let result = core::arch::x86_64::__cpuid_count(7, 0);

                // Check AVX2 (bit 5 of EBX)
                let avx2 = (result.ebx & (1 << 5)) != 0;

                if avx2 {
                    // Verify OS support via XGETBV
                    let xcr0 = core::arch::x86_64::_xgetbv(0);

                    // Check if AVX state (bits 1-2) is enabled
                    let avx_enabled = (xcr0 & 0x6) == 0x6;

                    if avx_enabled {
                        AVX2_AVAILABLE.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    DETECTION_DONE.store(true, Ordering::Relaxed);
}

/// Check if AVX2 is available on the current CPU
///
/// This function automatically detects CPU features if not already done.
/// Returns `true` if AVX2 instructions are available and the `simd-avx2`
/// feature is enabled.
pub fn has_avx2() -> bool {
    detect_cpu_features();
    AVX2_AVAILABLE.load(Ordering::Relaxed)
}

/// Get the best available SIMD implementation name
///
/// Returns a string describing the best available SIMD implementation
/// for the current CPU and feature configuration.
pub fn get_best_implementation() -> &'static str {
    if has_avx2() { "avx2" } else { "portable" }
}

/// Force re-detection of CPU features
///
/// This is primarily useful for testing. In normal operation,
/// CPU features are detected once and cached.
#[cfg(test)]
pub fn force_redetect() {
    DETECTION_DONE.store(false, Ordering::Relaxed);
    AVX2_AVAILABLE.store(false, Ordering::Relaxed);
    detect_cpu_features();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_always_works() {
        // Should not panic regardless of CPU features
        detect_cpu_features();
        let _ = has_avx2();
        let _ = get_best_implementation();
    }

    #[test]
    fn test_redetection() {
        force_redetect();
        detect_cpu_features();
        // Should not panic
    }
}
