//! CPU feature detection for lib-Q

/// CPU feature flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuFeatures {
    /// AVX2 support
    pub avx2: bool,
    /// AVX-512 support
    pub avx512: bool,
    /// ARM NEON support
    pub neon: bool,
    /// ARM SVE support
    pub sve: bool,
}

#[cfg(feature = "std")]
mod runtime {
    extern crate std;

    use super::CpuFeatures;

    pub fn detect() -> CpuFeatures {
        CpuFeatures {
            #[cfg(target_arch = "x86_64")]
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            #[cfg(not(target_arch = "x86_64"))]
            avx2: false,

            #[cfg(target_arch = "x86_64")]
            avx512: std::arch::is_x86_feature_detected!("avx512f"),
            #[cfg(not(target_arch = "x86_64"))]
            avx512: false,

            #[cfg(target_arch = "aarch64")]
            neon: std::arch::is_aarch64_feature_detected!("neon"),
            #[cfg(not(target_arch = "aarch64"))]
            neon: false,

            #[cfg(target_arch = "aarch64")]
            sve: std::arch::is_aarch64_feature_detected!("sve"),
            #[cfg(not(target_arch = "aarch64"))]
            sve: false,
        }
    }
}

impl Default for CpuFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuFeatures {
    /// Detect available CPU features at runtime.
    ///
    /// When the `std` feature is enabled, genuine runtime CPUID/hwcap detection
    /// is used via `is_x86_feature_detected!` and `is_aarch64_feature_detected!`.
    /// In `no_std` environments the detection falls back to compile-time
    /// `target_feature` flags set by the compiler (`-C target-feature=+avx2`,
    /// etc.); those flags reflect what the binary was compiled *for*, not what
    /// the runtime CPU actually supports.
    pub fn new() -> Self {
        #[cfg(feature = "std")]
        {
            runtime::detect()
        }
        #[cfg(not(feature = "std"))]
        {
            // Compile-time fallback: reflects target-feature flags only.
            Self {
                avx2: cfg!(all(target_arch = "x86_64", target_feature = "avx2")),
                avx512: cfg!(all(target_arch = "x86_64", target_feature = "avx512f")),
                neon: cfg!(all(target_arch = "aarch64", target_feature = "neon")),
                sve: cfg!(all(target_arch = "aarch64", target_feature = "sve")),
            }
        }
    }

    /// Check if AVX2 is supported
    pub fn has_avx2(&self) -> bool {
        self.avx2
    }

    /// Check if AVX-512 is supported
    pub fn has_avx512(&self) -> bool {
        self.avx512
    }

    /// Check if NEON is supported
    pub fn has_neon(&self) -> bool {
        self.neon
    }

    /// Check if SVE is supported
    pub fn has_sve(&self) -> bool {
        self.sve
    }
}
