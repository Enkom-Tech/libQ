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

impl Default for CpuFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuFeatures {
    /// Detect available CPU features
    pub fn new() -> Self {
        Self {
            avx2: cfg!(all(target_arch = "x86_64", target_feature = "avx2")),
            avx512: cfg!(all(target_arch = "x86_64", target_feature = "avx512f")),
            neon: cfg!(all(target_arch = "aarch64", target_feature = "neon")),
            sve: cfg!(all(target_arch = "aarch64", target_feature = "sve")),
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
