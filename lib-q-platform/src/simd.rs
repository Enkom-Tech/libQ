//! SIMD support detection for lib-Q

use crate::cpu::CpuFeatures;
use crate::platform::Platform;

/// SIMD feature support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimdSupport {
    /// SIMD128 support (ARM NEON or x86 SSE)
    pub simd128: bool,
    /// SIMD256 support (x86 AVX2)
    pub simd256: bool,
    /// SIMD512 support (x86 AVX-512)
    pub simd512: bool,
}

impl Default for SimdSupport {
    fn default() -> Self {
        Self::new()
    }
}

impl SimdSupport {
    /// Detect available SIMD support
    pub fn new() -> Self {
        let cpu = CpuFeatures::new();
        let platform = Platform::detect();

        Self {
            simd128: match platform {
                Platform::X86_64 => cfg!(target_feature = "sse2"),
                Platform::AArch64 => cpu.has_neon(),
                Platform::Unknown => false,
            },
            simd256: cpu.has_avx2(),
            simd512: cpu.has_avx512(),
        }
    }

    /// Check if SIMD128 is supported
    pub fn has_simd128(&self) -> bool {
        self.simd128
    }

    /// Check if SIMD256 is supported
    pub fn has_simd256(&self) -> bool {
        self.simd256
    }

    /// Check if SIMD512 is supported
    pub fn has_simd512(&self) -> bool {
        self.simd512
    }

    /// Get the best available SIMD level
    pub fn best_simd_level(&self) -> SimdLevel {
        if self.simd512 {
            SimdLevel::Simd512
        } else if self.simd256 {
            SimdLevel::Simd256
        } else if self.simd128 {
            SimdLevel::Simd128
        } else {
            SimdLevel::None
        }
    }
}

// Compatibility functions for external library integration
/// Check if SIMD128 support is available at runtime
pub fn simd128_support() -> bool {
    SimdSupport::new().has_simd128()
}

/// Check if SIMD256 support is available at runtime
pub fn simd256_support() -> bool {
    SimdSupport::new().has_simd256()
}

/// Check if SIMD512 support is available at runtime
pub fn simd512_support() -> bool {
    SimdSupport::new().has_simd512()
}

/// SIMD level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdLevel {
    /// No SIMD support
    None = 0,
    /// SIMD128 support
    Simd128 = 1,
    /// SIMD256 support
    Simd256 = 2,
    /// SIMD512 support
    Simd512 = 3,
}
