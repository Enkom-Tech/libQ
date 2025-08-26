//! Platform-specific functionality for lib-Q

use core::fmt;

/// Platform types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// x86_64 platform
    X86_64,
    /// AArch64 platform
    AArch64,
    /// Unknown platform
    Unknown,
}

impl Default for Platform {
    fn default() -> Self {
        Self::detect()
    }
}

impl Platform {
    /// Detect the current platform
    pub fn detect() -> Self {
        if cfg!(target_arch = "x86_64") {
            Platform::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Platform::AArch64
        } else {
            Platform::Unknown
        }
    }

    /// Check if this is an x86_64 platform
    pub fn is_x86_64(&self) -> bool {
        matches!(self, Platform::X86_64)
    }

    /// Check if this is an AArch64 platform
    pub fn is_aarch64(&self) -> bool {
        matches!(self, Platform::AArch64)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::X86_64 => write!(f, "x86_64"),
            Platform::AArch64 => write!(f, "aarch64"),
            Platform::Unknown => write!(f, "unknown"),
        }
    }
}
