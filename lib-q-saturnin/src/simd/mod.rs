//! SIMD helpers and optimized kernels for Saturnin.

use lib_q_core::{
    Error,
    Result,
};

pub mod runtime;

#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod avx2;

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub mod neon;

#[inline]
fn to_fixed_32(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(input);
    out
}

#[inline]
const fn uses_bs32_kernel(num_super_rounds: usize, domain: u8) -> bool {
    num_super_rounds == 16 && (domain == 7 || domain == 8)
}

/// Encrypts one block with runtime SIMD dispatch when available.
///
/// Uses AVX2/NEON kernels when enabled and detected, otherwise falls back to
/// the audited scalar bs32 core.
pub fn encrypt_block_dispatch(
    num_super_rounds: usize,
    domain: u8,
    key: &[u8],
    block: &mut [u8],
) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }
    if block.len() != 32 {
        return Err(Error::InvalidMessageSize {
            max: 32,
            actual: block.len(),
        });
    }

    let key32 = to_fixed_32(key);
    let mut block32 = to_fixed_32(block);

    if uses_bs32_kernel(num_super_rounds, domain) {
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            if runtime::has_avx2() {
                let mut lanes = [block32; 8];
                // SAFETY: runtime::has_avx2() verified before calling AVX2 kernel.
                unsafe {
                    avx2::encrypt_blocks8(num_super_rounds, domain, &key32, &mut lanes)?;
                }
                block32 = lanes[0];
                block.copy_from_slice(&block32);
                return Ok(());
            }
        }

        #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
        {
            if runtime::has_neon() {
                // SAFETY: runtime::has_neon() verified before calling NEON kernel.
                unsafe {
                    neon::encrypt_block_bs32(num_super_rounds, domain, &key32, &mut block32)?;
                }
                block.copy_from_slice(&block32);
                return Ok(());
            }
        }

        let scalar = crate::bs32_core::SaturninBs32Core::new(num_super_rounds, domain)?;
        scalar.encrypt_block(&key32, &mut block32)?;
    } else {
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            if runtime::has_avx2() {
                let mut lanes = [block32; 8];
                // SAFETY: runtime::has_avx2() verified before calling AVX2 core-equivalent kernel.
                unsafe {
                    avx2::encrypt_blocks8_core(num_super_rounds, domain, &key32, &mut lanes)?;
                }
                block32 = lanes[0];
                block.copy_from_slice(&block32);
                return Ok(());
            }
        }

        let scalar_core = crate::core::SaturninCore::new(num_super_rounds, domain)?;
        scalar_core.encrypt_block(&key32, &mut block32)?;
    }
    block.copy_from_slice(&block32);
    Ok(())
}

/// Encrypts eight independent blocks with runtime SIMD dispatch when available.
pub fn encrypt_blocks8_dispatch(
    num_super_rounds: usize,
    domain: u8,
    key: &[u8],
    blocks: &mut [[u8; 32]; 8],
) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    let key32 = to_fixed_32(key);

    if uses_bs32_kernel(num_super_rounds, domain) {
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            if runtime::has_avx2() {
                // SAFETY: runtime::has_avx2() verified before calling AVX2 kernel.
                unsafe {
                    avx2::encrypt_blocks8(num_super_rounds, domain, &key32, blocks)?;
                }
                return Ok(());
            }
        }

        #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
        {
            if runtime::has_neon() {
                for block in blocks.iter_mut() {
                    // SAFETY: runtime::has_neon() verified before calling NEON kernel.
                    unsafe {
                        neon::encrypt_block_bs32(num_super_rounds, domain, &key32, block)?;
                    }
                }
                return Ok(());
            }
        }

        let scalar = crate::bs32_core::SaturninBs32Core::new(num_super_rounds, domain)?;
        for block in blocks.iter_mut() {
            scalar.encrypt_block(&key32, block)?;
        }
    } else {
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            if runtime::has_avx2() {
                // SAFETY: runtime::has_avx2() verified before calling AVX2 core-equivalent kernel.
                unsafe {
                    avx2::encrypt_blocks8_core(num_super_rounds, domain, &key32, blocks)?;
                }
                return Ok(());
            }
        }

        let scalar_core = crate::core::SaturninCore::new(num_super_rounds, domain)?;
        for block in blocks.iter_mut() {
            scalar_core.encrypt_block(&key32, block)?;
        }
    }
    Ok(())
}

/// Runtime SIMD capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimdCapabilities {
    /// `true` when AVX2 is available for the current process.
    pub has_avx2: bool,
    /// `true` when NEON is available for the current process.
    pub has_neon: bool,
}

impl SimdCapabilities {
    /// Returns `true` when at least one SIMD backend is available.
    pub const fn has_simd(self) -> bool {
        self.has_avx2 || self.has_neon
    }

    /// Returns the highest-priority backend name.
    pub const fn best_simd(self) -> &'static str {
        if self.has_avx2 {
            "AVX2"
        } else if self.has_neon {
            "NEON"
        } else {
            "Scalar"
        }
    }
}

/// SIMD wrapper for block encryption/decryption paths.
///
/// For correctness, this keeps the scalar core as the reference implementation and
/// only uses optimized backends where feature detection and target support are both present.
pub struct SimdOptimizedCore {
    fallback_core: crate::core::SaturninCore,
    caps: SimdCapabilities,
}

impl SimdOptimizedCore {
    /// Creates a new SIMD-aware core wrapper.
    pub fn new(num_rounds: usize, domain: u8) -> Result<Self> {
        let fallback_core = crate::core::SaturninCore::new(num_rounds, domain)?;
        let caps = SimdCapabilities {
            has_avx2: runtime::has_avx2(),
            has_neon: runtime::has_neon(),
        };
        Ok(Self {
            fallback_core,
            caps,
        })
    }

    /// Returns detected SIMD capabilities.
    pub const fn simd_capabilities(&self) -> SimdCapabilities {
        self.caps
    }

    /// Encrypts one block.
    pub fn encrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        // Keep scalar as the audited default path for generic block-cipher API use.
        self.fallback_core.encrypt_block(key, block)
    }

    /// Decrypts one block.
    pub fn decrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        // Keep scalar as the audited default path.
        self.fallback_core.decrypt_block(key, block)
    }
}

/// XOR utilities using runtime SIMD dispatch.
pub mod simd_xor {
    use super::runtime;

    /// XOR two 32-byte blocks using the fastest available backend.
    pub fn xor_blocks_32(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
        #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
        {
            if runtime::has_avx2() {
                // SAFETY: runtime::has_avx2() guarantees AVX2 support before calling.
                unsafe {
                    super::avx2::xor_blocks_32(a, b, result);
                }
                return;
            }
        }

        #[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
        {
            if runtime::has_neon() {
                // SAFETY: runtime::has_neon() guarantees NEON support before calling.
                unsafe {
                    super::neon::xor_blocks_32(a, b, result);
                }
                return;
            }
        }

        xor_blocks_32_scalar(a, b, result);
    }

    /// Scalar fallback for XOR.
    pub fn xor_blocks_32_scalar(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
        for i in 0..32 {
            result[i] = a[i] ^ b[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_capabilities_shape() -> Result<()> {
        let core = SimdOptimizedCore::new(10, 1)?;
        let caps = core.simd_capabilities();
        assert!(
            caps.best_simd() == "AVX2" ||
                caps.best_simd() == "NEON" ||
                caps.best_simd() == "Scalar"
        );
        Ok(())
    }

    #[test]
    fn test_xor_equivalence() {
        let a = [0xAAu8; 32];
        let b = [0x55u8; 32];
        let mut out = [0u8; 32];
        simd_xor::xor_blocks_32(&a, &b, &mut out);
        assert_eq!(out, [0xFFu8; 32]);
    }
}
