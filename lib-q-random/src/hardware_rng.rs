//! CPU instruction-backed hardware entropy (RDRAND on x86 / `x86_64`).
//!
//! `AArch64` **`FEAT_RNG`** (`RNDR` / `RNDRRS`) and `PowerPC` **DARN** are not exposed
//! here: portable stable Rust does not yet ship stabilized `AArch64` RNG
//! intrinsics for this MSRV, and LLVM's inline assembler rejects `rndr` unless
//! the whole crate is built with an appropriate `+rand` target feature. Callers
//! on those architectures should use [`crate::entropy::OsEntropySource`] (the
//! OS stack typically mixes multiple entropy sources, including hardware where
//! the kernel supports it).

use crate::{
    Error,
    Result,
};

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
type RdrandFillResult = core::result::Result<(), ()>;

/// Upper bound for a single [`crate::traits::EntropySource::get_entropy`] fill
/// when backed by RDRAND (well above typical DRBG seed sizes, bounded for API
/// consistency).
pub(crate) const HW_RNG_MAX_PER_CALL: usize = 4096;

/// If CPUID / runtime detection reports RDRAND and a probe read succeeds,
/// returns a stable label used in diagnostics.
#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn probe_rdrand() -> Option<&'static str> {
    if !std::arch::is_x86_feature_detected!("rdrand") {
        return None;
    }
    if unsafe { rdrand_probe_once() } {
        Some("RDRAND")
    } else {
        None
    }
}

/// Without `std`, CPU feature detection is unavailable; hardware RNG stays off.
#[cfg(all(not(feature = "std"), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn probe_rdrand() -> Option<&'static str> {
    None
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_probe_once() -> bool {
    let mut scratch = [0u8; 8];
    // SAFETY: `is_x86_feature_detected!("rdrand")` was true before calling this
    // function, and this item is annotated with `target_feature(enable = "rdrand")`.
    unsafe { rdrand_fill_any_word(&mut scratch).is_ok() }
}

/// Fill `dest` using RDRAND. Caller must have verified availability (e.g. via
/// [`probe_rdrand`]).
#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn fill_hw_cpu(dest: &mut [u8], device: &'static str) -> Result<()> {
    if !std::arch::is_x86_feature_detected!("rdrand") {
        return Err(Error::hardware_rng_failed(device));
    }
    // SAFETY: `rdrand` is available per runtime check above.
    unsafe { rdrand_fill(dest) }.map_err(|()| {
        Error::hardware_rng_failed_with_status(
            device,
            0,
            "RDRAND did not produce output after bounded retries",
        )
    })
}

#[cfg(all(not(feature = "std"), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn fill_hw_cpu(dest: &mut [u8], device: &'static str) -> Result<()> {
    let _ = dest;
    Err(Error::hardware_rng_failed(device))
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn fill_hw_cpu(dest: &mut [u8], device: &'static str) -> Result<()> {
    let _ = dest;
    Err(Error::hardware_rng_failed(device))
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
const RDRAND_RETRIES: u32 = 16;

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_fill(dest: &mut [u8]) -> RdrandFillResult {
    use core::arch::x86_64::{
        _rdrand32_step,
        _rdrand64_step,
    };

    let mut offset = 0usize;
    while offset < dest.len() {
        let remain = dest.len() - offset;
        if remain >= 8 {
            let mut v = 0u64;
            let mut ok = false;
            for _ in 0..RDRAND_RETRIES {
                // SAFETY: `_rdrand64_step` is only used inside this `rdrand` target feature.
                if _rdrand64_step(&mut v) != 0 {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(());
            }
            dest[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
            offset += 8;
        } else if remain >= 4 {
            let mut v = 0u32;
            let mut ok = false;
            for _ in 0..RDRAND_RETRIES {
                if _rdrand32_step(&mut v) != 0 {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(());
            }
            dest[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
            offset += 4;
        } else {
            let mut v = 0u32;
            let mut ok = false;
            for _ in 0..RDRAND_RETRIES {
                if _rdrand32_step(&mut v) != 0 {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(());
            }
            let bytes = v.to_le_bytes();
            dest[offset..].copy_from_slice(&bytes[..remain]);
            break;
        }
    }
    Ok(())
}

#[cfg(all(feature = "std", target_arch = "x86"))]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_fill(dest: &mut [u8]) -> RdrandFillResult {
    use core::arch::x86::_rdrand32_step;

    let mut offset = 0usize;
    while offset < dest.len() {
        let remain = dest.len() - offset;
        let mut v = 0u32;
        let mut ok = false;
        for _ in 0..RDRAND_RETRIES {
            if _rdrand32_step(&mut v) != 0 {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(());
        }
        let take = remain.min(4);
        dest[offset..offset + take].copy_from_slice(&v.to_le_bytes()[..take]);
        offset += take;
    }
    Ok(())
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_fill_any_word(scratch: &mut [u8; 8]) -> RdrandFillResult {
    use core::arch::x86_64::_rdrand64_step;

    let mut v = 0u64;
    for _ in 0..RDRAND_RETRIES {
        if _rdrand64_step(&mut v) != 0 {
            scratch.copy_from_slice(&v.to_le_bytes());
            return Ok(());
        }
    }
    Err(())
}

#[cfg(all(feature = "std", target_arch = "x86"))]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_fill_any_word(scratch: &mut [u8; 8]) -> RdrandFillResult {
    use core::arch::x86::_rdrand32_step;

    let mut v = 0u32;
    for _ in 0..RDRAND_RETRIES {
        if _rdrand32_step(&mut v) != 0 {
            scratch[..4].copy_from_slice(&v.to_le_bytes());
            return Ok(());
        }
    }
    Err(())
}
