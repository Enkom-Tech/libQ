//! AES round function backends for AES-round AEADs (`lib-q-aegis`, `lib-q-hiae`).
//!
//! Those algorithms are built only from the AES encryption round
//! `AESRound(x, rk) = MixColumns(ShiftRows(SubBytes(x))) ^ rk`, plus XOR and AND on
//! 128-bit blocks. [`AesBlock`] abstracts those operations over a register type so
//! each algorithm core is written once and monomorphised per backend:
//!
//! - [`soft::Soft`]: portable and constant-time. SubBytes is evaluated as a Boolean
//!   circuit over bit planes (bitsliced): no table lookups, no secret-dependent
//!   branches or addresses.
//! - `aesni::Ni` (x86 / x86_64, feature `aes-round-hw`): `AESENC`.
//! - `neon::Neon` (aarch64, feature `aes-round-hw`): `AESE` + `AESMC`.
//!
//! All backends are bit-for-bit equivalent; the algorithm crates test this.
//!
//! # Safety contract
//!
//! Every [`AesBlock`] method is `unsafe` because the hardware implementations call
//! `#[target_feature]` intrinsics. A caller must only use a hardware backend after
//! [`hardware_aes_available`] returned `true`, and only from inside a function
//! compiled with the matching `#[target_feature]` (`aes,sse2` on x86, `aes` on
//! aarch64). The [`soft::Soft`] backend has no requirements.

#[cfg(all(
    feature = "aes-round-hw",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub mod aesni;
#[cfg(all(feature = "aes-round-hw", target_arch = "aarch64"))]
pub mod neon;
pub mod soft;

/// A 128-bit AES block held in a backend's native representation.
pub trait AesBlock: Copy {
    /// `true` for the bitsliced software backend, which is faster when several
    /// independent rounds are evaluated together (see [`AesBlock::round_n`]).
    const BITSLICED: bool;

    /// Load 16 bytes.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn load(b: &[u8; 16]) -> Self;
    /// Store 16 bytes.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn store(self) -> [u8; 16];
    /// The all-zero block.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn zero() -> Self;
    /// Bitwise XOR.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn xor(self, o: Self) -> Self;
    /// Bitwise AND.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn and(self, o: Self) -> Self;
    /// `AESRound(self, rk) = MixColumns(ShiftRows(SubBytes(self))) ^ rk`.
    ///
    /// # Safety
    /// See the module-level safety contract.
    unsafe fn round(self, rk: Self) -> Self;

    /// `AESL(x ^ y) ^ z`, where `AESL` is the AES round without key addition.
    ///
    /// x86 computes this as one `AESENC(x ^ y, z)`; aarch64 folds `x ^ y` into
    /// `AESE`, which XORs its operands before SubBytes.
    ///
    /// # Safety
    /// See the module-level safety contract.
    #[inline(always)]
    unsafe fn xaesl_x(x: Self, y: Self, z: Self) -> Self {
        unsafe { x.xor(y).round(z) }
    }

    /// `N` independent rounds `out[i] = AESRound(x[i], rk[i])`.
    ///
    /// The hardware backends issue `N` round instructions; the software backend
    /// evaluates the S-box circuit once for all `N` blocks (`N <= 8`).
    ///
    /// # Safety
    /// See the module-level safety contract.
    #[inline(always)]
    unsafe fn round_n<const N: usize>(x: [Self; N], rk: [Self; N]) -> [Self; N] {
        let mut out = x;
        for i in 0..N {
            out[i] = unsafe { x[i].round(rk[i]) };
        }
        out
    }
}

/// Whether this build and CPU run the AES round in hardware.
///
/// `true` only when the `aes-round-hw` feature is on for this architecture and the
/// CPU reports AES support (x86 `aes`+`sse2`, aarch64 `aes`). Protocols that
/// negotiate AES-round AEADs only when both peers have AES hardware should advertise
/// this value.
#[inline]
pub fn hardware_aes_available() -> bool {
    #[cfg(all(
        feature = "aes-round-hw",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    {
        return std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2");
    }
    #[cfg(all(feature = "aes-round-hw", target_arch = "aarch64"))]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    #[allow(unreachable_code)]
    false
}

/// Whether a hardware backend is compiled in for this target (independent of the
/// CPU the code runs on).
pub const fn hardware_backend_compiled() -> bool {
    cfg!(all(
        feature = "aes-round-hw",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64"
        )
    ))
}
