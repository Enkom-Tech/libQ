//! x86 SIMD optimizations for Keccak sponge absorption.
//!
//! This module provides AVX2 and AVX-512 accelerated data-to-state XOR for
//! absorption. A single Keccak state permutation does not map well to
//! 256/512-bit SIMD lanes, so `p1600_avx2` and `p1600_avx512` delegate to the
//! scalar `crate::keccak_p`.

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(cross_compile)))]
use core::arch::x86_64::{
    __m256i,
    _mm256_loadu_si256,
    _mm256_storeu_si256,
    _mm256_xor_si256,
};
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", not(cross_compile)))]
use core::arch::x86_64::{
    __m512i,
    _mm512_loadu_si512,
    _mm512_storeu_si512,
    _mm512_xor_si512,
};

/// AVX2 Keccak-p[1600,24] permutation entrypoint.
///
/// Delegates to the generic implementation because single-state Keccak
/// permutation does not vectorize correctly across 256-bit SIMD lanes.
///
/// # Safety
///
/// This is only ever compiled in when `cfg(target_feature = "avx2")` holds for the whole
/// compilation unit (i.e. the toolchain was told, via `-C target-feature=+avx2` or a target
/// whose baseline already includes it, that every instruction in this binary may assume
/// AVX2). The body itself is a plain safe call into `crate::keccak_p` and touches no raw
/// pointers or intrinsics, so the only real precondition is: **the CPU this binary actually
/// executes on must support AVX2** — running an AVX2-compiled binary on a CPU without it is
/// SIGILL. Callers that select this path via runtime feature detection (rather than a fixed
/// `target-feature` compile flag) must have already confirmed AVX2 is present.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(cross_compile)))]
pub unsafe fn p1600_avx2(state: &mut [u64; 25]) {
    crate::keccak_p(state, 24);
}

/// AVX-512 Keccak-p[1600,24] permutation entrypoint.
///
/// Delegates to the generic implementation for the same reason as AVX2.
///
/// # Safety
///
/// Same contract as [`p1600_avx2`], for AVX-512F instead: this function only exists when the
/// compilation unit's target features include `avx512f`. The precondition that must hold at
/// the call site is that **the executing CPU supports AVX-512F**; otherwise the process
/// receives SIGILL. The body is a plain call into `crate::keccak_p`, no raw pointers here.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", not(cross_compile)))]
pub unsafe fn p1600_avx512(state: &mut [u64; 25]) {
    crate::keccak_p(state, 24);
}

/// AVX2-accelerated absorb loop.
///
/// XORs `lane_count` little-endian 64-bit words from `data` into `state`, then
/// applies the 24-round permutation for each full block.
///
/// # Safety
///
/// - **CPU requirement**: as with [`p1600_avx2`], the executing CPU must support AVX2 —
///   this function is only compiled in when the compilation unit's target features include
///   `avx2`, and calling it on hardware that lacks the extension is SIGILL.
/// - **Memory safety of the internal `unsafe` block**: `state` is `&mut [u64; 25]`, so its
///   25-lane backing storage is always valid for the `state_ptr.add(lane)` writes below,
///   since the loop only ever advances `lane` up to `lane_count.min(25)`. The
///   `_mm256_loadu_si256`/`read_unaligned` reads from `data` are bounded by the enclosing
///   `while offset + block_bytes <= data.len()` check, so `data_ptr.add(offset + lane * 8)`
///   never reads past `data`'s end. Callers therefore only need to pass a `state` of the
///   required length (guaranteed by the type) and are not required to pre-validate `data`'s
///   length or `lane_count` themselves — the function clamps and bounds-checks both.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(cross_compile)))]
pub unsafe fn fast_loop_absorb_avx2(
    state: &mut [u64; 25],
    lane_count: usize,
    data: &[u8],
) -> usize {
    let lane_count = lane_count.min(25);
    let block_bytes = lane_count * 8;
    let mut offset = 0usize;

    while offset + block_bytes <= data.len() {
        unsafe {
            let data_ptr = data.as_ptr().add(offset);
            let state_ptr = state.as_mut_ptr();
            let mut lane = 0usize;

            while lane + 4 <= lane_count {
                let d = _mm256_loadu_si256(data_ptr.add(lane * 8).cast::<__m256i>());
                let s = _mm256_loadu_si256(state_ptr.add(lane).cast::<__m256i>());
                let r = _mm256_xor_si256(s, d);
                _mm256_storeu_si256(state_ptr.add(lane).cast::<__m256i>(), r);
                lane += 4;
            }

            while lane < lane_count {
                let d = core::ptr::read_unaligned(data_ptr.add(lane * 8).cast::<u64>());
                *state_ptr.add(lane) ^= d;
                lane += 1;
            }
        }

        crate::keccak_p(state, 24);
        offset += block_bytes;
    }

    offset
}

/// AVX-512 accelerated absorb loop.
///
/// Same as [`fast_loop_absorb_avx2`] but processes 8 lanes per SIMD chunk.
///
/// # Safety
///
/// - **CPU requirement**: the executing CPU must support AVX-512F — this function is only
///   compiled in when the compilation unit's target features include `avx512f`; calling it
///   on hardware without that extension is SIGILL.
/// - **Memory safety of the internal `unsafe` block**: identical reasoning to
///   [`fast_loop_absorb_avx2`] — `lane_count` is clamped to `state`'s fixed length (25) before
///   any pointer arithmetic, and every `data` access is bounded by the outer
///   `offset + block_bytes <= data.len()` loop condition, so no out-of-bounds read of `data`
///   or out-of-bounds write into `state` is possible regardless of caller-supplied
///   `lane_count`.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", not(cross_compile)))]
pub unsafe fn fast_loop_absorb_avx512(
    state: &mut [u64; 25],
    lane_count: usize,
    data: &[u8],
) -> usize {
    let lane_count = lane_count.min(25);
    let block_bytes = lane_count * 8;
    let mut offset = 0usize;

    while offset + block_bytes <= data.len() {
        unsafe {
            let data_ptr = data.as_ptr().add(offset);
            let state_ptr = state.as_mut_ptr();
            let mut lane = 0usize;

            while lane + 8 <= lane_count {
                let d = _mm512_loadu_si512(data_ptr.add(lane * 8).cast::<__m512i>());
                let s = _mm512_loadu_si512(state_ptr.add(lane).cast::<__m512i>());
                let r = _mm512_xor_si512(s, d);
                _mm512_storeu_si512(state_ptr.add(lane).cast::<__m512i>(), r);
                lane += 8;
            }

            while lane < lane_count {
                let d = core::ptr::read_unaligned(data_ptr.add(lane * 8).cast::<u64>());
                *state_ptr.add(lane) ^= d;
                lane += 1;
            }
        }

        crate::keccak_p(state, 24);
        offset += block_bytes;
    }

    offset
}

#[allow(dead_code)]
pub fn has_avx2() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(cross_compile)))]
    {
        true
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2", not(cross_compile))))]
    {
        false
    }
}

#[allow(dead_code)]
pub fn has_avx512f() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", not(cross_compile)))]
    {
        true
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f", not(cross_compile))))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use crate::p1600;

    #[test]
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(cross_compile),
        feature = "std"
    ))]
    fn test_avx2_consistency() {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        state1[0] = 0x1234567890ABCDEF;
        state2[0] = 0x1234567890ABCDEF;

        unsafe { super::p1600_avx2(&mut state1) };
        p1600(&mut state2, 24);

        assert_eq!(state1, state2);
    }

    #[test]
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(cross_compile),
        feature = "std"
    ))]
    fn test_avx2_absorb_consistency() {
        use core::mem::size_of;

        let mut state_avx = [0u64; 25];
        let mut state_ref = [0u64; 25];
        let data = [0xABu8; 256];
        let lane_count = 4usize;

        let consumed = unsafe { super::fast_loop_absorb_avx2(&mut state_avx, lane_count, &data) };

        let lane_size = size_of::<u64>();
        let block_bytes = lane_count * lane_size;
        let mut offset = 0usize;
        while offset + block_bytes <= data.len() {
            for lane in 0..lane_count {
                let start = offset + lane * lane_size;
                let value = u64::from_le_bytes([
                    data[start],
                    data[start + 1],
                    data[start + 2],
                    data[start + 3],
                    data[start + 4],
                    data[start + 5],
                    data[start + 6],
                    data[start + 7],
                ]);
                state_ref[lane] ^= value;
            }
            crate::keccak_p(&mut state_ref, 24);
            offset += block_bytes;
        }

        assert_eq!(consumed, offset);
        assert_eq!(state_avx, state_ref);
    }
}
