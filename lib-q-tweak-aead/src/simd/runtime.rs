//! CPU feature detection for AVX2.

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub fn has_avx2() -> bool {
    cpufeatures::new!(avx2_check, "avx2");
    avx2_check::get()
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd-avx2")))]
pub fn has_avx2() -> bool {
    false
}
