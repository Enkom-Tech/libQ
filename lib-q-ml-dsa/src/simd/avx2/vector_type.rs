/// The vector type - direct type alias to __m256i
pub(crate) type Vec256 = lib_q_intrinsics::Vec256;

/// An avx2 encoded ring element
pub(crate) type AVX2RingElement = [Vec256; super::SIMD_UNITS_IN_RING_ELEMENT];

/// Create an all-zero vector coefficient
pub(crate) fn zero() -> Vec256 {
    lib_q_intrinsics::mm256_setzero_si256()
}

/// Create a coefficient from an `i32` array
pub(crate) fn from_coefficient_array(coefficient_array: &[i32], out: &mut Vec256) {
    *out = lib_q_intrinsics::mm256_loadu_si256_i32(coefficient_array)
}

/// Write out the coefficient to an `i32` array
#[inline(always)]
pub(crate) fn to_coefficient_array(value: &Vec256, out: &mut [i32]) {
    lib_q_intrinsics::mm256_storeu_si256_i32(out, *value);
}
