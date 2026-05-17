//! Dense GF(2) polynomial multiply with modular reduction \(x^N - 1\).
//!
//! Port of [`reference/hqc/src/x86_64/common/hqc-*/gf2x.c`](../../../../../../reference/hqc/src/x86_64/common/hqc-1/gf2x.c):
//! **Toom–Cook 3-way**, recursive **Karatsuba**, **PCLMUL**, then **reduce**, parameterized by
//! [`HqcParams::PARAM_N_MULT`] and [`HqcParams::VEC_N_256_SIZE_64`].
//!
//! # Safety
//!
//! Call only when **AVX2** and **PCLMULQDQ** are available ([`crate::simd::runtime::has_avx2`]).

#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
#[path = "gf2x_toom3.rs"]
mod gf2x_toom3;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::arch::x86_64::_mm256_setzero_si256;

use crate::hqc_pke::HqcPkeError;
use crate::params_correct::HqcParams;

/// \(output = a \cdot b \bmod (x^N - 1)\); requires AVX2 + PCLMULQDQ.
#[cfg(feature = "alloc")]
pub fn avx2_vect_mul_mod_xnm1<P: HqcParams>(
    output: &mut [u64],
    a: &[u64],
    b: &[u64],
) -> Result<(), HqcPkeError> {
    let n = P::VEC_N_SIZE_64;
    if output.len() != n || a.len() < n || b.len() < n {
        return Err(HqcPkeError::InvalidKey);
    }
    debug_assert_ne!(
        P::N % 64,
        0,
        "gf2x: N multiple of 64 unsupported by reduction"
    );

    output.fill(0);

    unsafe {
        vect_mul_toom_avx2::<P>(output, a, b);
    }

    Ok(())
}

#[cfg(feature = "alloc")]
#[target_feature(enable = "avx2", enable = "pclmulqdq")]
unsafe fn vect_mul_toom_avx2<P: HqcParams>(output: &mut [u64], a: &[u64], b: &[u64]) {
    use gf2x_toom3::{
        ToomDims,
        reduce_avx2_to_u64,
        toom_3_mult,
    };

    let n = P::VEC_N_SIZE_64;
    let vec_n_array = (P::PARAM_N_MULT + 255) / 256;
    let nu64 = vec_n_array * 4;
    let mask = (1u64 << (P::N & 0x3F)) - 1;

    let mut aw = vec![0u64; nu64];
    let mut bw = vec![0u64; nu64];
    aw[..n].copy_from_slice(&a[..n]);
    bw[..n].copy_from_slice(&b[..n]);
    aw[n - 1] &= mask;
    bw[n - 1] &= mask;

    let a_m256 = aw.as_ptr().cast();
    let b_m256 = bw.as_ptr().cast();

    let prod_len = P::VEC_N_256_SIZE_64 >> 1;
    let mut prod: Vec<core::arch::x86_64::__m256i> =
        (0..prod_len).map(|_| _mm256_setzero_si256()).collect();

    let d = ToomDims::from_param_n_mult(P::PARAM_N_MULT);
    toom_3_mult(prod.as_mut_ptr(), a_m256, b_m256, d);

    let mut scratch: Vec<core::arch::x86_64::__m256i> =
        (0..vec_n_array).map(|_| _mm256_setzero_si256()).collect();

    reduce_avx2_to_u64(output, &prod, &mut scratch, P::N, P::VEC_N_SIZE_BYTES);
}

#[cfg(all(test, target_arch = "x86_64", feature = "simd-avx2", feature = "alloc"))]
mod tests {
    use super::*;
    use crate::hqc_pke::schoolbook_vect_mul_mod_xnm1;
    use crate::params_correct::{
        Hqc1Params,
        HqcParams,
    };
    use crate::simd::runtime::has_avx2;

    fn assert_avx2_matches_schoolbook<P: HqcParams>(seeds: &[u64]) {
        if !has_avx2() {
            return;
        }
        let n = P::VEC_N_SIZE_64;
        let mask = (1u64 << (P::N & 0x3F)) - 1;
        let mut a = alloc::vec![0u64; n];
        let mut b = alloc::vec![0u64; n];
        let mut s = alloc::vec![0u64; n];
        let mut v = alloc::vec![0u64; n];
        for &seed in seeds {
            for i in 0..n {
                let t = seed
                    .wrapping_add(i as u64)
                    .wrapping_mul(0xD1_B54_321_0FED_CBA9);
                a[i] = t;
                b[i] = t.rotate_left(17) ^ 0xA5A5_A5A5_A5A5_A5A5;
            }
            a[n - 1] &= mask;
            b[n - 1] &= mask;
            schoolbook_vect_mul_mod_xnm1(&mut s, &a, &b, n, P::N).unwrap();
            avx2_vect_mul_mod_xnm1::<P>(&mut v, &a, &b).unwrap();
            assert_eq!(s, v, "P={} seed={seed}", core::any::type_name::<P>());
        }
    }

    #[test]
    fn avx2_vect_mul_matches_schoolbook_hqc128() {
        assert_avx2_matches_schoolbook::<Hqc1Params>(&[1u64, 2, 42]);
    }

    #[cfg(feature = "hqc192")]
    #[test]
    fn avx2_vect_mul_matches_schoolbook_hqc192() {
        assert_avx2_matches_schoolbook::<crate::params_correct::Hqc3Params>(&[1u64, 7, 0xBEEF]);
    }

    #[cfg(feature = "hqc256")]
    #[test]
    fn avx2_vect_mul_matches_schoolbook_hqc256() {
        assert_avx2_matches_schoolbook::<crate::params_correct::Hqc5Params>(&[3u64, 11, 0xFACADE]);
    }
}
