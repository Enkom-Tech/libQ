//! Integration tests to exercise public APIs for coverage and smoke checks.

use lib_q_intrinsics::generic::{
    crypto_ops,
    vector_ops,
};
use lib_q_intrinsics::platform;

#[test]
fn platform_surface_runs() {
    let _ = platform::best_simd_support();
    let _ = platform::cpu_features();
    let _ = platform::current_platform();
    let _ = platform::has_avx2();
    let _ = platform::has_neon();
    let _ = platform::has_simd256();
    let _ = platform::has_simd128();
}

#[test]
fn generic_vector_ops() {
    let z = vector_ops::GenericVec256::zero();
    let a = vector_ops::GenericVec256::splat(3);
    let b = vector_ops::GenericVec256::splat(5);
    let _ = a.add(b).sub(z).mul(b).and(a).or(b).xor(a);
    let _ = a.shl(1).shr(1);

    let z8 = vector_ops::GenericVec128::zero();
    let u = vector_ops::GenericVec128::splat(2);
    let v = vector_ops::GenericVec128::splat(7);
    let _ = u.add(v).sub(z8).and(u).or(v).xor(u);
}

#[test]
fn generic_crypto_ops() {
    let h = crypto_ops::generic_hash(b"lib-q-intrinsics coverage");
    assert_ne!(h, [0u8; 32]);
    let out = crypto_ops::generic_block_cipher(b"data", b"key");
    assert_eq!(out[0], b'd' ^ b'k');
    assert_eq!(
        crypto_ops::crypto_vector_ops(),
        "Generic fallback implementation"
    );
}

#[cfg(feature = "simd128")]
#[test]
fn simd128_feature_surface() {
    let _ = platform::simd128_intrinsics::is_available();
    let _ = platform::simd128_intrinsics::get_implementation();
    assert_eq!(
        lib_q_intrinsics::simd128::Simd128Ops::placeholder(),
        "SIMD128 operations - placeholder implementation"
    );
}

#[cfg(feature = "simd256")]
#[test]
fn simd256_feature_surface() {
    let _ = platform::simd256_intrinsics::is_available();
    let _ = platform::simd256_intrinsics::get_implementation();
    assert_eq!(
        lib_q_intrinsics::simd256::Simd256Ops::placeholder(),
        "SIMD256 operations - placeholder implementation"
    );
}

#[cfg(feature = "simd512")]
#[test]
fn simd512_feature_surface() {
    let _ = platform::simd512_intrinsics::is_available();
    let _ = platform::simd512_intrinsics::get_implementation();
    assert_eq!(
        lib_q_intrinsics::simd512::Simd512Ops::placeholder(),
        "SIMD512 operations - placeholder implementation"
    );
}

#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
#[test]
fn avx2_wrappers_smoke() {
    use lib_q_intrinsics::{
        Vec128,
        Vec256,
        Vec256Float,
        avx2,
    };

    let mut u8buf = [0u8; 32];
    let mut u8_16 = [0u8; 16];
    let mut i16buf = [0i16; 16];
    let mut i32buf = [0i32; 8];
    let mut i32_4 = [0i32; 4];

    let z = avx2::mm256_setzero_si256();
    avx2::mm256_storeu_si256_u8(&mut u8buf, z);
    avx2::mm256_storeu_si256_i16(&mut i16buf, z);
    avx2::mm256_storeu_si256_i32(&mut i32buf, z);

    let v128 = avx2::mm_set_epi32(4, 3, 2, 1);
    avx2::mm_storeu_si128(&mut i16buf, v128);
    avx2::mm_storeu_si128_i32(&mut i32_4, v128);
    avx2::mm_storeu_bytes_si128(&mut u8_16, v128);

    let loaded = avx2::mm_loadu_si128(&u8_16);
    let _ = avx2::mm_movemask_epi8(loaded);

    let from_u8 = avx2::mm256_loadu_si256_u8(&u8buf);
    let from_i16 = avx2::mm256_loadu_si256_i16(&i16buf);
    let from_i32 = avx2::mm256_loadu_si256_i32(&i32buf);

    let a = avx2::mm256_set1_epi32(2);
    let b = avx2::mm256_set1_epi16(3);
    let c = avx2::mm256_set1_epi64x(-1);
    let d = avx2::mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);
    let e = avx2::mm256_set_epi16(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let f = avx2::mm256_set_epi8(
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
        8, 7, 6, 5, 4, 3, 2, 1, 0,
    );
    let g = avx2::mm256_set_epi64x(3, 2, 1, 0);
    let h = avx2::mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let i = avx2::mm_set1_epi16(9);
    let j = avx2::mm256_set_m128i(v128, v128);

    let mut acc = avx2::mm256_add_epi32(from_u8, a);
    acc = avx2::mm256_add_epi16(acc, b);
    acc = avx2::mm256_add_epi64(acc, c);
    acc = avx2::mm256_sub_epi32(acc, d);
    acc = avx2::mm256_sub_epi16(acc, e);
    let v128b = avx2::mm_add_epi16(v128, h);
    let _ = avx2::mm_sub_epi16(v128b, i);

    acc = avx2::mm256_mullo_epi32(acc, from_i32);
    acc = avx2::mm256_mullo_epi16(acc, f);
    let _ = avx2::mm_mullo_epi16(v128, h);
    acc = avx2::mm256_mul_epi32(acc, g);
    acc = avx2::mm256_mul_epu32(acc, from_i16);
    acc = avx2::mm256_madd_epi16(acc, j);
    acc = avx2::mm256_mulhi_epi16(acc, a);
    let _ = avx2::mm_mulhi_epi16(v128, v128);

    acc = avx2::mm256_slli_epi32::<1>(acc);
    acc = avx2::mm256_slli_epi16::<2>(acc);
    acc = avx2::mm256_slli_epi64::<1>(acc);
    acc = avx2::mm256_srai_epi32::<1>(acc);
    acc = avx2::mm256_srai_epi16::<1>(acc);
    acc = avx2::mm256_srli_epi32::<1>(acc);
    acc = avx2::mm256_srli_epi16::<1>(acc);
    acc = avx2::mm256_srli_epi64::<1>(acc);
    let v1 = avx2::mm_srli_epi64::<8>(v128);
    let counts = avx2::mm256_set1_epi32(1);
    acc = avx2::mm256_srlv_epi32(acc, counts);
    acc = avx2::mm256_srlv_epi64(acc, counts);
    acc = avx2::mm256_sllv_epi32(acc, counts);
    let _ = avx2::mm_sllv_epi32(v1, v1);

    acc = avx2::mm256_bsrli_epi128::<1>(acc);
    acc = avx2::mm256_bsrli_epi128::<2>(acc);
    acc = avx2::mm256_bsrli_epi128::<3>(acc);
    acc = avx2::mm256_bsrli_epi128::<4>(acc);
    acc = avx2::mm256_bsrli_epi128::<5>(acc);
    acc = avx2::mm256_bsrli_epi128::<6>(acc);
    acc = avx2::mm256_bsrli_epi128::<7>(acc);
    acc = avx2::mm256_bsrli_epi128::<8>(acc);
    acc = avx2::mm256_bsrli_epi128::<99>(acc);

    acc = avx2::mm256_and_si256(acc, a);
    acc = avx2::mm256_andnot_si256(acc, b);
    acc = avx2::mm256_or_si256(acc, c);
    acc = avx2::mm256_xor_si256(acc, d);

    let eq = avx2::mm256_cmpeq_epi32(acc, acc);
    let gt = avx2::mm256_cmpgt_epi32(acc, z);
    let lt = avx2::mm256_cmplt_epi32(acc, acc);
    let ge = avx2::mm256_cmpge_epi32(acc, z);
    let _ = avx2::mm256_testz_si256(eq, gt);
    acc = avx2::mm256_sign_epi32(lt, ge);

    let ps = avx2::mm256_castsi256_ps(acc);
    let back = avx2::mm256_castps_si256(ps);
    let _ = avx2::mm256_movemask_ps(ps);
    let lo = avx2::mm256_castsi256_si128(back);
    let wide = avx2::mm256_castsi128_si256(lo);
    let ext = avx2::mm256_cvtepi16_epi32(lo);
    acc = avx2::mm256_add_epi32(wide, ext);

    acc = avx2::mm256_shuffle_epi32::<0x1B>(acc);
    acc = avx2::mm256_shuffle_epi8(acc, avx2::mm256_setzero_si256());
    let sh = avx2::mm_shuffle_epi8(lo, avx2::mm_set_epi32(0, 0, 0, 0));
    let _ = avx2::mm_movemask_epi8(sh);

    acc = avx2::mm256_blend_epi32::<0xF0>(acc, z);
    acc = avx2::mm256_blend_epi16::<0xAA>(acc, a);
    acc = avx2::vec256_blendv_epi32(acc, b, avx2::mm256_cmpeq_epi32(acc, acc));

    acc = avx2::mm256_unpacklo_epi64(acc, b);
    acc = avx2::mm256_unpackhi_epi64(acc, c);
    acc = avx2::mm256_unpacklo_epi32(acc, d);
    acc = avx2::mm256_unpackhi_epi32(acc, e);

    acc = avx2::mm256_permute2x128_si256::<0x31>(acc, z);
    acc = avx2::mm256_permute4x64_epi64::<0x4E>(acc);
    acc = avx2::mm256_permutevar8x32_epi32(acc, avx2::mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0));

    let lane = avx2::mm256_extracti128_si256::<0>(acc);
    acc = avx2::mm256_inserti128_si256::<1>(acc, lane);

    acc = avx2::mm256_abs_epi32(acc);
    let _ = avx2::mm_packs_epi16(lo, lo);
    acc = avx2::mm256_packs_epi32(acc, z);

    avx2::mm256_storeu_si256_u8(&mut u8buf, acc);

    let _: Vec256 = acc;
    let _: Vec128 = lane;
    let _: Vec256Float = ps;
}

#[cfg(all(feature = "simd128", target_arch = "aarch64"))]
#[test]
fn arm64_wrappers_smoke() {
    use lib_q_intrinsics::arm64;

    let mut u8out = [0u8; 16];
    let mut u32out = [0u32; 4];

    let z8 = arm64::vdupq_n_u8(0);
    let z32 = arm64::vdupq_n_u32(0);
    arm64::vst1q_u8(&mut u8out, z8);
    arm64::vst1q_u32(&mut u32out, z32);

    let v8 = arm64::vld1q_u8(&u8out);
    let v32 = arm64::vld1q_u32(&u32out);

    let a = arm64::vaddq_u8(v8, v8);
    let b = arm64::vaddq_u32(v32, v32);
    let c = arm64::vsubq_u8(a, v8);
    let d = arm64::vsubq_u32(b, v32);
    let e = arm64::vmulq_u32(d, b);
    let f = arm64::vshlq_n_u32(e, 1);
    let g = arm64::vshrq_n_u32(f, 1);
    let h = arm64::vandq_u8(c, a);
    let i = arm64::vandq_u32(g, b);
    let j = arm64::vorrq_u8(h, c);
    let k = arm64::vorrq_u32(i, d);
    let l = arm64::veorq_u8(j, h);
    let m = arm64::veorq_u32(k, i);
    let n = arm64::vcgtq_u32(m, v32);
    let o = arm64::vcgeq_u32(n, v32);
    let p = arm64::vtbl1_u8(l, l);
    let q = arm64::vtbx1_u8(p, l, l);
    let r = arm64::vabdq_u8(q, l);
    let s = arm64::vabdq_u32(o, m);
    let t = arm64::vmaxq_u8(r, l);
    let u = arm64::vmaxq_u32(s, m);
    let v = arm64::vminq_u8(t, l);
    let w = arm64::vminq_u32(u, m);

    arm64::vst1q_u8(&mut u8out, v);
    arm64::vst1q_u32(&mut u32out, w);
}
