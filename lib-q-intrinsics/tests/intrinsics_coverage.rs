//! Integration tests to exercise public APIs for coverage and smoke checks.

#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
use lib_q_intrinsics::avx2;
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

#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
#[test]
fn simd256_avx2_integration_smoke() {
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }

    let mut input = [0i32; 8];
    let mut output = [0i32; 8];

    for (idx, slot) in input.iter_mut().enumerate() {
        *slot = idx as i32;
    }

    let base = avx2::mm256_loadu_si256_i32(&input);
    let inc = avx2::mm256_set1_epi32(1);
    let add = avx2::mm256_add_epi32(base, inc);
    let shl = avx2::mm256_slli_epi32::<1>(add);
    let shr = avx2::mm256_srli_epi32::<1>(shl);
    let mask = avx2::mm256_cmpeq_epi32(shr, add);
    let mixed = avx2::vec256_blendv_epi32(shr, add, mask);
    avx2::mm256_storeu_si256_i32(&mut output, mixed);

    assert_eq!(output, [1, 2, 3, 4, 5, 6, 7, 8]);
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

// AVX2 / generic smoke lives in `src/avx2.rs` and `src/generic.rs` under `#[cfg(test)]`
// so tarpaulin attributes inlined code to this crate (Linux integration tests under-report).

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
