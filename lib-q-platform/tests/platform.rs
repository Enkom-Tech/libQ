//! Integration tests for platform detection and SIMD helpers (std test harness).

use core::cmp::Ordering;

use lib_q_platform::{
    CpuFeatures,
    Platform,
    SimdLevel,
    SimdSupport,
    simd128_support,
    simd256_support,
    simd512_support,
};

#[test]
fn cpu_features_accessors_match_fields() {
    let f = CpuFeatures::new();
    assert_eq!(f.has_avx2(), f.avx2);
    assert_eq!(f.has_avx512(), f.avx512);
    assert_eq!(f.has_neon(), f.neon);
    assert_eq!(f.has_sve(), f.sve);
}

#[test]
fn cpu_features_default_matches_new() {
    assert_eq!(CpuFeatures::default(), CpuFeatures::new());
}

#[test]
fn platform_display() {
    assert_eq!(format!("{}", Platform::X86_64), "x86_64");
    assert_eq!(format!("{}", Platform::AArch64), "aarch64");
    assert_eq!(format!("{}", Platform::Unknown), "unknown");
}

#[test]
fn platform_predicates_match_detect() {
    let p = Platform::detect();
    assert_eq!(p.is_x86_64(), cfg!(target_arch = "x86_64"));
    assert_eq!(p.is_aarch64(), cfg!(target_arch = "aarch64"));
    assert!(!Platform::Unknown.is_x86_64());
    assert!(!Platform::Unknown.is_aarch64());
}

#[test]
fn platform_default_matches_detect() {
    assert_eq!(Platform::default(), Platform::detect());
}

#[test]
fn simd_support_default_matches_new() {
    assert_eq!(SimdSupport::default(), SimdSupport::new());
}

#[test]
fn simd_support_accessors_match_fields() {
    let s = SimdSupport::new();
    assert_eq!(s.has_simd128(), s.simd128);
    assert_eq!(s.has_simd256(), s.simd256);
    assert_eq!(s.has_simd512(), s.simd512);
}

#[test]
fn simd_support_new_matches_detected_platform() {
    let cpu = CpuFeatures::new();
    let platform = Platform::detect();
    let s = SimdSupport::new();
    let want_128 = match platform {
        Platform::X86_64 => cfg!(target_feature = "sse2"),
        Platform::AArch64 => cpu.has_neon(),
        Platform::Unknown => false,
    };
    assert_eq!(s.simd128, want_128);
    assert_eq!(s.simd256, cpu.has_avx2());
    assert_eq!(s.simd512, cpu.has_avx512());
}

#[test]
fn simd_free_functions_match_support_struct() {
    let s = SimdSupport::new();
    assert_eq!(simd128_support(), s.simd128);
    assert_eq!(simd256_support(), s.simd256);
    assert_eq!(simd512_support(), s.simd512);
}

#[test]
fn simd_level_ordering() {
    assert_eq!(SimdLevel::None.cmp(&SimdLevel::Simd128), Ordering::Less);
    assert_eq!(SimdLevel::Simd512.cmp(&SimdLevel::None), Ordering::Greater);
}

#[test]
fn debug_impls_smoke() {
    let _ = format!("{:?}", CpuFeatures::new());
    let _ = format!("{:?}", Platform::detect());
    let _ = format!("{:?}", SimdSupport::new());
    let _ = format!("{:?}", SimdLevel::Simd256);
}
