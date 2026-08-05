//! `Avx2` dispatcher equivalence tests that run under this crate's *default* features.
//!
//! Every existing AVX2-vs-`Portable` equivalence test (`tests/simd_correctness.rs`,
//! `tests/simd_unit_tests.rs`, `tests/simd_infrastructure_test.rs`) additionally gates on
//! `feature = "simd-avx2"`, which is off by default (`simd-avx2 = []`, not part of
//! `default = ["std", "alloc", "random"]`). That means none of them ever call into the `Avx2`
//! marker type in a default-feature build.
//!
//! But `Avx2` and its `PolynomialOps`/`SyndromeOps` impls (`src/simd/avx2/mod.rs`) are gated
//! only on `target_arch = "x86_64"` (`src/simd/mod.rs`), not on `simd-avx2` — so on any x86_64
//! build, including this crate's default-feature build, `Avx2::*` is real, callable, compiled
//! code, not dead code behind an inactive feature. Confirmed this host is x86_64 with a real
//! AVX2-capable CPU: `(Get-CimInstance Win32_Processor).Name` reported
//! "AMD Ryzen 9 5900X 12-Core Processor" (AVX2 since Zen1, 2017).
//!
//! What actually executes when `Avx2::*` is called depends on the `simd-avx2` feature, which
//! gates the intrinsics *bodies* inside `simd/avx2/{polynomial,syndrome,vector}.rs` one level
//! deeper than the module itself. But "the feature is on" does not by itself mean a given test
//! reaches an intrinsic: each function also has a length/alignment threshold below which it
//! falls back to scalar or to `portable::*` even with `simd-avx2` ON. Per test, with
//! `simd-avx2` ON:
//!
//! | Test | Reaches a real `_mm256_*` intrinsic? |
//! |------|----------------------------------------|
//! | `test_avx2_sparse_dense_mul_matches_portable` | **Never.** `sparse_dense_mul` has no AVX2 implementation; `Avx2::sparse_dense_mul` delegates to `portable::sparse_dense_mul_portable` in every configuration, so this test is a guard against a future divergent implementation, not evidence of AVX2 acceleration. |
//! | `test_avx2_shift_xor_matches_portable` | Only for the word-aligned distances (multiples of 64 with a full 4×u64 chunk in range). Sub-word distances always run the scalar branch, by design (see `polynomial::shift_xor_avx2`'s doc comment). |
//! | `test_avx2_vect_add_matches_portable` | Yes — the 40-byte input exceeds the 32-byte AVX2 chunk threshold, so at least one real intrinsic chunk executes. |
//! | `test_avx2_generate_syndrome_matches_portable` | Yes — the input length exceeds the 32-byte chunk threshold (raised from an original 20 bytes, which was entirely below threshold and never touched an intrinsic). |
//! | `test_avx2_correct_errors_matches_portable` | Yes — the input length exceeds the 32-byte chunk threshold (raised from an original 16 bytes, likewise entirely below threshold). |
//!
//! With `simd-avx2` OFF (this crate's default, and what the coverage gate measures): every
//! `*_avx2` free function compiles to its `#[cfg(not(all(target_arch = "x86_64",
//! feature = "simd-avx2")))]` fallback arm, which delegates straight to the matching
//! `super::super::portable::*_portable` function (or, for `shift_xor`/`vect_add`/syndrome ops,
//! runs the scalar/portable path directly) — so no intrinsic runs at all in that build.
//!
//! These tests don't gate on `simd-avx2` themselves, so the *same* assertions run — and must
//! hold — in both configurations: `cargo test -p lib-q-hqc` (fallback arms, no intrinsics) and
//! `cargo test -p lib-q-hqc --features simd-avx2` (real AVX2 intrinsics where the table above
//! says "yes"). Either way they check the one contract `Avx2` must uphold: bit-for-bit agreement
//! with `Portable` on identical inputs. That is real behavioural coverage of the dispatcher glue
//! in `simd/avx2/{mod,polynomial,syndrome,vector}.rs`, not a no-panic smoke test — every
//! assertion below compares a full computed output, not merely that the call returned.

#[cfg(target_arch = "x86_64")]
use lib_q_hqc::simd::{
    Avx2,
    PolynomialOps,
    Portable,
    SyndromeOps,
};

/// `sparse_dense_mul`: non-trivial sparse/dense inputs, `n_bits` not byte-aligned so the
/// cyclic-wrap tail path is exercised too.
///
/// Note: `Avx2::sparse_dense_mul` has no AVX2 implementation — it delegates to
/// `Portable::sparse_dense_mul`'s underlying routine in every build configuration, so this
/// equivalence holds *by construction*, not because an independent AVX2 code path was checked
/// against it. This test exists as a guard against someone later wiring in a divergent AVX2
/// implementation, not as evidence of AVX2 acceleration for this operation.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx2_sparse_dense_mul_matches_portable() {
    let sparse = [0xA5u8; 32];
    let dense = [0x3Cu8; 32];
    let n_bits = 251; // not a multiple of 8: exercises the cyclic-wrap remainder logic
    let mut out_avx2 = [0u8; 32];
    let mut out_portable = [0u8; 32];

    Avx2::sparse_dense_mul(&mut out_avx2, &sparse, &dense, 12, n_bits);
    Portable::sparse_dense_mul(&mut out_portable, &sparse, &dense, 12, n_bits);

    assert_eq!(
        out_avx2, out_portable,
        "Avx2::sparse_dense_mul must match Portable::sparse_dense_mul bit-for-bit"
    );
}

/// `shift_xor`: word-aligned, bit-aligned, and multi-word-shift distances over the same source.
///
/// The buffer is 16×u64 (1024 bits) so that the word-aligned distances below (`0`, `64`, `128`,
/// `256`) each satisfy `shift_xor_avx2`'s AVX2 condition (`bit_shift == 0` and at least one full
/// 4×u64 chunk in range) and actually execute `_mm256_loadu_si256`/`_mm256_xor_si256`/
/// `_mm256_storeu_si256`, not just the scalar fallback. The remaining distances are sub-word
/// (not multiples of 64) and exercise the scalar branch, which is intentional: see
/// `polynomial::shift_xor_avx2`'s doc comment for why bit-level shifts are scalar by design.
///
/// `dest` starts pre-populated with all-ones rather than zeros: `dest ^= source >> distance`
/// against an all-zero `dest` is indistinguishable from `dest |= source >> distance` on the
/// first write, which would make this test unable to tell a real XOR from a bugged OR in the
/// AVX2 branch (confirmed by observation: an in-place `_mm256_or_si256` swap-in for the AVX2
/// branch's XOR passed this test unmodified when `dest` started at zero, and only failed once
/// `dest` started non-zero).
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx2_shift_xor_matches_portable() {
    let source: [u64; 16] = core::array::from_fn(|i| {
        (i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .rotate_left((i as u32) * 7)
    });

    // 0, 64, 128, 256 are word-aligned and reach the real AVX2 chunk loop; the rest are
    // sub-word distances that exercise the scalar branch.
    for distance in [0usize, 1, 7, 8, 63, 64, 65, 128, 130, 256] {
        let mut dest_avx2 = [u64::MAX; 16];
        let mut dest_portable = [u64::MAX; 16];

        Avx2::shift_xor(&mut dest_avx2, &source, distance);
        Portable::shift_xor(&mut dest_portable, &source, distance);

        assert_eq!(
            dest_avx2, dest_portable,
            "Avx2::shift_xor mismatch at distance={distance}"
        );
    }
}

/// `vect_add` (XOR): asymmetric, non-repeating input bytes so a swapped-operand or off-by-one
/// bug would not accidentally cancel out.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx2_vect_add_matches_portable() {
    let a: [u8; 40] = core::array::from_fn(|i| i as u8);
    let b: [u8; 40] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let mut out_avx2 = [0u8; 40];
    let mut out_portable = [0u8; 40];

    Avx2::vect_add(&mut out_avx2, &a, &b);
    Portable::vect_add(&mut out_portable, &a, &b);

    assert_eq!(
        out_avx2, out_portable,
        "Avx2::vect_add must match Portable::vect_add bit-for-bit"
    );
}

/// `generate_syndrome`: length exceeds the AVX2 32-byte chunk threshold (`chunks = len / 32`),
/// so at least one real `_mm256_*` chunk executes before the scalar/portable tail handles the
/// remainder. (Originally 20 bytes, which is entirely below the 32-byte threshold and never
/// touched an intrinsic in any configuration — raised to 40 so this test actually covers the
/// AVX2 chunk loop.)
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx2_generate_syndrome_matches_portable() {
    let vector: [u8; 40] = core::array::from_fn(|i| (i as u8) ^ 0xDE);
    let parity: [u8; 40] = core::array::from_fn(|i| (i as u8).wrapping_mul(3) ^ 0xAD);
    let mut synd_avx2 = [0u8; 40];
    let mut synd_portable = [0u8; 40];

    Avx2::generate_syndrome(&mut synd_avx2, &vector, &parity);
    Portable::generate_syndrome(&mut synd_portable, &vector, &parity);

    assert_eq!(
        synd_avx2, synd_portable,
        "Avx2::generate_syndrome must match Portable::generate_syndrome bit-for-bit"
    );
}

/// `correct_errors`: checks both the boolean result and the corrected buffer. Length exceeds
/// the AVX2 32-byte chunk threshold (originally 16 bytes, entirely below threshold — raised to
/// 48 so this test actually covers the AVX2 chunk loop, not just the scalar tail).
#[cfg(target_arch = "x86_64")]
#[test]
fn test_avx2_correct_errors_matches_portable() {
    let received: [u8; 48] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
    let syndrome: [u8; 48] = core::array::from_fn(|i| (i as u8) ^ 0x2A);
    let mut corrected_avx2 = [0u8; 48];
    let mut corrected_portable = [0u8; 48];

    let ok_avx2 = Avx2::correct_errors(&mut corrected_avx2, &received, &syndrome);
    let ok_portable = Portable::correct_errors(&mut corrected_portable, &received, &syndrome);

    assert_eq!(
        ok_avx2, ok_portable,
        "success flag must agree with Portable"
    );
    assert_eq!(
        corrected_avx2, corrected_portable,
        "Avx2::correct_errors must match Portable::correct_errors bit-for-bit"
    );
}
