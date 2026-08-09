//! Regression tests for audit findings F3 and F4 (lens-api-soundness.md):
//!
//! - F3: `PublicHqcPke::test_vect_add` (and the private `vect_add` it forwards to) took an
//!   unchecked `len` that could exceed the buffers it indexed, producing an out-of-bounds
//!   read/write on the AVX2 branch (`from_raw_parts(a.as_ptr(), len * 8)` with no bound).
//! - F4: `lib_q_hqc::simd::Avx2::vect_add` (-> `vect_add_avx2`) sized its SIMD loop from
//!   `output.len()` alone while indexing `a`/`b` at the same offsets, so `a.len() <
//!   output.len()` (or same for `b`) produced an out-of-bounds read.
//!
//! Both are now checked unconditionally (not `debug_assert`), so the over-long/mismatched
//! call is rejected instead of reading/writing out of bounds.

use lib_q_hqc::Hqc128Kem;
use lib_q_hqc::simd::{
    Avx2,
    PolynomialOps,
    Portable,
};

/// F3 red/green target: `test_vect_add` must reject a `len` that exceeds any of the three
/// buffers, rather than silently reading/writing past their end.
#[test]
fn test_vect_add_rejects_oversized_len() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // 8-word buffers, `len` requests 10_000 words -> the AVX2 branch would (pre-fix)
    // reconstruct 80_000-byte slices from 64-byte allocations.
    let mut output = vec![0u64; 8];
    let a = vec![0u64; 8];
    let b = vec![0u64; 8];

    let result = pke.test_vect_add(&mut output, &a, &b, 10_000);
    assert!(
        result.is_err(),
        "test_vect_add must reject len (10000) exceeding the 8-word buffers, got Ok"
    );
}

/// F3: same check when only one of the three buffers is short.
#[test]
fn test_vect_add_rejects_len_exceeding_any_single_buffer() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    let mut output = vec![0u64; 277];
    let a = vec![0u64; 277];
    let short_b = vec![0u64; 4]; // shorter than the requested len

    let result = pke.test_vect_add(&mut output, &a, &short_b, 277);
    assert!(
        result.is_err(),
        "test_vect_add must reject len (277) exceeding `b`'s length (4), got Ok"
    );
}

/// F4 red/green target: `Avx2::vect_add` must not read out of bounds when `a`/`b` are
/// shorter than `output`. Pre-fix this sized its loop from `output.len()` alone; with a
/// short `a` this reads past `a`'s allocation. We can't directly observe UB from safe Rust,
/// so this test instead pins the CONTRACT fix: `Avx2::vect_add` must process only
/// `min(output.len(), a.len(), b.len())` bytes and leave any excess `output` tail
/// untouched, matching the portable implementation's behavior on the same inputs.
#[test]
fn avx2_vect_add_matches_portable_when_inputs_are_shorter_than_output() {
    let mut output_avx2 = vec![0xAAu8; 64];
    let mut output_portable = vec![0xAAu8; 64];
    let a = vec![0x0Fu8; 40]; // shorter than output
    let b = vec![0xF0u8; 40]; // shorter than output

    Avx2::vect_add(&mut output_avx2, &a, &b);
    Portable::vect_add(&mut output_portable, &a, &b);

    assert_eq!(
        output_avx2, output_portable,
        "Avx2::vect_add must agree with the portable implementation \
         (only touching min(output.len(), a.len(), b.len()) bytes) when a/b are shorter than output"
    );
}
