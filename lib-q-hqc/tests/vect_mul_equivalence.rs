//! Equivalence of schoolbook `vect_mul` vs cyclic `sparse_dense_mul` on real HQC parameters.

use std::collections::BTreeSet;

use lib_q_hqc::hqc_pke::{
    HqcPke,
    schoolbook_vect_mul_mod_xnm1,
};
use lib_q_hqc::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
use lib_q_hqc::simd::Avx2;
use lib_q_hqc::simd::Portable;
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "alloc"))]
use lib_q_hqc::simd::avx2::gf2x::avx2_vect_mul_mod_xnm1;
#[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "alloc"))]
use lib_q_hqc::simd::runtime::has_avx2;
use lib_q_hqc::simd::traits::PolynomialOps;

/// Place exactly `weight` distinct bits in `vec_u64` for indices in `0..n_bits`.
fn fill_sparse_fixed_weight(vec_u64: &mut [u64], n_bits: usize, weight: usize, seed: u64) {
    vec_u64.fill(0);
    let mut state = seed;
    let mut chosen = BTreeSet::new();
    while chosen.len() < weight {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let pos = (state as usize) % n_bits;
        chosen.insert(pos);
    }
    for p in chosen {
        vec_u64[p / 64] |= 1u64 << (p % 64);
    }
}

fn fill_dense_masked<P: HqcParams>(vec_u64: &mut [u64], seed: u64) {
    let mut s = seed;
    for w in vec_u64.iter_mut() {
        s = s.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
        *w = s;
    }
    let mask = (1u64 << (P::N & 0x3F)) - 1;
    vec_u64[P::VEC_N_SIZE_64 - 1] &= mask;
}

fn run_case<P: HqcParams>(seed: u64) {
    let pke = HqcPke::<P>::new().expect("PKE init");
    let mut sparse_u64 = vec![0u64; P::VEC_N_SIZE_64];
    let mut dense_u64 = vec![0u64; P::VEC_N_SIZE_64];
    let mut school_out = vec![0u64; P::VEC_N_SIZE_64];

    fill_sparse_fixed_weight(&mut sparse_u64, P::N, P::OMEGA, seed);
    fill_dense_masked::<P>(&mut dense_u64, seed.wrapping_add(1));

    schoolbook_vect_mul_mod_xnm1(
        &mut school_out,
        &sparse_u64,
        &dense_u64,
        P::VEC_N_SIZE_64,
        P::N,
    )
    .expect("schoolbook");

    let mut a_bytes = vec![0u8; P::VEC_N_SIZE_BYTES];
    let mut b_bytes = vec![0u8; P::VEC_N_SIZE_BYTES];
    let mut out_bytes = vec![0u8; P::VEC_N_SIZE_BYTES];
    pke.test_vect_to_bytes(&sparse_u64, &mut a_bytes)
        .expect("vect_to_bytes sparse");
    pke.test_vect_to_bytes(&dense_u64, &mut b_bytes)
        .expect("vect_to_bytes dense");

    Portable::sparse_dense_mul(&mut out_bytes, &a_bytes, &b_bytes, P::OMEGA as u32, P::N);

    let mut portable_out = vec![0u64; P::VEC_N_SIZE_64];
    pke.test_bytes_to_vect(&out_bytes, &mut portable_out)
        .expect("bytes_to_vect");

    assert_eq!(
        school_out,
        portable_out,
        "Portable sparse_dense_mul != schoolbook (P={}, seed={})",
        core::any::type_name::<P>(),
        seed
    );

    #[cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]
    {
        out_bytes.fill(0);
        Avx2::sparse_dense_mul(&mut out_bytes, &a_bytes, &b_bytes, P::OMEGA as u32, P::N);
        let mut avx_out = vec![0u64; P::VEC_N_SIZE_64];
        pke.test_bytes_to_vect(&out_bytes, &mut avx_out)
            .expect("bytes_to_vect avx");
        assert_eq!(
            school_out,
            avx_out,
            "AVX2 sparse_dense_mul != schoolbook (P={}, seed={})",
            core::any::type_name::<P>(),
            seed
        );
    }
}

/// Dense × dense: schoolbook vs PCLMUL Karatsuba (`gf2x`) on full `u64` vectors (AVX2 path only).
fn run_dense_case<P: HqcParams>(seed: u64) {
    let n = P::VEC_N_SIZE_64;
    let mask = (1u64 << (P::N & 0x3F)) - 1;
    let mut a = vec![0u64; n];
    let mut b = vec![0u64; n];
    let mut s = vec![0u64; n];

    let mut x = seed;
    for i in 0..n {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        a[i] = x;
        x = x.rotate_left(23).wrapping_add(i as u64);
        b[i] = x ^ 0xA5A5_A5A5_A5A5_A5A5;
    }
    a[n - 1] &= mask;
    b[n - 1] &= mask;

    schoolbook_vect_mul_mod_xnm1(&mut s, &a, &b, n, P::N).expect("schoolbook dense×dense");

    #[cfg(all(feature = "simd-avx2", target_arch = "x86_64", feature = "alloc"))]
    {
        if has_avx2() {
            let mut v = vec![0u64; n];
            avx2_vect_mul_mod_xnm1::<P>(&mut v, &a, &b).expect("avx2 dense×dense");
            assert_eq!(
                s,
                v,
                "AVX2 gf2x != schoolbook dense×dense (P={}, seed={})",
                core::any::type_name::<P>(),
                seed
            );
        }
    }
}

#[test]
fn vect_mul_matches_sparse_dense_hqc128() {
    for seed in [1u64, 2, 42, 99, 0xDEADBEEF] {
        run_case::<Hqc1Params>(seed);
    }
}

#[test]
fn vect_mul_matches_sparse_dense_hqc192() {
    for seed in [3u64, 7, 12345] {
        run_case::<Hqc3Params>(seed);
    }
}

#[test]
fn vect_mul_matches_sparse_dense_hqc256() {
    for seed in [5u64, 11, 777] {
        run_case::<Hqc5Params>(seed);
    }
}

#[test]
fn vect_mul_dense_matches_gf2x_hqc128() {
    for seed in [0u64, 1, 99, 0xC0FFEE] {
        run_dense_case::<Hqc1Params>(seed);
    }
}

#[test]
fn vect_mul_dense_matches_gf2x_hqc192() {
    for seed in [2u64, 17, 0xBEEF] {
        run_dense_case::<Hqc3Params>(seed);
    }
}

#[test]
fn vect_mul_dense_matches_gf2x_hqc256() {
    for seed in [4u64, 31, 0xFACADE] {
        run_dense_case::<Hqc5Params>(seed);
    }
}
