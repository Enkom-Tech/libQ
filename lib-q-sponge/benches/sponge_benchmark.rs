//! Benchmarks for lib-q-sponge functions
//!
//! These benchmarks test the performance of various sponge functions.
#![feature(test)]

extern crate test;
use lib_q_sponge::{
    OptimizationLevel,
    State as AsconState,
    f1600,
    p1600_optimized,
};
use test::{
    Bencher,
    black_box,
};

// Benchmarks for Keccak-f[1600] permutation
#[bench]
fn bench_keccak_f1600(b: &mut Bencher) {
    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    state[1] = 0xFEDCBA0987654321;

    b.iter(|| {
        let mut state = black_box(state);
        f1600(&mut state);
        black_box(state)
    });
}

// Benchmark for Keccak-f[1600] with Reference optimization level
#[bench]
fn bench_keccak_p1600_reference(b: &mut Bencher) {
    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    state[1] = 0xFEDCBA0987654321;

    b.iter(|| {
        let mut state = black_box(state);
        p1600_optimized(&mut state, OptimizationLevel::Reference);
        black_box(state)
    });
}

// Benchmark for Keccak-f[1600] with Basic optimization level
#[bench]
fn bench_keccak_p1600_basic(b: &mut Bencher) {
    // Skip if optimization level not available
    if !OptimizationLevel::Basic.is_available() {
        return;
    }

    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    state[1] = 0xFEDCBA0987654321;

    b.iter(|| {
        let mut state = black_box(state);
        p1600_optimized(&mut state, OptimizationLevel::Basic);
        black_box(state)
    });
}

// Benchmark for Keccak-f[1600] with Advanced optimization level
#[bench]
fn bench_keccak_p1600_advanced(b: &mut Bencher) {
    // Skip if optimization level not available
    if !OptimizationLevel::Advanced.is_available() {
        return;
    }

    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    state[1] = 0xFEDCBA0987654321;

    b.iter(|| {
        let mut state = black_box(state);
        p1600_optimized(&mut state, OptimizationLevel::Advanced);
        black_box(state)
    });
}

// Benchmark for Keccak-f[1600] with Maximum optimization level
#[bench]
fn bench_keccak_p1600_maximum(b: &mut Bencher) {
    // Skip if optimization level not available
    if !OptimizationLevel::Maximum.is_available() {
        return;
    }

    let mut state = [0u64; 25];
    state[0] = 0x1234567890ABCDEF;
    state[1] = 0xFEDCBA0987654321;

    b.iter(|| {
        let mut state = black_box(state);
        p1600_optimized(&mut state, OptimizationLevel::Maximum);
        black_box(state)
    });
}

// Benchmark for Ascon permutation with 12 rounds
#[bench]
fn bench_ascon_permute_12(b: &mut Bencher) {
    let state = AsconState::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    b.iter(|| {
        let mut state = black_box(state);
        state.permute_12();
        black_box(state)
    });
}

// Benchmark for Ascon permutation with 8 rounds
#[bench]
fn bench_ascon_permute_8(b: &mut Bencher) {
    let state = AsconState::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    b.iter(|| {
        let mut state = black_box(state);
        state.permute_8();
        black_box(state)
    });
}

// Benchmark for Ascon permutation with 6 rounds
#[bench]
fn bench_ascon_permute_6(b: &mut Bencher) {
    let state = AsconState::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    b.iter(|| {
        let mut state = black_box(state);
        state.permute_6();
        black_box(state)
    });
}

// Benchmark for Ascon permutation with 1 round
#[bench]
fn bench_ascon_permute_1(b: &mut Bencher) {
    let state = AsconState::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x0011223344556677,
        0x8899AABBCCDDEEFF,
        0xFFFFFFFF00000000,
    );

    b.iter(|| {
        let mut state = black_box(state);
        state.permute_1();
        black_box(state)
    });
}

// Benchmark for fast loop absorb
#[bench]
fn bench_fast_loop_absorb(b: &mut Bencher) {
    let state = [0u64; 25];
    let data = [0u8; 1024]; // 1 KB of data

    b.iter(|| {
        let mut state = black_box(state);
        let offset = lib_q_sponge::fast_loop_absorb_optimized(
            &mut state,
            &data,
            OptimizationLevel::Reference,
        );
        black_box((state, offset))
    });
}

#[cfg(feature = "simd")]
mod simd_benchmarks {
    use lib_q_sponge::parallel::p1600_parallel;
    use test::{
        Bencher,
        black_box,
    };

    use super::*;

    // Benchmark for parallel processing with 2 states
    #[bench]
    fn bench_keccak_parallel_2_states(b: &mut Bencher) {
        let mut states = [[0u64; 25]; 2];
        states[0][0] = 0x1234567890ABCDEF;
        states[1][0] = 0xFEDCBA0987654321;

        b.iter(|| {
            let mut states = black_box(states);
            p1600_parallel(&mut states, OptimizationLevel::Reference);
            black_box(states)
        });
    }

    // Benchmark for parallel processing with 4 states
    #[bench]
    fn bench_keccak_parallel_4_states(b: &mut Bencher) {
        let mut states = [[0u64; 25]; 4];
        for i in 0..4 {
            states[i][0] = 0x1234567890ABCDEF + i as u64;
        }

        b.iter(|| {
            let mut states = black_box(states);
            p1600_parallel(&mut states, OptimizationLevel::Reference);
            black_box(states)
        });
    }
}

#[cfg(all(feature = "simd", feature = "multithreading"))]
mod multithreading_benchmarks {
    use lib_q_sponge::parallel::p1600_multithreaded;
    use test::{
        Bencher,
        black_box,
    };

    use super::*;

    // Benchmark for multithreaded processing with 8 states
    #[bench]
    fn bench_keccak_multithreaded_8_states(b: &mut Bencher) {
        let mut states = [[0u64; 25]; 8];
        for i in 0..8 {
            states[i][0] = 0x1234567890ABCDEF + i as u64;
        }

        b.iter(|| {
            let states = black_box(states);
            let result = p1600_multithreaded(&states, OptimizationLevel::Reference);
            black_box(result.unwrap())
        });
    }
}
