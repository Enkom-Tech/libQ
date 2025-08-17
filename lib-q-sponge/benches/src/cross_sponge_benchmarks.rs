//! Cross-sponge benchmarks for lib-q-sponge
//! 
//! This module provides benchmarks that compare performance across different
//! sponge functions and optimization levels.

use lib_q_sponge::{f1600, State, OptimizationLevel, p1600_optimized};
use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_bench_cross_sponge_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cross-Sponge Comparison");
    
    // Benchmark Keccak-f[1600]
    let mut keccak_state = [0u64; 25];
    keccak_state[0] = 0x1234567890abcdef;
    
    group.bench_function("keccak_f1600", |b| {
        b.iter(|| {
            f1600(&mut keccak_state);
        })
    });
    
    // Benchmark Ascon permutation
    let mut ascon_state = State::new(0x1234567890abcdef, 0xfedcba0987654321, 0, 0, 0);
    
    group.bench_function("ascon_permute_12", |b| {
        b.iter(|| {
            ascon_state.permute_12();
        })
    });
    
    group.finish();
}

fn criterion_bench_optimization_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimization Levels");
    
    let mut state = [0u64; 25];
    state[0] = 0x1234567890abcdef;
    
    // Benchmark different optimization levels
    for level in [
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if level.is_available() {
            let level_name = format!("{:?}", level);
            group.bench_function(&level_name, |b| {
                b.iter(|| {
                    p1600_optimized(&mut state, level);
                })
            });
        }
    }
    
    group.finish();
}

criterion_group!(
    benches,
    criterion_bench_cross_sponge_comparison,
    criterion_bench_optimization_levels
);
criterion_main!(benches);
