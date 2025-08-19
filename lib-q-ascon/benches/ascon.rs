// Copyright 2022 Sebastian Ramacher
// Copyright 2025 Enkom Tech
// Copyright 2025 Nexlab-One
// SPDX-License-Identifier: Apache-2.0

use criterion::{Criterion, criterion_group, criterion_main};
use lib_q_ascon::State;
use rand::Rng;

fn criterion_bench_permutation(c: &mut Criterion) {
    let mut rng = rand::rng();
    let mut state = State::new(
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
    );

    let mut group = c.benchmark_group("Ascon Permutation");

    group.bench_function("1 round", |b| {
        b.iter(|| {
            state.permute_1();
        })
    });

    group.bench_function("6 rounds", |b| {
        b.iter(|| {
            state.permute_6();
        })
    });

    group.bench_function("8 rounds", |b| {
        b.iter(|| {
            state.permute_8();
        })
    });

    group.bench_function("12 rounds", |b| {
        b.iter(|| {
            state.permute_12();
        })
    });

    group.finish();
}

fn criterion_bench_state_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ascon State Operations");

    group.bench_function("state creation", |b| {
        b.iter(|| {
            State::new(
                0x1234567890abcdef,
                0xfedcba0987654321,
                0xdeadbeefcafebabe,
                0xbebafecaefbeadde,
                0x0123456789abcdef,
            );
        })
    });

    group.bench_function("as_bytes", |b| {
        let state = State::new(
            0x1234567890abcdef,
            0xfedcba0987654321,
            0xdeadbeefcafebabe,
            0xbebafecaefbeadde,
            0x0123456789abcdef,
        );
        b.iter(|| {
            state.as_bytes();
        })
    });

    group.finish();
}

fn criterion_bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ascon Throughput");

    // Test throughput for different round counts
    let mut state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("permute_12_throughput", |b| {
        b.iter(|| {
            state.permute_12();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    criterion_bench_permutation,
    criterion_bench_state_operations,
    criterion_bench_throughput
);
criterion_main!(benches);
