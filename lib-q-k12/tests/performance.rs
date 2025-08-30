// Copyright 2025 Enkom Tech
// Copyright 2025 Nexlab-One
// SPDX-License-Identifier: Apache-2.0

//! Performance regression tests for KangarooTwelve
//!
//! These tests monitor performance characteristics and detect regressions
//! in the KangarooTwelve implementation.

use std::time::{
    Duration,
    Instant,
};

use lib_q_k12::KangarooTwelve;
use lib_q_k12::digest::{
    ExtendableOutput,
    Reset,
    Update,
};

/// Performance baseline for small hash (1KB input, 32-byte output)
const BASELINE_SMALL_HASH_NS: u64 = 500000; // 500 microseconds baseline (more realistic for K12)
const PERFORMANCE_TOLERANCE: f64 = 10.0; // Allow 10x performance variation

/// Test baseline performance for small inputs
#[test]
fn test_small_input_performance() {
    let data = vec![0x42u8; 1024]; // 1KB
    const ITERATIONS: usize = 1000;

    // Warm up
    for _ in 0..100 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let result = hasher.finalize_boxed(32);
        std::hint::black_box(result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    assert!(
        avg_time_ns <= BASELINE_SMALL_HASH_NS as u128 * PERFORMANCE_TOLERANCE as u128,
        "Small input performance regression: {} ns (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SMALL_HASH_NS
    );
}

/// Test that performance scales reasonably with input size
#[test]
fn test_input_scaling_performance() {
    let sizes = [1024, 4096, 8192, 16384]; // 1KB, 4KB, 8KB, 16KB
    let mut times = Vec::new();
    const ITERATIONS: usize = 100;

    // Warm up
    let test_data = vec![0x55u8; 16384];
    for _ in 0..50 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&test_data[..1024]);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance for each size
    for &size in &sizes {
        let data = vec![0x55u8; size];
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    // Check that performance scales sub-linearly or linearly (not super-linearly)
    for i in 1..times.len() {
        let time_ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = sizes[i] as f64 / sizes[0] as f64;

        // Performance should not degrade super-linearly
        assert!(
            time_ratio <= size_ratio * 2.0,
            "Performance scaling too poor: {}x time for {}x size at index {}",
            time_ratio,
            size_ratio,
            i
        );
    }
}

/// Test output generation performance
#[test]
fn test_output_generation_performance() {
    let data = vec![0x33u8; 1000];
    let output_sizes = [32, 128, 512, 2048];
    let mut times = Vec::new();
    const ITERATIONS: usize = 500;

    // Warm up
    for _ in 0..100 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance for different output sizes
    for &size in &output_sizes {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(size);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    // Output generation should scale roughly linearly
    for i in 1..times.len() {
        let time_ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = output_sizes[i] as f64 / output_sizes[0] as f64;

        assert!(
            time_ratio <= size_ratio * 3.0,
            "Output generation scaling too poor: {}x time for {}x output size at index {}",
            time_ratio,
            size_ratio,
            i
        );
    }
}

/// Test customization processing performance
#[test]
fn test_customization_performance() {
    let data = vec![0x77u8; 1000];
    let custom_sizes = [0, 10, 100, 1000];
    let mut times = Vec::new();
    const ITERATIONS: usize = 500;

    // Warm up
    for _ in 0..100 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance for different customization sizes
    for &size in &custom_sizes {
        let custom = vec![0x99u8; size];
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::new(&custom);
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    // Customization processing should not cause severe performance degradation
    let base_time = times[0]; // No customization
    for (i, &time) in times.iter().enumerate().skip(1) {
        let ratio = time.as_nanos() as f64 / base_time.as_nanos() as f64;
        assert!(
            ratio <= 5.0, // Allow up to 5x slowdown for customization
            "Customization processing too slow: {}x slower for size {} at index {}",
            ratio,
            custom_sizes[i],
            i
        );
    }
}

/// Test chunk boundary performance
#[test]
fn test_chunk_boundary_performance() {
    const CHUNK_SIZE: usize = 8192;
    let sizes = [
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 2 - 1,
        CHUNK_SIZE * 2,
    ];
    let mut times = Vec::new();
    const ITERATIONS: usize = 100;

    // Warm up
    let test_data = vec![0x44u8; CHUNK_SIZE * 3];
    for _ in 0..50 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&test_data[..CHUNK_SIZE]);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance around chunk boundaries
    for &size in &sizes {
        let data = vec![0x44u8; size];
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    // Check for reasonable performance across chunk boundaries
    for i in 1..times.len() {
        let time_ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = sizes[i] as f64 / sizes[0] as f64;

        // Should not have severe performance cliffs at boundaries
        assert!(
            time_ratio <= size_ratio * 3.0,
            "Chunk boundary performance issue: {}x time for {}x size at index {}",
            time_ratio,
            size_ratio,
            i
        );
    }
}

/// Test incremental update performance
#[test]
fn test_incremental_update_performance() {
    let total_size = 8192;
    let chunk_sizes = [1, 64, 256, 1024, total_size];
    let mut times = Vec::new();
    const ITERATIONS: usize = 100;

    // Warm up
    let data = vec![0x66u8; total_size];
    for _ in 0..50 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Test different update patterns
    for &chunk_size in &chunk_sizes {
        let data = vec![0x66u8; total_size];
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::default();
            for chunk in data.chunks(chunk_size) {
                hasher.update(chunk);
            }
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    // Incremental updates should not be dramatically slower than bulk updates
    let bulk_time = times.last().unwrap(); // Single update
    for (i, &time) in times.iter().enumerate().take(times.len() - 1) {
        let ratio = time.as_nanos() as f64 / bulk_time.as_nanos() as f64;
        assert!(
            ratio <= 10.0, // Allow up to 10x overhead for very small chunks
            "Incremental update too slow: {}x slower for chunk size {} at index {}",
            ratio,
            chunk_sizes[i],
            i
        );
    }
}

/// Test reset operation performance
#[test]
fn test_reset_performance() {
    let data = vec![0x88u8; 5000];
    const ITERATIONS: usize = 1000;

    // Warm up
    for _ in 0..100 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        hasher.reset();
    }

    // Measure reset performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        hasher.reset();
        std::hint::black_box(&hasher);
    }
    let total_time = start.elapsed();

    let avg_reset_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Reset should be reasonably fast (less than 1 millisecond)
    assert!(
        avg_reset_time_ns < 1000000,
        "Reset operation too slow: {} ns per reset",
        avg_reset_time_ns
    );
}

/// Test memory allocation performance
#[test]
fn test_memory_allocation_performance() {
    const ITERATIONS: usize = 1000;
    let data = vec![0x99u8; 1000];

    // Warm up
    for _ in 0..100 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure hasher creation and basic operation
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let result = hasher.finalize_boxed(32);
        std::hint::black_box(result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Should be reasonably fast (less than 500 microseconds per operation)
    assert!(
        avg_time_ns < 500000,
        "Memory allocation too slow: {} ns per operation",
        avg_time_ns
    );
}

/// Test cloning performance
#[test]
fn test_cloning_performance() {
    let data = vec![0xAAu8; 2000];
    const ITERATIONS: usize = 1000;

    // Create a hasher with some state
    let mut base_hasher = KangarooTwelve::default();
    base_hasher.update(&data);

    // Warm up
    for _ in 0..100 {
        let _cloned = base_hasher.clone();
    }

    // Measure cloning performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let cloned = base_hasher.clone();
        std::hint::black_box(cloned);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Cloning should be reasonably fast (less than 1 millisecond)
    assert!(
        avg_time_ns < 1000000,
        "Cloning too slow: {} ns per clone",
        avg_time_ns
    );
}

/// Test performance consistency over multiple runs
#[test]
fn test_performance_consistency() {
    let data = vec![0xBBu8; 1000];
    const ITERATIONS: usize = 100;
    const RUNS: usize = 5;

    let mut run_times = Vec::new();

    // Warm up
    for _ in 0..50 {
        let mut hasher = KangarooTwelve::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure performance over multiple runs
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = KangarooTwelve::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        run_times.push(elapsed);
    }

    // Calculate variance
    let avg_time = run_times.iter().sum::<Duration>() / run_times.len() as u32;
    let max_deviation = run_times
        .iter()
        .map(|&time| {
            if time > avg_time {
                time - avg_time
            } else {
                avg_time - time
            }
        })
        .max()
        .unwrap();

    // Performance should be reasonably consistent (within 50% of average)
    let tolerance = avg_time / 2;
    assert!(
        max_deviation <= tolerance,
        "Performance inconsistent: max deviation {} from average {}",
        max_deviation.as_nanos(),
        avg_time.as_nanos()
    );
}
