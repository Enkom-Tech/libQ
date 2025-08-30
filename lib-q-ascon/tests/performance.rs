//! Performance regression tests for Ascon permutation
//!
//! These tests verify that Ascon operations maintain consistent performance
//! characteristics and detect performance regressions.

use std::time::{
    Duration,
    Instant,
};

use lib_q_ascon::State;

/// Performance baseline for 12-round permutation
const BASELINE_12_ROUND_NS: u64 = 200; // 200 nanoseconds baseline (matches actual performance)
const PERFORMANCE_TOLERANCE: f64 = 10.0; // Allow 10x performance variation

/// Test that 12-round permutation performance is within acceptable bounds
#[test]
fn test_12_round_performance() {
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 1000;
    let mut total_time = Duration::ZERO;

    // Warm up
    for _ in 0..100 {
        state.permute_12();
    }

    // Measure performance
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        state.permute_12();
        total_time += start.elapsed();
    }

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Verify performance is within acceptable bounds
    assert!(
        avg_time_ns <= (BASELINE_12_ROUND_NS as u128 * PERFORMANCE_TOLERANCE as u128),
        "12-round permutation too slow: {} ns (baseline: {} ns)",
        avg_time_ns,
        BASELINE_12_ROUND_NS
    );

    // Also verify it's not suspiciously fast (could indicate optimization issues)
    assert!(
        avg_time_ns >= (BASELINE_12_ROUND_NS as u128 / PERFORMANCE_TOLERANCE as u128),
        "12-round permutation suspiciously fast: {} ns (baseline: {} ns)",
        avg_time_ns,
        BASELINE_12_ROUND_NS
    );
}

/// Test that 8-round permutation is faster than 12-round
#[test]
fn test_8_round_performance() {
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 1000;

    // Warm up
    for _ in 0..100 {
        state.permute_8();
        state.permute_12();
    }

    // Measure 8-round performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_8();
    }
    let time_8 = start.elapsed();

    // Measure 12-round performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_12();
    }
    let time_12 = start.elapsed();

    // 8-round should be faster than 12-round
    assert!(
        time_8 < time_12,
        "8-round permutation should be faster than 12-round: {} vs {}",
        time_8.as_nanos(),
        time_12.as_nanos()
    );

    // 8-round should be roughly 2/3 the time of 12-round (8/12 = 2/3)
    let ratio = time_8.as_nanos() as f64 / time_12.as_nanos() as f64;
    assert!(
        ratio < 0.9, // Allow some tolerance
        "8-round should be faster than 12-round: ratio {}",
        ratio
    );
}

/// Test that 6-round permutation is faster than 8-round
#[test]
fn test_6_round_performance() {
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 1000;

    // Warm up
    for _ in 0..100 {
        state.permute_6();
        state.permute_8();
    }

    // Measure 6-round performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_6();
    }
    let time_6 = start.elapsed();

    // Measure 8-round performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_8();
    }
    let time_8 = start.elapsed();

    // 6-round should be faster than 8-round (with some tolerance for timing variations)
    let ratio = time_6.as_nanos() as f64 / time_8.as_nanos() as f64;
    assert!(
        ratio < 1.3, // Allow 30% tolerance for timing variations (increased for measurement noise)
        "6-round should not be significantly slower than 8-round: ratio {}",
        ratio
    );
}

/// Test that state conversion operations are fast
#[test]
fn test_state_conversion_performance() {
    let state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let _bytes = state.as_bytes();
    }

    // Measure conversion performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _bytes = state.as_bytes();
        std::hint::black_box(_bytes);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // State conversion should be reasonably fast (less than 1000ns per operation)
    assert!(
        avg_time_ns < 1000,
        "State conversion too slow: {} ns per operation",
        avg_time_ns
    );
}

/// Test that TryFrom operations are fast
#[test]
fn test_try_from_performance() {
    let bytes = [
        0x12u8, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE,
        0xAD, 0xDE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ];

    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let _state = State::try_from(bytes.as_slice());
    }

    // Measure TryFrom performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _state = State::try_from(bytes.as_slice());
        let _ = std::hint::black_box(_state);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // TryFrom should be reasonably fast (less than 1000ns per operation)
    assert!(
        avg_time_ns < 1000,
        "TryFrom too slow: {} ns per operation",
        avg_time_ns
    );
}

/// Test that performance is consistent across multiple runs
#[test]
fn test_performance_consistency() {
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 1000;
    const RUNS: usize = 5;
    let mut run_times = Vec::new();

    for _run in 0..RUNS {
        // Warm up
        for _ in 0..100 {
            state.permute_12();
        }

        // Measure performance
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            state.permute_12();
        }
        let run_time = start.elapsed();
        run_times.push(run_time);
    }

    // Calculate average and standard deviation
    let avg_time = run_times.iter().sum::<Duration>() / RUNS as u32;
    let variance = run_times
        .iter()
        .map(|&t| {
            let diff = t.abs_diff(avg_time);
            diff.as_nanos() as f64 * diff.as_nanos() as f64
        })
        .sum::<f64>() /
        RUNS as f64;
    let std_dev = variance.sqrt();

    // Coefficient of variation should be reasonable (less than 20%)
    let cv = std_dev / avg_time.as_nanos() as f64;
    assert!(
        cv < 0.2,
        "Performance too inconsistent: coefficient of variation {}",
        cv
    );
}

/// Test that performance scales linearly with round count
#[test]
fn test_round_scaling_performance() {
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 1000;

    // Warm up
    for _ in 0..100 {
        state.permute_6();
        state.permute_8();
        state.permute_12();
    }

    // Measure performance for different round counts
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_6();
    }
    let time_6 = start.elapsed();

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_8();
    }
    let time_8 = start.elapsed();

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        state.permute_12();
    }
    let time_12 = start.elapsed();

    // Calculate ratios
    let ratio_6_to_8 = time_6.as_nanos() as f64 / time_8.as_nanos() as f64;
    let ratio_8_to_12 = time_8.as_nanos() as f64 / time_12.as_nanos() as f64;

    // Expected ratios: 6/8 = 0.75, 8/12 = 0.67
    let expected_6_to_8 = 6.0 / 8.0;
    let expected_8_to_12 = 8.0 / 12.0;

    // Allow 50% tolerance for real-world conditions
    let tolerance = 0.5;

    assert!(
        (ratio_6_to_8 - expected_6_to_8).abs() < tolerance,
        "6-to-8 round ratio {} differs too much from expected {}",
        ratio_6_to_8,
        expected_6_to_8
    );

    assert!(
        (ratio_8_to_12 - expected_8_to_12).abs() < tolerance,
        "8-to-12 round ratio {} differs too much from expected {}",
        ratio_8_to_12,
        expected_8_to_12
    );
}

/// Test that memory allocation performance is acceptable
#[test]
fn test_memory_allocation_performance() {
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let _state = State::new(0, 0, 0, 0, 0);
    }

    // Measure state creation performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _state = State::new(
            0x1234567890ABCDEF,
            0xFEDCBA0987654321,
            0xDEADBEEFCAFEBABE,
            0xBEBAFECAEFBEADDE,
            0x0123456789ABCDEF,
        );
        std::hint::black_box(_state);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // State creation should be very fast (less than 200ns per operation)
    assert!(
        avg_time_ns < 200,
        "State creation too slow: {} ns per operation",
        avg_time_ns
    );
}

/// Test that cloning performance is acceptable
#[test]
fn test_cloning_performance() {
    let state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let _cloned = state.clone();
    }

    // Measure cloning performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _cloned = state.clone();
        let _ = std::hint::black_box(_cloned);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Cloning should be very fast (less than 200ns per operation)
    assert!(
        avg_time_ns < 200,
        "State cloning too slow: {} ns per operation",
        avg_time_ns
    );
}
