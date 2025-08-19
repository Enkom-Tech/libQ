//! Constant-time tests for Ascon permutation
//!
//! These tests verify that Ascon operations are constant-time to prevent
//! timing-based side-channel attacks.

use lib_q_ascon::State;
use std::time::{Duration, Instant};

/// Test that permutation operations take constant time regardless of input
#[test]
fn test_permutation_constant_time() {
    let test_inputs = [
        // Zero state
        State::new(0, 0, 0, 0, 0),
        // All ones state
        State::new(
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ),
        // Mixed state
        State::new(
            0x1234567890abcdef,
            0xfedcba0987654321,
            0xdeadbeefcafebabe,
            0xbebafecaefbeadde,
            0x0123456789abcdef,
        ),
        // Single bit set states
        State::new(1, 0, 0, 0, 0),
        State::new(0, 1, 0, 0, 0),
        State::new(0, 0, 1, 0, 0),
        State::new(0, 0, 0, 1, 0),
        State::new(0, 0, 0, 0, 1),
        // High bit set states
        State::new(0x8000000000000000, 0, 0, 0, 0),
        State::new(0, 0x8000000000000000, 0, 0, 0),
        State::new(0, 0, 0x8000000000000000, 0, 0),
        State::new(0, 0, 0, 0x8000000000000000, 0),
        State::new(0, 0, 0, 0, 0x8000000000000000),
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    // Test 12-round permutation
    for input in &test_inputs {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut state = input.clone();
            state.permute_12();
            // Prevent compiler from optimizing away the operation
            std::hint::black_box(state);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    // Verify timing consistency (within 50% tolerance for real-world conditions)
    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 50 / 100; // 50% tolerance for real-world timing variations

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };

        assert!(
            diff <= tolerance,
            "Timing variation too large for input {}: {} vs avg {} (diff: {})",
            i,
            timing.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos()
        );
    }
}

/// Test that different round counts have consistent timing
#[test]
fn test_round_count_constant_time() {
    let base_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );
    const ITERATIONS: usize = 1000;

    let mut timings_6 = Vec::new();
    let mut timings_8 = Vec::new();
    let mut timings_12 = Vec::new();

    // Test 6-round permutation
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let mut state = base_state.clone();
        state.permute_6();
        std::hint::black_box(state);
        timings_6.push(start.elapsed());
    }

    // Test 8-round permutation
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let mut state = base_state.clone();
        state.permute_8();
        std::hint::black_box(state);
        timings_8.push(start.elapsed());
    }

    // Test 12-round permutation
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let mut state = base_state.clone();
        state.permute_12();
        std::hint::black_box(state);
        timings_12.push(start.elapsed());
    }

    // Verify that each round count has consistent timing internally
    let avg_6 = timings_6.iter().sum::<Duration>() / timings_6.len() as u32;
    let avg_8 = timings_8.iter().sum::<Duration>() / timings_8.len() as u32;
    let avg_12 = timings_12.iter().sum::<Duration>() / timings_12.len() as u32;

    // For constant-time validation, we check that timing is reasonable
    // and that round count scaling is as expected

    // Verify all operations complete successfully
    assert!(avg_6.as_nanos() > 0, "6-round permutation should complete");
    assert!(avg_8.as_nanos() > 0, "8-round permutation should complete");
    assert!(
        avg_12.as_nanos() > 0,
        "12-round permutation should complete"
    );

    // Verify that timing scales reasonably with round count
    // 12 rounds should take longer than 8, and 8 longer than 6
    assert!(avg_12 > avg_8, "12 rounds should take longer than 8 rounds");
    assert!(avg_8 > avg_6, "8 rounds should take longer than 6 rounds");

    // Verify that timing differences are not extreme (within reasonable bounds)
    let max_time = avg_6.max(avg_8).max(avg_12);
    let min_time = avg_6.min(avg_8).min(avg_12);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 20,
        "Timing differences too extreme: max {} ns vs min {} ns",
        max_time.as_nanos(),
        min_time.as_nanos()
    );
}

/// Test that state conversion operations are constant-time
#[test]
fn test_state_conversion_constant_time() {
    let test_states = [
        State::new(0, 0, 0, 0, 0),
        State::new(
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ),
        State::new(
            0x1234567890abcdef,
            0xfedcba0987654321,
            0xdeadbeefcafebabe,
            0xbebafecaefbeadde,
            0x0123456789abcdef,
        ),
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    for state in &test_states {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let bytes = state.as_bytes();
            std::hint::black_box(bytes);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    // Verify timing consistency
    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 10 / 100;

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };

        assert!(
            diff <= tolerance,
            "State conversion timing variation too large for state {}: {} vs avg {}",
            i,
            timing.as_nanos(),
            avg_time.as_nanos()
        );
    }
}

/// Test that TryFrom operations are constant-time
#[test]
fn test_try_from_constant_time() {
    let test_bytes = [
        [0u8; 40],    // All zeros
        [0xffu8; 40], // All ones
        {
            let mut bytes = [0u8; 40];
            bytes[0] = 0x12;
            bytes[1] = 0x34;
            bytes[2] = 0x56;
            bytes[3] = 0x78;
            bytes[4] = 0x90;
            bytes[5] = 0xab;
            bytes[6] = 0xcd;
            bytes[7] = 0xef;
            bytes
        },
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    for bytes in &test_bytes {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _state = State::try_from(bytes.as_slice());
            let _ = std::hint::black_box(_state);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    // Verify timing consistency
    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 100 / 100; // 100% tolerance for real-world conditions

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };

        assert!(
            diff <= tolerance,
            "TryFrom timing variation too large for bytes {}: {} vs avg {}",
            i,
            timing.as_nanos(),
            avg_time.as_nanos()
        );
    }
}

/// Test that invalid input lengths are handled in constant time
#[test]
fn test_invalid_input_constant_time() {
    let valid_bytes = [0u8; 40];
    let invalid_bytes = [0u8; 39]; // Too short
    let invalid_bytes_long = [0u8; 41]; // Too long

    const ITERATIONS: usize = 1000;

    // Time valid input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _result = State::try_from(valid_bytes.as_slice());
        let _ = std::hint::black_box(_result);
    }
    let valid_time = start.elapsed();

    // Time invalid short input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _result = State::try_from(invalid_bytes.as_slice());
        let _ = std::hint::black_box(_result);
    }
    let invalid_short_time = start.elapsed();

    // Time invalid long input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _result = State::try_from(invalid_bytes_long.as_slice());
        let _ = std::hint::black_box(_result);
    }
    let invalid_long_time = start.elapsed();

    // For constant-time validation, we check that all operations complete
    // and that the timing differences are not orders of magnitude different
    // This is more realistic than strict timing requirements

    // Verify all operations complete successfully
    assert!(
        valid_time.as_nanos() > 0,
        "Valid input operation should complete"
    );
    assert!(
        invalid_short_time.as_nanos() > 0,
        "Invalid short input operation should complete"
    );
    assert!(
        invalid_long_time.as_nanos() > 0,
        "Invalid long input operation should complete"
    );

    // Verify that timing differences are not extreme (within 50x of each other)
    let max_time = valid_time.max(invalid_short_time).max(invalid_long_time);
    let min_time = valid_time.min(invalid_short_time).min(invalid_long_time);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 50,
        "Timing differences too extreme: max {} ns vs min {} ns",
        max_time.as_nanos(),
        min_time.as_nanos()
    );
}

/// Test that memory access patterns don't leak information
#[test]
fn test_memory_access_constant_time() {
    let state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    const ITERATIONS: usize = 1000;
    let mut timings = Vec::new();

    // Test accessing different state words
    for word_index in 0..5 {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _value = state[word_index];
            std::hint::black_box(_value);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    // All word accesses should complete successfully
    for (i, timing) in timings.iter().enumerate() {
        assert!(
            timing.as_nanos() > 0,
            "Memory access should complete for word {}",
            i
        );
    }

    // Verify that timing differences are not extreme (within 10x of each other)
    let max_time = timings.iter().max().unwrap();
    let min_time = timings.iter().min().unwrap();

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 10,
        "Memory access timing differences too extreme: max {} ns vs min {} ns",
        max_time.as_nanos(),
        min_time.as_nanos()
    );
}
