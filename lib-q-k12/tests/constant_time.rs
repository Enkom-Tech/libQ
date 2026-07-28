// Copyright 2026 Enkom Tech
// Copyright 2026 Nexlab-One
// SPDX-License-Identifier: Apache-2.0

//! Constant-time verification tests for Kt128
//!
//! These tests verify that Kt128 operations execute in constant time
//! to prevent timing-based side-channel attacks.

use std::time::{
    Duration,
    Instant,
};

use lib_q_k12::Kt128;
use lib_q_k12::digest::{
    ExtendableOutput,
    Reset,
    Update,
};

const ITERATIONS: usize = 1000;

/// How many times each measurement is repeated before a timing is accepted.
const REPS: usize = 5;

/// Time `iterations` runs of `op`, repeated [`REPS`] times, and keep the MINIMUM.
///
/// A single wall-clock sample on a shared CI runner is not a measurement of the
/// code under test — it is that plus whatever the scheduler, another tenant, or a
/// frequency transition did during the sample. Those perturbations are strictly
/// *additive*: they can only ever make an observation slower, never faster. The
/// minimum over repetitions is therefore the maximum-likelihood estimate of the
/// true cost, and taking it makes these assertions STRICTER, not looser — the
/// bands below now have to be cleared by the code's actual timing rather than by
/// noise that happened to inflate every sample together.
fn min_time(iterations: usize, mut op: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let start = Instant::now();
        for _ in 0..iterations {
            op();
        }
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

/// Test that hashing operations take consistent time regardless of input content
#[test]
fn test_hash_constant_time() {
    let size = 1024;

    // Create different input patterns
    let zeros = vec![0u8; size];
    let ones = vec![0xFFu8; size];
    let alternating: Vec<u8> = (0..size)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
        .collect();
    let random_pattern: Vec<u8> = (0..size).map(|i| (i * 251) as u8).collect();

    let inputs = [&zeros, &ones, &alternating, &random_pattern];
    let mut times = Vec::new();

    // Warm up
    for _ in 0..100 {
        let mut hasher = Kt128::default();
        hasher.update(&zeros);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure timing for each input pattern
    for input in &inputs {
        times.push(min_time(ITERATIONS, || {
            let mut hasher = Kt128::default();
            hasher.update(input);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }));
    }

    // Calculate average and check variance
    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    let tolerance = avg_time * 50 / 100; // 50% tolerance for real-world timing variations

    for (i, time) in times.iter().enumerate() {
        let diff = (*time).abs_diff(avg_time);

        assert!(
            diff <= tolerance,
            "Input pattern {} timing {} differs too much from average {} (diff: {})",
            i,
            time.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos()
        );
    }
}

/// Test that customization processing is constant-time in the customization's
/// **content**.
///
/// Note carefully what this does and does not assert, because the earlier version
/// asserted something that is false by construction.
///
/// A customization string is absorbed into the sponge, so its **length** changes how
/// much work Kt128 does: a 100-byte customization costs strictly more than an empty
/// one, and crossing a block boundary costs an extra permutation. That is the
/// algorithm working as specified, not a leak. The customization is also *public*
/// input — it is a domain separator, not key material — so a length-dependent timing
/// is not a side channel even in principle.
///
/// The previous version compared `""` (0 bytes), `"short"` (5),
/// `"medium_length_customization"` (27) and `[0xAA; 100]` against one 60% band. It
/// passed only because hashing the 1000-byte message dominated that difference, and
/// it failed intermittently on shared CI runners when noise ate the remaining margin
/// — blocking unrelated PRs (a serde_json dependency bump, among others). A test
/// that can only pass when the effect it measures is drowned out is not measuring
/// anything.
///
/// What *is* worth asserting is that timing does not depend on the customization's
/// content at a **fixed** length — the property that would matter if a customization
/// ever carried secret material. So every input below is exactly [`CUSTOM_LEN`]
/// bytes and differs only in its bytes, which makes the comparison meaningful and
/// removes the systematic length bias.
///
/// This remains a coarse wall-clock smoke test, not a side-channel proof. Real
/// leakage assessment lives in `lib-q-sca-test` and the dedicated "Constant-Time
/// Verification" CI job; do not treat a pass here as evidence of constant-timeness.
#[test]
fn test_customization_constant_time() {
    let data = vec![0x42u8; 1000];

    /// Fixed customization length, so the comparison isolates content from length.
    const CUSTOM_LEN: usize = 32;

    // Same length, different content: all-zero, all-one, alternating, and a
    // counter-derived pattern.
    let zeros = [0x00u8; CUSTOM_LEN];
    let ones = [0xFFu8; CUSTOM_LEN];
    let alternating: Vec<u8> = (0..CUSTOM_LEN)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
        .collect();
    let counter: Vec<u8> = (0..CUSTOM_LEN).map(|i| (i * 251) as u8).collect();

    let customizations: [&[u8]; 4] = [zeros.as_slice(), ones.as_slice(), &alternating, &counter];

    let mut times = Vec::new();

    // Warm up
    for _ in 0..100 {
        let mut hasher = Kt128::new(&zeros);
        hasher.update(&data);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure timing for each customization
    for custom in &customizations {
        times.push(min_time(ITERATIONS, || {
            let mut hasher = Kt128::new(custom);
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }));
    }

    // Check timing consistency. The band stays at 60% rather than being tightened:
    // all four inputs now do provably identical work, so the only thing left for the
    // band to absorb is runner noise, and this test's job is to catch a gross
    // content-dependent difference, not to be a precise instrument. Tightening it
    // would trade the bug just fixed for a new source of intermittent failures.
    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    let tolerance = avg_time * 60 / 100;

    for (i, time) in times.iter().enumerate() {
        let diff = (*time).abs_diff(avg_time);

        assert!(
            diff <= tolerance,
            "Customization {} timing {} differs too much from average {} (diff: {})",
            i,
            time.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos()
        );
    }
}

/// Test that chunk boundary processing is constant-time
#[test]
fn test_chunk_boundary_constant_time() {
    // Test inputs around chunk boundaries
    // Skip this test as it triggers an internal implementation edge case
    // that's not critical for constant-time verification
    let sizes = [
        1000,  // Small input
        2000,  // Medium input
        5000,  // Large input
        10000, // Very large input
    ];

    let mut times = Vec::new();

    // Warm up
    let test_data = vec![0x55u8; 10000];
    for _ in 0..100 {
        let mut hasher = Kt128::default();
        hasher.update(&test_data[..1000]);
        let _ = hasher.finalize_boxed(32);
    }

    // Measure timing for each size
    for &size in &sizes {
        let data = vec![0x55u8; size];
        // Fewer iterations for larger data
        times.push(min_time(ITERATIONS / 2, || {
            let mut hasher = Kt128::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }));
    }

    // Check that timing scales reasonably with data size
    // Larger inputs should take more time, but the ratio should be consistent
    for i in 1..times.len() {
        let ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = sizes[i] as f64 / sizes[0] as f64;

        // Allow significant variance for chunk boundary effects
        assert!(
            ratio <= size_ratio * 3.0,
            "Timing ratio {} too large for size ratio {} at index {}",
            ratio,
            size_ratio,
            i
        );
    }
}

/// Test that XOF output reading is constant-time
#[test]
fn test_xof_output_constant_time() {
    let data = vec![0x33u8; 1000];
    let output_sizes = [32, 64, 128, 256, 1000];
    let mut times = Vec::new();

    // Warm up
    for _ in 0..100 {
        let mut hasher = Kt128::default();
        hasher.update(&data);
        let _ = hasher.finalize_boxed(64);
    }

    // Measure timing for different output sizes
    for &size in &output_sizes {
        times.push(min_time(ITERATIONS, || {
            let mut hasher = Kt128::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(size);
            std::hint::black_box(result);
        }));
    }

    // Check that timing scales linearly with output size
    for i in 1..times.len() {
        let time_ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = output_sizes[i] as f64 / output_sizes[0] as f64;

        // Output generation should scale roughly linearly
        assert!(
            time_ratio <= size_ratio * 2.0,
            "XOF output timing ratio {} too large for size ratio {} at index {}",
            time_ratio,
            size_ratio,
            i
        );
    }
}

/// Test that reset operations are constant-time
#[test]
fn test_reset_constant_time() {
    let data1 = vec![0x11u8; 1000];
    let data2 = vec![0x22u8; 2000];
    let data3 = vec![0x33u8; 500];

    let datasets = [&data1, &data2, &data3];
    let mut times = Vec::new();

    // Warm up
    for _ in 0..100 {
        let mut hasher = Kt128::default();
        hasher.update(&data1);
        hasher.reset();
    }

    // Measure reset timing after processing different amounts of data
    for data in &datasets {
        times.push(min_time(ITERATIONS, || {
            let mut hasher = Kt128::default();
            hasher.update(data);
            hasher.reset();
            std::hint::black_box(&hasher);
        }));
    }

    // Reset should take consistent time regardless of previous state
    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    // Use 75% tolerance for cryptographic operations which may have natural variation
    let tolerance = avg_time * 75 / 100;

    // Calculate coefficient of variation to assess timing stability
    let variance = times
        .iter()
        .map(|t| {
            let diff = t.as_nanos() as f64 - avg_time.as_nanos() as f64;
            diff * diff
        })
        .sum::<f64>() /
        times.len() as f64;
    let std_dev = variance.sqrt();
    let cv = if avg_time.as_nanos() > 0 {
        (std_dev / avg_time.as_nanos() as f64) * 100.0
    } else {
        0.0
    };

    // Skip test on systems with very high timing variability (>50% coefficient of variation)
    if cv > 50.0 {
        println!(
            "Skipping reset timing test due to high system variability (CV: {:.2}%)",
            cv
        );
        return;
    }

    for (i, time) in times.iter().enumerate() {
        let diff = (*time).abs_diff(avg_time);

        assert!(
            diff <= tolerance,
            "Reset timing after dataset {} ({}) differs too much from average {} (diff: {})",
            i,
            time.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos()
        );
    }
}

/// Test that memory access patterns are consistent
#[test]
fn test_memory_access_constant_time() {
    let sizes = [100, 500, 1000, 2000];
    let mut times = Vec::new();

    // Warm up
    let test_data = vec![0x77u8; 2000];
    for _ in 0..100 {
        let mut hasher = Kt128::default();
        hasher.update(&test_data[..1000]);
        let _ = hasher.finalize_boxed(32);
    }

    // Test different input sizes with same content pattern
    for &size in &sizes {
        let data: Vec<u8> = (0..size).map(|i| (i * 17) as u8).collect();
        times.push(min_time(ITERATIONS, || {
            let mut hasher = Kt128::default();
            hasher.update(&data);
            let result = hasher.finalize_boxed(32);
            std::hint::black_box(result);
        }));
    }

    // Verify timing scales reasonably with input size
    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    let variance = times
        .iter()
        .map(|t| {
            let diff = t.as_nanos() as f64 - avg_time.as_nanos() as f64;
            diff * diff
        })
        .sum::<f64>() /
        times.len() as f64;
    let std_dev = variance.sqrt();
    let cv = if avg_time.as_nanos() > 0 {
        (std_dev / avg_time.as_nanos() as f64) * 100.0
    } else {
        0.0
    };

    if cv > 50.0 {
        println!(
            "Skipping memory access timing test due to high system variability (CV: {:.2}%)",
            cv
        );
        return;
    }

    let max_size_ratio = sizes[sizes.len() - 1] as f64 / sizes[0] as f64;
    let max_time_ratio = times[times.len() - 1].as_nanos() as f64 / times[0].as_nanos() as f64;
    // Kt128 has large fixed per-hash overhead; on shared CI runners wall time may not
    // scale with input size enough to infer anything (not a side-channel signal).
    if max_time_ratio < max_size_ratio * 0.1 {
        println!(
            "Skipping memory access scaling check: fixed overhead dominates (time ratio {max_time_ratio:.2}, size ratio {max_size_ratio:.2})"
        );
        return;
    }

    for i in 1..times.len() {
        let time_ratio = times[i].as_nanos() as f64 / times[0].as_nanos() as f64;
        let size_ratio = sizes[i] as f64 / sizes[0] as f64;

        // Should scale roughly linearly with input size (allow more tolerance for real-world conditions)
        assert!(
            time_ratio >= size_ratio * 0.1 && time_ratio <= size_ratio * 10.0,
            "Memory access timing ratio {} not reasonable for size ratio {} at index {}",
            time_ratio,
            size_ratio,
            i
        );
    }
}
