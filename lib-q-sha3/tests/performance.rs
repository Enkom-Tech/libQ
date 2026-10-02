//! Performance tests for SHA3 family algorithms
//!
//! These tests verify performance characteristics and detect regressions.
//!
//! They run in the ordinary `cargo test` gate, usually on shared or loaded CI hosts and in
//! parallel with the other tests in this binary. A long wall-clock total on such a host includes
//! whatever time the scheduler gave to other processes, so a single preemption can inflate one
//! measurement by an arbitrary factor. Every timing here is therefore taken as the **minimum over
//! many short samples** (see [`min_ns_per_call`]): the fastest sample is the one least disturbed
//! by the rest of the machine, so it tracks the cost of the code rather than the load on the host.
//! Where several algorithms or inputs are compared, their samples are interleaved so that
//! frequency scaling and load changes affect all of them alike.

use std::time::{
    Duration,
    Instant,
};

use digest::Digest;
use digest::common::BlockSizeUser;
#[cfg(not(tarpaulin))]
use lib_q_sha3::{
    Sha3_224,
    Sha3_384,
};
use lib_q_sha3::{
    Sha3_256,
    Sha3_512,
};

#[cfg(not(tarpaulin))]
/// Upper bound on mean ns/op for SHA3-256-class algorithms (short input, many iterations).
///
/// Debug builds and shared CI runners are often ~1.5× slower than this vs a typical dev laptop;
/// the check is only to catch large regressions, not to micro-benchmark in `cargo test`.
const BASELINE_SHA3_256_NS: u64 = 220_000;

/// Number of timed samples per measured case. The minimum over this many short samples is
/// stable under heavy CPU contention; only a host that preempts every single sample can skew it.
const SAMPLES: usize = 60;

/// One hash of `input` with `D`, result kept alive so the work is not optimised away.
#[inline(never)]
fn hash_once<D: Digest>(input: &[u8]) {
    let mut hasher = D::new();
    hasher.update(input);
    std::hint::black_box(hasher.finalize());
}

/// Measures each case in `cases` and returns its cost in ns per call.
///
/// Each case is `(batch, f)`: one sample times `batch` back-to-back calls of `f`. Cases are
/// sampled round-robin `samples` times after one untimed warm-up round, and each case's result
/// is its **fastest** sample divided by `batch`. Pick `batch` so that a sample is short (tens to
/// hundreds of microseconds): long enough that `Instant` resolution does not matter, short enough
/// that most samples complete inside one scheduler time slice.
fn min_ns_per_call(cases: &[(usize, &dyn Fn())], samples: usize) -> Vec<f64> {
    assert!(samples > 0);
    for &(batch, f) in cases {
        for _ in 0..batch {
            f();
        }
    }

    let mut best = vec![Duration::MAX; cases.len()];
    for _ in 0..samples {
        for (best, &(batch, f)) in best.iter_mut().zip(cases) {
            let start = Instant::now();
            for _ in 0..batch {
                f();
            }
            *best = (*best).min(start.elapsed());
        }
    }

    best.iter()
        .zip(cases)
        .map(|(t, &(batch, _))| t.as_nanos() as f64 / batch as f64)
        .collect()
}

/// Mean ns per call of `D` over `input`, as the minimum over [`SAMPLES`] batches.
#[cfg(not(tarpaulin))]
fn ns_per_hash<D: Digest>(input: &[u8]) -> u128 {
    let f = || hash_once::<D>(input);
    min_ns_per_call(&[(64, &f)], SAMPLES)[0] as u128
}

/// Test SHA3-256 performance baseline
#[test]
#[cfg(not(tarpaulin))]
fn test_sha3_256_performance() {
    let avg_time_ns = ns_per_hash::<Sha3_256>(b"test input for performance analysis");

    // Performance should be within reasonable bounds
    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "SHA3-256 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test SHA3-224 performance
#[test]
#[cfg(not(tarpaulin))]
fn test_sha3_224_performance() {
    let avg_time_ns = ns_per_hash::<Sha3_224>(b"test input for SHA3-224 performance analysis");

    // SHA3-224 should be similar to SHA3-256 (same number of rounds)
    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "SHA3-224 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test SHA3-384 performance
#[test]
#[cfg(not(tarpaulin))]
fn test_sha3_384_performance() {
    let avg_time_ns = ns_per_hash::<Sha3_384>(b"test input for SHA3-384 performance analysis");

    // SHA3-384 has a smaller rate than SHA3-256, so long inputs need more permutations
    assert!(
        avg_time_ns < (BASELINE_SHA3_256_NS * 2) as u128,
        "SHA3-384 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS * 2
    );
}

/// Test SHA3-512 performance
#[test]
#[cfg(not(tarpaulin))]
fn test_sha3_512_performance() {
    let avg_time_ns = ns_per_hash::<Sha3_512>(b"test input for SHA3-512 performance analysis");

    // SHA3-512 has the smallest rate of the family, so long inputs need the most permutations
    assert!(
        avg_time_ns < (BASELINE_SHA3_256_NS * 3) as u128,
        "SHA3-512 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS * 3
    );
}

/// Test performance scaling with input size
#[test]
fn test_performance_scaling() {
    // SHA3-256 absorbs 136 bytes per Keccak-f[1600] call: 1, 8 and 74 permutations respectively.
    let small_input: &[u8] = b"small input";
    let medium_input: &[u8] = &[0x42u8; 1000];
    let large_input: &[u8] = &[0x42u8; 10000];

    let small = || hash_once::<Sha3_256>(small_input);
    let medium = || hash_once::<Sha3_256>(medium_input);
    let large = || hash_once::<Sha3_256>(large_input);
    // Batches sized so each sample does roughly the same amount of absorbing work.
    let ns = min_ns_per_call(&[(64, &small), (8, &medium), (1, &large)], SAMPLES);
    let (small_ns, medium_ns, large_ns) = (ns[0], ns[1], ns[2]);

    // Verify that performance scales reasonably with input size
    let small_to_medium_ratio = medium_ns / small_ns;
    let medium_to_large_ratio = large_ns / medium_ns;

    // Medium input should be slower than small input
    assert!(
        small_to_medium_ratio > 1.5,
        "Medium input should be slower than small input, got ratio: {} (ns/op small={}, medium={})",
        small_to_medium_ratio,
        small_ns,
        medium_ns
    );

    // Large input should be slower than medium input
    assert!(
        medium_to_large_ratio > 1.5,
        "Large input should be slower than medium input, got ratio: {} (ns/op medium={}, large={})",
        medium_to_large_ratio,
        medium_ns,
        large_ns
    );
}

/// Test performance consistency across multiple runs
#[test]
fn test_performance_consistency() {
    let test_input = b"test input for performance consistency";
    // Each run is the best of SUB_SAMPLES batches (~10k hashes per run in total), so a run
    // reports the undisturbed cost of the code; the spread across runs then measures how
    // repeatable that cost is, not how busy the host was while it ran.
    const RUNS: usize = 12;
    const SUB_SAMPLES: usize = 16;
    const BATCH: usize = 625;
    const TRIM_EACH_SIDE: usize = 2;

    let hash = || hash_once::<Sha3_256>(test_input);
    let measure_cv = || -> (f64, Vec<f64>) {
        let mut run_ns: Vec<f64> = (0..RUNS)
            .map(|_| min_ns_per_call(&[(BATCH, &hash)], SUB_SAMPLES)[0])
            .collect();
        let reported = run_ns.clone();

        run_ns.sort_by(f64::total_cmp);
        let trimmed = &run_ns[TRIM_EACH_SIDE..run_ns.len() - TRIM_EACH_SIDE];
        let avg = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
        let variance =
            trimmed.iter().map(|&t| (t - avg) * (t - avg)).sum::<f64>() / trimmed.len() as f64;
        (variance.sqrt() / avg, reported)
    };

    let (first_cv, first_ns) = measure_cv();
    eprintln!(
        "consistency check attempt 1: cv={:.6}, run_ns_per_op={:?}",
        first_cv, first_ns
    );

    // Retry once before failing to absorb occasional noisy host scheduling windows.
    let (second_cv, second_ns) = measure_cv();
    eprintln!(
        "consistency check attempt 2: cv={:.6}, run_ns_per_op={:?}",
        second_cv, second_ns
    );

    let best_cv = first_cv.min(second_cv);
    // Coefficient of variation: lenient cap for shared CI hosts (VM timer / CPU noise).
    const MAX_CV: f64 = 0.35;
    assert!(
        best_cv < MAX_CV,
        "Performance too inconsistent: best coefficient of variation {} (expected < {}), attempt1={}, attempt2={}",
        best_cv,
        MAX_CV,
        first_cv,
        second_cv
    );
}

/// Test that different hash algorithms have expected performance relationships
#[test]
fn test_algorithm_performance_relationships() {
    // The cost of a SHA-3 hash is set by its sponge rate: one Keccak-f[1600] permutation per
    // rate-sized block absorbed. Check the rates themselves first; they are exact.
    let rate_256 = <Sha3_256 as BlockSizeUser>::block_size();
    let rate_512 = <Sha3_512 as BlockSizeUser>::block_size();
    assert_eq!(rate_256, 136, "SHA3-256 rate (bytes per permutation)");
    assert_eq!(rate_512, 72, "SHA3-512 rate (bytes per permutation)");

    // A 1 KiB input costs SHA3-256 8 permutations and SHA3-512 15, so SHA3-512 should take
    // roughly twice as long. Short inputs fit one block for both and would compare equal
    // permutation counts, which tests less.
    let test_input = [0x5Au8; 1024];
    let perms = |rate: usize| (test_input.len() + 1).div_ceil(rate);
    assert_eq!((perms(rate_256), perms(rate_512)), (8, 15));

    let sha3_256 = || hash_once::<Sha3_256>(&test_input);
    let sha3_512 = || hash_once::<Sha3_512>(&test_input);
    let ns = min_ns_per_call(&[(16, &sha3_256), (16, &sha3_512)], SAMPLES);
    let (sha3_256_ns, sha3_512_ns) = (ns[0], ns[1]);

    // SHA3-512 can be several times slower than SHA3-256 (smaller sponge rate, longer output).
    const MAX_RATIO_512_TO_256: f64 = 5.0;
    let ratio_512_to_256 = sha3_512_ns / sha3_256_ns;
    eprintln!(
        "ns/op SHA3-256={sha3_256_ns:.0}, SHA3-512={sha3_512_ns:.0}, ratio={ratio_512_to_256:.3}"
    );
    assert!(
        ratio_512_to_256 > 0.5 && ratio_512_to_256 < MAX_RATIO_512_TO_256,
        "SHA3-512 vs SHA3-256 time ratio out of range (expected > 0.5 and < {}), got: {} \
         (ns/op SHA3-256={}, SHA3-512={}; permutation ratio {})",
        MAX_RATIO_512_TO_256,
        ratio_512_to_256,
        sha3_256_ns,
        sha3_512_ns,
        15.0 / 8.0
    );
}
