//! Serial-vs-parallel behavioural equivalence for the `lib-q-stark-rayon` shim.
//!
//! This single source file is compiled TWICE by CI/the reporting agent: once with the default
//! (serial, `core`-backed) configuration and once with `--features parallel` (real `rayon`
//! backend). Because the shim's whole purpose is to present one API over two backends, every test
//! here is written purely against `lib_q_stark_rayon::prelude::*` / `lib_q_stark_rayon::iter` and
//! asserts against an expected value computed independently (plain slice/iterator arithmetic that
//! does not go through the shim at all). If both compilations agree with that independent
//! reference, they agree with each other — this is the only way to check "equivalence" here, since
//! a single compilation only ever has one backend linked in (the two are feature-exclusive: the
//! `parallel` feature pulls in `rayon`, its absence removes the dependency entirely).
//!
//! The combinator this crate exists to get right is [`SharedExt::par_fold_reduce`]: on the
//! parallel backend it is `fold(..).reduce(..)`, on the serial backend it collapses to a single
//! `fold` and *ignores* `reduce_op` entirely (only one partial accumulator ever exists). That is
//! only correct if callers only ever pass an associative/commutative combination — which is
//! exactly the class of bug this file is meant to catch if it regresses (see the negative control
//! in the report: hard-coding the fold to ignore its input reproduces the exact "computes something
//! else, not slower" failure mode described in the task).

use lib_q_stark_rayon::iter as pariter;
use lib_q_stark_rayon::prelude::*;

// ---------------------------------------------------------------------------
// into_par_iter / par_iter / par_iter_mut
// ---------------------------------------------------------------------------

#[test]
fn into_par_iter_preserves_order_and_sum() {
    let v = vec![5, 3, -1, 42, 0, 7];
    let expected_sum: i64 = v.iter().copied().sum();
    let expected_order = v.clone();

    let collected: Vec<i64> = v.into_par_iter().collect();
    assert_eq!(collected, expected_order);
    assert_eq!(collected.iter().sum::<i64>(), expected_sum);
}

#[test]
fn into_par_iter_empty() {
    let v: Vec<i64> = vec![];
    let collected: Vec<i64> = v.into_par_iter().collect();
    assert!(collected.is_empty());
}

#[test]
fn par_iter_matches_serial_reference() {
    let v = vec![10i64, 20, 30, 40];
    let doubled: Vec<i64> = v.par_iter().map(|x| x * 2).collect();
    assert_eq!(doubled, vec![20, 40, 60, 80]);
}

#[test]
fn par_iter_mut_mutates_in_place_in_order() {
    let mut v = vec![1i64, 2, 3, 4, 5];
    v.par_iter_mut().for_each(|x| *x *= 10);
    assert_eq!(v, vec![10, 20, 30, 40, 50]);
}

// ---------------------------------------------------------------------------
// ParallelSlice: chunks / chunks_exact / rchunks / rchunks_exact / windows / split
// ---------------------------------------------------------------------------

#[test]
fn par_chunks_uneven_matches_std_chunks() {
    let data = [1, 2, 3, 4, 5, 6, 7]; // length 7, chunk_size 3 -> [3,3,1]
    let expected: Vec<Vec<i32>> = data.chunks(3).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_chunks(3).map(<[i32]>::to_vec).collect();
    assert_eq!(got, expected);
    assert_eq!(expected.last().unwrap().len(), 1, "sanity: tail is uneven");
}

#[test]
fn par_chunks_exact_drops_uneven_tail() {
    let data = [1, 2, 3, 4, 5, 6, 7]; // length 7, chunk_size 3 -> exact chunks [1,2,3],[4,5,6], tail 7 dropped
    let expected: Vec<Vec<i32>> = data.chunks_exact(3).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_chunks_exact(3).map(<[i32]>::to_vec).collect();
    assert_eq!(expected, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    assert_eq!(
        got, expected,
        "par_chunks_exact must drop the tail exactly like core::slice::chunks_exact"
    );
}

#[test]
fn par_rchunks_uneven_matches_std_rchunks() {
    let data = [1, 2, 3, 4, 5, 6, 7];
    let expected: Vec<Vec<i32>> = data.rchunks(3).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_rchunks(3).map(<[i32]>::to_vec).collect();
    assert_eq!(got, expected);
}

#[test]
fn par_rchunks_exact_drops_head_remainder() {
    let data = [1, 2, 3, 4, 5, 6, 7];
    let expected: Vec<Vec<i32>> = data.rchunks_exact(3).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_rchunks_exact(3).map(<[i32]>::to_vec).collect();
    assert_eq!(expected, vec![vec![5, 6, 7], vec![2, 3, 4]]);
    assert_eq!(got, expected);
}

#[test]
fn par_chunks_on_empty_slice_is_empty() {
    let data: [i32; 0] = [];
    let got: Vec<Vec<i32>> = data.par_chunks(4).map(<[i32]>::to_vec).collect();
    assert!(got.is_empty());
    let got_exact: Vec<Vec<i32>> = data.par_chunks_exact(4).map(<[i32]>::to_vec).collect();
    assert!(got_exact.is_empty());
}

#[test]
fn par_windows_matches_std_windows() {
    let data = [1, 2, 3, 4, 5];
    let expected: Vec<Vec<i32>> = data.windows(3).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_windows(3).map(<[i32]>::to_vec).collect();
    assert_eq!(expected, vec![vec![1, 2, 3], vec![2, 3, 4], vec![3, 4, 5]]);
    assert_eq!(got, expected);
}

#[test]
fn par_split_matches_std_split() {
    let data = [1, 2, 0, 3, 4, 0, 0, 5];
    let expected: Vec<Vec<i32>> = data.split(|x| *x == 0).map(<[i32]>::to_vec).collect();
    let got: Vec<Vec<i32>> = data.par_split(|x| *x == 0).map(<[i32]>::to_vec).collect();
    assert_eq!(got, expected);
}

#[test]
fn par_chunks_mut_and_split_mut_match_std_mutation() {
    let mut a = [1, 2, 3, 4, 5, 6, 7];
    let mut b = a;
    a.chunks_mut(3)
        .for_each(|c| c.iter_mut().for_each(|x| *x *= 2));
    b.par_chunks_mut(3)
        .for_each(|c| c.iter_mut().for_each(|x| *x *= 2));
    assert_eq!(a, b);

    let mut c = [1, 0, 2, 3, 0, 4];
    let mut d = c;
    c.split_mut(|x| *x == 0)
        .for_each(|s| s.iter_mut().for_each(|x| *x += 100));
    d.par_split_mut(|x| *x == 0)
        .for_each(|s| s.iter_mut().for_each(|x| *x += 100));
    assert_eq!(c, d);
}

// ---------------------------------------------------------------------------
// ParIterExt: find_any / flat_map_iter
// ---------------------------------------------------------------------------

#[test]
fn find_any_locates_unique_match() {
    let v = vec![1, 2, 3, 42, 5];
    // Unique match makes "any" order-independent: both backends must return the same element.
    let found = v.into_par_iter().find_any(|&x| x == 42);
    assert_eq!(found, Some(42));
}

#[test]
fn find_any_no_match_is_none() {
    let v = vec![1, 2, 3];
    let found = v.into_par_iter().find_any(|&x| x == 999);
    assert_eq!(found, None);
}

#[test]
fn flat_map_iter_matches_serial_reference() {
    let v = vec![1, 2, 3];
    let expected: Vec<i32> = v.iter().flat_map(|&x| vec![x, x * 10]).collect();
    let got: Vec<i32> = v
        .into_par_iter()
        .flat_map_iter(|x| vec![x, x * 10])
        .collect();
    assert_eq!(expected, vec![1, 10, 2, 20, 3, 30]);
    assert_eq!(got, expected);
}

#[test]
fn flat_map_iter_on_empty_is_empty() {
    let v: Vec<i32> = vec![];
    let got: Vec<i32> = v.into_par_iter().flat_map_iter(|x| vec![x, x]).collect();
    assert!(got.is_empty());
}

// ---------------------------------------------------------------------------
// SharedExt::par_fold_reduce — the associativity-sensitive combinator.
// ---------------------------------------------------------------------------

#[test]
fn par_fold_reduce_sum_matches_plain_sum() {
    let v: Vec<i64> = (1..=1000).collect();
    let expected: i64 = v.iter().sum();
    let got = v
        .into_par_iter()
        .par_fold_reduce(|| 0i64, |acc, x| acc + x, |a, b| a + b);
    assert_eq!(got, expected);
}

#[test]
fn par_fold_reduce_on_empty_returns_identity() {
    // NOTE: `identity()` must be a genuine identity element for `reduce_op` (reduce_op(id, id) ==
    // id), exactly like `rayon::iter::ParallelIterator::reduce`'s documented contract. serial.rs's
    // fallback ignores `reduce_op` and just returns `identity()`, so it looks like *any* value
    // works there — but on the real rayon backend an empty input can still route through
    // `reduce_op(identity(), identity())` (an empty parallel split still yields one folded leaf
    // equal to `identity()`, which `reduce` then folds against the identity accumulator again).
    // With a non-identity "identity" (e.g. `-7` under `+`) this was CONFIRMED to diverge:
    // serial -> -7, parallel -> reduce_op(-7, -7) == -14. See the equivalence-tests report for the
    // reproduction. Use a real identity (`0` for `+`) so both backends agree, as any correct
    // caller must.
    let v: Vec<i64> = vec![];
    let got = v
        .into_par_iter()
        .par_fold_reduce(|| 0i64, |acc, x| acc + x, |a, b| a + b);
    assert_eq!(got, 0);
}

#[test]
fn par_fold_reduce_with_non_identity_seed_diverges_by_design() {
    // REGRESSION PIN, NOT a conformance/spec check: `-7` is deliberately NOT a real additive
    // identity (only `0` is one for `+`), which `SharedExt::par_fold_reduce`'s own doc comment
    // states is a misuse of the contract (`reduce_op(identity(), x) == x` must hold). This test
    // exists to turn that doc-comment claim into something that actually runs and would go red if
    // either backend's numeric behavior on non-conforming input silently changed — this is
    // deliberately checking that the two backends DISAGREE by a specific, measured amount, not
    // that they agree.
    //
    // Values were measured directly against this tree, not invented:
    //   `cargo test -p lib-q-stark-rayon --features parallel -- --nocapture` on a temporary probe
    //   printed -14 for an empty input and -36 for `[1, 2, 3]`, reproduced identically under
    //   `RAYON_NUM_THREADS` in {1, 2, 4, 12} (stable because rayon's split structure for such tiny
    //   inputs does not depend on the configured thread count). The serial backend's value follows
    //   directly from its documented behavior (`fold(identity(), fold_op)`, `reduce_op` never
    //   called): -7 for empty, -7+1+2+3=-1 for `[1,2,3]`.
    //
    //   IMPORTANT: this determinism does NOT extend to larger inputs. The same probe over
    //   `1..=100_000` gave a DIFFERENT parallel-backend result under each `RAYON_NUM_THREADS`
    //   value tried (5000049888 / 5000049524 / 5000047774 / 5000040802 for 1/2/4/12 threads) —
    //   i.e. for a non-conforming "identity", the parallel result is not even deterministic across
    //   machines/thread-pool sizes once real splitting kicks in, so no fixed constant could be
    //   pinned there. That is exactly why this crate cannot "fix" the general divergence: matching
    //   serial and parallel bit-for-bit under a contract violation would require the serial
    //   fallback to replicate rayon's thread-count-dependent split tree, which is neither
    //   deterministic nor something a `no_std`, single-threaded fallback can do. The two backends
    //   are only guaranteed to agree when `identity`/`reduce_op` form a genuine monoid, exactly as
    //   documented — see `par_fold_reduce_sum_matches_plain_sum` /
    //   `par_fold_reduce_on_empty_returns_identity` / `par_fold_reduce_max_matches_plain_max` above
    //   for the contract-respecting (and therefore backend-agnostic) usage.
    let empty: Vec<i64> = vec![];
    let three: Vec<i64> = vec![1, 2, 3];

    let got_empty = empty
        .into_par_iter()
        .par_fold_reduce(|| -7i64, |acc, x| acc + x, |a, b| a + b);
    let got_three = three
        .into_par_iter()
        .par_fold_reduce(|| -7i64, |acc, x| acc + x, |a, b| a + b);

    #[cfg(feature = "parallel")]
    {
        assert_eq!(got_empty, -14, "parallel empty-input regression pin");
        assert_eq!(got_three, -36, "parallel len-3 regression pin");
    }
    #[cfg(not(feature = "parallel"))]
    {
        assert_eq!(
            got_empty, -7,
            "serial empty-input regression pin (fold_op never runs on 0 items; reduce_op ignored)"
        );
        assert_eq!(got_three, -1, "serial len-3 regression pin: -7 + 1 + 2 + 3");
    }
}

#[test]
fn par_fold_reduce_max_matches_plain_max() {
    let v: Vec<i64> = vec![3, -5, 42, 17, -100, 8];
    let expected: i64 = v.iter().copied().max().unwrap();
    let got = v
        .into_par_iter()
        .par_fold_reduce(|| i64::MIN, |acc, x| acc.max(x), |a, b| a.max(b));
    assert_eq!(got, expected);
}

// ---------------------------------------------------------------------------
// join / current_num_threads
// ---------------------------------------------------------------------------

#[test]
fn join_runs_both_closures_and_returns_both_results() {
    let (a, b) = lib_q_stark_rayon::prelude::join(|| 1 + 1, || 2 * 3);
    assert_eq!((a, b), (2, 6));
}

#[test]
fn current_num_threads_is_at_least_one() {
    // Not an equivalence property (thread counts legitimately differ between backends/machines);
    // this is a sanity bound on the API contract only.
    assert!(lib_q_stark_rayon::prelude::current_num_threads() >= 1);
}

// ---------------------------------------------------------------------------
// iter::repeat / iter::repeat_n
// ---------------------------------------------------------------------------

#[test]
fn repeat_take_n_matches_expected() {
    let got: Vec<i32> = pariter::repeat(9).take(4).collect();
    assert_eq!(got, vec![9, 9, 9, 9]);
}

#[test]
fn repeat_n_matches_expected() {
    let got: Vec<i32> = pariter::repeat_n(9, 4).collect();
    assert_eq!(got, vec![9, 9, 9, 9]);
}

#[test]
fn repeat_n_zero_is_empty() {
    let got: Vec<i32> = pariter::repeat_n(9, 0).collect();
    assert!(got.is_empty());
}
