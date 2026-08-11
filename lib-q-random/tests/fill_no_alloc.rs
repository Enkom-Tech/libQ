//! Regression test: `LibQRng::fill` must write directly into the caller's
//! destination, never through an intermediate heap buffer sized like the
//! request.
//!
//! Card t_b0acaea1: `fill` used to allocate a temporary `Vec<u8>`, fill it
//! with CSPRNG output, copy it into `dest`, then drop it unscrubbed — every
//! caller generating key material via `fill` stranded a copy of that
//! material in freed heap memory. The fix removes the intermediate entirely
//! rather than scrubbing it.
//!
//! We track the *largest single allocation size* observed while `fill` runs,
//! rather than demanding a raw allocation count of zero. Zero-tolerance was
//! tried first and is flaky in practice: the underlying OS entropy backend
//! (e.g. Windows `BCryptGenRandom` via the `getrandom` crate) can perform
//! small allocations of its own on some calls (provider handle/state setup)
//! that have nothing to do with `fill`'s own buffer-management choice.
//! Tracking size instead is still a strict regression test for the actual
//! defect: a reintroduced `vec![0u8; total_bytes]` inside `fill` shows up as
//! a single allocation whose size equals the fill request (4096 bytes for
//! the buffer below), which no plausible unrelated OS-backend allocation
//! would incidentally match.
//!
//! This file gets its own `[[test]]` binary (see `Cargo.toml`) specifically
//! so the counting `#[global_allocator]` below applies to a dedicated
//! process and can't be perturbed by unrelated tests sharing a binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{
    GlobalAlloc,
    Layout,
    System,
};
use std::sync::atomic::{
    AtomicUsize,
    Ordering,
};
use std::sync::{
    Mutex,
    MutexGuard,
};

use lib_q_random::LibQRng;

/// Tracks the largest single allocation size made through the global
/// allocator since it was last reset.
struct MaxSizeAllocator;

static MAX_ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);

fn record(size: usize) {
    MAX_ALLOC_SIZE.fetch_max(size, Ordering::SeqCst);
}

// SAFETY: forwards every call unchanged to `System`; only adds bookkeeping
// before delegating, which does not affect the allocator contract.
unsafe impl GlobalAlloc for MaxSizeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static ALLOCATOR: MaxSizeAllocator = MaxSizeAllocator;

/// Serializes the two tests below, because `MAX_ALLOC_SIZE` is process-global.
///
/// libtest runs a binary's tests on several threads at once. Without this the
/// two tests race on the tracker: each begins with `MAX_ALLOC_SIZE.store(0)`,
/// so whichever starts second wipes the other's recorded maximum between its
/// allocation and its read. That is not hypothetical — it is how this file
/// first failed, with the control reporting `max seen=0` immediately after
/// allocating 4096 bytes.
///
/// The consequence was worse than a flaky failure. When the race went the
/// other way it silenced the CONTROL, and a silent control means the real
/// assertion below (`max_seen < DEST_BYTES`) passes against a tracker that
/// observes nothing — a check that cannot fail, which is exactly what this
/// file exists to rule out.
static TRACKER_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`TRACKER_LOCK`], ignoring poisoning: the guarded state is `()`, so
/// one failing test should not cascade into a `PoisonError` in the other and
/// obscure which assertion actually broke.
fn tracker_lock() -> MutexGuard<'static, ()> {
    TRACKER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Sanity control: prove the tracker actually observes allocator traffic, so
/// a low result for `fill` below is meaningful rather than an inert tracker.
#[test]
fn allocator_tracker_observes_a_deliberate_allocation() {
    let _serialized = tracker_lock();
    MAX_ALLOC_SIZE.store(0, Ordering::SeqCst);
    let v: Vec<u8> = vec![0u8; 4096];
    std::hint::black_box(&v);
    let seen = MAX_ALLOC_SIZE.load(Ordering::SeqCst);
    assert!(
        seen >= 4096,
        "control allocation of 4096 bytes was not observed by the tracker \
         (max seen={seen}) — the harness itself is broken"
    );
}

/// `LibQRng::fill` must not allocate an intermediate buffer sized like the
/// fill request. This fails against the pre-fix implementation, which
/// allocated a `total_bytes`-sized `Vec<u8>` inside `fill` — here that would
/// be a single 4096-byte allocation, tracked as `DEST_BYTES` below.
#[test]
fn fill_performs_no_dest_sized_intermediate_allocation() {
    let _serialized = tracker_lock();
    const DEST_LEN: usize = 1024;
    const DEST_BYTES: usize = DEST_LEN * core::mem::size_of::<u32>(); // 4096

    let mut rng = LibQRng::new_secure().expect("failed to create secure RNG");

    // Warm up: creating the RNG / first entropy pulls may themselves
    // allocate (reseed buffers, provider handle setup, etc). We only care
    // about `fill`'s own allocator footprint, so prime the RNG with an
    // unmeasured call first and reset the tracker right before the call
    // under test.
    let mut warmup = [0u8; 32];
    rng.fill(&mut warmup);

    // Use a large-ish buffer so a reintroduced `vec![0u8; total_bytes]`
    // would be unmistakable, and a non-u8 element type so a `Vec<T>` sized
    // by element count (rather than byte count) would also be caught: at
    // `size_of::<u32>() == 4`, a mis-sized `Vec<u32>` would still land at or
    // above `DEST_BYTES`.
    let mut dest = [0u32; DEST_LEN];

    MAX_ALLOC_SIZE.store(0, Ordering::SeqCst);
    rng.fill(&mut dest);
    let max_seen = MAX_ALLOC_SIZE.load(Ordering::SeqCst);

    assert!(
        max_seen < DEST_BYTES,
        "LibQRng::fill made an allocation of {max_seen} bytes while filling a \
         {DEST_BYTES}-byte destination — looks like a reintroduced \
         dest-sized intermediate buffer (expected all allocations, if any, \
         to be well below the request size)"
    );

    // Not part of the allocation property, but confirms `fill` still did its
    // real job (didn't just skip writing anything).
    assert!(dest.iter().any(|&x| x != 0), "fill left dest all zero");
}
