//! `SaturninAead::{encrypt,decrypt}_in_place_detached` must not touch the heap.
//!
//! A counting global allocator records every `alloc`/`realloc` made by the current thread while a
//! flag is set; the flag is thread-local, so the test harness's own threads cannot pollute the
//! count. The sizes cover the scalar CTR tail, exact block multiples and, at 600 bytes, two full
//! 8-lane CTR batches (the path that, under `simd-avx2`, used to build a fresh core per batch).
//! Run with `--features simd` on an AVX2 host to exercise that kernel.

#![cfg(all(feature = "alloc", feature = "aead"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use lib_q_saturnin::SaturninAead;

struct CountingAlloc;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

fn note_alloc() {
    // `try_with`: the thread-locals may already be gone while a thread is being torn down.
    let _ = COUNTING.try_with(|on| {
        if on.get() {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        }
    });
}

// SAFETY: forwards every call to `System` unchanged; only counts.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_alloc();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Heap allocations the current thread makes while running `f`.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    ALLOCS.with(|n| n.set(0));
    COUNTING.with(|on| on.set(true));
    let r = f();
    COUNTING.with(|on| on.set(false));
    (r, ALLOCS.with(Cell::get))
}

#[test]
fn counting_allocator_sees_a_heap_allocation() {
    // Negative control: without it, a broken counter would make the real test vacuous.
    let (v, n) = allocations_during(|| std::hint::black_box(vec![0u8; 64]));
    drop(v);
    assert!(n >= 1, "counting allocator missed a Vec allocation");
}

#[test]
fn in_place_detached_paths_do_not_allocate() {
    let aead = SaturninAead::new();
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 16];
    let ad = [0x5Au8; 47];
    let mut storage = [0u8; 600];

    for len in [0usize, 1, 31, 32, 33, 255, 256, 257, 600] {
        for (i, b) in storage[..len].iter_mut().enumerate() {
            *b = i as u8;
        }
        let buf = &mut storage[..len];

        let (tag, n) =
            allocations_during(|| aead.encrypt_in_place_detached(&key, &nonce, &ad, buf));
        let tag = tag.expect("encrypt");
        assert_eq!(
            n, 0,
            "encrypt_in_place_detached allocated {n} times at len={len}"
        );

        let (res, n) =
            allocations_during(|| aead.decrypt_in_place_detached(&key, &nonce, &ad, buf, &tag));
        res.expect("decrypt");
        assert_eq!(
            n, 0,
            "decrypt_in_place_detached allocated {n} times at len={len}"
        );
        assert!(
            buf.iter().enumerate().all(|(i, &b)| b == i as u8),
            "round trip at len={len}"
        );
    }
}
