//! Empirical proof that `KemSecretKey`, `SigSecretKey`, and `AeadKey` actually wipe
//! their secret bytes when dropped (card t_51797de7).
//!
//! # Why not just read the freed memory back?
//!
//! The straightforward version of this test ("drop the key, then read the bytes at
//! its old address") is undefined behavior: the allocation is gone and the pointer
//! is dangling by the time we would read it. Instead this harness installs a
//! `#[global_allocator]` wrapper that snapshots the watched buffer **inside
//! `GlobalAlloc::dealloc`, before forwarding to the real allocator** — at that point
//! the block is still a live allocation and every byte in it is an initialized
//! `u8`, so reading it is defined behavior. This observes exactly the bytes the
//! allocator (and, in a real attack, a heap-scraper reading freed-but-not-yet-
//! reused memory) would see, without ever dereferencing freed memory ourselves.
//!
//! `#[global_allocator]` is process-wide, but it is scoped to this compiled test
//! *binary* — `cargo test` builds each file under `tests/` as its own binary, and
//! no other global allocator exists anywhere else in this workspace (checked with
//! `git grep -n "global_allocator"` returning no hits outside this file), so there
//! is no conflict.
#![cfg(feature = "alloc")]

use std::alloc::{
    GlobalAlloc,
    Layout,
    System,
};
use std::sync::Mutex;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{
    AtomicBool,
    AtomicUsize,
};

use lib_q_core::{
    AeadKey,
    KemKeypair,
    KemSecretKey,
    SigSecretKey,
};

struct WatchAlloc;

static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static WATCH_ARMED: AtomicBool = AtomicBool::new(false);
static DEALLOC_SEEN: AtomicBool = AtomicBool::new(false);
static NONZERO_AT_DEALLOC: AtomicUsize = AtomicUsize::new(usize::MAX);
static SIZE_AT_DEALLOC: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for WatchAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: forwards verbatim to `System`, which upholds `GlobalAlloc`'s
        // contract given the same (valid, by our caller's obligation) `Layout`.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
        if WATCH_ARMED.load(SeqCst) &&
            ptr as usize == WATCH_PTR.load(SeqCst) &&
            WATCH_ARMED.swap(false, SeqCst)
        // consume: safe against address reuse after this point
        {
            // SAFETY: `ptr` is still a live allocation of size `l.size()` — we are
            // inside `dealloc`, before the call to `System.dealloc` below frees it.
            // Every byte in [ptr, ptr + l.size()) is an initialized `u8`. No freed
            // memory is read.
            let mut nonzero = 0usize;
            for i in 0..l.size() {
                if unsafe { *ptr.add(i) } != 0 {
                    nonzero += 1;
                }
            }
            NONZERO_AT_DEALLOC.store(nonzero, SeqCst);
            SIZE_AT_DEALLOC.store(l.size(), SeqCst);
            DEALLOC_SEEN.store(true, SeqCst);
        }
        // SAFETY: forwards verbatim to `System`; `ptr`/`l` are exactly this
        // function's own parameters, whose validity is our caller's obligation.
        unsafe { System.dealloc(ptr, l) }
    }
}

#[global_allocator]
static WATCHED_ALLOC: WatchAlloc = WatchAlloc;

/// Serializes watched sections: the watcher statics above are process-global, and
/// `cargo test` runs tests in this binary on multiple threads by default.
static WATCH_LOCK: Mutex<()> = Mutex::new(());

/// Watches `buf_addr`, runs `consume` (which must drop the buffer at that address
/// exactly once), and returns `(dealloc_seen, nonzero_bytes_at_dealloc, size_at_dealloc)`.
fn observe_dealloc(buf_addr: usize, consume: impl FnOnce()) -> (bool, usize, usize) {
    DEALLOC_SEEN.store(false, SeqCst);
    NONZERO_AT_DEALLOC.store(usize::MAX, SeqCst);
    SIZE_AT_DEALLOC.store(0, SeqCst);
    WATCH_PTR.store(buf_addr, SeqCst);
    WATCH_ARMED.store(true, SeqCst);
    consume();
    WATCH_ARMED.store(false, SeqCst);
    (
        DEALLOC_SEEN.load(SeqCst),
        NONZERO_AT_DEALLOC.load(SeqCst),
        SIZE_AT_DEALLOC.load(SeqCst),
    )
}

/// Locks the watcher, then asserts that dropping `key` (whose secret buffer lives
/// at `key`'s current `data` pointer) deallocates a fully-zeroed buffer.
macro_rules! assert_wiped_on_drop {
    ($key:expr) => {{
        let _guard = WATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = $key;
        let addr = key.data.as_ptr() as usize;
        let (seen, nonzero, size) = observe_dealloc(addr, move || drop(key));
        assert!(seen, "watched buffer was never deallocated");
        assert_eq!(
            nonzero, 0,
            "secret buffer held {nonzero} nonzero of {size} bytes at dealloc — NOT wiped on drop"
        );
    }};
}

#[test]
fn kem_secret_key_is_wiped_on_drop() {
    assert_wiped_on_drop!(KemSecretKey::new(vec![0xAB; 64]));
}

#[test]
fn sig_secret_key_is_wiped_on_drop() {
    assert_wiped_on_drop!(SigSecretKey::new(vec![0xAB; 64]));
}

#[test]
fn aead_key_is_wiped_on_drop() {
    assert_wiped_on_drop!(AeadKey::new(vec![0xAB; 64]));
}

/// Transitivity: `KemKeypair` does not implement `Drop` itself, but Rust always
/// drops every field of a value going out of scope regardless of whether the
/// containing type implements `Drop` — so the contained `KemSecretKey` must still
/// wipe when the keypair is dropped.
#[test]
fn kem_keypair_secret_is_wiped_on_drop() {
    let _guard = WATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let keypair = KemKeypair::new(vec![0xCD; 8], vec![0xAB; 64]);
    let addr = keypair.secret_key.data.as_ptr() as usize;
    let (seen, nonzero, size) = observe_dealloc(addr, move || drop(keypair));
    assert!(seen, "watched secret-key buffer was never deallocated");
    assert_eq!(
        nonzero, 0,
        "keypair secret buffer held {nonzero} nonzero of {size} bytes at dealloc — NOT wiped on drop"
    );
}

/// Documents a known, intentional limitation rather than silently leaving it
/// unaddressed: `data` is a `pub` field, so a caller can `mem::take` the buffer out
/// from under the key. `Drop` only forbids a true move out of a by-value binding;
/// `mem::take` goes through `&mut` and is legal even on a type that implements
/// `Drop`. Ownership of the secret bytes — and the responsibility to wipe them —
/// transfers to whoever took them; the original key's `Drop` only wipes the empty
/// `Vec` left behind. This test is expected to pass both BEFORE and AFTER the
/// on-drop-wipe fix: it pins today's documented behavior, not the defect. If a
/// future redesign (see the crate-level docs) closes this escape hatch, this test
/// should start failing loudly and its assertion should be inverted.
#[test]
fn mem_take_transfers_wipe_responsibility_away_from_the_key() {
    let _guard = WATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut key = KemSecretKey::new(vec![0xAB; 64]);
    let stolen = std::mem::take(&mut key.data);
    let stolen_addr = stolen.as_ptr() as usize;
    drop(key); // wipes only the now-empty Vec left in `key`.
    let (seen, nonzero, _size) = observe_dealloc(stolen_addr, move || drop(stolen));
    assert!(seen, "stolen buffer was never deallocated");
    assert_eq!(
        nonzero, 64,
        "mem::take transfers wipe responsibility to the caller — update this test \
         (and the crate docs) if that changed"
    );
}
