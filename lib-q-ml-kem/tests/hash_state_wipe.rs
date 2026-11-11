//! The hashers behind ML-KEM's G, H, J, PRF and XOF are keyed by secrets (`d`, `sigma`, `z`, the
//! KEM coins). `lib-q-ml-kem` must build `lib-q-sha3` with its `zeroize` feature so those states
//! (Keccak lanes *and* the absorbed-input block buffer) are cleared when dropped.
//!
//! Method: build the value in a heap slot, snapshot its bytes, run its destructor in place, then
//! look for surviving content. Windows of the pre-drop image are compared, not "all bytes zero",
//! so padding bytes cannot make the test flaky. Without `features = ["zeroize"]` on the
//! `lib-q-sha3` dependency this fails: the absorbed seed is still in the freed slot.
use std::mem::{MaybeUninit, size_of};

use lib_q_sha3::digest::{ExtendableOutput, Update, XofReader};
use lib_q_sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake128Reader, Shake256, Shake256Reader};

const WINDOW: usize = 16;

fn snapshot<T>(slot: &MaybeUninit<T>) -> Vec<u8> {
    let p = slot.as_ptr().cast::<u8>();
    // SAFETY: `p` points at `size_of::<T>()` bytes of a live, zero-initialised allocation.
    (0..size_of::<T>())
        .map(|i| unsafe { core::ptr::read_volatile(p.add(i)) })
        .collect()
}

/// Number of non-zero `WINDOW`-byte windows of `before` that still appear in `after`.
fn survivors(before: &[u8], after: &[u8]) -> usize {
    before
        .windows(WINDOW)
        .filter(|w| w.iter().any(|&b| b != 0))
        .filter(|w| after.windows(WINDOW).any(|a| a == *w))
        .count()
}

/// Build `value`, drop it in place, and return `(non-zero windows before, windows surviving)`.
fn drop_and_scan<T>(value: T) -> (usize, usize) {
    let mut slot: Box<MaybeUninit<T>> = Box::new_zeroed();
    slot.write(value);
    let before = snapshot(&slot);
    let live = before
        .windows(WINDOW)
        .filter(|w| w.iter().any(|&b| b != 0))
        .count();
    // SAFETY: `slot` holds an initialised `T` that is never used again.
    unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
    (live, survivors(&before, &snapshot(&slot)))
}

fn secret() -> [u8; 32] {
    core::array::from_fn(|i| 0xA0 ^ (i as u8).wrapping_mul(7))
}

fn assert_wiped((live, left): (usize, usize), what: &str) {
    assert!(live > 0, "{what}: control failed, nothing was in the state");
    assert_eq!(left, 0, "{what}: {left} of {live} windows survived drop");
}

#[test]
fn shake256_hasher_wipes_absorbed_seed() {
    let mut h = Shake256::default();
    h.update(&secret());
    assert_wiped(drop_and_scan(h), "Shake256 hasher");
}

#[test]
fn shake128_hasher_wipes_absorbed_seed() {
    let mut h = Shake128::default();
    h.update(&secret());
    assert_wiped(drop_and_scan(h), "Shake128 hasher");
}

#[test]
fn shake256_reader_wipes_squeezed_state() {
    let mut h = Shake256::default();
    h.update(&secret());
    let mut r: Shake256Reader = h.finalize_xof();
    let mut out = [0u8; 16];
    r.read(&mut out);
    assert_wiped(drop_and_scan(r), "Shake256 reader");
}

#[test]
fn shake128_reader_wipes_squeezed_state() {
    let mut h = Shake128::default();
    h.update(&secret());
    let mut r: Shake128Reader = h.finalize_xof();
    let mut out = [0u8; 16];
    r.read(&mut out);
    assert_wiped(drop_and_scan(r), "Shake128 reader");
}

#[test]
fn sha3_512_wipes_absorbed_seed() {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, secret());
    assert_wiped(drop_and_scan(h), "Sha3_512 (G)");
}

#[test]
fn sha3_256_wipes_absorbed_input() {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, secret());
    assert_wiped(drop_and_scan(h), "Sha3_256 (H)");
}
