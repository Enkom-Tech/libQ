//! Exercises `AlgorithmName` and `Debug` on public types (often missed when tests only use
//! `finalize_boxed` / `ExtendableOutput` helpers).

use core::fmt::{
    self,
    Display,
};

use lib_q_k12::digest::block_api::AlgorithmName;
use lib_q_k12::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_k12::{
    KangarooTwelve,
    KangarooTwelve256,
};

struct AlgNameKt128;
impl Display for AlgNameKt128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        KangarooTwelve::write_alg_name(f)
    }
}

struct AlgNameKt256;
impl Display for AlgNameKt256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        KangarooTwelve256::write_alg_name(f)
    }
}

#[test]
fn kangaroo_twelve_alg_name() {
    let s = format!("{}", AlgNameKt128);
    assert!(s.contains("KangarooTwelve"), "unexpected: {s}");
}

#[test]
fn kangaroo_twelve256_alg_name() {
    let s = format!("{}", AlgNameKt256);
    assert!(s.contains("KangarooTwelve256"), "unexpected: {s}");
}

#[test]
fn kangaroo_twelve_debug_hasher_and_reader() {
    let h = KangarooTwelve::new(b"c");
    assert!(!format!("{h:?}").is_empty());
    let mut r = {
        let mut h2 = KangarooTwelve::new(b"c");
        h2.update(b"m");
        h2.finalize_xof()
    };
    let mut buf = [0u8; 8];
    r.read(&mut buf);
    assert!(!format!("{r:?}").is_empty());
}

#[test]
fn kangaroo_twelve256_debug_hasher_and_reader() {
    let h = KangarooTwelve256::default();
    assert!(!format!("{h:?}").is_empty());
    let r = {
        let mut h2 = KangarooTwelve256::default();
        h2.update(b"x");
        h2.finalize_xof()
    };
    assert!(!format!("{r:?}").is_empty());
}
