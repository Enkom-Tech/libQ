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
    Kt128,
    Kt256,
};

struct AlgNameKt128;
impl Display for AlgNameKt128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt128::write_alg_name(f)
    }
}

struct AlgNameKt256;
impl Display for AlgNameKt256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt256::write_alg_name(f)
    }
}

#[test]
fn kt128_alg_name() {
    let s = format!("{}", AlgNameKt128);
    assert_eq!(s, "KT128");
}

#[test]
fn kt256_alg_name() {
    let s = format!("{}", AlgNameKt256);
    assert_eq!(s, "KT256");
}

#[test]
fn kt128_debug_hasher_and_reader() {
    let h = Kt128::new(b"c");
    assert!(!format!("{h:?}").is_empty());
    let mut r = {
        let mut h2 = Kt128::new(b"c");
        h2.update(b"m");
        h2.finalize_xof()
    };
    let mut buf = [0u8; 8];
    r.read(&mut buf);
    assert!(!format!("{r:?}").is_empty());
}

#[test]
fn kt256_debug_hasher_and_reader() {
    let h = Kt256::default();
    assert!(!format!("{h:?}").is_empty());
    let r = {
        let mut h2 = Kt256::default();
        h2.update(b"x");
        h2.finalize_xof()
    };
    assert!(!format!("{r:?}").is_empty());
}
