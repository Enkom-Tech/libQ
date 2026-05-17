//! One-shot helpers match `Digest::digest` on the corresponding types.

use digest::Digest;
use lib_q_keccak_digest::{
    Keccak224,
    Keccak256,
    Keccak256Full,
    Keccak384,
    Keccak512,
    keccak_224,
    keccak_256,
    keccak_256_full,
    keccak_384,
    keccak_512,
};

#[test]
fn one_shot_matches_typed_digest_empty() {
    let d: &[u8] = b"";
    assert_eq!(keccak_224(d).as_slice(), Keccak224::digest(d).as_slice());
    assert_eq!(keccak_256(d).as_slice(), Keccak256::digest(d).as_slice());
    assert_eq!(keccak_384(d).as_slice(), Keccak384::digest(d).as_slice());
    assert_eq!(keccak_512(d).as_slice(), Keccak512::digest(d).as_slice());
    assert_eq!(
        keccak_256_full(d).as_slice(),
        Keccak256Full::digest(d).as_slice()
    );
}

#[test]
fn one_shot_matches_typed_digest_short() {
    let d: &[u8] = b"lib-q one-shot keccak";
    assert_eq!(keccak_224(d).as_slice(), Keccak224::digest(d).as_slice());
    assert_eq!(keccak_256(d).as_slice(), Keccak256::digest(d).as_slice());
    assert_eq!(keccak_384(d).as_slice(), Keccak384::digest(d).as_slice());
    assert_eq!(keccak_512(d).as_slice(), Keccak512::digest(d).as_slice());
    assert_eq!(
        keccak_256_full(d).as_slice(),
        Keccak256Full::digest(d).as_slice()
    );
}
