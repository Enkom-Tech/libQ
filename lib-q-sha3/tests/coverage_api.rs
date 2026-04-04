//! Exercises public helpers and traits that are easy to miss in line coverage
//! (`sha256`, `AlgorithmName`, `Debug`, state serialization, cSHAKE customization
//! paths, TurboSHAKE reset).

use core::fmt::{
    self,
    Display,
};

use digest::block_api::AlgorithmName;
use digest::common::hazmat::SerializableState;
use digest::{
    CustomizedInit,
    Digest,
    ExtendableOutput,
    ExtendableOutputReset,
    Update,
    XofReader,
};
use lib_q_sha3::block_api::{
    CShake128Core,
    CShake256Core,
};

struct AlgName<T: AlgorithmName>(core::marker::PhantomData<T>);

impl<T: AlgorithmName> Display for AlgName<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)
    }
}

fn alg_name_string<T: AlgorithmName>() -> String {
    format!("{}", AlgName::<T>(core::marker::PhantomData))
}

#[test]
fn sha256_matches_sha3_256_digest() {
    let data = b"lib-q-sha3 coverage";
    let a = lib_q_sha3::sha256(data);
    let b = lib_q_sha3::Sha3_256::digest(data);
    assert_eq!(a, b.as_slice());
}

#[test]
fn sha3_256_alg_name_and_debug() {
    let hasher = lib_q_sha3::Sha3_256::new();
    let name = alg_name_string::<lib_q_sha3::Sha3_256>();
    assert!(name.contains("Sha3"), "unexpected name: {name}");

    let dbg = format!("{hasher:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn shake128_alg_name_and_debug() {
    let hasher = lib_q_sha3::Shake128::default();
    let name = alg_name_string::<lib_q_sha3::Shake128>();
    assert!(!name.is_empty());

    let dbg = format!("{hasher:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn sha3_256_serializable_state_roundtrip() {
    let mut h = lib_q_sha3::Sha3_256::new();
    Digest::update(&mut h, b"partial");
    let state = h.serialize();
    let mut h2 = lib_q_sha3::Sha3_256::deserialize(&state).unwrap();
    Digest::update(&mut h2, b" rest");
    Digest::update(&mut h, b" rest");
    assert_eq!(h.finalize(), h2.finalize());
}

#[test]
fn shake128_serializable_state_roundtrip() {
    let mut h = lib_q_sha3::Shake128::default();
    h.update(b"abc");
    let state = h.serialize();
    let mut h2 = lib_q_sha3::Shake128::deserialize(&state).unwrap();
    h2.update(b"def");
    h.update(b"def");
    let mut o1 = [0u8; 32];
    let mut o2 = [0u8; 32];
    h.finalize_xof_into(&mut o1);
    h2.finalize_xof_into(&mut o2);
    assert_eq!(o1, o2);
}

#[test]
fn cshake128_customized_differs_from_plain_shake() {
    let mut plain = lib_q_sha3::CShake128::default();
    plain.update(b"x");
    let mut custom = lib_q_sha3::CShake128::new_customized(b"app");
    custom.update(b"x");

    let mut p = [0u8; 16];
    let mut c = [0u8; 16];
    plain.finalize_xof_into(&mut p);
    custom.finalize_xof_into(&mut c);
    assert_ne!(p, c);
}

#[test]
fn cshake128_with_function_name_matches_customized_when_fn_empty() {
    let mut a = lib_q_sha3::CShake128::new_customized(b"Email Signature");
    let mut b = lib_q_sha3::CShake128::new_with_function_name(&[], b"Email Signature");
    a.update(b"msg");
    b.update(b"msg");
    let mut oa = [0u8; 32];
    let mut ob = [0u8; 32];
    a.finalize_xof_into(&mut oa);
    b.finalize_xof_into(&mut ob);
    assert_eq!(oa, ob);
}

#[test]
fn cshake128_non_empty_function_name_path() {
    let mut h = lib_q_sha3::CShake128::new_with_function_name(b"KMAC", b"");
    h.update(b"");
    let mut out = [0u8; 32];
    h.finalize_xof_into(&mut out);
    let mut h2 = lib_q_sha3::CShake128::new_with_function_name(b"KMAC", b"");
    h2.update(b"");
    let mut out2 = [0u8; 32];
    h2.finalize_xof_into(&mut out2);
    assert_eq!(out, out2);
}

#[test]
fn cshake_core_serializable_state_roundtrip() {
    let c128 = CShake128Core::new_with_function_name(b"fn", b"custom");
    let s128 = c128.serialize();
    let c128_2 = CShake128Core::deserialize(&s128).unwrap();
    assert_eq!(c128.serialize(), c128_2.serialize());

    let c256 = CShake256Core::new_customized(b"domain");
    let s256 = c256.serialize();
    let c256_2 = CShake256Core::deserialize(&s256).unwrap();
    assert_eq!(c256.serialize(), c256_2.serialize());
}

#[test]
fn turboshake_finalize_xof_reset_matches_finalize() {
    let mut h = lib_q_sha3::TurboShake128::<6>::default();
    h.update(b"chunk");
    let mut r = h.finalize_xof_reset();
    let mut buf = [0u8; 40];
    r.read(&mut buf);

    let mut h2 = lib_q_sha3::TurboShake128::<6>::default();
    h2.update(b"chunk");
    let mut r2 = h2.finalize_xof();
    let mut buf2 = [0u8; 40];
    r2.read(&mut buf2);

    assert_eq!(buf, buf2);

    let mut r3 = h.finalize_xof_reset();
    let mut out3 = [0u8; 16];
    r3.read(&mut out3);

    let fresh = lib_q_sha3::TurboShake128::<6>::default();
    let mut r4 = fresh.finalize_xof();
    let mut out4 = [0u8; 16];
    r4.read(&mut out4);
    assert_eq!(out3, out4);
}

#[test]
fn turboshake_reader_debug() {
    let h = lib_q_sha3::TurboShake128::<6>::default();
    let r = h.finalize_xof();
    let s = format!("{r:?}");
    assert!(!s.is_empty());
}

#[test]
fn turboshake_hasher_alg_name_and_debug() {
    let h = lib_q_sha3::TurboShake128::<6>::default();
    let name = alg_name_string::<lib_q_sha3::TurboShake128<6>>();
    assert!(!name.is_empty());
    let dbg = format!("{h:?}");
    assert!(!dbg.is_empty());
}
