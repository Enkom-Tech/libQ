//! Exercises public helpers and traits that are easy to miss in line coverage
//! (`sha3_256`, `AlgorithmName`, `Debug`, state serialization, cSHAKE customization
//! paths, TurboSHAKE reset).

use core::fmt::{
    self,
    Display,
};

use digest::block_api::AlgorithmName;
use digest::common::hazmat::SerializableState;
use digest::consts::{
    U0,
    U32,
    U136,
    U168,
};
use digest::{
    CustomizedInit,
    Digest,
    ExtendableOutput,
    ExtendableOutputReset,
    XofReader,
};
use lib_q_sha3::Update;
use lib_q_sha3::block_api::{
    CShake128Core,
    CShake256Core,
    SpongeHasherCore,
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
fn sha3_256_matches_sha3_256_digest() {
    let data = b"lib-q-sha3 coverage";
    let a = lib_q_sha3::sha3_256(data);
    let b = lib_q_sha3::Sha3_256::digest(data);
    assert_eq!(a, b.as_slice());
}

#[test]
fn sha3_256_alg_name_and_debug() {
    let hasher = lib_q_sha3::Sha3_256::new();
    let name = alg_name_string::<lib_q_sha3::Sha3_256>();
    assert_eq!(name, "SpongeHasherCore");

    let dbg = format!("{hasher:?}");
    assert_eq!(dbg, "Sha3_256 { ... }");
}

#[test]
fn shake128_alg_name_and_debug() {
    let hasher = lib_q_sha3::Shake128::default();
    let name = alg_name_string::<lib_q_sha3::Shake128>();
    assert_eq!(name, "SpongeHasherCore");

    let dbg = format!("{hasher:?}");
    assert_eq!(dbg, "Shake128 { ... }");
}

/// `buffer_fixed!` / `buffer_xof!` forward [`AlgorithmName`] to the core; this pins the core string.
#[test]
fn sponge_hasher_core_alg_name_and_debug() {
    const SHA3_PAD: u8 = 0x06;
    const SHAKE_PAD: u8 = 0x1F;

    let fixed = SpongeHasherCore::<U136, U32, SHA3_PAD>::default();
    assert_eq!(
        alg_name_string::<SpongeHasherCore<U136, U32, SHA3_PAD>>(),
        "SpongeHasherCore"
    );
    assert_eq!(format!("{fixed:?}"), "SpongeHasherCore { ... }");

    let xof = SpongeHasherCore::<U168, U0, SHAKE_PAD>::default();
    assert_eq!(
        alg_name_string::<SpongeHasherCore<U168, U0, SHAKE_PAD>>(),
        "SpongeHasherCore"
    );
    assert_eq!(format!("{xof:?}"), "SpongeHasherCore { ... }");
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
fn cshake128_serializable_state_roundtrip() {
    // `CShake*::serialize` is **core-only**; any bytes still in the `block_buffer` are not
    // preserved. Use a full rate block (168 B) so the buffer is empty after `update`.
    let mut h = lib_q_sha3::CShake128::new_customized(b"Email Signature");
    h.update(&[0u8; 168]);
    let state = h.serialize();
    let mut h2 = lib_q_sha3::CShake128::deserialize(&state).unwrap();
    h2.update(b"tail");
    h.update(b"tail");
    let mut o1 = [0u8; 32];
    let mut o2 = [0u8; 32];
    h.finalize_xof_into(&mut o1);
    h2.finalize_xof_into(&mut o2);
    assert_eq!(o1, o2);
}

/// Two full rate blocks (2×168 B) — boundary around block multiples.
#[test]
fn cshake128_serializable_state_roundtrip_after_two_rate_blocks() {
    let mut h = lib_q_sha3::CShake128::new_customized(b"two blocks");
    h.update(&[1u8; 336]);
    let state = h.serialize();
    let mut h2 = lib_q_sha3::CShake128::deserialize(&state).unwrap();
    h2.update(b"more");
    h.update(b"more");
    let mut o1 = [0u8; 48];
    let mut o2 = [0u8; 48];
    h.finalize_xof_into(&mut o1);
    h2.finalize_xof_into(&mut o2);
    assert_eq!(o1, o2);
}

/// cSHAKE-256 rate 136 B: full block, then round-trip and tail (mirrors 128 test).
#[test]
fn cshake256_serializable_state_roundtrip() {
    let mut h = lib_q_sha3::CShake256::new_customized(b"domain 256");
    h.update(&[0u8; 136]);
    let state = h.serialize();
    let mut h2 = lib_q_sha3::CShake256::deserialize(&state).unwrap();
    h2.update(b"tail");
    h.update(b"tail");
    let mut o1 = [0u8; 32];
    let mut o2 = [0u8; 32];
    h.finalize_xof_into(&mut o1);
    h2.finalize_xof_into(&mut o2);
    assert_eq!(o1, o2);
}

/// One byte short of a full 168 B block — rate buffer is non-empty; serialized façade must not
/// be treated as equivalent to mid-stream (documented: core-only snapshot; buffer cleared).
#[test]
fn cshake128_serialize_at_rate_minus_one_does_not_match_continued_uninterrupted() {
    let customization = b"block boundary check";
    let input167 = [7u8; 167];
    let tail = b"Z";

    let mut uninterrupted = lib_q_sha3::CShake128::new_customized(customization);
    uninterrupted.update(&input167);
    uninterrupted.update(tail);
    let mut out_full = [0u8; 32];
    uninterrupted.finalize_xof_into(&mut out_full);

    let mut snap = lib_q_sha3::CShake128::new_customized(customization);
    snap.update(&input167);
    let st = snap.serialize();
    let mut h2 = lib_q_sha3::CShake128::deserialize(&st).unwrap();
    h2.update(tail);
    let mut out_snap = [0u8; 32];
    h2.finalize_xof_into(&mut out_snap);

    assert_ne!(
        out_full, out_snap,
        "core-only snapshot omits 167 B still in the buffer"
    );
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
    assert_eq!(name, "TurboSHAKE128");
    let dbg = format!("{h:?}");
    assert_eq!(dbg, "TurboShake128 { ... }");
}
