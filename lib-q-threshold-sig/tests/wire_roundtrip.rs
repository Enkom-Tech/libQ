//! Wire round-trip coverage for the retained codecs.
//!
//! **What this test used to do:** run a 3-of-5 ceremony, `aggregate` it into a real signature,
//! then assert the produced wire blob decoded back to that signature. That assertion depended
//! on `aggregate` succeeding, which is precisely the behaviour that has been withdrawn — the
//! ceremony can no longer run, so the old test could not pass. It has been rewritten rather
//! than deleted, so the loss of coverage is visible instead of silent.
//!
//! **What it does now:** exercises the codecs on hand-built bytes, since they are pure
//! serialization and remain live, and pins the fact that `aggregate` no longer supplies input
//! to them. See the crate documentation for why the scheme was withdrawn.

mod common;

#[allow(deprecated)]
use lib_q_threshold_sig::{
    ThresholdSigError,
    aggregate,
    decode_signature,
    decode_threshold_sig_wire_v1,
    encode_signature,
    encode_threshold_sig_wire_v1,
    setup,
};

#[test]
fn wire_roundtrip_is_pure_serialization() {
    let profile = setup();
    let signature = common::inert_signature();
    let signature_bytes = encode_signature(&signature).expect("encode signature");
    let meta = vec![0x77u8; 64];

    let wire =
        encode_threshold_sig_wire_v1(&profile, &signature_bytes, &meta).expect("encode wire");
    let decoded = decode_threshold_sig_wire_v1(&profile, &wire).expect("decode wire");

    assert_eq!(decoded.signature, signature_bytes);
    assert_eq!(decoded.meta, meta);
    assert_eq!(
        decode_signature(&decoded.signature).expect("decode signature"),
        signature,
    );
}

/// The producer side of the old round-trip is gone: nothing can mint a wire blob from a real
/// ceremony any more.
#[test]
#[allow(deprecated)]
fn aggregate_no_longer_supplies_wire_input() {
    let profile = setup();
    let pk = common::inert_public_key();
    let commitments: Vec<_> = (1..=common::THRESHOLD)
        .map(common::inert_commitment)
        .collect();
    let partials: Vec<_> = (1..=common::THRESHOLD).map(common::inert_partial).collect();
    assert_eq!(
        aggregate(&profile, &pk, b"wire", &commitments, &partials).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
    );
}
