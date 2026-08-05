//! Falsification test for the qPRF label-length domain separation defect (lane `b-params`).
//!
//! `qprf_eval` absorbs `label.len() as u8` as a single-byte length prefix (`src/qprf.rs`). A
//! label of exactly 256 bytes wrapped that prefix to `0x00`, which is bit-identical to the
//! prefix absorbed for the empty label — so `qprf_eval(k, [0u8; 256], x)` collided with
//! `qprf_eval(k, [], [0u8; 256] || x)`. This was a genuine domain-separation break, not merely a
//! theoretical one: two different non-empty labels (257 bytes vs. 1 byte) collided the same way.
//!
//! Observed RED (before the fix, `qprf_eval` still returned `Vec<u8>` unconditionally):
//! ```text
//! assertion `left != right` failed: 256-byte label must not absorb the same stream as the empty label
//!   left: [141, 97, 222, 187, 162, 50, 113, 159, 5, 225, 176, 178, 243, 31, 98, 129, 187, 219, 250,
//!          24, 161, 135, 196, 5, 42, 250, 17, 17, 67, 127, 53, 118]
//!  right: [141, 97, 222, 187, 162, 50, 113, 159, 5, 225, 176, 178, 243, 31, 98, 129, 187, 219, 250,
//!          24, 161, 135, 196, 5, 42, 250, 17, 17, 67, 127, 53, 118]
//! ```
//! The fix rejects labels above [`lib_q_mac::qprf::QPRF_MAX_LABEL_BYTES`] (255) instead of
//! widening the prefix, so every already-valid label keeps its v1 output bit-for-bit.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_mac::MacError;

#[test]
fn qprf_label_length_prefix_does_not_wrap() {
    let k = [0x11u8; 32];
    let x = b"input-payload";

    // The ambiguous input: a 256-byte label is now rejected outright rather than silently
    // colliding with the empty label.
    assert_eq!(
        lib_q_mac::qprf::qprf_eval(&k, &[0u8; 256], x, 32),
        Err(MacError::LabelTooLong)
    );

    // Boundary: 255 must still succeed, 256 must not.
    assert!(lib_q_mac::qprf::qprf_eval(&k, &[0u8; 255], x, 32).is_ok());
    assert!(lib_q_mac::qprf::qprf_eval(&k, &[0u8; 256], x, 32).is_err());

    // Positive control: the <= 255 regime is unchanged — a short label still separates from the
    // empty-label-plus-concatenated-input encoding (measured `false` at HEAD before the fix too).
    let mut cat3 = Vec::new();
    cat3.extend_from_slice(&[0u8; 3]);
    cat3.extend_from_slice(x);
    assert_ne!(
        lib_q_mac::qprf::qprf_eval(&k, &[0u8; 3], x, 32).unwrap(),
        lib_q_mac::qprf::qprf_eval(&k, &[], &cat3, 32).unwrap(),
    );

    // The 257-vs-1 case the original card missed: two different non-empty labels also collided.
    let label257 = [7u8; 257];
    let label1 = [7u8; 1];
    assert_eq!(
        lib_q_mac::qprf::qprf_eval(&k, &label257, x, 32),
        Err(MacError::LabelTooLong)
    );
    assert!(lib_q_mac::qprf::qprf_eval(&k, &label1, x, 32).is_ok());
}

/// Regression guard (green at HEAD, not a falsification): the committed "baseline" KAT tag
/// (`lib-q-mac/tests/vectors/qcw-mac-v1.json`) must still reproduce bit-for-bit through the fixed
/// `qprf_eval`/`qprf_tag`, because `MAC_LABEL` (3 bytes, `src/qcw_mac.rs`) is far below
/// `QPRF_MAX_LABEL_BYTES` and the absorb stream for that regime is untouched.
/// `cargo test -p lib-q-mac --features host-tests` (`tests/kat_vectors.rs`) already covers this
/// against the vectors file via `tests/common`; the seed here is copied verbatim from
/// `tests/common/mod.rs::KAT_SEED` (not shared via `mod common` to avoid an unused-item
/// `dead_code` warning in this standalone test binary, which only needs `kat_key`).
#[test]
fn qprf_v1_outputs_are_unchanged_for_short_labels() {
    use lib_q_mac::{
        QcwMac,
        QcwMacKey,
    };

    const KAT_SEED: [u8; 32] = [
        0x71, 0x63, 0x77, 0x2D, 0x6D, 0x61, 0x63, 0x2D, 0x76, 0x31, 0x2D, 0x6B, 0x61, 0x74, 0x2D,
        0x73, 0x65, 0x65, 0x64, 0x2D, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    // "6a428c1aab9b75c2c74af6e85256693189427798527eff7b5869158cb5f75b96" — the committed
    // "baseline" `tag_hex` from `tests/vectors/qcw-mac-v1.json`, restated as bytes because `hex`
    // is a host-only (`cfg(not(target_arch = "wasm32"))`) dev-dependency and this test file,
    // unlike the `host-tests`-gated ones, is also compiled for wasm32 test builds.
    const EXPECTED_TAG: [u8; 32] = [
        0x6A, 0x42, 0x8C, 0x1A, 0xAB, 0x9B, 0x75, 0xC2, 0xC7, 0x4A, 0xF6, 0xE8, 0x52, 0x56, 0x69,
        0x31, 0x89, 0x42, 0x77, 0x98, 0x52, 0x7E, 0xFF, 0x7B, 0x58, 0x69, 0x15, 0x8C, 0xB5, 0xF7,
        0x5B, 0x96,
    ];
    let key = QcwMacKey::from_bytes(KAT_SEED);
    let msg = b"hello quantum mac";
    let ad = b"ad0";
    let tag = QcwMac::sign(&key, msg, ad);
    assert_eq!(
        tag.as_slice(),
        EXPECTED_TAG.as_slice(),
        "the committed 'baseline' KAT tag must be unchanged by the label-length-cap fix"
    );
}
