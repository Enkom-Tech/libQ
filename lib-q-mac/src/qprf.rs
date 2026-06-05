//! Quantum PRF interface (SHAKE256 expansion keyed by secret material).

use lib_q_sha3::Shake256;
use lib_q_sha3::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::profile::QCW_MAC_TAG_BYTES;

const QPRF_DOMAIN: &[u8] = b"lib-q-mac/qprf/v1";

/// Expand a keyed quantum PRF output of `out_len` bytes.
pub fn qprf_eval(
    key: &[u8; 32],
    label: &[u8],
    input: &[u8],
    out_len: usize,
) -> alloc::vec::Vec<u8> {
    let mut shake = Shake256::default();
    shake.update(QPRF_DOMAIN);
    shake.update(key);
    shake.update(&[label.len() as u8]);
    shake.update(label);
    shake.update(input);
    let mut reader = shake.finalize_xof();
    let mut out = alloc::vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Fixed-length qPRF tag (32 bytes).
#[must_use]
pub fn qprf_tag(key: &[u8; 32], label: &[u8], input: &[u8]) -> [u8; QCW_MAC_TAG_BYTES] {
    let v = qprf_eval(key, label, input, QCW_MAC_TAG_BYTES);
    let mut tag = [0u8; QCW_MAC_TAG_BYTES];
    tag.copy_from_slice(&v);
    tag
}
