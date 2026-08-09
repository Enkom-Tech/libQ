//! Quantum PRF interface (SHAKE256 expansion keyed by secret material).

use lib_q_sha3::Shake256;
use lib_q_sha3::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::profile::QCW_MAC_TAG_BYTES;

const QPRF_DOMAIN: &[u8] = b"lib-q-mac/qprf/v1";

/// Maximum `label` length accepted by [`qprf_eval`] / [`qprf_tag`].
///
/// The v1 domain absorbs the label length as a **single byte**, so a label of 256 bytes would
/// absorb prefix `0x00` — identical to the empty label — and `qprf_eval(k, L256, x)` would equal
/// `qprf_eval(k, &[], L256 || x)`. The prefix is rejected rather than widened so that every
/// already-valid (<= 255 byte) label keeps its v1 output and every deployed tag keeps verifying.
pub const QPRF_MAX_LABEL_BYTES: usize = u8::MAX as usize; // 255

/// Expand a keyed quantum PRF output of `out_len` bytes.
///
/// # Errors
/// Returns [`crate::error::MacError::LabelTooLong`] if `label.len() > QPRF_MAX_LABEL_BYTES`: the
/// single-byte length prefix cannot encode a longer label without wrapping (see
/// [`QPRF_MAX_LABEL_BYTES`]).
#[cfg(feature = "alloc")]
pub fn qprf_eval(
    key: &[u8; 32],
    label: &[u8],
    input: &[u8],
    out_len: usize,
) -> Result<alloc::vec::Vec<u8>, crate::error::MacError> {
    let mut out = alloc::vec![0u8; out_len];
    qprf_eval_into(key, label, input, &mut out)?;
    Ok(out)
}

/// Expand a keyed quantum PRF into a caller-supplied buffer, filling it completely.
///
/// This is the allocation-free form of [`qprf_eval`] and carries the whole implementation;
/// `qprf_eval` is a thin wrapper that owns the buffer. Bare-metal callers should use this or
/// [`qprf_tag`], both of which are available without the `alloc` feature.
///
/// # Errors
/// Returns [`crate::error::MacError::LabelTooLong`] if `label.len() > QPRF_MAX_LABEL_BYTES`: the
/// single-byte length prefix cannot encode a longer label without wrapping (see
/// [`QPRF_MAX_LABEL_BYTES`]).
pub fn qprf_eval_into(
    key: &[u8; 32],
    label: &[u8],
    input: &[u8],
    out: &mut [u8],
) -> Result<(), crate::error::MacError> {
    if label.len() > QPRF_MAX_LABEL_BYTES {
        return Err(crate::error::MacError::LabelTooLong);
    }
    let mut shake = Shake256::default();
    shake.update(QPRF_DOMAIN);
    shake.update(key);
    shake.update(&[label.len() as u8]);
    shake.update(label);
    shake.update(input);
    let mut reader = shake.finalize_xof();
    reader.read(out);
    Ok(())
}

/// Fixed-length qPRF tag (32 bytes).
///
/// # Errors
/// Returns [`crate::error::MacError::LabelTooLong`] under the same condition as [`qprf_eval`].
pub fn qprf_tag(
    key: &[u8; 32],
    label: &[u8],
    input: &[u8],
) -> Result<[u8; QCW_MAC_TAG_BYTES], crate::error::MacError> {
    // Stack buffer, not `qprf_eval`: this returns a fixed-size array, so allocating to produce
    // it made the one API that is usable bare-metal depend on `alloc` for no reason.
    let mut tag = [0u8; QCW_MAC_TAG_BYTES];
    qprf_eval_into(key, label, input, &mut tag)?;
    Ok(tag)
}
