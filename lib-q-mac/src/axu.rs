//! Epsilon-almost XOR-universal hash used in the Boneh-Zhandry qCW-MAC construction.

use lib_q_sha3::Shake256;
use lib_q_sha3::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::profile::QCW_MAC_TAG_BYTES;

const AXU_DOMAIN: &[u8] = b"lib-q-mac/axu/v1";

/// Keyed epsilon-AXU digest over `(ad, msg)`.
#[must_use]
pub fn epsilon_axu(key: &[u8; 32], ad: &[u8], msg: &[u8]) -> [u8; QCW_MAC_TAG_BYTES] {
    let mut shake = Shake256::default();
    shake.update(AXU_DOMAIN);
    shake.update(key);
    shake.update(&(ad.len() as u32).to_le_bytes());
    shake.update(ad);
    shake.update(&(msg.len() as u32).to_le_bytes());
    shake.update(msg);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; QCW_MAC_TAG_BYTES];
    reader.read(&mut out);
    out
}
