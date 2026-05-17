//! Public federation ring = ordered list of issuer commitments.

use alloc::vec::Vec;

use lib_q_lattice_zkp::AjtaiCommitment;
use lib_q_lattice_zkp::serialize::write_module_vec;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};

/// Ordered federation members (commitment images under a shared CRS).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationRing {
    pub members: Vec<AjtaiCommitment>,
}

impl FederationRing {
    /// Borrow the member commitment slice.
    #[must_use]
    pub fn as_slice(&self) -> &[AjtaiCommitment] {
        &self.members
    }
}

/// Domain-separated digest of the ring (order-sensitive).
#[must_use]
pub fn federation_digest(ring: &[AjtaiCommitment]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-ring-sig/federation-v1");
    h.update(&(ring.len() as u64).to_le_bytes());
    for c in ring {
        h.update(&write_module_vec(&c.value.0));
    }
    let mut out = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut out);
    out
}
