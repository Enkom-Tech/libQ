use lib_q_sha3::{
    Digest,
    Sha3_256,
};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindOpening {
    pub message: Vec<u8>,
    pub blind: Vec<u8>,
}

// SHA3-256 rather than SHAKE/K12: fixed 32-byte output, matching the commitment type.
fn hash_commitment(message: &[u8], blind: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lib-q-blind-pcs-v1");
    hasher.update((message.len() as u64).to_le_bytes());
    hasher.update(message);
    hasher.update((blind.len() as u64).to_le_bytes());
    hasher.update(blind);
    hasher.finalize().into()
}

pub fn blind_commit(message: &[u8], blind: &[u8]) -> [u8; 32] {
    hash_commitment(message, blind)
}

pub fn blind_open(message: &[u8], blind: &[u8]) -> BlindOpening {
    BlindOpening {
        message: message.to_vec(),
        blind: blind.to_vec(),
    }
}

pub fn verify(commitment: &[u8; 32], opening: &BlindOpening) -> bool {
    let expected = hash_commitment(&opening.message, &opening.blind);
    commitment.ct_eq(&expected).into()
}
