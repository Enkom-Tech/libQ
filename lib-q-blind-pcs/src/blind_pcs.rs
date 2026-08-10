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

/// Domain separator, and the crate's **format version**. It moves whenever the commitment bytes
/// move — that is the whole point of the version suffix, and it has already failed to once.
///
/// Format history, because a commitment is a bare 32-byte hash with no room for a version field,
/// so this label is the only thing that distinguishes formats:
///
/// | label | hash | notes |
/// |---|---|---|
/// | `-v1` | SHA-256 | original |
/// | `-v1` | SHA3-256 | `df33c57` swapped the hash and **left the label alone** — so `-v1` named two mutually unverifiable formats |
/// | `-v2` | SHA3-256 | current; the label moved to match the bytes |
///
/// `df33c57` was a policy win (it emptied `classical-crypto-allowlist.txt`) and neutral on
/// security — both are 256-bit-output hashes, and binding/hiding rest on collision/preimage
/// resistance either way. The defect was that every stored commitment silently stopped verifying,
/// with `verify == false` indistinguishable from tampering, and nothing in the tree could detect
/// it: every test was a same-process round-trip that stays green across any hash swap.
///
/// Changing this constant is a **wire break**. If you change it, update
/// `tests/commitment_kat.rs`, whose expected values come from an independent SHA3-256
/// implementation rather than from this code.
const DOMAIN: &[u8] = b"lib-q-blind-pcs-v2";

// SHA3-256 rather than SHAKE/K12: fixed 32-byte output, matching the commitment type.
fn hash_commitment(message: &[u8], blind: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN);
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
